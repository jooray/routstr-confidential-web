/**
 * Protocol v2 proof channel: one long-lived wasm `cu-prover --channel` driver
 * per session, bridged to the node's `zkchan` socket
 * (`/v1/confidential/zk?proof=zkchan`). The OT/VOLE setup of π_NK, π_C2S and
 * π_C3S runs while the session is armed; each proof at claim time then only
 * runs QuickSilver over existing correlations. If the channel fails before
 * any proof started on it, the session falls back to the per-proof path;
 * after that a failure ends the session.
 */

import { ProverError } from "./errors.js";
import { DriverRelay } from "./relay.js";
import type { TwoPcTiming } from "./twopc.js";
import type { WasmHost } from "./wasm/host.js";

export interface ProofChannelResult {
  proof: string;
  ok: boolean;
  checks?: { label: string; ok: boolean }[];
  ms?: number;
  bytes_sent?: number;
  bytes_recv?: number;
  err?: string;
}

type Pending = { res: (m: ProofChannelResult) => void; rej: (e: Error) => void };

export class ProofChannel {
  readonly timings: TwoPcTiming[] = [];
  readonly tStart = Date.now();
  tReady = 0;
  used = false;
  private relay?: DriverRelay;
  private pending = new Map<number, Pending>();
  private nextId = 1;
  private failureErr: Error | undefined;
  private closed = false;
  private readyP: Promise<void>;
  private readyRes!: () => void;
  private readyRej!: (e: Error) => void;

  constructor(
    private readonly host: WasmHost,
    private readonly opts: { prealloc?: { nk?: number; cp?: number }; webSocketImpl?: typeof WebSocket } = {},
  ) {
    this.readyP = new Promise<void>((res, rej) => {
      this.readyRes = res;
      this.readyRej = rej;
    });
    this.readyP.catch(() => {});
  }

  start(url: string): void {
    this.relay = new DriverRelay({
      host: this.host,
      kind: "zkchan",
      driverOptions: { prealloc: this.opts.prealloc },
      url,
      webSocketImpl: this.opts.webSocketImpl,
      label: "proof channel",
      onEvent: (m) => this.onControl(m),
      onFailure: (e) => this.fail(e),
      closeIsNormal: () => this.closed,
    });
    this.relay.start().catch((e: unknown) => this.fail(e instanceof Error ? e : new ProverError(String(e))));
  }

  private onControl(m: Record<string, unknown>): void {
    const ev = typeof m.ev === "string" ? m.ev : "";
    if (ev === "ready") {
      for (const t of (m.timings as TwoPcTiming[] | undefined) ?? []) this.timings.push(t);
      this.tReady = Date.now();
      this.readyRes();
    } else if (ev === "done") {
      const id = Number(m.id);
      const w = this.pending.get(id);
      if (w) {
        this.pending.delete(id);
        w.res(m as unknown as ProofChannelResult);
      }
    } else if (ev === "error") {
      this.fail(new ProverError(`proof channel: ${String(m.msg ?? "unknown error")}`));
    }
  }

  private fail(e: Error): void {
    if (this.failureErr) return;
    this.failureErr = e;
    this.readyRej(e);
    for (const w of this.pending.values()) w.rej(e);
    this.pending.clear();
  }

  get failed(): boolean {
    return this.failureErr !== undefined;
  }

  get failure(): Error | undefined {
    return this.failureErr;
  }

  /** Waits for both correlation chains; false (never throws) if the channel failed or timed out. */
  async ready(ms = 120_000): Promise<boolean> {
    if (this.failureErr) return false;
    let t: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        this.readyP,
        new Promise<never>((_, rej) => {
          t = setTimeout(() => rej(new ProverError("proof channel not ready in time")), ms);
        }),
      ]);
      return !this.failureErr;
    } catch (e) {
      this.fail(e instanceof Error ? e : new ProverError(String(e)));
      return false;
    } finally {
      if (t) clearTimeout(t);
    }
  }

  async run(
    cmd: "prove" | "verify",
    proof: string,
    params: unknown,
    witness?: unknown,
    ms = 60_000,
  ): Promise<ProofChannelResult> {
    if (this.failureErr) throw this.failureErr;
    this.used = true;
    const id = this.nextId++;
    const p = new Promise<ProofChannelResult>((res, rej) => {
      const t = setTimeout(() => {
        this.pending.delete(id);
        rej(new ProverError(`proof channel: ${proof} timed out (${ms}ms)`));
      }, ms);
      this.pending.set(id, {
        res: (m) => {
          clearTimeout(t);
          res(m);
        },
        rej: (e) => {
          clearTimeout(t);
          rej(e);
        },
      });
    });
    this.relay?.command({ cmd, id, proof, params, witness: witness ?? null });
    const m = await p;
    if (!m.ok) throw new ProverError(`proof channel: ${proof} failed: ${m.err ?? "unknown"}`);
    if (cmd === "verify" && !(m.checks ?? []).every((c) => c.ok)) {
      throw new ProverError(`proof channel: ${proof} checks failed`);
    }
    return m;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.relay?.command({ cmd: "close" });
    // Let the driver flush its last bytes before the socket goes.
    this.relay?.close(500);
  }
}
