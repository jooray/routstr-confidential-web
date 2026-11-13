/**
 * A connection's proof channel (protocol v3): one long-lived wasm
 * `cu-prover --channel` driver per connection, bridged to the node's
 * `zkchan` socket (`/v1/confidential/zk?proof=zkchan`). The OT/VOLE setup of
 * π_NK and of the client's proofs (π_WIN, π_C3S: any number, per request and
 * per control record) runs while the connection is armed; each proof then
 * only runs QuickSilver over existing correlations. On a kept framing-"2"
 * connection the correlations are topped up between requests (`topup`,
 * PROTOCOL-V3.md §9.2); a proof that still runs short extends them online. If the channel fails before any proof started on
 * it, the connection falls back to the per-proof path; after that a failure
 * ends the connection.
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

/** Most bytes a proof channel may receive over its connection's life (1 GiB). */
export const ZKCHAN_MAX_INBOUND = 1 << 30;

/** What one top-up did (PROTOCOL-V3.md §9.2). */
export interface ProofChannelTopup {
  /** The node granted a step and the chain was extended. */
  granted: boolean;
  /** Correlations on the proof chain before and after. */
  before: number;
  after: number;
  /** Bytes the top-up moved (both ways). */
  bytes: number;
  ms: number;
}

type Pending = { res: (m: ProofChannelResult) => void; rej: (e: Error) => void };

export class ProofChannel {
  readonly timings: TwoPcTiming[] = [];
  readonly tStart = Date.now();
  tReady = 0;
  used = false;
  /** Top-ups the node granted, in order. */
  readonly topups: ProofChannelTopup[] = [];
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

  /** Bytes on the proof-channel socket, each way. */
  get bytesSent(): number {
    return this.relay?.bytesSent ?? 0;
  }

  get bytesRecv(): number {
    return this.relay?.bytesRecv ?? 0;
  }

  start(url: string): void {
    this.relay = new DriverRelay({
      host: this.host,
      kind: "zkchan",
      driverOptions: { prealloc: this.opts.prealloc },
      url,
      webSocketImpl: this.opts.webSocketImpl,
      label: "proof channel",
      // A kept framing-"2" connection runs a π_WIN and a π_C3S per request
      // (up to the offer's h2.max_requests, 100 on the shipped node) and
      // extends its correlations online: the per-socket budget is the
      // connection's, not one session's.
      maxInbound: ZKCHAN_MAX_INBOUND,
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
    this.relay?.command({ cmd, id, proof, params, witness: witness ?? null, timeout_ms: ms });
    const m = await p;
    if (!m.ok) throw new ProverError(`proof channel: ${proof} failed: ${m.err ?? "unknown"}`);
    // A verification with no checks verified nothing: refused, never passed.
    if (cmd === "verify" && (!m.checks?.length || !m.checks.every((c) => c.ok))) {
      throw new ProverError(`proof channel: ${proof} checks failed`);
    }
    return m;
  }

  /**
   * Between requests on a kept connection: ask the node to top the proof
   * chain up to one more request's worth (§9.2). The driver runs its commands
   * in order, so a proof sent meanwhile waits for it. Resolves undefined when
   * there is nothing to do (no proof ran on the channel yet, or it is closed);
   * throws, and fails the channel, when the top-up fails.
   */
  async topup(ms = 60_000): Promise<ProofChannelTopup | undefined> {
    if (this.failureErr || this.closed || !this.used) return undefined;
    const id = this.nextId++;
    const m = await new Promise<ProofChannelResult & Partial<ProofChannelTopup>>((res, rej) => {
      const t = setTimeout(() => {
        this.pending.delete(id);
        rej(new ProverError(`proof channel: top-up timed out (${ms}ms)`));
      }, ms);
      this.pending.set(id, {
        res: (r) => {
          clearTimeout(t);
          res(r);
        },
        rej: (e) => {
          clearTimeout(t);
          rej(e);
        },
      });
      this.relay?.command({ cmd: "topup", id, timeout_ms: ms });
    }).catch((e: unknown) => {
      const err = e instanceof Error ? e : new ProverError(String(e));
      this.fail(err);
      throw err;
    });
    if (!m.ok) {
      const err = new ProverError(`proof channel: top-up failed: ${m.err ?? "unknown"}`);
      this.fail(err);
      throw err;
    }
    const done: ProofChannelTopup = {
      granted: m.granted === true,
      before: Number(m.before ?? 0),
      after: Number(m.after ?? 0),
      bytes: Number(m.bytes ?? 0),
      ms: Number(m.ms ?? 0),
    };
    if (done.granted) this.topups.push(done);
    return done;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    // A proof or top-up still waiting is answered now: its timer (up to 60 s)
    // would otherwise be the only thing to settle it, after the connection is gone.
    const closed = new ProverError("proof channel closed");
    this.readyRej(closed);
    for (const w of this.pending.values()) w.rej(closed);
    this.pending.clear();
    this.relay?.command({ cmd: "close" });
    // Let the driver flush its last bytes before the socket goes.
    this.relay?.close(500);
  }
}
