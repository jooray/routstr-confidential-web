/**
 * The client side of the protocol v2 two-party handshake
 * (docs/TWOPC-DESIGN.md in routstr-confidential), run by the wasm build of
 * `cu-2pc` and bridged to the node's `twopc` WebSocket
 * (`/v1/confidential/zk?proof=twopc`). Same events and commands as the SDK's
 * `twopc.ts`: `key_share`, `hs`, `ap`, `timing`, `error`; `handshake`, `app`.
 * The secrets it returns (c_hs, s_hs, s_ap_0, c_ap_1) stay in memory and are
 * never logged.
 */

import { fromHex, hex } from "./bytes";
import { ProverError } from "./errors";
import { DriverRelay } from "./relay";
import type { WasmHost } from "./wasm/host";

export interface TwoPcHandshakeSecrets {
  clientHs: Uint8Array;
  serverHs: Uint8Array;
}

export interface TwoPcApplicationSecrets {
  /** s_ap_0: the response epoch (never known to the node). */
  serverAp0: Uint8Array;
  /** c_ap_1: our body epoch (never known to the node). */
  clientAp1: Uint8Array;
  /** Public anchors: SHA256(c_ap_1), SHA256(s_ap_0), SHA256(K_0 ‖ IV_0). */
  h1: Uint8Array;
  h2: Uint8Array;
  hk: Uint8Array;
}

export interface TwoPcTiming {
  step: string;
  ms: number;
  bytes_sent?: number;
  bytes_recv?: number;
}

type Waiter = { res: (m: Record<string, unknown>) => void; rej: (e: Error) => void };

function hexField(m: Record<string, unknown>, key: string, len: number): Uint8Array {
  const v = m[key];
  if (typeof v !== "string" || v.length !== len * 2 || !/^[0-9a-fA-F]*$/.test(v)) {
    throw new ProverError(`2pc: bad ${key}`);
  }
  return fromHex(v);
}

export class TwoPcSession {
  readonly timings: TwoPcTiming[] = [];
  private relay?: DriverRelay;
  private waiters = new Map<string, Waiter>();
  private queued = new Map<string, Record<string, unknown>>();
  private failureErr: Error | undefined;
  private closed = false;
  /** Phase B delivered: the node closing the socket afterwards is normal. */
  private done = false;

  constructor(
    private readonly host: WasmHost,
    private readonly webSocketImpl?: typeof WebSocket,
  ) {}

  /** Start the wasm 2PC driver and connect it to the node's twopc socket. */
  start(url: string): void {
    this.relay = new DriverRelay({
      host: this.host,
      kind: "twopc",
      url,
      webSocketImpl: this.webSocketImpl,
      label: "2PC",
      onEvent: (m) => this.onControl(m),
      onFailure: (e) => this.fail(e),
      closeIsNormal: () => this.done || this.closed,
    });
    this.relay.start().catch((e: unknown) => this.fail(e instanceof Error ? e : new ProverError(String(e))));
  }

  get bytes(): { sent: number; recv: number } {
    return { sent: this.relay?.bytesSent ?? 0, recv: this.relay?.bytesRecv ?? 0 };
  }

  private onControl(m: Record<string, unknown>): void {
    const ev = typeof m.ev === "string" ? m.ev : "";
    if (ev === "timing") {
      this.timings.push({
        step: String(m.step),
        ms: Number(m.ms),
        bytes_sent: m.bytes_sent as number | undefined,
        bytes_recv: m.bytes_recv as number | undefined,
      });
      return;
    }
    if (ev === "error") {
      this.fail(new ProverError(`2pc: ${String(m.msg ?? "unknown error")}`));
      return;
    }
    if (ev === "exit") return;
    if (ev === "ap") this.done = true;
    const w = this.waiters.get(ev);
    if (w) {
      this.waiters.delete(ev);
      w.res(m);
    } else this.queued.set(ev, m);
  }

  private fail(e: Error): void {
    if (this.failureErr) return;
    this.failureErr = e;
    for (const w of this.waiters.values()) w.rej(e);
    this.waiters.clear();
  }

  private wait(ev: string, ms: number): Promise<Record<string, unknown>> {
    if (this.failureErr) return Promise.reject(this.failureErr);
    const q = this.queued.get(ev);
    if (q) {
      this.queued.delete(ev);
      return Promise.resolve(q);
    }
    return new Promise((res, rej) => {
      const t = setTimeout(() => {
        this.waiters.delete(ev);
        rej(new ProverError(`timeout waiting for 2PC ${ev}`));
      }, ms);
      this.waiters.set(ev, {
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
  }

  private command(cmd: Record<string, unknown>): void {
    if (this.failureErr) throw this.failureErr;
    this.relay?.command(cmd);
  }

  /** Preprocessing plus the commit-then-open joint key share P = P_C + P_N (65-byte SEC1). */
  async keyShare(ms = 120_000): Promise<Uint8Array> {
    const m = await this.wait("key_share", ms);
    return hexField(m, "p", 65);
  }

  /** ECtF + phase A: the handshake traffic secrets. */
  async handshake(serverShare: Uint8Array, thSH: Uint8Array, ms = 15_000): Promise<TwoPcHandshakeSecrets> {
    this.command({ cmd: "handshake", s: hex(serverShare), th_sh: hex(thSH) });
    const m = await this.wait("hs", ms);
    return { clientHs: hexField(m, "c_hs", 32), serverHs: hexField(m, "s_hs", 32) };
  }

  /** Phase B: s_ap_0 and c_ap_1 for us; h1, h2, hk public. */
  async application(thSF: Uint8Array, ms = 30_000): Promise<TwoPcApplicationSecrets> {
    this.command({ cmd: "app", th_sf: hex(thSF) });
    const m = await this.wait("ap", ms);
    return {
      serverAp0: hexField(m, "s_ap_0", 32),
      clientAp1: hexField(m, "c_ap_1", 32),
      h1: hexField(m, "h1", 32),
      h2: hexField(m, "h2", 32),
      hk: hexField(m, "hk", 32),
    };
  }

  get failed(): boolean {
    return this.failureErr !== undefined;
  }

  get failure(): Error | undefined {
    return this.failureErr;
  }

  close(): void {
    this.closed = true;
    this.relay?.close(0);
  }
}
