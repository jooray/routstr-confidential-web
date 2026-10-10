/**
 * A wasm driver bridged to one node WebSocket: channel-0 frames go to the
 * socket, socket messages come back as channel-0 frames, and channel-1 frames
 * are control JSON events. Shared by the 2PC, the proof channel and the
 * per-proof fallback (the SDK's twopc.ts/zkchan.ts/prover.ts with the child
 * process replaced by a wasm driver).
 */

import { ProverError } from "./errors";
import type { DriverHandle, DriverKind, DriverOptions, WasmHost } from "./wasm/host";

export const CHANNEL_NET = 0;
export const CHANNEL_CONTROL = 1;

export interface RelayOptions {
  host: WasmHost;
  kind: DriverKind;
  driverOptions?: DriverOptions;
  url: string;
  webSocketImpl?: typeof WebSocket;
  onEvent(m: Record<string, unknown>): void;
  onFailure(e: Error): void;
  /** True when the socket may close without that being a failure. */
  closeIsNormal?(): boolean;
  /** Label for errors. */
  label: string;
}

export class DriverRelay {
  private driver?: DriverHandle;
  private ws?: WebSocket;
  private wsOpen = false;
  private outbox: Uint8Array[] = [];
  private closed = false;
  bytesSent = 0;
  bytesRecv = 0;

  constructor(private readonly o: RelayOptions) {}

  /** Opens the socket and starts the driver (after the wasm module is ready). */
  async start(): Promise<void> {
    await this.o.host.ready();
    if (this.closed) return;
    const WS = this.o.webSocketImpl ?? WebSocket;
    const ws = new WS(this.o.url);
    this.ws = ws;
    ws.binaryType = "arraybuffer";
    ws.onopen = () => {
      this.wsOpen = true;
      for (const b of this.outbox) ws.send(b);
      this.outbox.length = 0;
    };
    ws.onmessage = (ev: MessageEvent) => {
      const d = ev.data as ArrayBuffer | string;
      if (typeof d === "string") {
        this.o.onFailure(new ProverError(`${this.o.label} websocket sent a text frame`));
        return;
      }
      const bytes = new Uint8Array(d);
      this.bytesRecv += bytes.length;
      this.driver?.push(CHANNEL_NET, bytes);
    };
    ws.onerror = () => {
      if (!this.closed) this.o.onFailure(new ProverError(`${this.o.label} websocket error`));
    };
    ws.onclose = () => {
      if (!this.closed && !(this.o.closeIsNormal?.() ?? false)) {
        this.o.onFailure(new ProverError(`${this.o.label} websocket closed`));
      }
    };
    this.driver = this.o.host.start(this.o.kind, this.o.driverOptions ?? {}, (ch, data) => {
      if (ch === CHANNEL_NET) {
        this.bytesSent += data.length;
        if (this.wsOpen) ws.send(data);
        else this.outbox.push(data);
      } else if (ch === CHANNEL_CONTROL) {
        let m: Record<string, unknown>;
        try {
          m = JSON.parse(new TextDecoder().decode(data));
        } catch {
          this.o.onFailure(new ProverError(`${this.o.label}: bad control JSON`));
          return;
        }
        this.o.onEvent(m);
      }
    });
  }

  command(cmd: Record<string, unknown>): void {
    const bytes = new TextEncoder().encode(JSON.stringify(cmd));
    this.driver?.push(CHANNEL_CONTROL, bytes);
    bytes.fill(0);
  }

  /** Stop the driver; the socket closes after `graceMs` (last bytes flushed). */
  close(graceMs = 0): void {
    if (this.closed) return;
    this.closed = true;
    this.driver?.close();
    const shut = () => {
      try {
        this.ws?.close();
      } catch {
        /* ignore */
      }
    };
    if (graceMs > 0) setTimeout(shut, graceMs);
    else shut();
  }
}
