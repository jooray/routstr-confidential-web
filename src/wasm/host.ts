/**
 * Where the Rust client (crates/client-wasm) runs.
 *
 * The wasm module exposes three drivers with the frame protocol of the native
 * binaries (`cu-2pc`, `cu-prover --channel`, `cu-prover --job-stdin`): JS feeds
 * `(channel, bytes)` frames in and gets frames out. A host owns the wasm
 * instance:
 *
 *  - `InlineWasmHost` runs it on the calling thread (tests, workers);
 *  - `WorkerWasmHost` runs it in a dedicated module Worker (the default in a
 *    page: the garbled-circuit evaluation is ~1 s of CPU and must not freeze
 *    the UI). Frames cross with transferable buffers.
 */

export type DriverKind = "twopc" | "zkchan" | "job";

export interface DriverOptions {
  /** zkchan: preallocated correlations (0 / absent = defaults). */
  prealloc?: { nk?: number; cp?: number };
  /** job: the per-proof job JSON (`{proof, role, params, witness}`). */
  job?: Uint8Array;
}

export type FrameHandler = (channel: number, data: Uint8Array) => void;

/**
 * Called at most once when the driver can no longer run: the worker hosting
 * it crashed, or it could not be started. No frames follow.
 */
export type DriverErrorHandler = (error: Error) => void;

export interface DriverHandle {
  push(channel: number, data: Uint8Array): void;
  close(): void;
}

export interface WasmHost {
  /** Resolves once the wasm module is instantiated. */
  ready(): Promise<void>;
  start(kind: DriverKind, options: DriverOptions, onFrame: FrameHandler, onError?: DriverErrorHandler): DriverHandle;
  /** zkbench fixtures (benchmarks only). */
  fixtures?(): Promise<string>;
  terminate?(): void;
}

/** What `wasm-bindgen --target web` generates (crates/client-wasm/src/web.rs). */
interface WasmModule {
  default(input?: unknown): Promise<unknown>;
  TwoPcClient: new (cb: FrameHandler) => WasmDriver;
  ProofChannelClient: new (cb: FrameHandler, nk: number, cp: number) => WasmDriver;
  ProverJob: new (cb: FrameHandler, job: Uint8Array) => WasmDriver;
  fixturesV2(): string;
  buildInfo(): string;
}

interface WasmDriver {
  push(channel: number, data: Uint8Array): void;
  close(): void;
  free(): void;
}

export interface InlineHostOptions {
  /**
   * The `.wasm` bytes, URL or compiled module. Default: the file next to the
   * generated glue (`wasm/pkg/client_wasm_bg.wasm`), resolved by the bundler.
   */
  wasm?: BufferSource | URL | string | WebAssembly.Module;
}

export class InlineWasmHost implements WasmHost {
  private mod?: WasmModule;
  private readyP?: Promise<void>;

  constructor(private readonly options: InlineHostOptions = {}) {}

  ready(): Promise<void> {
    this.readyP ??= (async () => {
      const mod = (await import("../../wasm/pkg/client_wasm.js")) as unknown as WasmModule;
      await mod.default(this.options.wasm !== undefined ? { module_or_path: this.options.wasm } : undefined);
      this.mod = mod;
    })();
    return this.readyP;
  }

  get buildInfo(): string | undefined {
    return this.mod?.buildInfo();
  }

  async fixtures(): Promise<string> {
    await this.ready();
    return this.mod!.fixturesV2();
  }

  start(kind: DriverKind, options: DriverOptions, onFrame: FrameHandler, onError?: DriverErrorHandler): DriverHandle {
    const mod = this.mod;
    if (!mod) throw new Error("wasm host not ready (await host.ready() first)");
    // The callback runs inside wasm's event-loop tasks; never let a JS error
    // propagate into Rust.
    const cb: FrameHandler = (ch, data) => {
      try {
        onFrame(ch, data);
      } catch (e) {
        console.error("confidential-web: frame handler failed", e);
      }
    };
    let d: WasmDriver;
    if (kind === "twopc") d = new mod.TwoPcClient(cb);
    else if (kind === "zkchan") d = new mod.ProofChannelClient(cb, options.prealloc?.nk ?? 0, options.prealloc?.cp ?? 0);
    else d = new mod.ProverJob(cb, options.job ?? new Uint8Array(0));
    let closed = false;
    return {
      push: (ch, data) => {
        if (closed) return;
        try {
          d.push(ch, data);
        } catch (e) {
          // A driver that already stopped drops late input (its own events
          // report why it stopped); a backlog over the limit ends it.
          const msg = e instanceof Error ? e.message : String(e);
          if (msg.includes("backlog")) {
            closed = true;
            onError?.(new Error(msg));
          }
        }
      },
      close: () => {
        if (closed) return;
        closed = true;
        // End of input: the driver flushes what it has and stops. The JS
        // wrapper object can go; the Rust tasks own their state.
        d.close();
        d.free();
      },
    };
  }
}

// ─── worker host ────────────────────────────────────────────────────────────

/** Main thread → worker. */
export type ToWorker =
  | { op: "init"; wasm?: string }
  | { op: "start"; id: number; kind: DriverKind; options: DriverOptions }
  | { op: "push"; id: number; ch: number; data: Uint8Array }
  | { op: "close"; id: number }
  | { op: "fixtures"; id: number };

/** Worker → main thread. */
export type FromWorker =
  | { op: "ready"; info: string }
  | { op: "init_error"; msg: string }
  | { op: "frame"; id: number; ch: number; data: Uint8Array }
  | { op: "driver_error"; id: number; msg: string }
  | { op: "fixtures"; id: number; json: string };

export interface WorkerHostOptions {
  /** A ready Worker running `worker.ts`; default: one created from this package. */
  worker?: Worker;
  /** URL of the `.wasm` for the worker to fetch (default: bundler-resolved). */
  wasmUrl?: string;
}

export class WorkerWasmHost implements WasmHost {
  readonly worker: Worker;
  private readyP: Promise<void>;
  private nextId = 1;
  private handlers = new Map<number, { onFrame: FrameHandler; onError?: DriverErrorHandler }>();
  private fixtureWaiters = new Map<number, { res: (s: string) => void; rej: (e: Error) => void }>();
  /** Set once the worker failed: every driver on it is gone. */
  private dead?: Error;
  info = "";

  constructor(options: WorkerHostOptions = {}) {
    this.worker =
      options.worker ?? new Worker(new URL("./worker.js", import.meta.url), { type: "module", name: "routstr-confidential" });
    this.readyP = new Promise<void>((res, rej) => {
      this.worker.onmessage = (ev: MessageEvent<FromWorker>) => {
        const m = ev.data;
        if (m.op === "ready") {
          this.info = m.info;
          res();
        } else if (m.op === "init_error") {
          const e = new Error(`wasm worker: ${m.msg}`);
          rej(e);
          this.fail(e);
        } else if (m.op === "frame") this.handlers.get(m.id)?.onFrame(m.ch, m.data);
        else if (m.op === "driver_error") {
          const h = this.handlers.get(m.id);
          this.handlers.delete(m.id);
          h?.onError?.(new Error(`wasm driver: ${m.msg}`));
        } else if (m.op === "fixtures") {
          this.fixtureWaiters.get(m.id)?.res(m.json);
          this.fixtureWaiters.delete(m.id);
        }
      };
      // An uncaught error in the worker (a wasm trap or panic included) leaves
      // its wasm instance unusable: before ready it fails `ready()`, after it
      // every live driver, and the page-wide host is replaced.
      this.worker.onerror = (e: ErrorEvent) => {
        e.preventDefault?.();
        const err = new Error(`wasm worker failed: ${e.message ?? "error"}`);
        rej(err);
        this.fail(err);
      };
      this.worker.onmessageerror = () => {
        const err = new Error("wasm worker: undecodable message");
        rej(err);
        this.fail(err);
      };
    });
    this.readyP.catch(() => {});
    this.post({ op: "init", wasm: options.wasmUrl });
  }

  /** The worker failed: fail every pending handler, stop the worker, stop being the default host. */
  private fail(err: Error): void {
    if (this.dead) return;
    this.dead = err;
    const handlers = [...this.handlers.values()];
    this.handlers.clear();
    const waiters = [...this.fixtureWaiters.values()];
    this.fixtureWaiters.clear();
    this.readyP = Promise.reject(err);
    this.readyP.catch(() => {});
    try {
      this.worker.terminate();
    } catch {
      /* ignore */
    }
    if (defaultHost === this) defaultHost = undefined;
    for (const h of handlers) {
      try {
        h.onError?.(err);
      } catch (e) {
        console.error("confidential-web: driver error handler failed", e);
      }
    }
    for (const w of waiters) w.rej(err);
  }

  /** The error that ended this host's worker, if it failed. */
  get failure(): Error | undefined {
    return this.dead;
  }

  private post(m: ToWorker, transfer: Transferable[] = []): void {
    if (this.dead) return;
    this.worker.postMessage(m, transfer);
  }

  ready(): Promise<void> {
    return this.readyP;
  }

  async fixtures(): Promise<string> {
    await this.readyP;
    const id = this.nextId++;
    const p = new Promise<string>((res, rej) => this.fixtureWaiters.set(id, { res, rej }));
    this.post({ op: "fixtures", id });
    return p;
  }

  start(kind: DriverKind, options: DriverOptions, onFrame: FrameHandler, onError?: DriverErrorHandler): DriverHandle {
    const id = this.nextId++;
    if (this.dead) {
      const err = this.dead;
      queueMicrotask(() => onError?.(err));
      return { push: () => {}, close: () => {} };
    }
    this.handlers.set(id, { onFrame, onError });
    this.post({ op: "start", id, kind, options });
    let closed = false;
    return {
      push: (ch, data) => {
        if (closed) return;
        // Copy: the caller may reuse its buffer; the copy is transferred.
        const copy = data.slice();
        this.post({ op: "push", id, ch, data: copy }, [copy.buffer]);
      },
      close: () => {
        if (closed) return;
        closed = true;
        this.post({ op: "close", id });
        // Late frames (the driver's last flush) are dropped after a grace
        // period; a closed driver's failure is no longer reported.
        const h = this.handlers.get(id);
        if (h) h.onError = undefined;
        setTimeout(() => this.handlers.delete(id), 5_000);
      },
    };
  }

  terminate(): void {
    this.fail(new Error("wasm worker terminated"));
  }
}

let defaultHost: WasmHost | undefined;

/** The page-wide host: a Worker where available, else inline. */
export function getDefaultWasmHost(): WasmHost {
  if (!defaultHost) {
    defaultHost = typeof Worker !== "undefined" && typeof window !== "undefined" ? new WorkerWasmHost() : new InlineWasmHost();
  }
  return defaultHost;
}

export function setDefaultWasmHost(host: WasmHost): void {
  defaultHost = host;
}
