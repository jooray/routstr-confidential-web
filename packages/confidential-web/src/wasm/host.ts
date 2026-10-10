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

export interface DriverHandle {
  push(channel: number, data: Uint8Array): void;
  close(): void;
}

export interface WasmHost {
  /** Resolves once the wasm module is instantiated. */
  ready(): Promise<void>;
  start(kind: DriverKind, options: DriverOptions, onFrame: FrameHandler): DriverHandle;
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

  start(kind: DriverKind, options: DriverOptions, onFrame: FrameHandler): DriverHandle {
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
        if (!closed) d.push(ch, data);
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
  private handlers = new Map<number, FrameHandler>();
  private fixtureWaiters = new Map<number, (s: string) => void>();
  info = "";

  constructor(options: WorkerHostOptions = {}) {
    this.worker =
      options.worker ?? new Worker(new URL("./worker.ts", import.meta.url), { type: "module", name: "routstr-confidential" });
    this.readyP = new Promise<void>((res, rej) => {
      this.worker.onmessage = (ev: MessageEvent<FromWorker>) => {
        const m = ev.data;
        if (m.op === "ready") {
          this.info = m.info;
          res();
        } else if (m.op === "init_error") rej(new Error(`wasm worker: ${m.msg}`));
        else if (m.op === "frame") this.handlers.get(m.id)?.(m.ch, m.data);
        else if (m.op === "fixtures") {
          this.fixtureWaiters.get(m.id)?.(m.json);
          this.fixtureWaiters.delete(m.id);
        }
      };
      this.worker.onerror = (e) => rej(new Error(`wasm worker failed: ${e.message}`));
    });
    this.readyP.catch(() => {});
    this.post({ op: "init", wasm: options.wasmUrl });
  }

  private post(m: ToWorker, transfer: Transferable[] = []): void {
    this.worker.postMessage(m, transfer);
  }

  ready(): Promise<void> {
    return this.readyP;
  }

  async fixtures(): Promise<string> {
    await this.readyP;
    const id = this.nextId++;
    const p = new Promise<string>((res) => this.fixtureWaiters.set(id, res));
    this.post({ op: "fixtures", id });
    return p;
  }

  start(kind: DriverKind, options: DriverOptions, onFrame: FrameHandler): DriverHandle {
    const id = this.nextId++;
    this.handlers.set(id, onFrame);
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
        // Late frames (the driver's last flush) are dropped after a grace period.
        setTimeout(() => this.handlers.delete(id), 5_000);
      },
    };
  }

  terminate(): void {
    this.worker.terminate();
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
