/* tslint:disable */
/* eslint-disable */

/**
 * Client end of the session's proof channel (`cu-prover --channel`).
 */
export class ProofChannelClient {
    free(): void;
    [Symbol.dispose](): void;
    close(): void;
    /**
     * `prealloc_nk`/`prealloc_cp` = 0 keep the defaults.
     */
    constructor(on_frame: Function, prealloc_nk: number, prealloc_cp: number);
    push(channel: number, data: Uint8Array): void;
}

/**
 * One proof over its own connection (the per-proof fallback,
 * `cu-prover --job-stdin`). `job` is the JSON job.
 */
export class ProverJob {
    free(): void;
    [Symbol.dispose](): void;
    close(): void;
    constructor(on_frame: Function, job: Uint8Array);
    push(channel: number, data: Uint8Array): void;
}

/**
 * Client side of the 2PC handshake (same frames as the `cu-2pc` binary).
 */
export class TwoPcClient {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * End of input (like closing the process's stdin).
     */
    close(): void;
    /**
     * Starts preprocessing immediately; `on_frame(channel, bytes)` receives
     * protocol bytes (channel 0, for the `twopc` WebSocket) and events
     * (channel 1, JSON).
     */
    constructor(on_frame: Function);
    /**
     * Feed one frame: channel 0 = bytes from the WebSocket, 1 = command JSON.
     */
    push(channel: number, data: Uint8Array): void;
}

export function buildInfo(): string;

/**
 * zkbench v2 fixtures (params + witness) as JSON, for benchmarks only.
 */
export function fixturesV2(): string;

export function start(): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_proofchannelclient_free: (a: number, b: number) => void;
    readonly __wbg_proverjob_free: (a: number, b: number) => void;
    readonly __wbg_twopcclient_free: (a: number, b: number) => void;
    readonly buildInfo: () => [number, number];
    readonly fixturesV2: () => [number, number];
    readonly proofchannelclient_close: (a: number) => void;
    readonly proofchannelclient_new: (a: any, b: number, c: number) => number;
    readonly proofchannelclient_push: (a: number, b: number, c: number, d: number) => [number, number];
    readonly proverjob_close: (a: number) => void;
    readonly proverjob_new: (a: any, b: number, c: number) => number;
    readonly proverjob_push: (a: number, b: number, c: number, d: number) => [number, number];
    readonly start: () => void;
    readonly twopcclient_close: (a: number) => void;
    readonly twopcclient_new: (a: any) => number;
    readonly twopcclient_push: (a: number, b: number, c: number, d: number) => [number, number];
    readonly wasm_bindgen_96bbe4b92e825b21___convert__closures_____invoke___wasm_bindgen_96bbe4b92e825b21___JsValue__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_96bbe4b92e825b21___JsError___true_: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen_96bbe4b92e825b21___convert__closures_____invoke_______true_: (a: number, b: number) => void;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
