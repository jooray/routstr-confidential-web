/// <reference lib="webworker" />
/**
 * Dedicated Worker hosting the Rust client (see host.ts). All CPU-heavy
 * protocol work (OT extension, garbled-circuit evaluation, VOLE-ZK proofs)
 * happens here; the page only relays WebSocket bytes.
 */

import { InlineWasmHost, type DriverHandle, type FromWorker, type ToWorker } from "./host.js";

const scope = self as unknown as DedicatedWorkerGlobalScope;
let host: InlineWasmHost | undefined;
const drivers = new Map<number, DriverHandle>();
const queue: ToWorker[] = [];

function post(m: FromWorker, transfer: Transferable[] = []): void {
  scope.postMessage(m, transfer);
}

function handle(m: ToWorker): void {
  if (m.op === "start") {
    // A driver that cannot start fails alone, not the whole worker.
    let d: DriverHandle;
    try {
      d = host!.start(
        m.kind,
        m.options,
        (ch, data) => {
          const copy = data.slice();
          post({ op: "frame", id: m.id, ch, data: copy }, [copy.buffer]);
        },
        (e) => post({ op: "driver_error", id: m.id, msg: e.message }),
      );
    } catch (e) {
      post({ op: "driver_error", id: m.id, msg: e instanceof Error ? e.message : String(e) });
      return;
    }
    drivers.set(m.id, d);
  } else if (m.op === "push") {
    drivers.get(m.id)?.push(m.ch, m.data);
  } else if (m.op === "close") {
    drivers.get(m.id)?.close();
    drivers.delete(m.id);
  } else if (m.op === "fixtures") {
    void host!.fixtures().then((json) => post({ op: "fixtures", id: m.id, json }));
  }
}

scope.onmessage = (ev: MessageEvent<ToWorker>) => {
  const m = ev.data;
  if (m.op === "init") {
    host = new InlineWasmHost(m.wasm ? { wasm: m.wasm } : {});
    host.ready().then(
      () => {
        post({ op: "ready", info: host!.buildInfo ?? "" });
        for (const q of queue.splice(0)) handle(q);
      },
      (e: unknown) => post({ op: "init_error", msg: e instanceof Error ? e.message : String(e) }),
    );
    return;
  }
  if (!host?.buildInfo) {
    queue.push(m);
    return;
  }
  handle(m);
};
