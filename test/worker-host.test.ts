import { describe, expect, it } from "vitest";
import { WorkerWasmHost, getDefaultWasmHost, setDefaultWasmHost, type FromWorker, type ToWorker } from "../src/wasm/host.js";

/** A stand-in for a module Worker: records what the host posts, lets the test answer. */
class FakeWorker {
  posted: ToWorker[] = [];
  terminated = false;
  onmessage: ((ev: MessageEvent<FromWorker>) => void) | null = null;
  onerror: ((ev: ErrorEvent) => void) | null = null;
  onmessageerror: (() => void) | null = null;
  postMessage(m: ToWorker): void {
    this.posted.push(m);
  }
  terminate(): void {
    this.terminated = true;
  }
  send(m: FromWorker): void {
    this.onmessage?.({ data: m } as MessageEvent<FromWorker>);
  }
  crash(message: string): void {
    this.onerror?.({ message, preventDefault() {} } as unknown as ErrorEvent);
  }
}

const flush = () => new Promise((r) => setTimeout(r, 0));

describe("worker host failures", () => {
  it("a worker crash after ready fails every live driver and replaces the default host", async () => {
    const w = new FakeWorker();
    const host = new WorkerWasmHost({ worker: w as unknown as Worker });
    w.send({ op: "ready", info: "test" });
    await host.ready();
    setDefaultWasmHost(host);

    const errors: string[] = [];
    const frames: number[] = [];
    host.start("twopc", {}, (ch) => frames.push(ch), (e) => errors.push(`a:${e.message}`));
    host.start("zkchan", {}, () => {}, (e) => errors.push(`b:${e.message}`));
    const closed = host.start("job", {}, () => {}, (e) => errors.push(`c:${e.message}`));
    closed.close();
    const fixtures = host.fixtures();
    await flush();

    w.crash("RuntimeError: unreachable");
    expect(errors).toEqual(["a:wasm worker failed: RuntimeError: unreachable", "b:wasm worker failed: RuntimeError: unreachable"]);
    await expect(fixtures).rejects.toThrow(/wasm worker failed/);
    expect(w.terminated).toBe(true);
    await expect(host.ready()).rejects.toThrow(/wasm worker failed/);
    // Late frames for the dead drivers go nowhere.
    w.send({ op: "frame", id: 1, ch: 0, data: new Uint8Array(1) });
    expect(frames).toEqual([]);
    // A driver started on the dead host fails at once instead of hanging.
    const late: string[] = [];
    host.start("twopc", {}, () => {}, (e) => late.push(e.message));
    await flush();
    expect(late).toEqual(["wasm worker failed: RuntimeError: unreachable"]);
    // The page-wide default is no longer the dead host.
    expect(getDefaultWasmHost()).not.toBe(host);
  });

  it("a driver that cannot start fails alone", async () => {
    const w = new FakeWorker();
    const host = new WorkerWasmHost({ worker: w as unknown as Worker });
    w.send({ op: "ready", info: "test" });
    await host.ready();
    const errors: string[] = [];
    host.start("twopc", {}, () => {}, (e) => errors.push(`a:${e.message}`));
    host.start("zkchan", {}, () => {}, (e) => errors.push(`b:${e.message}`));
    const id = (w.posted.find((m) => m.op === "start" && m.kind === "zkchan") as { id: number }).id;
    w.send({ op: "driver_error", id, msg: "bad options" });
    expect(errors).toEqual(["b:wasm driver: bad options"]);
    expect(w.terminated).toBe(false);
  });

  it("an init error fails ready()", async () => {
    const w = new FakeWorker();
    const host = new WorkerWasmHost({ worker: w as unknown as Worker });
    w.send({ op: "init_error", msg: "no wasm" });
    await expect(host.ready()).rejects.toThrow(/no wasm/);
  });
});
