import { describe, expect, it } from "vitest";
import { CHANNEL_NET, DriverRelay } from "../src/relay.js";
import type { DriverHandle, WasmHost } from "../src/wasm/host.js";

class FakeWs {
  static last?: FakeWs;
  binaryType = "";
  closed = false;
  onopen?: () => void;
  onmessage?: (ev: { data: ArrayBuffer | string }) => void;
  onerror?: () => void;
  onclose?: () => void;
  constructor(readonly url: string) {
    FakeWs.last = this;
  }
  send(): void {}
  close(): void {
    this.closed = true;
  }
}

function host(pushed: number[]): WasmHost {
  return {
    ready: async () => {},
    start(): DriverHandle {
      return { push: (ch, d) => ch === CHANNEL_NET && pushed.push(d.length), close: () => {} };
    },
  } as unknown as WasmHost;
}

describe("DriverRelay", () => {
  it("fails and closes the socket once the node sends more than the inbound budget", async () => {
    const pushed: number[] = [];
    const failures: Error[] = [];
    const relay = new DriverRelay({
      host: host(pushed),
      kind: "twopc",
      url: "wss://node.example/zk",
      webSocketImpl: FakeWs as unknown as typeof WebSocket,
      onEvent: () => {},
      onFailure: (e) => failures.push(e),
      label: "2PC",
      maxInbound: 1000,
    });
    await relay.start();
    const ws = FakeWs.last!;
    ws.onopen?.();
    for (let i = 0; i < 5; i++) ws.onmessage?.({ data: new ArrayBuffer(300) });
    expect(pushed).toEqual([300, 300, 300]);
    expect(failures).toHaveLength(1);
    expect(failures[0].message).toMatch(/more than 1000 bytes/);
    expect(ws.closed).toBe(true);
  });
});
