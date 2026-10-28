import { describe, expect, it } from "vitest";
import { ConfidentialSession } from "../src/session.js";
import type { VerifiedOffer } from "../src/offer.js";
import prod from "./fixtures/cypherpunk-offer.json";

function session(onSocket: () => void, ready: () => Promise<void> = async () => {}) {
  class FakeWs {
    constructor() {
      onSocket();
    }
    send() {}
    close() {}
  }
  return new ConfidentialSession({
    baseUrl: "https://node.example",
    offer: prod as never as VerifiedOffer,
    auth: "sk-test",
    model: Object.keys(prod.price_list)[0]!,
    maxTokens: 50,
    bodyLength: 4096,
    host: { ready } as never,
    webSocketImpl: FakeWs as never,
  });
}

describe("session close is sticky", () => {
  it("a session closed before it opened never opens a socket", async () => {
    let sockets = 0;
    const s = session(() => sockets++);
    s.close();
    expect(s.isClosed).toBe(true);
    expect(s.healthy).toBe(false);
    await expect(s.arm()).rejects.toThrow(/closed/);
    await expect(s.open()).rejects.toThrow(/closed/);
    await expect(s.claim(new Uint8Array(4096))).rejects.toThrow(/closed/);
    expect(sockets).toBe(0);
  });

  it("a close while the wasm host starts stops the arm before the socket", async () => {
    let sockets = 0;
    let go!: () => void;
    const s = session(
      () => sockets++,
      () => new Promise<void>((r) => (go = r)),
    );
    const armed = s.arm();
    await new Promise((r) => setTimeout(r, 0));
    s.close();
    go();
    await expect(armed).rejects.toThrow(/closed/);
    expect(sockets).toBe(0);
  });
});
