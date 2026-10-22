import { describe, expect, it } from "vitest";
import type { VerifiedOffer } from "../src/offer";
import { checkReady, claimTiming, ConfidentialSession } from "../src/session";
import prod from "./fixtures/cypherpunk-offer.json";

describe("claim timing", () => {
  it("an arm finished before the request is pre-warmed", () => {
    expect(claimTiming(1000, 900, true)).toEqual({ prewarmed: true, waitedForArmMs: undefined });
  });
  it("a request sent while the arm was running waited for it and is not pre-warmed", () => {
    expect(claimTiming(1000, 84_000, true)).toEqual({ prewarmed: false, waitedForArmMs: 83_000 });
  });
  it("an arm started by the claim itself is cold, not a wait", () => {
    expect(claimTiming(1000, 5000, false)).toEqual({ prewarmed: false, waitedForArmMs: undefined });
  });
});

describe("the ready frame", () => {
  const offer = { notary_pubkey: "ab".repeat(32) };
  const sid = "0f".repeat(32);
  it("takes a v2 session under the signed offer's key", () => {
    expect(() => checkReady({ v: 2, pubkey: offer.notary_pubkey, sid }, offer)).not.toThrow();
  });
  it("refuses a missing or different key and another version, before the 2PC", () => {
    expect(() => checkReady({ v: 2, sid }, offer)).toThrow(/session key/);
    expect(() => checkReady({ v: 2, pubkey: "cd".repeat(32), sid }, offer)).toThrow(/session key/);
    expect(() => checkReady({ v: 1, pubkey: offer.notary_pubkey, sid }, offer)).toThrow(/v1 session/);
  });
  it("refuses a session id that is not 64 lowercase hex digits", () => {
    for (const bad of [undefined, 7, "", "0f".repeat(31), "0f".repeat(33), "0F".repeat(32), `${"0f".repeat(31)}&x`, `${"0f".repeat(32)}\n`]) {
      expect(() => checkReady({ v: 2, pubkey: offer.notary_pubkey, sid: bad }, offer)).toThrow(/malformed session id/);
    }
  });
});

describe("control frames", () => {
  /** A socket that delivers the given text frames, then opens. */
  const socketSending = (frames: string[]) =>
    class {
      binaryType = "";
      onopen?: () => void;
      onmessage?: (ev: { data: string }) => void;
      onerror?: () => void;
      onclose?: () => void;
      constructor() {
        queueMicrotask(() => {
          for (const data of frames) this.onmessage?.({ data });
          this.onopen?.();
        });
      }
      send(): void {}
      close(): void {}
    };
  const session = (frames: string[]) =>
    new ConfidentialSession({
      baseUrl: "http://127.0.0.1:1",
      offer: { ...(prod as never as VerifiedOffer), signedPayload: "" },
      auth: "sk-test",
      model: "m",
      maxTokens: 8,
      bodyLength: 64,
      host: {} as never,
      webSocketImpl: socketSending(frames) as never,
    });

  it("queues at most 16 unanswered frames of one type", async () => {
    const frame = JSON.stringify({ type: "noise" });
    await expect(session(Array(16).fill(frame)).open()).resolves.toBeUndefined();
    await expect(session(Array(17).fill(frame)).open()).rejects.toThrow(/too many unanswered "noise" frames/);
  });

  it("queues at most 256 unanswered frames in all", async () => {
    const frames = Array.from({ length: 257 }, (_, i) => JSON.stringify({ type: `t${Math.floor(i / 16)}` }));
    await expect(session(frames).open()).rejects.toThrow(/too many unanswered "t16" frames/);
  });

  it("refuses a control frame without a type", async () => {
    await expect(session(["[]"]).open()).rejects.toThrow(/control frame without a type/);
    await expect(session(['{"type":7}']).open()).rejects.toThrow(/control frame without a type/);
  });
});
