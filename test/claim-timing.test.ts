import { describe, expect, it } from "vitest";
import { checkReady, claimTiming } from "../src/session";

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
  it("takes a v2 session under the signed offer's key", () => {
    expect(() => checkReady({ v: 2, pubkey: offer.notary_pubkey }, offer)).not.toThrow();
  });
  it("refuses a missing or different key and another version, before the 2PC", () => {
    expect(() => checkReady({ v: 2 }, offer)).toThrow(/session key/);
    expect(() => checkReady({ v: 2, pubkey: "cd".repeat(32) }, offer)).toThrow(/session key/);
    expect(() => checkReady({ v: 1, pubkey: offer.notary_pubkey }, offer)).toThrow(/v1 session/);
  });
});
