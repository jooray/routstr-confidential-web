import { describe, expect, it } from "vitest";
import { claimTiming } from "../src/session";

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
