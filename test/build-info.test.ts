import { describe, expect, it } from "vitest";
// @ts-expect-error plain .mjs script without types
import { committedBuildInfo, sourceDigest } from "../scripts/source-digest.mjs";

describe("committed wasm", () => {
  it("was built from the sources in this tree (buildInfo source digest)", () => {
    const info = committedBuildInfo() as string | undefined;
    expect(info, "wasm/pkg has no buildInfo with a source digest: rebuild with npm run build:wasm").toBeDefined();
    expect(info).toContain(`src:${sourceDigest() as string})`);
  });
});
