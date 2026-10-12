import { describe, expect, it } from "vitest";
import { ConfidentialClient } from "../src/client.js";
import { encryptedNodeTransport } from "../src/hosts.js";

describe("node transport", () => {
  const base = { nodePubkeys: ["00".repeat(32)], trustedHosts: ["api.venice.ai"], host: {} as never };

  it("refuses a plain-http node unless loopback, onion or an explicit opt-in", () => {
    expect(() => new ConfidentialClient({ ...base, node: "http://node.example" })).toThrow(/plain http/);
    expect(() => new ConfidentialClient({ ...base, node: "http://192.168.1.5:8000" })).toThrow(/plain http/);
    for (const node of ["https://node.example", "http://127.0.0.1:8010", "http://localhost:8010", "http://abc.onion"]) {
      expect(() => new ConfidentialClient({ ...base, node })).not.toThrow();
    }
    expect(() => new ConfidentialClient({ ...base, node: "http://node.example", allowInsecureTransport: true })).not.toThrow();
    expect(encryptedNodeTransport("ws://node.example")).toBe(false);
  });
});
