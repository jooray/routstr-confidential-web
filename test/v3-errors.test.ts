/**
 * Protocol v3 failure paths of the browser library: the node's upgrade error
 * (426 upgrade_required), a deposit the balance does not cover, the signed
 * deposit outcome in the connection's last frame, the 2PC version tag
 * mismatch from the wasm driver, and caller aborts before and after release.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import { ConfidentialConnection } from "../src/connection.js";
import { canonicalJson } from "../src/canonical.js";
import { ConnectionDepositError, TwoPcVersionMismatchError, UpgradeRequiredError } from "../src/errors.js";
import { chatSuffixKeys } from "../src/suffix.js";
import { TwoPcSession } from "../src/twopc.js";
import { ProofChannel } from "../src/zkchan.js";
import { createConfidentialClient } from "../src/client.js";
import type { WasmHost } from "../src/wasm/host.js";
import { VENICE_CHAT } from "./fixtures/chat.js";
import { NODE_PUB, NO_HOST, fakeConnections, mockNodeOffer, restoreFetch } from "./fixtures/v3.js";

const PRIV = new Uint8Array(32).fill(5);
const PUB = bytesToHex(schnorr.getPublicKey(PRIV));

/** A control socket that answers the setup with `reply` (frames, in order). */
function nodeSocket(reply: (setup: Record<string, unknown>) => Record<string, unknown>[]) {
  class Ws {
    static sent: Record<string, unknown>[] = [];
    static url = "";
    binaryType = "arraybuffer";
    onopen?: () => void;
    onmessage?: (ev: { data: string }) => void;
    onclose?: (ev: { reason?: string }) => void;
    onerror?: () => void;
    constructor(url: string) {
      Ws.url = url;
      setTimeout(() => this.onopen?.(), 0);
    }
    send(d: string) {
      const m = JSON.parse(d) as Record<string, unknown>;
      Ws.sent.push(m);
      if (m.type === "setup") {
        setTimeout(() => {
          for (const f of reply(m)) this.onmessage?.({ data: JSON.stringify(f) });
          this.onclose?.({});
        }, 0);
      }
    }
    close() {}
  }
  return Ws;
}

const conn = (Ws: unknown, extra: Record<string, unknown> = {}) =>
  new ConfidentialConnection({
    baseUrl: "http://127.0.0.1:8010",
    offer: {
      v: 3,
      notary_pubkey: PUB,
      chat: VENICE_CHAT,
      suffix_keys: chatSuffixKeys(VENICE_CHAT),
      connection_deposit_msat: 3000,
      sig: "ab".repeat(32),
    },
    auth: "sk-x",
    host: NO_HOST,
    webSocketImpl: Ws as typeof WebSocket,
    twoPcFactory: () => {
      throw new Error("2PC started");
    },
    ...extra,
  } as never);

afterEach(() => {
  vi.restoreAllMocks();
  restoreFetch();
});

describe("the node's refusals of a setup", () => {
  it("a v2-or-older client's socket gets 426 upgrade_required: a typed error naming the version", async () => {
    const Ws = nodeSocket(() => [
      { type: "error", status: 426, reason: "upgrade_required", min_v: 4, detail: "this node speaks routstr-confidential v4; update your client" },
    ]);
    const c = conn(Ws);
    const e = await c.arm().catch((x) => x);
    expect(e).toBeInstanceOf(UpgradeRequiredError);
    expect(e).toMatchObject({ code: "upgrade_required", status: 426, minVersion: 4 });
    expect(e.message).toMatch(/update the client/);
    // The setup named v3, the framing, no request terms, and the credential in-band.
    expect(Ws.sent[0]).toMatchObject({ type: "setup", v: 3, http: "1.1", armed: false, auth: "sk-x" });
    expect(Ws.sent[0]).not.toHaveProperty("model");
    expect(Ws.url).toMatch(/\/v1\/confidential\/ws\?session_id=[0-9a-f-]+&v=3$/);
  });

  it("a deposit the balance does not cover is a ConnectionDepositError (402, nothing garbled)", async () => {
    const Ws = nodeSocket(() => [
      {
        type: "error",
        status: 402,
        reason: "connection deposit not funded",
        detail: { error: { type: "connection_deposit_unfunded", connection_deposit_msat: 3000 } },
      },
    ]);
    const e = await conn(Ws).arm().catch((x) => x);
    expect(e).toBeInstanceOf(ConnectionDepositError);
    expect(e).toMatchObject({ status: 402, depositMsat: 3000 });
  });

  it("the signed deposit outcome in the last frame is recorded (and its signature checked)", async () => {
    const deposit = { sid: null, msat: 3000, outcome: "released", reason: "not_started", cost_msats: 0, balance_msats: 10, time: 1 };
    const json = canonicalJson(deposit);
    const sig = bytesToHex(schnorr.sign(sha256(utf8ToBytes(json)), PRIV));
    const good = conn(nodeSocket(() => [{ type: "error", status: 503, reason: "no session slot", deposit, deposit_json: json, deposit_sig: sig }]));
    await good.arm().catch(() => {});
    expect(good.deposit).toEqual({ msat: 3000, outcome: "released", reason: "not_started", signed: true });
    const forged = conn(nodeSocket(() => [{ type: "error", status: 503, reason: "x", deposit, deposit_json: json, deposit_sig: "00".repeat(64) }]));
    await forged.arm().catch(() => {});
    expect(forged.deposit).toMatchObject({ outcome: "released", signed: false });
  });

  it("a node error with code twopc_version_mismatch is its own error", async () => {
    const e = await conn(nodeSocket(() => [{ type: "error", status: 400, code: "twopc_version_mismatch", reason: "tag" }]))
      .arm()
      .catch((x) => x);
    expect(e).toBeInstanceOf(TwoPcVersionMismatchError);
  });

  it("a deposit above the client's maximum is refused before anything is sent", () => {
    expect(() => conn(nodeSocket(() => []), { maxDepositMsat: 2999 })).toThrow(ConnectionDepositError);
  });
});

describe("the wasm 2PC driver's version tag (split-public-1)", () => {
  it("a driver error with code twopc_version_mismatch fails the 2PC with TwoPcVersionMismatchError", async () => {
    let emit!: (ch: number, data: Uint8Array) => void;
    const host: WasmHost = {
      ready: async () => {},
      start: (_kind, _o, onFrame) => {
        emit = onFrame;
        return { push() {}, close() {} };
      },
    };
    class Ws {
      binaryType = "arraybuffer";
      onopen?: () => void;
      onmessage?: unknown;
      onclose?: unknown;
      onerror?: unknown;
      constructor() {
        setTimeout(() => this.onopen?.(), 0);
      }
      send() {}
      close() {}
    }
    const tp = new TwoPcSession(host, Ws as never);
    tp.start("ws://127.0.0.1:1/v1/confidential/zk?proof=twopc");
    const share = tp.keyShare(5000);
    await new Promise((r) => setTimeout(r, 10));
    emit(1, new TextEncoder().encode(JSON.stringify({ ev: "error", code: "twopc_version_mismatch", msg: "twopc_version_mismatch: peer tag" })));
    const e = await share.catch((x) => x);
    expect(e).toBeInstanceOf(TwoPcVersionMismatchError);
    expect(e.message).toMatch(/split-public-1/);
    tp.close();
  });
});

describe("caller aborts", () => {
  const client = () =>
    createConfidentialClient({ node: "https://abort.example", nodePubkeys: [NODE_PUB], trustedHosts: ["*.venice.ai"], credential: "sk-x", host: NO_HOST });

  it("before release: the connection is closed and the caller gets AbortError", async () => {
    mockNodeOffer();
    let free!: () => void;
    const gate = new Promise<void>((r) => (free = r));
    fakeConnections(() => ({ wait: gate }));
    const close = vi.spyOn(ConfidentialConnection.prototype, "close");
    const ac = new AbortController();
    const c = client();
    const p = c.chat.completions.create({ model: "cheap", messages: [{ role: "user", content: "x" }], stream: true }, { signal: ac.signal });
    await new Promise((r) => setTimeout(r, 20));
    ac.abort();
    await expect(p).rejects.toMatchObject({ name: "AbortError" });
    expect(close).toHaveBeenCalledWith("request aborted");
    free();
    c.close();
  });

  it("after release: only the stream ends; the request settles in the background", async () => {
    mockNodeOffer();
    let free!: () => void;
    const gate = new Promise<void>((r) => (free = r));
    fakeConnections(() => ({ released: true, wait: gate }));
    const close = vi.spyOn(ConfidentialConnection.prototype, "close");
    const ac = new AbortController();
    const c = client();
    const p = c.chat.completions.create({ model: "cheap", messages: [{ role: "user", content: "x" }], stream: true }, { signal: ac.signal });
    await new Promise((r) => setTimeout(r, 20));
    ac.abort();
    await expect(p).rejects.toMatchObject({ name: "AbortError" });
    expect(close).not.toHaveBeenCalledWith("request aborted");
    free();
    await new Promise((r) => setTimeout(r, 20));
    // The connection settled its request and stays in the pool.
    expect(c.connections()).toMatchObject([{ state: "idle", requests: 1 }]);
    c.close();
  });
});

describe("close() ends the waits it leaves (review finding 22)", () => {
  it("a proof or top-up waiting on the proof channel is rejected at once", async () => {
    const ch = new ProofChannel({} as WasmHost);
    (ch as unknown as { used: boolean }).used = true;
    const t = Date.now();
    const proof = ch.run("prove", "pi_win", {}, undefined, 60_000);
    const topup = ch.topup(60_000);
    const ready = ch.ready(120_000);
    ch.close();
    await expect(proof).rejects.toThrow(/proof channel closed/);
    await expect(topup).rejects.toThrow(/proof channel closed/);
    await expect(ready).resolves.toBe(false);
    expect(Date.now() - t).toBeLessThan(1000);
  });

  it("a 2PC wait (the key share) is rejected at once", async () => {
    const s = new TwoPcSession({} as WasmHost);
    const t = Date.now();
    const share = s.keyShare(120_000);
    s.close();
    await expect(share).rejects.toThrow(/2PC closed/);
    expect(Date.now() - t).toBeLessThan(1000);
  });
});
