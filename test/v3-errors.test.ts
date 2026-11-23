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
import { ConfidentialConnection, depositProblems, missingLastFrameProblem } from "../src/connection.js";
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

describe("the wasm 2PC driver's version tag (split-public-3)", () => {
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
    expect(e.message).toMatch(/split-public-3/);
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

describe("the deposit outcome is checked against the signed terms (detection only)", () => {
  const signedDeposit = (d: Record<string, unknown>) => {
    const deposit = { sid: null, msat: 3000, cost_msats: 0, balance_msats: 10, time: 1, ...d };
    const json = canonicalJson(deposit);
    return { deposit, deposit_json: json, deposit_sig: bytesToHex(schnorr.sign(sha256(utf8ToBytes(json)), PRIV)) };
  };
  /** Arms against a node whose last frame is `last`; returns the events seen. */
  async function lastFrame(last: Record<string, unknown>) {
    const events: Record<string, unknown>[] = [];
    const c = conn(nodeSocket(() => [last]), { onEvent: (e: Record<string, unknown>) => events.push(e) });
    await c.arm().catch(() => {});
    return { c, events, warnings: events.filter((e) => e.ev === "warning") };
  }

  it("an outcome within the rules raises no warning and keeps the deposit event", async () => {
    for (const last of [
      { type: "error", status: 503, reason: "x", ...signedDeposit({ outcome: "released", reason: "not_started" }) },
      { type: "closed", reason: "idle", ...signedDeposit({ outcome: "charged", reason: "unused" }) },
      { type: "error", status: 400, reason: "x", ...signedDeposit({ outcome: "charged", reason: "unused" }) },
    ]) {
      const { events, warnings } = await lastFrame(last);
      expect(events.some((e) => e.ev === "deposit")).toBe(true);
      expect(warnings).toEqual([]);
    }
  });

  it("another amount than the signed offer's is a deposit_outcome warning", async () => {
    const { c, events, warnings } = await lastFrame({
      type: "closed",
      reason: "idle",
      ...signedDeposit({ outcome: "released", reason: "not_started", msat: 2999 }),
    });
    expect(c.deposit).toMatchObject({ msat: 2999, outcome: "released" });
    expect(events.some((e) => e.ev === "deposit")).toBe(true);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatchObject({ ev: "warning", code: "deposit_outcome" });
    expect(String(warnings[0].message)).toMatch(/2999 msat, the signed offer's is 3000/);
  });

  it("charged after a fault of the node or the provider is a warning", async () => {
    for (const fault of ["node", "upstream"]) {
      const { warnings } = await lastFrame({
        type: "error",
        status: 502,
        reason: "x",
        fault,
        ...signedDeposit({ outcome: "charged", reason: "unused" }),
      });
      expect(warnings).toHaveLength(1);
      expect(String(warnings[0].message)).toMatch(new RegExp(`fault of the ${fault === "node" ? "node" : "provider"}`));
    }
  });

  it("charged with a reason that releases the deposit is a warning", async () => {
    for (const reason of ["request_settled", "not_started", "provider_unreachable", "sidecar_failure", "provider_closed", "node_failure", "request_received", "provider_refused"]) {
      const { warnings } = await lastFrame({ type: "closed", reason: "x", ...signedDeposit({ outcome: "charged", reason }) });
      expect(warnings, reason).toHaveLength(1);
      expect(String(warnings[0].message)).toContain(JSON.stringify(reason));
    }
  });

  it("charged after a receipt of the connection released it is a warning", async () => {
    const events: Record<string, unknown>[] = [];
    const c = conn(nodeSocket(() => []), { onEvent: (e: Record<string, unknown>) => events.push(e) }) as any;
    c.deposit = { msat: 3000, outcome: "released", reason: "request_settled", signed: true };
    c.onText(JSON.stringify({ type: "closed", reason: "idle", ...signedDeposit({ outcome: "charged", reason: "unused" }) }));
    const warnings = events.filter((e) => e.ev === "warning");
    expect(warnings).toHaveLength(1);
    expect(String(warnings[0].message)).toMatch(/a receipt of this connection released it/);
    c.close();
  });

  const SID = "ab".repeat(32);
  /** A connection past `ready` (it has a sid) with no network side; `frame` is its last frame. */
  function after(frame: Record<string, unknown>, state: Record<string, unknown> = {}, offer?: Record<string, unknown>) {
    const events: Record<string, unknown>[] = [];
    const c = conn(nodeSocket(() => []), { onEvent: (e: Record<string, unknown>) => events.push(e) }) as any;
    c.sid = SID;
    Object.assign(c, state);
    if (offer) c.offer = { ...c.offer, ...offer };
    c.onText(JSON.stringify(frame));
    const warnings = events.filter((e) => e.ev === "warning").map((e) => String(e.message));
    const deposit = c.deposit;
    c.close();
    return { warnings, deposit, events };
  }
  const own = (d: Record<string, unknown>) => signedDeposit({ sid: SID, ...d });

  it("a release, and a signed charge after the client left, raise no warning", () => {
    for (const frame of [
      { type: "closed", reason: "upstream_closed", ...own({ outcome: "released", reason: "provider_closed" }) },
      { type: "error", status: 502, reason: "x", fault: "node", ...own({ outcome: "released", reason: "sidecar_failure" }) },
      { type: "closed", reason: "client_closed", ...own({ outcome: "charged", reason: "unused" }) },
      { type: "error", status: 400, reason: "x", ...own({ outcome: "charged", reason: "unused" }) },
    ]) {
      const { warnings, deposit } = after(frame);
      expect(deposit).toMatchObject({ outcome: (frame.deposit as Record<string, unknown>).outcome, signed: true });
      expect(warnings, JSON.stringify(frame.deposit)).toEqual([]);
    }
  });

  it("charged without a valid signature is a warning", () => {
    const charged = { type: "closed", reason: "x", ...own({ outcome: "charged", reason: "unused" }) };
    for (const bad of [{ deposit_sig: "00".repeat(64) }, { deposit_sig: undefined }]) {
      const { warnings, deposit, events } = after({ ...charged, ...bad });
      expect(deposit).toMatchObject({ outcome: "charged", signed: false });
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toMatch(/unsigned deposit outcome names charged without a valid signature/);
      expect(events.find((e) => e.ev === "warning")).toMatchObject({ code: "deposit_outcome" });
    }
    // A signature over another connection's outcome is none for this one.
    const other = after({ type: "closed", reason: "x", ...signedDeposit({ sid: "cd".repeat(32), outcome: "charged", reason: "unused" }) });
    expect(other.warnings.join("\n")).toMatch(/charged without a valid signature/);
    // An unsigned release costs nothing: recorded as unsigned, not reported.
    const released = { type: "closed", reason: "x", ...own({ outcome: "released", reason: "not_started" }), deposit_sig: "00".repeat(64) };
    expect(after(released).warnings).toEqual([]);
  });

  it("charged though the provider closed the idle connection is a warning", () => {
    const charged = own({ outcome: "charged", reason: "unused" });
    const { warnings } = after({ type: "closed", reason: "upstream_closed", ...charged });
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/charged though the provider closed the idle connection \(§12\.10 row 5 releases it\)/);
    // Not after the client's own control frames, nor with a request of ours outstanding or accepted before.
    for (const [extra, state] of [
      [{ reason: "upstream_closed", after_client_frames: true }, {}],
      [{ reason: "upstream_closed" }, { cur: { n: 1 } }],
      [{ reason: "upstream_closed" }, { requests: 1 }],
      [{ reason: "idle" }, {}],
    ] as const) {
      expect(after({ type: "closed", ...extra, ...charged }, state).warnings, JSON.stringify([extra, state])).toEqual([]);
    }
  });

  it("a last frame without an outcome for a deposit the setup reserved is a warning", () => {
    for (const frame of [
      { type: "closed", reason: "idle" },
      { type: "error", status: 500, reason: "x" },
      { type: "closed", reason: "idle", deposit: null },
      { type: "closed", reason: "idle", deposit: { msat: 3000, outcome: "kept" } },
      { type: "closed", reason: "idle", deposit: { msat: 3000, outcome: "released" }, deposit_json: "{" },
    ]) {
      const { warnings, deposit, events } = after(frame);
      expect(deposit).toBeUndefined();
      expect(warnings, JSON.stringify(frame)).toHaveLength(1);
      expect(warnings[0]).toMatch(/the node's last frame carries no deposit outcome for a deposit of 3000 msat/);
      expect(events.find((e) => e.ev === "warning")).toMatchObject({ code: "deposit_outcome" });
    }
  });

  it("no outcome is expected once a receipt released the deposit, before ready, or without a deposit", () => {
    const settled = after(
      { type: "closed", reason: "idle" },
      { deposit: { msat: 3000, outcome: "released", reason: "request_settled", signed: true } },
    );
    expect(settled.deposit).toMatchObject({ outcome: "released", reason: "request_settled" });
    expect(settled.warnings).toEqual([]);
    expect(after({ type: "error", status: 503, reason: "no session slot" }, { sid: "" }).warnings).toEqual([]);
    expect(after({ type: "closed", reason: "idle" }, { depositMsat: 0 }).warnings).toEqual([]);
  });

  const outcome = (o: Record<string, unknown>) => {
    const ro = { v: 1, sid: SID, http: "1.1", balance_msats: 1, time: 1, ...o };
    const json = canonicalJson(ro);
    return { request_outcome: ro, request_outcome_json: json, request_outcome_sig: bytesToHex(schnorr.sign(sha256(utf8ToBytes(json)), PRIV)) };
  };
  const evicted = { type: "closed", reason: "evicted", unused: true };
  const settledDeposit = { deposit: { msat: 3000, outcome: "released", reason: "request_settled", signed: true } };

  const hoard = { evicted: { unused_at_address: 5 } };
  const lone = { evicted: { unused_at_address: 1 } };

  it("an unused connection closed for a newer setup is charged, also a lone spare, without warning", () => {
    const { warnings, deposit } = after({ ...evicted, ...own({ outcome: "charged", reason: "evicted", ...hoard }) });
    expect(deposit).toMatchObject({ outcome: "charged", reason: "evicted", signed: true, evicted: { unusedAtAddress: 5 } });
    expect(warnings).toEqual([]);
    const spare = after({ ...evicted, ...own({ outcome: "charged", reason: "evicted", ...lone }) });
    expect(spare.deposit).toMatchObject({ outcome: "charged", reason: "evicted", evicted: { unusedAtAddress: 1 } });
    expect(spare.warnings).toEqual([]);
  });

  it("an older node's eviction fields raise no warning", () => {
    const old = after({ ...evicted, ...own({ outcome: "charged", reason: "evicted", evicted: { unused_at_address: 5, charge_from: 5 } }) });
    expect(old.warnings).toEqual([]);
    const spare = after({ ...evicted, ...own({ outcome: "released", reason: "evicted_released", evicted: { unused_at_address: 1, charge_from: 5 } }) });
    expect(spare.deposit).toMatchObject({ outcome: "released", reason: "evicted_released" });
    expect(spare.warnings).toEqual([]);
  });

  it("an eviction charge before the signed minimum age, or with a request in flight, is a warning", () => {
    const young = { tSetup: Date.now() - 5000 };
    const w = (state: Record<string, unknown>, offer?: Record<string, unknown>) => {
      const s = { ...state } as Record<string, unknown>;
      return after({ ...evicted, ...own({ outcome: "charged", reason: "evicted", ...lone }) }, s, offer).warnings.join();
    };
    expect(w(young, { evict_unused_after_s: 60 })).toMatch(/before the signed offer's evict_unused_after_s of 60 s/);
    expect(w({ tSetup: Date.now() - 61_000 }, { evict_unused_after_s: 60 })).toBe("");
    expect(w({ tSetup: Date.now() - 61_000 }, { evict_unused_after_s: 0 })).toMatch(/never evicted/);
    expect(w({ framing: "2", cur: { n: 1, accepted: true, released: false, first: true } })).toMatch(/had accepted a request/);
    expect(w({ framing: "1.1", helloSent: true, cur: { n: 1, accepted: true, released: false, first: true } })).toMatch(/had accepted a request/);
    // Framing "1.1": a request 1 without its ClientHello goes with the connection.
    expect(w({ framing: "1.1", helloSent: false, cur: { n: 1, accepted: true, released: false, first: true } })).not.toMatch(/had accepted a request/);
  });

  it("an eviction charge without the count, after a settled request, on another frame, or of a used connection is a warning", () => {
    expect(after({ ...evicted, ...own({ outcome: "charged", reason: "evicted" }) }).warnings.join()).toMatch(/without the signed count/);
    expect(after({ ...evicted, ...own({ outcome: "charged", reason: "evicted", ...hoard }) }, settledDeposit).warnings.join()).toMatch(/receipt of this connection released it/);
    expect(after({ type: "closed", reason: "idle", ...own({ outcome: "charged", reason: "evicted", ...hoard }) }).warnings.join()).toMatch(/not `closed` `evicted`/);
    expect(after({ type: "closed", reason: "evicted", ...own({ outcome: "charged", reason: "unused" }) }).warnings.join()).toMatch(/used connection/);
  });

  it("the signed request outcome is checked against the open request", () => {
    const state = { cur: { n: 2, accepted: true, reservedMsat: 9000, released: true, first: false }, ...settledDeposit };
    const ok = { n: 2, outcome: "charged", reason: "request_received", cost_msats: 9000, reserved_msats: 9000 };
    expect(after({ type: "error", status: 502, reason: "x", ...outcome(ok) }, state).warnings).toEqual([]);
    for (const [frame, re] of [
      [{ type: "error", status: 502, reason: "x" }, /no signed outcome for request 2/],
      [{ type: "error", status: 502, reason: "x", ...outcome({ ...ok, cost_msats: 9001 }) }, /above the announced reservation/],
      [{ type: "error", status: 502, reason: "x", ...outcome({ ...ok, n: 3 }) }, /names request 3/],
      [{ type: "error", status: 502, reason: "x", ...outcome(ok), request_outcome_sig: "00".repeat(64) }, /without a valid signature/],
    ] as const) {
      expect(after(frame as Record<string, unknown>, state).warnings.join(), JSON.stringify(frame).slice(0, 80)).toMatch(re);
    }
  });
});

describe("missingLastFrameProblem", () => {
  const base = { sid: "ab".repeat(32), depositMsat: 1000, releasedByReceipt: false };
  it("names what the node holds when its last frame never came", () => {
    expect(missingLastFrameProblem(base)).toMatch(/no signed outcome for the deposit of 1000 msat/);
    expect(missingLastFrameProblem({ ...base, releasedByReceipt: true, openAccepted: 3 })).toMatch(
      /no signed outcome for the reservation of request 3/,
    );
    expect(missingLastFrameProblem({ ...base, openAccepted: 1 })).toMatch(/deposit of 1000 msat and the reservation of request 1/);
  });
  it("is silent when nothing is held", () => {
    expect(missingLastFrameProblem({ ...base, releasedByReceipt: true })).toBeNull();
    expect(missingLastFrameProblem({ ...base, depositMsat: 0 })).toBeNull();
    expect(missingLastFrameProblem({ ...base, sid: "", openAccepted: 1 })).toBeNull();
  });
});

describe("the eviction of an unused connection", () => {
  const ctx = { sid: "ab".repeat(32), depositMsat: 1000, releasedByReceipt: false, requestOutstanding: false, requestAccepted: false };
  const frame = { type: "closed", reason: "evicted", unused: true };
  const out = { msat: 1000, outcome: "charged", reason: "evicted", evicted: { unused_at_address: 1 } } as const;
  it("is always charged, also for a lone spare", () => {
    expect(depositProblems(frame, out, true, ctx)).toEqual([]);
    expect(depositProblems(frame, out, true, { ...ctx, evictAfterS: 60, ageS: 60 })).toEqual([]);
  });
  it("is a deviation before the signed minimum age, or when the offer says never", () => {
    expect(depositProblems(frame, out, true, { ...ctx, evictAfterS: 60, ageS: 59 }).join()).toMatch(/before the signed offer/);
    expect(depositProblems(frame, out, true, { ...ctx, evictAfterS: 0, ageS: 900 }).join()).toMatch(/never evicted/);
  });
});

describe("depositProblems", () => {
  const ctx = { sid: "ab".repeat(32), depositMsat: 1000, releasedByReceipt: false, requestOutstanding: false, requestAccepted: false };
  const charged = { msat: 1000, outcome: "charged", reason: "unused" } as const;
  const released = { msat: 1000, outcome: "released", reason: "provider_closed" } as const;

  it("honest outcomes have none", () => {
    expect(depositProblems({ type: "closed", reason: "upstream_closed" }, released, true, ctx)).toEqual([]);
    expect(depositProblems({ type: "closed", reason: "client_closed" }, charged, true, ctx)).toEqual([]);
    expect(depositProblems({ type: "closed", reason: "upstream_closed", after_client_frames: true }, charged, true, ctx)).toEqual([]);
    expect(depositProblems({ type: "closed", reason: "done" }, undefined, false, { ...ctx, releasedByReceipt: true })).toEqual([]);
    expect(depositProblems({ type: "error" }, undefined, false, { ...ctx, sid: "" })).toEqual([]);
    expect(depositProblems({ type: "closed" }, undefined, false, { ...ctx, depositMsat: 0 })).toEqual([]);
  });

  it("names each deviation", () => {
    expect(depositProblems({ type: "closed", reason: "idle" }, charged, false, ctx)).toEqual(["charged without a valid signature"]);
    expect(depositProblems({ type: "closed", reason: "upstream_closed" }, charged, true, ctx)).toEqual([
      "charged though the provider closed the idle connection (§12.10 row 5 releases it)",
    ]);
    expect(depositProblems({ type: "closed", reason: "upstream_closed" }, charged, true, { ...ctx, requestOutstanding: true })).toEqual([]);
    expect(depositProblems({ type: "closed", reason: "upstream_closed" }, charged, true, { ...ctx, requestAccepted: true })).toEqual([]);
    expect(depositProblems({ type: "closed", reason: "idle" }, undefined, false, ctx)).toEqual(["no deposit outcome for a deposit of 1000 msat"]);
    expect(depositProblems({ type: "closed", reason: "idle" }, charged, true, { ...ctx, releasedByReceipt: true })).toEqual([
      "charged, though a receipt of this connection released it",
    ]);
  });
});

describe("the node's last frame never came", () => {
  class Ws {
    static last: Ws;
    binaryType = "arraybuffer";
    onopen?: () => void;
    onmessage?: (ev: { data: string }) => void;
    onclose?: (ev: { reason?: string }) => void;
    onerror?: () => void;
    constructor() {
      Ws.last = this;
    }
    send() {}
    close() {}
  }
  it("is a warning after a socket error or a malformed frame, not after the client's own close", async () => {
    for (const cause of ["error", "malformed", "client"] as const) {
      const events: Record<string, unknown>[] = [];
      const c = conn(Ws, { onEvent: (e: Record<string, unknown>) => events.push(e) }) as any;
      void c.openSocket().catch(() => {});
      c.sid = "ab".repeat(32);
      c.depositMsat = 3000;
      if (cause === "error") Ws.last.onerror?.();
      else if (cause === "malformed") Ws.last.onmessage?.({ data: "x" });
      else c.close();
      Ws.last.onclose?.({});
      const warnings = events.filter((e) => e.ev === "warning").map((e) => String(e.message)).join("\n");
      if (cause === "client") expect(warnings).not.toMatch(/without the node's last frame/);
      else expect(warnings, cause).toMatch(/without the node's last frame: no signed outcome for the deposit of 3000 msat/);
    }
  });
});

describe("SETTINGS acknowledgements", () => {
  const settings = { type: 0x4, flags: 0, stream: 0, payload: new Uint8Array(0), off: 0 };
  const ping = { type: 0x6, flags: 0, stream: 0, payload: new Uint8Array(8), off: 0 };
  const spy = (c: any) => {
    const sent: string[] = [];
    c.sendCtl = (name: string) => {
      sent.push(name);
      return Promise.resolve(0);
    };
    return sent;
  };
  it("the first waits for the next request, a later one goes at once while idle", () => {
    const c = conn(nodeSocket(() => [])) as any;
    const sent = spy(c);
    c.onFrame(settings);
    expect(sent).toEqual([]);
    c.onFrame(settings);
    expect(sent).toEqual(["settings_ack", "settings_ack"]);
  });
  it("inside a request it waits for body_released; a PING is answered at once", () => {
    const c = conn(nodeSocket(() => [])) as any;
    const sent = spy(c);
    c.settingsAckSent = true;
    c.requestOpen = true;
    c.cur = { n: 1, stream: 3, released: false, accepted: true, first: true, dataLens: [] };
    c.onFrame(settings);
    c.onFrame(ping);
    expect(sent).toEqual(["ping_ack"]);
    c.onText(JSON.stringify({ type: "body_released", n: 1 }));
    expect(sent).toEqual(["ping_ack", "settings_ack"]);
  });
});
