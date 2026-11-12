/**
 * The browser client on protocol v3 (ported from routstr-sdk
 * tests/unit/confidential-v3-transport.test.ts): the framing it chooses
 * (PROTOCOL-V3.md §2.3), the fallback from "2" to "1.1", connection reuse and
 * its scopes (§9.1), refused requests (§12.4), the deposit, armed connections
 * (§9.2), and what a failure does before and after a request was released.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { chooseFraming, createConfidentialClient, http2OpenFailure, type ConfidentialClient } from "../src/client.js";
import {
  ConfidentialError,
  ConnectionDepositError,
  NodeProtocolOutdatedError,
  RequestRefusedError,
  SessionProtocolError,
  SessionRejectedError,
  TwoPcVersionMismatchError,
  UpgradeRequiredError,
} from "../src/errors.js";
import { verifyConfidentialOffer } from "../src/offer.js";
import { ConfidentialConnection, type ConnectionRequestOptions } from "../src/connection.js";
import {
  BOTH,
  BOTH_IMAGES,
  H2_BLOCK,
  IMAGES,
  NODE_PUB,
  NO_HOST,
  ONLY_11,
  fakeConnections,
  mockNodeOffer,
  restoreFetch,
  signedV3Offer,
  type Behaviour,
} from "./fixtures/v3.js";

let node = 0;
const freshNode = () => `https://v3-${++node}.example`;
const clients: ConfidentialClient[] = [];
function client(extra: Record<string, unknown> = {}): ConfidentialClient {
  const c = createConfidentialClient({
    node: freshNode(),
    nodePubkeys: [NODE_PUB],
    trustedHosts: ["*.venice.ai"],
    credential: "sk-x",
    host: NO_HOST,
    ...extra,
  });
  clients.push(c);
  return c;
}
async function chat(c: ConfidentialClient, extra: Record<string, unknown> = {}) {
  const s = await c.chat.completions.create({ model: "cheap", messages: [{ role: "user", content: "x" }], stream: true, ...extra });
  let text = "";
  for await (const ch of s) text += ch.choices[0]?.delta?.content ?? "";
  const r = await s.verification;
  return { r, text };
}
const image = (c: ConfidentialClient) => c.images.generate({ model: "z-image-turbo", prompt: "a red circle" });
const verified = (extra: Record<string, unknown> = BOTH) =>
  verifyConfidentialOffer(signedV3Offer(extra), { pinnedPubkeys: [NODE_PUB], trustedHosts: ["*.venice.ai"] });
const framings = (connect: { mock: { contexts: unknown[] } }) => connect.mock.contexts.map((c: any) => c.framing);
const settle = () => new Promise((r) => setTimeout(r, 15));

afterEach(() => {
  for (const c of clients.splice(0)) c.close();
  vi.restoreAllMocks();
  restoreFetch();
});

describe("v3 offer", () => {
  it("is fetched with ?v=3", async () => {
    const { urls } = mockNodeOffer();
    fakeConnections();
    await chat(client());
    expect(urls[0]).toMatch(/\/v1\/confidential\/offer\?v=3$/);
  });

  it("an offer below v3 is node_protocol_outdated, whatever its shape, reported once", async () => {
    for (const raw of [signedV3Offer({ v: 2 }), { v: 2, min_v: 2, max_v: 2, upstream_host: "api.venice.ai" }, { v: 1 }]) {
      expect(() => verifyConfidentialOffer(raw, { pinnedPubkeys: [NODE_PUB], trustedHosts: ["*.venice.ai"] })).toThrow(
        /node_protocol_outdated.*v[12].*this client speaks v3/,
      );
    }
    globalThis.fetch = (async () => new Response(JSON.stringify(signedV3Offer({ v: 2 })))) as typeof fetch;
    const seen: [string, number][] = [];
    const c = client({ onNodeProtocolOutdated: (n: string, v: number) => seen.push([n, v]) });
    await expect(chat(c)).rejects.toBeInstanceOf(NodeProtocolOutdatedError);
    await expect(chat(c)).rejects.toMatchObject({ code: "node_protocol_outdated" });
    expect(seen).toEqual([[c.node, 2]]);
  });

  it("the signed version counts, not the envelope's", () => {
    const signed = signedV3Offer({ v: 2 });
    expect(() => verifyConfidentialOffer({ ...signed, v: 3 }, { pinnedPubkeys: [NODE_PUB], trustedHosts: ["*.venice.ai"] })).toThrow(
      NodeProtocolOutdatedError,
    );
  });

  it("refuses a newer version, another key schedule, unknown or repeated framings and a bad deposit", () => {
    const check = (extra: Record<string, unknown>) => () => verified(extra);
    expect(check({ v: 4 })).toThrow(/update the client/);
    expect(check({ twopc: "split-proven-1" })).toThrow(/two-party key schedule/);
    expect(check({ twopc: undefined })).toThrow(/two-party key schedule/);
    expect(check({ http: [] })).toThrow(/offer.http/);
    expect(check({ http: ["3"] })).toThrow(/offer.http/);
    expect(check({ http: ["1.1", "1.1"] })).toThrow(/offer.http/);
    expect(check({ connection_deposit_msat: -1 })).toThrow(/connection_deposit_msat/);
    expect(check({ idle_timeout_s: 5 })).toThrow(/idle_timeout_s/);
  });

  it("keeps the operator's order of framings, and drops a refused h2 block when 1.1 is offered", () => {
    expect(verified(BOTH).http).toEqual(["2", "1.1"]);
    expect(verified({ http: ["1.1", "2"], h2: H2_BLOCK }).http).toEqual(["1.1", "2"]);
    expect(verified({}).http).toEqual(["1.1"]);
    const badProbe = verified({ http: ["2", "1.1"], h2: { ...H2_BLOCK, probe_path: "/api/v1/api_keys" } });
    expect(badProbe.http).toEqual(["1.1"]);
    expect(badProbe.http2Refused).toMatch(/probe_path/);
    expect(() => verified({ http: ["2"], h2: { ...H2_BLOCK, max_requests: 0 } })).toThrow(/only framing "2"/);
  });
});

describe("choosing the framing (§2.3)", () => {
  it("auto takes the offer's first entry that serves the request; a bad mark skips 2", () => {
    expect(chooseFraming(verified(BOTH), "chat")).toBe("2");
    expect(chooseFraming(verified(ONLY_11), "chat")).toBe("1.1");
    expect(chooseFraming(verified(BOTH_IMAGES), "images")).toBe("2");
    expect(chooseFraming(verified({ ...BOTH_IMAGES, h2: H2_BLOCK }), "images")).toBe("1.1");
    expect(chooseFraming(verified(BOTH), "chat", { bad: true })).toBe("1.1");
    expect(chooseFraming(verified({ http: ["2"], h2: H2_BLOCK }), "chat", { bad: true })).toBe("2");
  });

  it("a configured framing is the only one used; a one-off bearer prefers 1.1", () => {
    expect(chooseFraming(verified(BOTH), "chat", { http: "1.1" })).toBe("1.1");
    expect(chooseFraming(verified(BOTH), "chat", { http: "2", bad: true })).toBe("2");
    expect(() => chooseFraming(verified(ONLY_11), "chat", { http: "2" })).toThrow(/does not serve chat requests with framing "2"/);
    expect(chooseFraming(verified(BOTH), "chat", { oneOff: true })).toBe("1.1");
  });

  it("which failures of a framing-2 open the fallback covers", () => {
    const withCode = (code: string, status?: number) => {
      const e = new SessionRejectedError("node rejected", undefined, status);
      e.nodeCode = code;
      return e;
    };
    expect(http2OpenFailure(withCode("h2_withdrawn", 400))).toBe(true);
    expect(http2OpenFailure(withCode("upstream_unreachable", 502))).toBe(true);
    expect(http2OpenFailure(new SessionRejectedError("connection closed"))).toBe(true);
    expect(http2OpenFailure(new SessionProtocolError("handshake"))).toBe(true);
    expect(http2OpenFailure(new SessionRejectedError("no funds", undefined, 402))).toBe(false);
    expect(http2OpenFailure(new ConnectionDepositError("deposit", 1000, 402))).toBe(false);
    expect(http2OpenFailure(new RequestRefusedError(409, "offer_changed"))).toBe(false);
    expect(http2OpenFailure(new UpgradeRequiredError("upgrade", 4))).toBe(false);
    expect(http2OpenFailure(new TwoPcVersionMismatchError("tag"))).toBe(false);
    expect(http2OpenFailure(new DOMException("aborted", "AbortError"))).toBe(false);
  });

  it("the client's http setting is checked and can be changed (HTTP/2 off)", async () => {
    expect(() => client({ http: "3" })).toThrow(/http is not/);
    mockNodeOffer(BOTH);
    const { connect } = fakeConnections();
    const c = client();
    expect(await c.framing()).toBe("2");
    c.setHttp("1.1");
    expect(await c.framing()).toBe("1.1");
    const { r } = await chat(c);
    expect(r.framing).toBe("1.1");
    expect(framings(connect)).toEqual(["1.1"]);
  });
});

describe("framing 2 connections", () => {
  it("runs sequential requests on one connection", async () => {
    mockNodeOffer();
    const { connect, request } = fakeConnections();
    const c = client();
    const seen: [string, number, string][] = [];
    for (let i = 1; i <= 3; i++) {
      const { r, text } = await chat(c);
      expect(text).toBe("hi");
      seen.push([r.framing, r.n, r.connection]);
      expect(r.costMsats).toBe(7);
      expect(r.protocol).toBe(3);
    }
    expect(seen).toEqual([
      ["2", 1, "new"],
      ["2", 2, "reused"],
      ["2", 3, "reused"],
    ]);
    expect(connect).toHaveBeenCalledTimes(1);
    expect(request).toHaveBeenCalledTimes(3);
    expect(c.connections()).toMatchObject([{ http: "2", state: "idle", requests: 3 }]);
  });

  it("opens a second connection for an overlapping request", async () => {
    mockNodeOffer();
    let free!: () => void;
    const gate = new Promise<void>((r) => (free = r));
    const { connect } = fakeConnections((_c, n) => (n === 1 ? { wait: gate } : {}));
    const c = client();
    const first = chat(c);
    await settle();
    const second = chat(c);
    await settle();
    expect(connect).toHaveBeenCalledTimes(2);
    free();
    const [a, b] = await Promise.all([first, second]);
    expect(a.r.sid).not.toBe(b.r.sid);
  });

  it("does not share a connection across credentials or reuse scopes", async () => {
    mockNodeOffer();
    const { connect } = fakeConnections();
    const c = client();
    await chat(c);
    c.setCredential("sk-y");
    await chat(c);
    const scoped = client({ reuseScope: "user-2" });
    await chat(scoped);
    expect(connect).toHaveBeenCalledTimes(3);
  });

  it("reuse none closes the connection after its request", async () => {
    mockNodeOffer();
    const { connect } = fakeConnections();
    const c = client({ http2: { reuse: "none" } });
    await chat(c);
    expect(c.connections()).toHaveLength(0);
    const { r } = await chat(c);
    expect(r.connection).toBe("new");
    expect(connect).toHaveBeenCalledTimes(2);
  });

  it("an image request runs on the connection a chat request left and is settled by accept", async () => {
    const { connect, request } = fakeConnections();
    mockNodeOffer(BOTH_IMAGES);
    const c = client();
    await chat(c);
    const res = await image(c);
    expect(res.confidential).toMatchObject({ framing: "2", n: 2, connection: "reused", imageVariant: "webp", imageCount: 1 });
    expect(res.costMsats).toBe(12100);
    expect(res.images).toHaveLength(1);
    expect(res.images[0]!.type).toBe("image/webp");
    expect(new Uint8Array(await res.images[0]!.arrayBuffer())).toEqual(new TextEncoder().encode("hello"));
    expect(connect).toHaveBeenCalledTimes(1);
    const opts = request.mock.calls[1]![0] as ConnectionRequestOptions;
    expect(opts.image).toEqual({ variant: "webp", count: 1 });
    expect(new TextDecoder().decode(opts.body)).toBe(
      '{"prompt":"a red circle","model":"z-image-turbo","variants":1,"return_binary":false,"format":"webp"}',
    );
  });

  it("an image request uses 1.1 when the h2 block does not list images", async () => {
    const { connect } = fakeConnections();
    mockNodeOffer({ ...BOTH_IMAGES, h2: H2_BLOCK });
    const res = await image(client());
    expect(res.confidential.framing).toBe("1.1");
    expect(framings(connect)).toEqual(["1.1"]);
  });
});

describe("framing 1.1", () => {
  it("runs each request on a connection of its own", async () => {
    mockNodeOffer(ONLY_11);
    const { connect, request } = fakeConnections();
    const c = client();
    for (let i = 0; i < 2; i++) {
      const { r } = await chat(c);
      expect([r.framing, r.n, r.connection]).toEqual(["1.1", 1, "new"]);
    }
    expect(framings(connect)).toEqual(["1.1", "1.1"]);
    expect(request).toHaveBeenCalledTimes(2);
    expect(c.connections()).toHaveLength(0);
  });

  it("is forced by http: 1.1 (HTTP/2 off), also when the offer prefers 2", async () => {
    mockNodeOffer(BOTH);
    const { connect } = fakeConnections();
    const { r } = await chat(client({ http: "1.1" }));
    expect(r.framing).toBe("1.1");
    expect(framings(connect)).toEqual(["1.1"]);
  });

  it("a node that does not offer the forced framing is not used", async () => {
    mockNodeOffer(ONLY_11);
    const { connect } = fakeConnections();
    await expect(chat(client({ http: "2" }))).rejects.toThrow(/does not serve chat requests with framing "2"/);
    expect(connect).not.toHaveBeenCalled();
  });

  it("serves a one-off Cashu bearer on 1.1 and closes its connection", async () => {
    mockNodeOffer(BOTH);
    const { connect } = fakeConnections();
    const close = vi.spyOn(ConfidentialConnection.prototype, "close");
    const c = client({ credential: "cashuBtoken" });
    const { r } = await chat(c);
    expect(r.framing).toBe("1.1");
    expect(framings(connect)).toEqual(["1.1"]);
    expect(close).toHaveBeenCalled();
    expect(c.connections()).toHaveLength(0);
  });
});

describe("fallback from 2 to 1.1 (§2.3)", () => {
  it("a connection that fails to open is served on 1.1 on the same node, and 2 is not tried for 10 minutes", async () => {
    mockNodeOffer(BOTH);
    const events: Record<string, unknown>[] = [];
    const { connect } = fakeConnections(undefined, {
      connectFails: (conn) => {
        if (conn.framing !== "2") return undefined;
        const e = new SessionRejectedError("node rejected: h2 not selected");
        e.nodeCode = "h2_not_selected";
        return e;
      },
    });
    const c = client({ onEvent: (e: Record<string, unknown>) => events.push(e) });
    const { r } = await chat(c);
    expect(r.framing).toBe("1.1");
    expect(r.fellBack).toBe(true);
    expect(framings(connect)).toEqual(["2", "1.1"]);
    expect(events.some((e) => e.ev === "framing_fallback")).toBe(true);
    expect(await c.framing()).toBe("1.1");
    await chat(c);
    expect(framings(connect)).toEqual(["2", "1.1", "1.1"]);
    vi.useFakeTimers({ now: Date.now() + 10 * 60_000 + 1, toFake: ["Date"] });
    try {
      await chat(c);
    } finally {
      vi.useRealTimers();
    }
    expect(framings(connect).slice(3)).toEqual(["2", "1.1"]);
  });

  it("the first request failing before its body was released falls back too; never after release", async () => {
    mockNodeOffer(BOTH);
    let released = false;
    const { connect } = fakeConnections((conn) => (conn.framing === "2" ? { released, fail: new SessionRejectedError("connection closed") } : {}));
    expect((await chat(client())).r.framing).toBe("1.1");
    expect(framings(connect)).toEqual(["2", "1.1"]);
    released = true;
    await expect(chat(client())).rejects.toThrow(/connection closed/);
    expect(framings(connect)).toEqual(["2", "1.1", "2"]);
  });

  it("not for a refusal with a status, not when 2 is forced, not when 1.1 is not offered", async () => {
    mockNodeOffer(BOTH);
    let fail: Error = new SessionRejectedError("node rejected: no funds", undefined, 402);
    const { connect } = fakeConnections(undefined, { connectFails: (conn) => (conn.framing === "2" ? fail : undefined) });
    await expect(chat(client())).rejects.toMatchObject({ status: 402 });
    fail = new SessionRejectedError("connection closed");
    await expect(chat(client({ http: "2" }))).rejects.toThrow(/connection closed/);
    mockNodeOffer({ http: ["2"], h2: H2_BLOCK });
    await expect(chat(client())).rejects.toThrow(/connection closed/);
    expect(framings(connect)).toEqual(["2", "2", "2"]);
  });
});

describe("a refused request (§12.4)", () => {
  it("throws the node's refusal, and the connection serves the next request with the same number", async () => {
    mockNodeOffer();
    let behave: Behaviour = () => ({});
    const { connect, request } = fakeConnections((conn, n, o) => behave(conn, n, o));
    const c = client();
    await chat(c);
    behave = () => ({ refuse: { status: 402, reason: "Insufficient balance", detail: { error: { code: "insufficient_balance" } } } });
    const err = await chat(c).catch((e) => e);
    expect(err).toBeInstanceOf(RequestRefusedError);
    expect(err).toMatchObject({ status: 402, code: "request_refused" });
    expect(c.connections()).toMatchObject([{ state: "idle", requests: 1 }]);
    behave = () => ({});
    const { r } = await chat(c);
    expect([r.n, r.connection]).toEqual([2, "reused"]);
    expect(connect).toHaveBeenCalledTimes(1);
    expect(request).toHaveBeenCalledTimes(3);
  });

  it("offer_expired refetches the offer and runs the request again on the same connection", async () => {
    const { urls } = mockNodeOffer();
    let refusals = 0;
    const { connect, request } = fakeConnections((_c, n) => (n === 2 && refusals++ === 0 ? { refuse: { status: 409, reason: "offer_expired" } } : {}));
    const c = client();
    await chat(c);
    const { r } = await chat(c);
    expect([r.n, r.connection]).toEqual([2, "reused"]);
    expect(connect).toHaveBeenCalledTimes(1);
    expect(request).toHaveBeenCalledTimes(3);
    expect(urls).toHaveLength(2);
  });

  it("offer_changed opens a new connection on the new offer's terms", async () => {
    mockNodeOffer();
    let changed = false;
    const { connect } = fakeConnections((_c, n) => {
      if (n !== 2 || changed) return {};
      changed = true;
      mockNodeOffer({ ...BOTH, connection_deposit_msat: 2000 });
      return { refuse: { status: 409, reason: "offer_changed" } };
    });
    const c = client();
    await chat(c);
    const { r } = await chat(c);
    expect([r.n, r.connection]).toEqual([1, "new"]);
    expect(connect).toHaveBeenCalledTimes(2);
    expect((connect.mock.contexts[1] as any).depositMsat).toBe(2000);
    expect(r.deposit.msat).toBe(2000);
  });
});

describe("offer_changed with unchanged terms, padding, evicted", () => {
  it("offer_changed closes the connection even when the refetched offer has the same terms", async () => {
    mockNodeOffer();
    let refused = 0;
    const { connect, request } = fakeConnections((conn, n) =>
      conn.sid.startsWith("00000001") && n === 2 && refused++ === 0 ? { refuse: { status: 409, reason: "offer_changed" } } : {},
    );
    const c = client();
    await chat(c);
    const { r } = await chat(c);
    expect([r.n, r.connection]).toEqual([1, "new"]);
    expect(connect).toHaveBeenCalledTimes(2);
    expect(request).toHaveBeenCalledTimes(3);
  });

  it("padBucket reaches the connection's request", async () => {
    mockNodeOffer();
    const { request } = fakeConnections();
    await chat(client({ padBucket: "pow2" }));
    expect((request.mock.calls[0]![0] as ConnectionRequestOptions).padBucket).toBe("pow2");
  });

  it("an idle connection the node evicted is never reused: the next request opens its own", async () => {
    mockNodeOffer();
    const { connect } = fakeConnections();
    const c = client();
    await chat(c);
    const conn = (connect.mock.contexts[0] as any);
    conn.closedReason = "evicted";
    conn.goaway = true;
    const { r } = await chat(c);
    expect([r.n, r.connection]).toEqual([1, "new"]);
    expect(connect).toHaveBeenCalledTimes(2);
  });
});

describe("a pooled connection is a cache, never a promise", () => {
  it("runs the request on a fresh connection when the pooled one fails before the release", async () => {
    mockNodeOffer();
    const { connect, request } = fakeConnections((conn, n) =>
      conn.sid.startsWith("00000001") && n === 2 ? { fail: new SessionRejectedError("connection closed by the node: idle") } : {},
    );
    const c = client();
    await chat(c);
    const { r } = await chat(c);
    expect(r.connection).toBe("new");
    expect(framings(connect)).toEqual(["2", "2"]);
    expect(request).toHaveBeenCalledTimes(3);
  });

  it("never runs a released request again", async () => {
    mockNodeOffer();
    const { connect } = fakeConnections((_c, n) => (n === 2 ? { released: true, fail: new SessionRejectedError("connection closed") } : {}));
    const c = client();
    await chat(c);
    await expect(chat(c)).rejects.toThrow(/connection closed/);
    expect(connect).toHaveBeenCalledTimes(1);
    expect(c.connections()).toHaveLength(0);
  });
});

describe("the connection deposit", () => {
  it("a node asking for more than the client's maximum is not used, before anything is sent", async () => {
    const { connect } = fakeConnections();
    mockNodeOffer({ ...BOTH, connection_deposit_msat: 100_001 });
    await expect(chat(client())).rejects.toThrow(ConnectionDepositError);
    await expect(chat(client())).rejects.toThrow(/connection deposit of 100001 msat, above the maximum of 100000 msat/);
    expect(connect).not.toHaveBeenCalled();
    expect((await chat(client({ maxConnectionDepositMsat: 100_001 }))).r.framing).toBe("2");
    mockNodeOffer({ ...BOTH, connection_deposit_msat: 7000 });
    await expect(chat(client({ maxConnectionDepositMsat: 6999 }))).rejects.toThrow(ConnectionDepositError);
    mockNodeOffer({ ...BOTH, connection_deposit_msat: 0 });
    expect((await chat(client({ maxConnectionDepositMsat: 0 }))).r.deposit.msat).toBe(0);
  });

  it("is in the pricing: a new connection needs the deposit plus one reservation", async () => {
    mockNodeOffer({ ...BOTH, connection_deposit_msat: 3000 });
    const c = client();
    vi.spyOn(c, "models").mockResolvedValue([{ id: "cheap", context_length: 1000 } as never]);
    const [p] = await c.pricing(100);
    expect(p!.connectionDepositMsat).toBe(3000);
    // 1000 tokens of context and 100 + 0 margin out, at 1000 msat/1k each: 1100 msat, no fees.
    expect(p!.reservationMsat).toBe(1100);
    expect(p!.requiredMsat).toBe(4100);
  });
});

describe("armed connections (§9.2)", () => {
  const visible = () => {
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: { visibilityState: "visible", addEventListener: () => {} },
    });
  };
  const funded = (c: ConfidentialClient, balance = 1e9) => vi.spyOn(c.api, "balance").mockResolvedValue({ balance, reserved: 0 } as never);
  afterEach(() => {
    delete (globalThis as { document?: unknown }).document;
  });

  it("framing 1.1: after a settled request an armed connection waits for the next one", async () => {
    visible();
    mockNodeOffer(ONLY_11);
    const { arm } = fakeConnections();
    const c = client({ prewarm: true });
    funded(c);
    vi.spyOn(c, "models").mockResolvedValue([{ id: "cheap", context_length: 1000 } as never]);
    expect((await chat(c)).r.connection).toBe("new");
    await new Promise((r) => setTimeout(r, 60));
    expect(arm).toHaveBeenCalledWith(true);
    expect(c.connections()).toMatchObject([{ http: "1.1", state: "armed", requests: 0 }]);
    const { r } = await chat(c);
    expect([r.connection, r.prewarmed]).toEqual(["armed", true]);
  });

  it("framing 2: with armWithoutOpen, a spare is armed once the open connection is gone", async () => {
    visible();
    mockNodeOffer(BOTH);
    const conns: any[] = [];
    const { arm } = fakeConnections((conn) => (conns.push(conn), {}));
    const c = client({ prewarm: true });
    funded(c);
    vi.spyOn(c, "models").mockResolvedValue([{ id: "cheap", context_length: 1000 } as never]);
    await chat(c);
    await new Promise((r) => setTimeout(r, 60));
    // One idle open connection: nothing to arm.
    expect(arm.mock.calls.filter((x) => x[0] === true)).toHaveLength(0);
    // It ends (the node's idle limit): one connection is armed, so the next message does not wait for a 2PC.
    conns[0].close("idle");
    await new Promise((r) => setTimeout(r, 60));
    expect(arm.mock.calls.filter((x) => x[0] === true)).toHaveLength(1);
    expect(c.connections()).toMatchObject([{ http: "2", state: "armed" }]);
    const { r } = await chat(c);
    expect([r.framing, r.n, r.connection, r.prewarmed]).toEqual(["2", 1, "armed", true]);
  });

  it("framing 2 without armWithoutOpen: no spare while the key has no open connection", async () => {
    visible();
    mockNodeOffer(BOTH);
    const conns: any[] = [];
    const { arm } = fakeConnections((conn) => (conns.push(conn), {}));
    const c = client({ prewarm: { armWithoutOpen: false } });
    funded(c);
    vi.spyOn(c, "models").mockResolvedValue([{ id: "cheap", context_length: 1000 } as never]);
    await chat(c);
    conns[0].close("idle");
    await new Promise((r) => setTimeout(r, 60));
    expect(arm.mock.calls.filter((x) => x[0] === true)).toHaveLength(0);
  });

  it("never arms without funds for the deposit plus one reservation, above maxDepositMsat, or when off", async () => {
    visible();
    mockNodeOffer({ ...ONLY_11, connection_deposit_msat: 1000 });
    const { arm } = fakeConnections();
    const poor = client({ prewarm: true });
    funded(poor, 1500);
    vi.spyOn(poor, "models").mockResolvedValue([{ id: "cheap", context_length: 1000 } as never]);
    await chat(poor);
    await new Promise((r) => setTimeout(r, 60));
    expect(poor.prewarmer!.status).toBe("waiting-funds");
    mockNodeOffer({ ...ONLY_11, connection_deposit_msat: 5001 });
    const dear = client({ prewarm: true });
    funded(dear);
    vi.spyOn(dear, "models").mockResolvedValue([{ id: "cheap", context_length: 1000 } as never]);
    await chat(dear);
    await new Promise((r) => setTimeout(r, 60));
    const off = client({ prewarm: { enabled: false } });
    await chat(off);
    await new Promise((r) => setTimeout(r, 60));
    expect(arm.mock.calls.filter((x) => x[0] === true)).toHaveLength(0);
  });
});

describe("requests the client refuses before anything is sent", () => {
  it("n other than 1 is refused (one completion per request)", async () => {
    mockNodeOffer();
    const { connect } = fakeConnections();
    await expect(chat(client(), { n: 2 })).rejects.toMatchObject({ code: "pinned_parameter" });
    await expect(chat(client(), { n: 1 })).resolves.toBeTruthy();
    expect(connect).toHaveBeenCalledTimes(1);
  });

  it("an image request needs an offer with images", async () => {
    mockNodeOffer(BOTH);
    fakeConnections();
    await expect(image(client())).rejects.toBeInstanceOf(ConfidentialError);
    mockNodeOffer({ ...ONLY_11, capabilities: ["chat", "images"], images: IMAGES });
    await expect(image(client({ http: "2" }))).rejects.toThrow(/framing "2"/);
  });
});
