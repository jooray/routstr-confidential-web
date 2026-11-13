/**
 * What the client knows of a request's reservation before it releases
 * anything (`request_ok.reserved_msats`, the caller's ceiling), how that
 * bounds an error receipt, what a released request's errors carry so nothing
 * runs it twice, and what a connection erases when it ends (ported from
 * routstr-sdk tests/unit/confidential-reservation-bound.test.ts).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { createConfidentialClient, http2OpenFailure, type ConfidentialClient } from "../src/client.js";
import { ConfidentialConnection, type ConnectionRequestOptions } from "../src/connection.js";
import {
  CONFIDENTIAL_ERROR_CODES,
  ConfidentialError,
  MAY_HAVE_REACHED_PROVIDER,
  ReceiptVerificationError,
  ReservationAboveCeilingError,
  SessionProtocolError,
  SessionRejectedError,
  confidentialErrorCode,
  mayHaveReachedProvider,
} from "../src/errors.js";
import { requestStream } from "../src/h2.js";
import { verifyConfidentialOffer, type VerifiedOffer } from "../src/offer.js";
import type { NodeModel } from "../src/node-api.js";
import { reservationCeilingMsat, reservationMsat } from "../src/pricing.js";
import { checkUpstreamErrorReceipt } from "../src/receipt.js";
import { canonicalSuffix } from "../src/suffix.js";
import { makeTLSClient } from "../src/tls-fork/lib/index.js";
import * as lib from "../src/index.js";
import { VENICE_CHAT } from "./fixtures/chat.js";
import { BOTH, IMAGE_BODY, NODE_PUB, NO_HOST, restoreFetch, signedV3Offer } from "./fixtures/v3.js";

const enc = (t: string) => new TextEncoder().encode(t);
const verified = (extra: Record<string, unknown> = {}): VerifiedOffer =>
  verifyConfidentialOffer(signedV3Offer(extra), { pinnedPubkeys: [NODE_PUB], trustedHosts: ["*.venice.ai"] });

afterEach(() => {
  vi.restoreAllMocks();
  restoreFetch();
});

describe("error receipts for a status billed at the reservation", () => {
  const err = (status: number, extra: Record<string, unknown>) =>
    ({ sid: "s1", model: "m", usage: { error_status: status }, ...extra }) as never;

  it("never take the receipt's own reservation as the bound", () => {
    for (const status of [500, 502, 504]) {
      // A validly shaped receipt whose cost and reservation were both inflated.
      const inflated = err(status, { cost_msats: 9_000_000, reserved_msats: 9_000_000 });
      expect(() => checkUpstreamErrorReceipt(inflated, status, 0)).toThrow(/no reservation bound/);
      expect(() => checkUpstreamErrorReceipt(inflated, status, 0, { reservationMsat: 50_000 })).toThrow(
        /reservation bound \(50000 msats\)/,
      );
      // The node announced 50 000 and signs another reservation in the receipt.
      expect(() =>
        checkUpstreamErrorReceipt(inflated, status, 0, { reservationMsat: 50_000, reservationAnnounced: true }),
      ).toThrow(/announced 50000/);
    }
  });

  it("accept a charge at the exact bound, and the fee without any bound", () => {
    const at = err(500, { cost_msats: 50_000, reserved_msats: 50_000 });
    expect(checkUpstreamErrorReceipt(at, 500, 0, { reservationMsat: 50_000, reservationAnnounced: true })).toBe(true);
    expect(checkUpstreamErrorReceipt(at, 500, 0, { reservationMsat: 50_000 })).toBe(true);
    // The caller's ceiling is an upper bound, the node may reserve (and charge) less.
    expect(checkUpstreamErrorReceipt(at, 500, 0, { reservationMsat: 80_000 })).toBe(true);
    expect(() =>
      checkUpstreamErrorReceipt(err(500, { cost_msats: 50_001, reserved_msats: 50_001 }), 500, 0, { reservationMsat: 50_000 }),
    ).toThrow(ReceiptVerificationError);
    // At most the fee needs no reservation at all.
    expect(checkUpstreamErrorReceipt(err(502, { cost_msats: 2000 }), 502, 2000)).toBe(true);
    // A malformed bound is refused, not ignored.
    expect(() => checkUpstreamErrorReceipt(at, 500, 0, { reservationMsat: -1 })).toThrow(/not a valid amount/);
  });

  it("an image request keeps its own ceiling as the bound", () => {
    const image = { model: "z", variant: "webp", count: 2, msatPerImage: 12_000 };
    const ok = { kind: "images", model: "z", variant: "webp", count: 2 };
    expect(
      checkUpstreamErrorReceipt(err(500, { ...ok, cost_msats: 26_000, reserved_msats: 26_000 }), 500, 0, { abandonFeeMsat: 2000, image }),
    ).toBe(true);
    expect(() =>
      checkUpstreamErrorReceipt(err(500, { ...ok, cost_msats: 26_001, reserved_msats: 26_001 }), 500, 0, { abandonFeeMsat: 2000, image }),
    ).toThrow(/price × count/);
  });
});

describe("the reservation announced in request_ok", () => {
  /** A connection whose network side never runs: `sent` gets the control frames. */
  function conn(framing: "2" | "1.1") {
    const offer = verified({ ...BOTH, connection_deposit_msat: 2000 });
    const c = new ConfidentialConnection({ baseUrl: "https://node.example", offer, framing, auth: "sk-x", host: NO_HOST }) as any;
    c.phaseNow = framing === "2" ? "ready" : "armed";
    c.probeAnswered = true;
    const sent: any[] = [];
    c.sendText = (m: unknown) => sent.push(m);
    vi.spyOn(c, "connect").mockResolvedValue(undefined);
    vi.spyOn(c, "arm").mockResolvedValue(undefined);
    // Framing "2": the request's records; framing "1.1": the ClientHello.
    const records = vi.spyOn(c, "sendRecord").mockReturnValue(new Promise(() => {}));
    const hello = vi.spyOn(c, "handshake").mockReturnValue(new Promise(() => {}));
    return { c, sent, records, hello, offer };
  }

  function ask(c: any, opts: Partial<ConnectionRequestOptions> = {}) {
    const suffix = canonicalSuffix(VENICE_CHAT, "cheap", 100);
    const handle = c.request({ model: "cheap", maxTokens: 100, body: enc(`{"messages":[]${suffix}`), ...opts });
    handle.done.catch(() => {});
    return { handle, suffix };
  }

  async function answer(c: any, sent: any[], suffix: string, extra: Record<string, unknown>) {
    await vi.waitFor(() => expect(sent.some((m) => m.type === "request")).toBe(true));
    c.onText(
      JSON.stringify({
        type: "request_ok",
        n: 1,
        suffix,
        ...(c.framing === "2" ? { stream: requestStream(1) } : { head_len: 200 }),
        ...extra,
      }),
    );
  }

  for (const framing of ["2", "1.1"] as const) {
    it(`framing ${framing}: above the caller's ceiling, nothing of the request is sent`, async () => {
      const { c, sent, records, hello } = conn(framing);
      const { handle, suffix } = ask(c, { maxReservationMsat: 40_000 });
      await answer(c, sent, suffix, { reserved_msats: 40_001 });
      const error = await handle.done.catch((e: unknown) => e);
      expect(error).toBeInstanceOf(ReservationAboveCeilingError);
      expect(error).toMatchObject({ code: "reservation_above_ceiling", reservedMsat: 40_001, ceilingMsat: 40_000 });
      expect(records).not.toHaveBeenCalled();
      expect(hello).not.toHaveBeenCalled();
      expect(sent.some((m) => m.type === "release" || m.type === "release_head")).toBe(false);
      expect(handle.bodyReleased).toBe(false);
      expect(c.phase).toBe("closed");
      // "1.1" on this node would be refused the same way: no framing fallback.
      expect(http2OpenFailure(error)).toBe(false);
    });

    it(`framing ${framing}: at the ceiling, or from a node that announces none, the request goes on`, async () => {
      for (const extra of [{ reserved_msats: 40_000 }, {}]) {
        for (const ceiling of [40_000, undefined]) {
          const { c, sent, records, hello } = conn(framing);
          const { suffix } = ask(c, { maxReservationMsat: ceiling });
          await answer(c, sent, suffix, extra);
          await vi.waitFor(() => expect(framing === "2" ? records : hello).toHaveBeenCalled());
          expect(c.cur.reservedMsat).toBe((extra as { reserved_msats?: number }).reserved_msats);
          c.close();
        }
      }
    });
  }

  it("a malformed reservation is a protocol error", async () => {
    for (const bad of [-1, 1.5, "40000", null, 2 ** 60]) {
      const { c, sent, records } = conn("2");
      const { handle, suffix } = ask(c);
      await answer(c, sent, suffix, { reserved_msats: bad });
      await expect(handle.done).rejects.toThrow(SessionProtocolError);
      expect(records).not.toHaveBeenCalled();
    }
  });

  it("a ceiling that is not a whole number of msat is refused before anything is sent", async () => {
    const { c, sent } = conn("2");
    expect(() => ask(c, { maxReservationMsat: Number.NaN })).toThrow(/maxReservationMsat/);
    await Promise.resolve();
    expect(sent).toEqual([]);
  });

  it("bounds a 5xx receipt by the announced reservation, else the caller's ceiling, else only the fee", () => {
    const { c, offer } = conn("2");
    const cur = (opts: Record<string, unknown>, reservedMsat?: number) =>
      ({ n: 2, first: false, model: "cheap", offer, opts, reservedMsat }) as never;
    const receipt = (cost: number, reserved: number) =>
      ({ sid: "s", model: "cheap", usage: { error_status: 500 }, cost_msats: cost, reserved_msats: reserved }) as never;
    // Announced: the receipt must name exactly that, and cost no more.
    expect(() => c.checkErrorReceipt(cur({}, 30_000), receipt(30_000, 30_000), 500)).not.toThrow();
    expect(() => c.checkErrorReceipt(cur({}, 30_000), receipt(30_000, 31_000), 500)).toThrow(/announced 30000/);
    expect(() => c.checkErrorReceipt(cur({}, 30_000), receipt(31_000, 31_000), 500)).toThrow(ReceiptVerificationError);
    // An old node (no announcement): the caller's ceiling.
    expect(() => c.checkErrorReceipt(cur({ maxReservationMsat: 40_000 }), receipt(40_000, 40_000), 500)).not.toThrow();
    expect(() => c.checkErrorReceipt(cur({ maxReservationMsat: 40_000 }), receipt(40_001, 40_001), 500)).toThrow(
      /reservation bound/,
    );
    // Neither: fail closed above the fee.
    expect(() => c.checkErrorReceipt(cur({}), receipt(1, 1), 500)).toThrow(/no reservation bound/);
    expect(() => c.checkErrorReceipt(cur({}), receipt(0, 0), 500)).not.toThrow();
  });
});

describe("the reservation ceiling a client derives", () => {
  const offer = (extra: Record<string, unknown> = {}) =>
    verified({
      price_list: { m: { in: 1000, cached_in: 1000, out: 2000 } },
      session_fee_msat: 100,
      abandon_fee_msat: 300,
      reserve_margin_tokens: 16,
      connection_deposit_msat: 2000,
      ...extra,
    });
  const model = (extra: Record<string, unknown> = {}) =>
    ({ id: "m", context_length: 8192, sats_pricing: { max_cost: 20 }, ...extra }) as unknown as NodeModel;

  it("is the node's formula, never below its floor (the deposit bounds min_request_msat)", () => {
    const o = offer();
    const mirror = reservationMsat(o, o.price_list.m!, model(), 100)!;
    // ceil((8192 × 1000 + 116 × 2000) / 1000) + 300
    expect(mirror).toBe(8192 + 232 + 300);
    expect(reservationCeilingMsat(o, "m", model(), 100)).toBe(mirror);
    // A tiny reservation: the node's floor may lift it up to the deposit.
    expect(reservationCeilingMsat(offer({ price_list: { m: { in: 0.001, cached_in: 0.001, out: 0.001 } } }), "m", model(), 1)).toBe(
      2000 + 300,
    );
  });

  it("is none where the client cannot bound what an honest node reserves", () => {
    // No deposit: the node's minimum reservation is unknown.
    expect(reservationCeilingMsat(offer({ connection_deposit_msat: 0 }), "m", model(), 100)).toBeUndefined();
    // No context length: the node's fallback reads the model's sats price.
    expect(reservationCeilingMsat(offer(), "m", model({ context_length: undefined }), 100)).toBeUndefined();
    expect(reservationCeilingMsat(offer(), "m", undefined, 100)).toBeUndefined();
    // The offer does not price the model.
    expect(reservationCeilingMsat(offer(), "other", model({ id: "other" }), 100)).toBeUndefined();
  });

  it("without a context length scales the maximum cost by the cache-write premium, like the node", () => {
    const rates = { in: 6000, cached_in: 600, cache_write: 7500, out: 30_000 };
    const o = offer({ price_list: { m: rates }, rate_surcharge_pct: 20, session_fee_msat: 2000, abandon_fee_msat: 5000 });
    const m = model({ context_length: undefined, sats_pricing: { max_cost: 70 } });
    // ceil(70 000 × 1.25 × 1.2 + 16 × 30 000 / 1000) + 5000
    expect(reservationMsat(o, rates, m, 100)).toBe(Math.ceil(70_000 * 1.25 * 1.2 + 480) + 5000);
    // A cache write at or below `in` scales nothing.
    for (const cache_write of [6000, 100, 0]) {
      const r = { ...rates, cache_write };
      expect(reservationMsat(o, r, m, 100)).toBe(Math.ceil(70_000 * 1.2 + 480) + 5000);
    }
  });
});

describe("a connection's secrets when it ends", () => {
  const conn = () =>
    new ConfidentialConnection({ baseUrl: "https://node.example", offer: verified(BOTH), framing: "2", auth: "sk-x", host: NO_HOST }) as any;
  const secrets = () => ({
    serverAp0: new Uint8Array(32).fill(1),
    clientAp1: new Uint8Array(32).fill(2),
    h1: new Uint8Array(32).fill(3),
    h2: new Uint8Array(32).fill(4),
    hk: new Uint8Array(32).fill(5),
  });

  it("are zero-filled and dropped, and the TLS client erases its own", () => {
    const c = conn();
    const ap = secrets();
    c.ap = ap;
    const destroySecrets = vi.fn();
    c.tls = { destroySecrets };
    c.close("test");
    for (const v of Object.values(ap)) expect(v.every((b) => b === 0)).toBe(true);
    expect(c.ap).toBeUndefined();
    expect(destroySecrets).toHaveBeenCalledTimes(1);
  });

  it("are erased when the connection fails, not only when it is closed", () => {
    const c = conn();
    const ap = secrets();
    c.ap = ap;
    c.fail(new SessionProtocolError("broken"));
    expect(ap.clientAp1.every((b) => b === 0)).toBe(true);
    expect(c.ap).toBeUndefined();
  });

  it("anything still running gets the connection's failure, not a TypeError", async () => {
    const c = conn();
    c.ap = secrets();
    c.close("gone");
    expect(() => c.secrets()).toThrow(/connection closed: gone/);
    await expect(c.proveRecords({ first_seq: 0, count: 1, params: {} })).rejects.toBeInstanceOf(SessionRejectedError);
    await expect(c.settleErrorHead({ proofs: [], head: { off: 0, raw: new Uint8Array(0) } }, 500)).rejects.toThrow(
      /connection closed: gone/,
    );
  });

  it("the TLS fork's destroySecrets ends the client and drops its keys", () => {
    const tls = makeTLSClient({ host: "api.venice.ai", write: () => {}, logger: { trace() {}, debug() {}, info() {}, warn() {}, error() {} } } as never) as any;
    tls.destroySecrets();
    expect(tls.hasEnded()).toBe(true);
    expect(tls.getKeys()).toBeUndefined();
    expect(tls.isHandshakeDone()).toBe(false);
  });
});

// --- the client around the release -----------------------------------------------------

const SSE_HEAD = { status: 200, statusText: "OK", headers: { "content-type": "text/event-stream" } };
const SSE = 'data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n\n';

/** The node: the signed offer, and `/v1/models` with these models. */
function mockNode(offerExtra: Record<string, unknown> = BOTH, models: unknown[] = []) {
  globalThis.fetch = (async (input: unknown) => {
    if (String(input).endsWith("/v1/models")) return new Response(JSON.stringify({ data: models }), { status: 200 });
    return new Response(JSON.stringify(signedV3Offer(offerExtra)), { status: 200 });
  }) as typeof fetch;
}

/**
 * Stand-in for a connection's one request: `steps` runs with a state
 * (`released`, the response handlers) and returns the response head or throws.
 */
function fakeRun(steps: (s: any, opts: ConnectionRequestOptions) => Promise<{ status: number; headers?: Record<string, string> }>) {
  let sids = 0;
  const open = async function (this: any) {
    if (this.failure) throw this.failure;
    if (this.phaseNow === "new") {
      this.sid = (++sids).toString(16).padStart(64, "0");
      this.phaseNow = this.framing === "2" ? "ready" : "armed";
      this.opened = true;
      this.tOpen = this.tLastSettled = Date.now();
    }
  };
  vi.spyOn(ConfidentialConnection.prototype, "arm").mockImplementation(open);
  vi.spyOn(ConfidentialConnection.prototype, "connect").mockImplementation(open);
  return vi.spyOn(ConfidentialConnection.prototype, "request").mockImplementation(function (this: any, opts: ConnectionRequestOptions) {
    const conn = this;
    const s: any = { released: false, onResponseHead: opts.onResponseHead, onResponseBody: opts.onResponseBody };
    conn.cur = { n: 1 };
    const done = (async () => {
      try {
        const r = await steps(s, opts);
        conn.cur = undefined;
        conn.requests = 1;
        conn.settled = 1;
        conn.goaway = true;
        return {
          sid: conn.sid,
          http: conn.framing,
          n: 1,
          model: opts.model,
          status: r.status,
          headers: r.headers ?? {},
          body: opts.image ? new Uint8Array(0) : enc(SSE),
          bodyChunks: opts.image ? [enc(IMAGE_BODY)] : undefined,
          receipt: { sid: conn.sid, model: opts.model, usage: {}, cost_msats: 7, n: 1 },
          receiptJson: "{}",
          attestation: {},
          timings: { startedAt: Date.now(), totalMs: 1, proofs: [] },
          bytes: { relaySent: 0, relayRecv: 0, controlSent: 0, controlRecv: 0, twoPcSent: 0, twoPcRecv: 0, zkSent: 0, zkRecv: 0 },
        };
      } catch (e) {
        conn.fail(e);
        throw e;
      }
    })();
    done.catch(() => {});
    return {
      n: 1,
      get sid() {
        return conn.sid;
      },
      get bodyReleased() {
        return s.released === true;
      },
      get credentialSent() {
        return true;
      },
      done,
      close() {
        conn.close("request aborted");
      },
    } as never;
  });
}

let node = 0;
const clients: ConfidentialClient[] = [];
function client(extra: Record<string, unknown> = {}): ConfidentialClient {
  const c = createConfidentialClient({
    node: `https://release-${++node}.example`,
    nodePubkeys: [NODE_PUB],
    trustedHosts: ["*.venice.ai"],
    credential: "sk-x",
    host: NO_HOST,
    ...extra,
  });
  clients.push(c);
  return c;
}
afterEach(() => {
  for (const c of clients.splice(0)) c.close();
});

async function chat(c: ConfidentialClient, body: Record<string, unknown> = {}, options: Record<string, unknown> = {}) {
  const s = await c.chat.completions.create({ model: "cheap", messages: [{ role: "user", content: "x" }], stream: true, ...body }, options);
  for await (const _ of s) {
    /* drain */
  }
  return s.verification;
}

describe("errors after the release carry the release marker", () => {
  it("set (not enumerable) once released, whatever the node's close reason says; never before", async () => {
    mockNode();
    let release = true;
    const run = fakeRun(async (s) => {
      s.released = release;
      throw new SessionRejectedError("connection closed: ECONNRESET");
    });
    const error = await chat(client()).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SessionRejectedError);
    expect(mayHaveReachedProvider(error)).toBe(true);
    expect((error as Record<string, unknown>)[MAY_HAVE_REACHED_PROVIDER]).toBe(true);
    expect(Object.keys(error as object)).not.toContain("mayHaveReachedProvider");
    // Run once: a released request is never sent again.
    expect(run).toHaveBeenCalledTimes(1);

    release = false;
    run.mockClear();
    const early = await chat(client()).catch((e: unknown) => e);
    expect(early).toBeInstanceOf(SessionRejectedError);
    expect(mayHaveReachedProvider(early)).toBe(false);
  });

  it("on a stream's later failure too (the stream's error and its verification)", async () => {
    mockNode();
    fakeRun(async (s) => {
      s.released = true;
      s.onResponseHead?.(SSE_HEAD);
      s.onResponseBody?.(enc(SSE));
      throw new ReceiptVerificationError("bad receipt");
    });
    const stream = await client().chat.completions.create({ model: "cheap", messages: [], stream: true });
    const streamError = await (async () => {
      for await (const _ of stream) {
        /* drain */
      }
    })().catch((e: unknown) => e);
    const settled = await stream.verification.catch((e: unknown) => e);
    expect(streamError).toBeInstanceOf(ReceiptVerificationError);
    expect(mayHaveReachedProvider(streamError)).toBe(true);
    expect(mayHaveReachedProvider(settled)).toBe(true);
  });

  it("a response head alone marks the error, even when the body was never marked released", async () => {
    mockNode();
    fakeRun(async (s) => {
      s.onResponseHead?.(SSE_HEAD);
      throw new SessionRejectedError("connection closed: going away");
    });
    const stream = await client().chat.completions.create({ model: "cheap", messages: [], stream: true });
    const settled = await stream.verification.catch((e: unknown) => e);
    expect(mayHaveReachedProvider(settled)).toBe(true);
  });

  it("image requests: a failure after the release and an HTTP error of the provider are marked", async () => {
    mockNode({ ...BOTH, capabilities: ["chat", "images"], images: (await import("./fixtures/v3.js")).IMAGES, h2: { ...BOTH.h2, kinds: ["chat", "images"] } });
    let outcome: "fail" | "error" = "fail";
    fakeRun(async (s) => {
      s.released = true;
      if (outcome === "fail") throw new SessionRejectedError("connection closed: ECONNRESET");
      return { status: 500, headers: { "content-type": "application/json" } };
    });
    const failed = await client()
      .images.generate({ model: "z-image-turbo", prompt: "a red circle" })
      .catch((e: unknown) => e);
    expect(failed).toBeInstanceOf(SessionRejectedError);
    expect(mayHaveReachedProvider(failed)).toBe(true);
    outcome = "error";
    const upstream = await client()
      .images.generate({ model: "z-image-turbo", prompt: "a red circle" })
      .catch((e: unknown) => e);
    expect(upstream).toMatchObject({ code: "upstream_error", status: 500 });
    expect(mayHaveReachedProvider(upstream)).toBe(true);
  });

  it("an abort after the release is marked; one before it is not", async () => {
    mockNode();
    let release!: () => void;
    fakeRun(
      (s) =>
        new Promise((_, reject) => {
          release = () => (s.released = true);
          setTimeout(() => reject(new SessionRejectedError("connection closed: late")), 50);
        }),
    );
    const ac = new AbortController();
    const p = chat(client(), {}, { signal: ac.signal }).catch((e: unknown) => e);
    await vi.waitFor(() => expect(release).toBeTypeOf("function"));
    release();
    ac.abort();
    const after = await p;
    expect((after as Error).name).toBe("AbortError");
    expect(mayHaveReachedProvider(after)).toBe(true);

    const ac2 = new AbortController();
    const p2 = chat(client(), {}, { signal: ac2.signal }).catch((e: unknown) => e);
    await new Promise((r) => setTimeout(r, 5));
    ac2.abort();
    const before = await p2;
    expect((before as Error).name).toBe("AbortError");
    expect(mayHaveReachedProvider(before)).toBe(false);
  });

  it("the error helpers read by shape (another bundle's errors too)", () => {
    const foreign = Object.assign(new Error("x"), { code: "session_rejected" });
    expect(confidentialErrorCode(foreign)).toBe("session_rejected");
    expect(confidentialErrorCode(new ConfidentialError("reservation_above_ceiling", "x"))).toBe("reservation_above_ceiling");
    expect(confidentialErrorCode(Object.assign(new Error("x"), { code: "ECONNRESET" }))).toBeUndefined();
    expect(confidentialErrorCode("session_rejected")).toBeUndefined();
    expect(CONFIDENTIAL_ERROR_CODES).toContain("reservation_above_ceiling");
    expect(mayHaveReachedProvider(Object.defineProperty(new Error("x"), MAY_HAVE_REACHED_PROVIDER, { value: true }))).toBe(true);
    expect(mayHaveReachedProvider(null)).toBe(false);
    // The package exports them.
    expect(lib.mayHaveReachedProvider).toBe(mayHaveReachedProvider);
    expect(lib.ReservationAboveCeilingError).toBe(ReservationAboveCeilingError);
    expect(lib.reservationCeilingMsat).toBe(reservationCeilingMsat);
  });
});

describe("the client's reservation ceiling", () => {
  const MODELS = [{ id: "cheap", context_length: 8192 }];

  it("defaults to the node's own formula for the model on this node", async () => {
    mockNode(BOTH, MODELS);
    const seen: unknown[] = [];
    fakeRun(async (s, opts) => {
      seen.push(opts.maxReservationMsat);
      s.released = true;
      s.onResponseHead?.(SSE_HEAD);
      return SSE_HEAD;
    });
    await chat(client(), { max_tokens: 77 });
    const offer = verified(BOTH);
    expect(seen).toEqual([reservationCeilingMsat(offer, "cheap", MODELS[0] as NodeModel, 77)]);
    expect(typeof seen[0]).toBe("number");
  });

  it("is none when the node lists no context length, and the caller's own value or function wins", async () => {
    mockNode(BOTH, []);
    const seen: unknown[] = [];
    fakeRun(async (s, opts) => {
      seen.push(opts.maxReservationMsat);
      s.released = true;
      s.onResponseHead?.(SSE_HEAD);
      return SSE_HEAD;
    });
    await chat(client());
    expect(seen).toEqual([undefined]);
    const ceiling = vi.fn((_offer: VerifiedOffer, request: { model: string; maxTokens: number }) => 1000 + request.maxTokens);
    await chat(client(), { max_tokens: 77 }, { maxReservationMsat: ceiling });
    expect(ceiling).toHaveBeenCalledTimes(1);
    expect(ceiling.mock.calls[0]![0].sig).toBeDefined();
    expect(ceiling.mock.calls[0]![1]).toEqual({ model: "cheap", maxTokens: 77 });
    expect(seen[1]).toBe(1077);
    await chat(client(), {}, { maxReservationMsat: 5000.7 });
    expect(seen[2]).toBe(5000);
    await expect(chat(client(), {}, { maxReservationMsat: -1 })).rejects.toThrow(/maxReservationMsat/);
  });

  it("a node above the ceiling: the call fails before release and is not retried on a fresh connection", async () => {
    mockNode(BOTH, MODELS);
    const run = fakeRun(async () => {
      throw new ReservationAboveCeilingError(10_000_000, 9000);
    });
    const c = client({ prewarm: false });
    const error = await chat(c).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ReservationAboveCeilingError);
    expect(mayHaveReachedProvider(error)).toBe(false);
    expect(run).toHaveBeenCalledTimes(1);
  });
});
