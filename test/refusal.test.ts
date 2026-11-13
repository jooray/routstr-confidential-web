/**
 * A stream the provider did not process (PROTOCOL-V3.md §5.4, §12.8
 * `disclose_reset`): the R rule the sidecar checks (`h2::parse_refusal`, the
 * same cases as its tests), the refusal receipt, the connection's disclosure
 * and settlement, and the reservation every receipt must name.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import { ConfidentialConnection } from "../src/connection.js";
import { ReceiptVerificationError, StreamNotProcessedError } from "../src/errors.js";
import { FLAG, FRAME, frame, refusalProblem } from "../src/h2.js";
import { verifyConfidentialOffer } from "../src/offer.js";
import { checkAnnouncedReservation, checkRefusedReceipt } from "../src/receipt.js";
import { canonicalJson } from "../src/canonical.js";
import * as lib from "../src/index.js";
import { BOTH, NODE_PRIV, NODE_PUB, NO_HOST, signedV3Offer } from "./fixtures/v3.js";

const word = (v: number) => Uint8Array.from([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);
const cat = (...p: Uint8Array[]) => {
  const out = new Uint8Array(p.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of p) {
    out.set(x, o);
    o += x.length;
  }
  return out;
};
const rst = (stream: number, code: number) => frame(FRAME.RST_STREAM, 0, stream, word(code));
const goaway = (last: number, code: number, debug = new Uint8Array(0)) => frame(FRAME.GOAWAY, 0, 0, cat(word(last), word(code), debug));
const wu = (stream: number) => frame(FRAME.WINDOW_UPDATE, 0, stream, Uint8Array.from([0, 0, 1, 0]));

describe("the refusal R (as the sidecar's parse_refusal)", () => {
  it("RST_STREAM(REFUSED_STREAM) on the stream, or GOAWAY(NO_ERROR) below it", () => {
    expect(refusalProblem(rst(3, 7), 3, true)).toEqual({ kind: "rst_stream" });
    expect(refusalProblem(goaway(1, 0), 3, true)).toEqual({ kind: "goaway", lastStreamId: 1 });
    expect(refusalProblem(goaway(1, 0), 3, false)).toEqual({ kind: "goaway", lastStreamId: 1 });
    // The reserved bit of the last-stream-id is ignored; debug data is fine.
    expect(refusalProblem(goaway(0x80000001, 0), 5, true)).toEqual({ kind: "goaway", lastStreamId: 1 });
    expect(refusalProblem(goaway(3, 0, new TextEncoder().encode("shutting down")), 5, true)).toEqual({ kind: "goaway", lastStreamId: 3 });
    const before = [
      wu(0),
      wu(3),
      frame(FRAME.SETTINGS, 0, 0, Uint8Array.from([0, 3, 0, 0, 0, 100])),
      frame(FRAME.SETTINGS, FLAG.ACK, 0),
      frame(FRAME.PING, 0, 0, new Uint8Array(8).fill(1)),
      frame(FRAME.DATA, FLAG.END_STREAM, 1, new TextEncoder().encode('{"data":[]}')),
      rst(1, 7),
      goaway(3, 0),
      goaway(0x7fffffff, 0),
    ];
    expect(refusalProblem(cat(...before, rst(3, 7)), 3, true)).toEqual({ kind: "rst_stream" });
    for (const f of before) expect(refusalProblem(cat(f, rst(3, 7)), 3, true)).toEqual({ kind: "rst_stream" });
  });

  it("refuses what does not prove the request unprocessed", () => {
    const cases: [string, Uint8Array, boolean][] = [
      ["CANCEL", rst(3, 8), true],
      ["NO_ERROR reset", rst(3, 0), true],
      ["another request stream", rst(5, 7), true],
      ["the probe stream", rst(1, 7), true],
      ["a reset before anything was written", rst(3, 7), false],
      ["GOAWAY covering the stream", goaway(3, 0), true],
      ["GOAWAY PROTOCOL_ERROR", goaway(1, 1), true],
      ["GOAWAY ENHANCE_YOUR_CALM", goaway(1, 11), true],
      ["a short GOAWAY", frame(FRAME.GOAWAY, 0, 0, Uint8Array.from([0, 0, 0, 1])), true],
      ["GOAWAY on a stream", frame(FRAME.GOAWAY, 0, 3, cat(word(1), word(0))), true],
      ["a long reset", frame(FRAME.RST_STREAM, 0, 3, Uint8Array.from([0, 0, 0, 7, 0])), true],
      ["nothing", new Uint8Array(0), true],
    ];
    for (const [what, r, ok] of cases) expect(typeof refusalProblem(r, 3, ok), what).toBe("string");
    expect(typeof refusalProblem(rst(1, 7), 1, true)).toBe("string");
    for (const bad of [
      frame(FRAME.HEADERS, FLAG.END_HEADERS, 3, Uint8Array.from([0x88])),
      frame(FRAME.HEADERS, FLAG.END_HEADERS | FLAG.END_STREAM, 3, Uint8Array.from([0x88])),
      frame(FRAME.DATA, 0, 3, new TextEncoder().encode("data: {}\n\n")),
      frame(FRAME.HEADERS, FLAG.END_HEADERS, 5, Uint8Array.from([0x88])),
      frame(FRAME.DATA, 0, 5, Uint8Array.from([1])),
      frame(FRAME.PING, 0, 3, new Uint8Array(8)),
      frame(5, 0, 0, new Uint8Array(4)),
      goaway(1, 2),
    ]) {
      expect(typeof refusalProblem(cat(bad, rst(3, 7)), 3, true)).toBe("string");
      expect(typeof refusalProblem(cat(bad, goaway(1, 0)), 3, true)).toBe("string");
    }
    // The refusal ends R, on a frame boundary.
    expect(typeof refusalProblem(cat(rst(3, 7), frame(FRAME.PING, 0, 0, new Uint8Array(8))), 3, true)).toBe("string");
    expect(typeof refusalProblem(rst(3, 7).subarray(0, 12), 3, true)).toBe("string");
    const ping = frame(FRAME.PING, FLAG.ACK, 0, new Uint8Array(8).fill(1));
    ping[2] = 12;
    expect(typeof refusalProblem(cat(ping, rst(3, 7)), 3, true)).toBe("string");
    const reserved = rst(3, 7);
    reserved[5]! |= 0x80;
    expect(typeof refusalProblem(reserved, 3, true)).toBe("string");
  });
});

describe("the refusal receipt", () => {
  const r = (usage: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
    ({ sid: "s", model: "m", usage, cost_msats: 0, reserved_msats: 9000, ...extra }) as never;
  const RST = { refused: "rst_stream", error_code: 7, choices: [] };
  const GOAWAY = { refused: "goaway", error_code: 0, last_stream_id: 1, choices: [] };

  it("names what we saw and costs at most the session fee due", () => {
    expect(() => checkRefusedReceipt(r(RST), { kind: "rst_stream" })).not.toThrow();
    expect(() => checkRefusedReceipt(r(GOAWAY), { kind: "goaway", lastStreamId: 1 })).not.toThrow();
    expect(() => checkRefusedReceipt(r(RST, { cost_msats: 2000, session_fee_msat: 2000 }), { kind: "rst_stream" }, 2000)).not.toThrow();
    for (const [usage, extra, fee] of [
      [GOAWAY, {}, 0],
      [{ ...RST, error_code: 8 }, {}, 0],
      [{ ...RST, choices: [{}] }, {}, 0],
      [{ error_status: 429, choices: [] }, {}, 0],
      [RST, { cost_msats: 1 }, 0],
      [RST, { cost_msats: 2001 }, 2000],
      [RST, { cost_msats: -1 }, 0],
      [RST, { session_fee_msat: 5 }, 0],
    ] as const) {
      expect(() => checkRefusedReceipt(r(usage, extra), { kind: "rst_stream" }, fee)).toThrow(ReceiptVerificationError);
    }
    expect(() => checkRefusedReceipt(r(GOAWAY), { kind: "goaway", lastStreamId: 3 })).toThrow(/last stream/);
    const image = { model: "m", variant: "webp", count: 2 };
    expect(() => checkRefusedReceipt(r(RST, { kind: "images", variant: "webp", count: 2 }), { kind: "rst_stream" }, 0, { image })).not.toThrow();
    expect(() => checkRefusedReceipt(r(RST, { kind: "images", variant: "webp", count: 1 }), { kind: "rst_stream" }, 0, { image })).toThrow(/count/);
  });

  it("every receipt names the reservation announced in request_ok", () => {
    expect(() => checkAnnouncedReservation(r(RST), 9000)).not.toThrow();
    expect(() => checkAnnouncedReservation(r(RST), undefined)).not.toThrow();
    expect(() => checkAnnouncedReservation(r(RST, { reserved_msats: undefined }), 9000)).not.toThrow();
    expect(() => checkAnnouncedReservation(r(RST), 8000)).toThrow(/announced 8000/);
  });

  it("the error is exported", () => {
    expect(lib.StreamNotProcessedError).toBe(StreamNotProcessedError);
  });
});

// --- the connection ---------------------------------------------------------------

const offer = () => verifyConfidentialOffer(signedV3Offer(BOTH), { pinnedPubkeys: [NODE_PUB], trustedHosts: ["*.venice.ai"] });
const ATT_JSON = '{"a":1}';
const sign = (json: string) => bytesToHex(schnorr.sign(sha256(utf8ToBytes(json)), NODE_PRIV));

function receiptFrame(receipt: Record<string, unknown>) {
  const text = canonicalJson(receipt);
  return { type: "receipt", receipt, receipt_json: text, sig: sign(text) };
}

/** A framing-"2" connection with no network side; request 1 on stream 3 is in flight. */
function conn() {
  const o = offer();
  const c = new ConfidentialConnection({ baseUrl: "https://node.example", offer: o, framing: "2", auth: "sk-x", host: NO_HOST }) as any;
  c.phaseNow = "ready";
  c.sid = "ab".repeat(32);
  c.ready = { pubkey: NODE_PUB };
  c.ap = { serverAp0: new Uint8Array(32).fill(1), clientAp1: new Uint8Array(32), h1: new Uint8Array(32), h2: new Uint8Array(32), hk: new Uint8Array(32) };
  c.hsCipher = 2;
  const sent: any[] = [];
  c.sendText = (m: unknown) => sent.push(m);
  const cur: any = {
    n: 1,
    stream: 3,
    first: false,
    model: "cheap",
    offer: o,
    opts: {},
    recvAtSend: 2,
    seqs: [],
    dataLens: [],
    upto: 0,
    streamCredit: 65535,
    accepted: true,
    reservedMsat: 9000,
    releaseSent: true,
    released: false,
    tLastData: Date.now(),
    parts: [],
    ended: false,
    proofs: [{ proof: "pi_win" }],
    settled: false,
  };
  c.cur = cur;
  /** One server record (abs index in order) holding `content`. */
  const record = (content: Uint8Array) => {
    const abs = c.hsCipher + c.serverPost.length;
    c.serverPost.push({ data: true, keyUpdates: 0 });
    c.plain.set(abs, cat(content, Uint8Array.from([0x17])));
    c.serverRecords.set(abs, new Uint8Array(content.length + 17));
    c.wireRecords = abs + 1;
    for (const f of c.reader.push(content, abs)) c.onFrame(f);
  };
  return { c, cur, sent, record };
}

describe("a refusal on a connection", () => {
  afterEach(() => vi.restoreAllMocks());

  it("is disclosed from the first record after the request, proven and settled like a 429", async () => {
    const { c, cur, sent, record } = conn();
    record(wu(3));
    record(rst(3, 7));
    expect(cur.refusal).toEqual({ seen: { kind: "rst_stream" }, end: 26 });
    const d = c.refusalDisclosure(cur);
    expect(d.record).toBe(2);
    expect(bytesToHex(d.raw)).toBe(bytesToHex(cat(wu(3), rst(3, 7))));
    expect([...d.chunks]).toEqual([[2, 13], [3, 13]]);

    vi.spyOn(c, "checkAttestation").mockResolvedValue({ json: ATT_JSON, a: {} });
    vi.spyOn(c, "checkServerWindows").mockReturnValue({ windows: 2 });
    const prove = vi.spyOn(c, "proof").mockResolvedValue({ proof: "pi_win", ms: 1 });
    c.onText(JSON.stringify({ type: "attestation", n: 1 }));
    c.onText(JSON.stringify({ type: "zk_params", proof: "pi_win", purpose: "refusal", n: 1, record: 2, params: {} }));
    const usage = { refused: "rst_stream", error_code: 7, choices: [] };
    const hash = bytesToHex(sha256(utf8ToBytes(ATT_JSON)));
    c.onText(
      JSON.stringify(receiptFrame({ v: 1, sid: c.sid, http: "2", n: 1, model: "cheap", usage, cost_msats: 0, reserved_msats: 9000, attestation_hash: hash })),
    );
    const error = await c.settleRefusal(cur).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(StreamNotProcessedError);
    expect(error).toMatchObject({ costMsats: 0, receipt: { usage } });
    expect(sent.find((m) => m.type === "disclose_reset")).toEqual({ type: "disclose_reset", n: 1, record: 2, r: bytesToHex(cat(wu(3), rst(3, 7))) });
    expect(prove.mock.calls[0]![3]).toEqual({ Secret: Array.from(new Uint8Array(32).fill(1)) });
    expect(c.goaway).toBe(true);
  });

  it("a GOAWAY below the stream before anything was released: only that form", () => {
    const { c, cur, record } = conn();
    cur.releaseSent = false;
    record(goaway(1, 0));
    expect(cur.refusal.seen).toEqual({ kind: "goaway", lastStreamId: 1 });
    expect(c.refusalDisclosure(cur).record).toBe(2);
    // A GOAWAY with an error code is no refusal the client can show.
    const other = conn();
    other.record(goaway(1, 1));
    expect(other.cur.refusal).toBeUndefined();
  });

  it("nothing is disclosed after a response head, or past a frame that is not allowed", async () => {
    const { c, cur, sent, record } = conn();
    record(frame(FRAME.HEADERS, FLAG.END_HEADERS, 3, Uint8Array.from([0x88])));
    record(rst(3, 7));
    expect(cur.refusal).toBeUndefined();
    await expect(c.settleRefusal(cur)).resolves.toBeUndefined();
    expect(sent.some((m) => m.type === "disclose_reset")).toBe(false);

    const second = conn();
    second.record(frame(FRAME.DATA, 0, 5, Uint8Array.from([1])));
    second.record(rst(3, 7));
    expect(typeof second.c.refusalDisclosure(second.cur)).toBe("string");
    await expect(second.c.settleRefusal(second.cur)).resolves.toBeUndefined();
    expect(second.sent.some((m) => m.type === "disclose_reset")).toBe(false);
  });

  it("a receipt that charges more than the fee due, or names another reservation, is refused", async () => {
    for (const extra of [{ cost_msats: 1 }, { reserved_msats: 9001 }]) {
      const { c, cur, record } = conn();
      record(rst(3, 7));
      vi.spyOn(c, "checkAttestation").mockResolvedValue({ json: ATT_JSON, a: {} });
      vi.spyOn(c, "checkServerWindows").mockReturnValue({ windows: 1 });
      vi.spyOn(c, "proof").mockResolvedValue({ proof: "pi_win", ms: 1 });
      c.onText(JSON.stringify({ type: "attestation", n: 1 }));
      c.onText(JSON.stringify({ type: "zk_params", proof: "pi_win", purpose: "refusal", n: 1, record: 2, params: {} }));
      const hash = bytesToHex(sha256(utf8ToBytes(ATT_JSON)));
      const receipt = {
        v: 1,
        sid: c.sid,
        http: "2",
        n: 1,
        model: "cheap",
        usage: { refused: "rst_stream", error_code: 7, choices: [] },
        cost_msats: 0,
        reserved_msats: 9000,
        attestation_hash: hash,
        ...extra,
      };
      c.onText(JSON.stringify(receiptFrame(receipt)));
      await expect(c.settleRefusal(cur)).rejects.toBeInstanceOf(ReceiptVerificationError);
    }
  });
});
