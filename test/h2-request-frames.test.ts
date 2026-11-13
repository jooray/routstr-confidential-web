/**
 * Framing "2": how one request reacts to the provider's frames, with the
 * node, the TLS layer and the proofs stubbed out (only `runRequest`,
 * `onFrame` and `updateRelease` run). Review findings on PR
 * Routstr/routstr-sdk#112: an error head followed by RST_STREAM(NO_ERROR)
 * is disclosed (18); a GOAWAY's last-stream-id holds the release back;
 * SETTINGS_INITIAL_WINDOW_SIZE applies to the open stream; a frame above
 * 16 KiB is refused.
 */

import { describe, expect, it } from "vitest";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";

import { canonicalJson } from "../src/canonical.js";
import { ConfidentialConnection } from "../src/connection.js";
import { ResponseVerificationError, SessionProtocolError, SessionRejectedError } from "../src/errors.js";
import { FLAG, FRAME, FrameReader, frame, type RxFrame } from "../src/h2.js";
import { verifyConfidentialOffer } from "../src/offer.js";
import { canonicalSuffix } from "../src/suffix.js";
import { VENICE_CHAT } from "./fixtures/chat.js";
import { NO_HOST } from "./fixtures/v3.js";

function connection(): { conn: any; wire: Record<string, unknown>[] } {
  const priv = new Uint8Array(32).fill(7);
  const pubHex = bytesToHex(schnorr.getPublicKey(priv));
  const o: Record<string, unknown> = {
    v: 3,
    http: ["2", "1.1"],
    h2: { probe_path: "/api/v1/models", idle_secs: 300, max_requests: 100 },
    twopc: "split-public-1",
    upstream_host: "api.venice.ai",
    notary_pubkey: pubHex,
    max_tokens_cap: 4096,
    key_length: 42,
    key_alphabet: "[A-Za-z0-9_-]",
    head_template:
      "POST /api/v1/chat/completions HTTP/1.1\r\nHost: api.venice.ai\r\nAuthorization: Bearer {KEY:42}\r\n" +
      "Content-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {LEN}\r\n\r\n",
    suffix_keys: ["model", "max_tokens", "max_completion_tokens", "n", "stream", "stream_options", "venice_parameters"],
    chat: VENICE_CHAT,
    price_list: { cheap: { in: 1000, cached_in: 1000, out: 1000 } },
  };
  const payload = canonicalJson(o);
  const sig = bytesToHex(schnorr.sign(sha256(utf8ToBytes(payload)), priv));
  const offer = verifyConfidentialOffer({ ...o, sig, sig_payload: payload }, { pinnedPubkey: pubHex, trustedHosts: ["api.venice.ai"] });
  const conn: any = new ConfidentialConnection({ baseUrl: "https://node.example", offer, auth: "sk-x", host: NO_HOST, framing: "2" });
  // Stubs: the node accepts the request, records are "sent", the head is settled.
  const wire: Record<string, unknown>[] = [];
  let seq = 0;
  conn.connect = async () => {};
  conn.phaseNow = "ready";
  conn.probeAnswered = true;
  conn.gotSettings = true;
  conn.sendOrdered = (m: Record<string, unknown>) => wire.push(m);
  conn.sendText = (m: Record<string, unknown>) => wire.push(m);
  conn.sendRecord = async () => seq++;
  conn.openRequest = async (cur: any) => {
    cur.accepted = true;
    wire.push({ type: "request", n: cur.n });
    conn.onAccepted?.(cur);
    return { stream: cur.stream, suffix: "" };
  };
  conn.settleErrorHead = async (_cur: unknown, status: number) => {
    wire.push({ type: "disclose_head" });
    return { receipt: { status }, attestation: {} };
  };
  conn.result = (_cur: unknown, status: number) => ({ status });
  return { conn, wire };
}

function body(): Uint8Array {
  const suffix = canonicalSuffix(VENICE_CHAT, "cheap", 16);
  return new TextEncoder().encode(`{"messages":[{"role":"user","content":"x"}]${suffix}`);
}

/** Frames as the provider's records deliver them: one record each, or several in one. */
let abs = 0;
function feed(conn: any, ...frames: Uint8Array[]): void {
  const bytes = new Uint8Array(frames.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of frames) {
    bytes.set(x, o);
    o += x.length;
  }
  for (const fr of conn.reader.push(bytes, abs++) as RxFrame[]) conn.onFrame(fr);
  conn.kick();
}
const releases = (wire: Record<string, unknown>[]) => wire.filter((m) => m.type === "release").map((m) => m.upto as number);
// HPACK static index 8 (:status 200) would not do: a literal :status 429.
const status429 = new Uint8Array([0x08, 0x03, ...new TextEncoder().encode("429")]);
const tick = () => new Promise((r) => setTimeout(r, 5));

describe("framing 2: the provider's frames during a request", () => {
  it("an error head followed by RST_STREAM(NO_ERROR) in one record is disclosed (finding 18)", async () => {
    const { conn, wire } = connection();
    const h = conn.request({ model: "cheap", maxTokens: 16, body: body() });
    await tick();
    const stream = conn.cur.stream;
    // Both frames are processed before the request's wait wakes.
    feed(conn, frame(FRAME.HEADERS, FLAG.END_HEADERS | FLAG.END_STREAM, stream, status429), frame(FRAME.RST_STREAM, 0, stream, new Uint8Array(4)));
    await expect(h.done).resolves.toMatchObject({ status: 429 });
    expect(wire.map((m) => m.type)).toContain("disclose_head");
    conn.close();
  });

  it("an error head without END_STREAM, then a reset, does not wait out the error-body timeout", async () => {
    const { conn, wire } = connection();
    conn.timeouts.errorBody = 60_000;
    const h = conn.request({ model: "cheap", maxTokens: 16, body: body() });
    await tick();
    const stream = conn.cur.stream;
    feed(conn, frame(FRAME.HEADERS, FLAG.END_HEADERS, stream, status429));
    await tick();
    feed(conn, frame(FRAME.RST_STREAM, 0, stream, new Uint8Array(4)));
    const t = Date.now();
    await expect(h.done).resolves.toMatchObject({ status: 429 });
    expect(Date.now() - t).toBeLessThan(2000);
    expect(wire.map((m) => m.type)).toContain("disclose_head");
    conn.close();
  });

  it("a reset with no error head still fails the request", async () => {
    const { conn, wire } = connection();
    const h = conn.request({ model: "cheap", maxTokens: 16, body: body() });
    await tick();
    feed(conn, frame(FRAME.RST_STREAM, 0, conn.cur.stream, new Uint8Array([0, 0, 0, 2])));
    await expect(h.done).rejects.toBeInstanceOf(ResponseVerificationError);
    expect(wire.map((m) => m.type)).not.toContain("disclose_head");
    conn.close();
  });

  it("a GOAWAY whose last-stream-id is below the request's stream holds the release back; the request may run again", async () => {
    const { conn, wire } = connection();
    // The GOAWAY arrives while the node accepts the request, before any release.
    conn.onAccepted = (cur: any) => feed(conn, frame(FRAME.GOAWAY, 0, 0, new Uint8Array([0, 0, 0, cur.stream - 2, 0, 0, 0, 0])));
    const h = conn.request({ model: "cheap", maxTokens: 16, body: body() });
    await tick();
    const e = await h.done.catch((x: unknown) => x);
    expect(e).toBeInstanceOf(SessionRejectedError);
    expect(String((e as Error).message)).toMatch(/GOAWAY/);
    expect(h.bodyReleased).toBe(false);
    expect(wire.map((m) => m.type)).not.toContain("release");
    conn.close();
  });

  it("SETTINGS_INITIAL_WINDOW_SIZE applies to the open stream (RFC 9113 §6.9.2)", async () => {
    const { conn, wire } = connection();
    conn.initialWindow = 0;
    const h = conn.request({ model: "cheap", maxTokens: 16, body: body() });
    await tick();
    // The HEADERS record only: the stream has no credit for DATA.
    expect(releases(wire)).toEqual([1]);
    feed(conn, frame(FRAME.SETTINGS, 0, 0, new Uint8Array([0x00, 0x04, 0x00, 0x01, 0x00, 0x00])));
    expect(conn.cur.streamCredit).toBe(0x10000);
    expect(releases(wire)).toEqual([1, 2]);
    h.close();
    conn.close();
  });
});

describe("framing 2: the frame reader", () => {
  it("refuses a frame above 16 KiB before reassembling it", () => {
    const r = new FrameReader();
    expect(() => r.push(new Uint8Array([0x00, 0x40, 0x01, 0, 0, 0, 0, 0, 1]), 0)).toThrow(SessionProtocolError);
    const ok = new FrameReader();
    const max = frame(FRAME.DATA, 0, 1, new Uint8Array(1 << 14));
    expect(ok.push(max, 0)).toHaveLength(1);
  });
});
