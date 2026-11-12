/**
 * The client-side checks of the π_NK / π_WIN (framing "1.1") / π_C3S parameters the node
 * sends (ported from routstr-sdk; the cu-2pc process codec and bridge tests
 * have no browser counterpart: test/twopc-version.test.ts covers the wasm bridge).
 */

import { describe, expect, it } from "vitest";

import {
  checkPiC3SParams,
  checkPiNKParams,
  firstTailOffset,
  serverTailEpoch,
} from "../src/params.js";
import { checkPiWinFinalRecord } from "../src/h2.js";
import { ProverError, SessionProtocolError, TwoPcVersionMismatchError } from "../src/errors.js";

const bytes = (n: number, fill: number) => new Uint8Array(n).fill(fill);

describe("π_NK statement rebuild (framing 1.1)", () => {
  const keyLen = 4;
  const alphabet = "[A-Za-z0-9_-]";
  const tpl =
    "POST /v1/chat/completions HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer {KEY:4}\r\nContent-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {LEN}\r\n\r\n";
  const offer = { head_template: tpl, key_length: keyLen, key_alphabet: alphabet, upstream_host: "api.example.com" };
  const hk = bytes(32, 0x5a);
  const filled = new TextEncoder().encode(
    tpl.replace("{KEY:4}", "\u0000".repeat(keyLen)).replace("{LEN}", "10"),
  );
  const offs: number[] = [];
  filled.forEach((b, i) => {
    if (b === 0) offs.push(i);
  });
  const n = filled.length + 1;
  const honest = () => ({
    PiNK: {
      hk: Array.from(hk),
      head_len: filled.length,
      key_len: keyLen,
      key_alphabet: alphabet,
      key_offsets: offs.slice(),
      template: Array.from(filled),
      c_commit: Array.from(bytes(32, 1)),
      header: [0x17, 0x03, 0x03, (n + 16) >> 8, (n + 16) & 0xff],
    },
  });
  const own = { offer, hk, bodyLen: 10 };

  it("accepts the statement the node builds for our body and our hk", () => {
    expect(() => checkPiNKParams(honest(), own)).not.toThrow();
  });

  it("holds the published template to one POST head for the upstream host", () => {
    const withTpl = (t: string, host = "api.example.com") => () =>
      checkPiNKParams(honest(), { ...own, offer: { ...offer, head_template: t, upstream_host: host } });
    const bad = [
      tpl.replace("Host: api.example.com", "Host: other.example.com"),
      tpl.replace("Host: api.example.com\r\n", ""),
      tpl.replace("POST /v1", "GET /v1"),
      // No other endpoint, no query string, nothing that changes how the provider answers.
      tpl.replace("/v1/chat/completions", "/v1/responses"),
      tpl.replace("/v1/chat/completions", "/v1/chat/completions?store=true"),
      tpl.replace("Connection: close\r\n", "Expect: 100-continue\r\nConnection: close\r\n"),
      tpl.replace("Connection: close\r\n", "TE: trailers\r\nConnection: close\r\n"),
      tpl.replace("Connection: close\r\n", "Upgrade: h2c\r\nConnection: close\r\n"),
      tpl.replace("Accept-Encoding: identity", "Accept-Encoding: gzip"),
      tpl.replace("Connection: close", "Connection: keep-alive"),
      tpl.replace("Connection: close\r\n", ""),
      tpl.replace("Content-Type: application/json", "Content-Type: text/plain"),
      tpl.replace("Connection: close\r\n", "Connection: close\r\nConnection: close\r\n"),
      tpl.replace("{LEN}", "10"),
      tpl.replace("\r\n\r\n", "\r\nX-Key: {KEY:4}\r\n\r\n"),
      tpl.replace("\r\n\r\n", "\r\nTransfer-Encoding: chunked\r\n\r\n"),
      tpl + "POST /y HTTP/1.1\r\n\r\n",
      tpl.replace("\r\n\r\n", "\r\nX-A: {OTHER}\r\n\r\n"),
    ];
    for (const t of bad) expect(withTpl(t)).toThrow(/template/);
    expect(withTpl(tpl, "API.EXAMPLE.COM")).not.toThrow();
    // An image head must name an image endpoint, a chat head a chat endpoint.
    const imageTpl = tpl.replace("/v1/chat/completions", "/api/v1/image/generate");
    expect(() =>
      checkPiNKParams(honest(), { ...own, offer: { ...offer, head_template: imageTpl }, kind: "chat" }),
    ).toThrow(/not a chat endpoint/);
    // A path a provider might normalise onto another route is refused.
    for (const path of ["/v1/chat/completions/../../image/generate", "/v1/./chat/completions", "//v1/chat/completions", "/v1/%63hat/completions"]) {
      const t = tpl.replace("/v1/chat/completions", path);
      expect(() =>
        checkPiNKParams(honest(), { ...own, offer: { ...offer, head_template: t }, kind: path.endsWith("generate") ? "images" : "chat" }),
      ).toThrow(/not canonical/);
    }
  });

  it("rejects a K_0 other than the one our 2PC anchored", () => {
    const p = honest();
    p.PiNK.hk = Array.from(bytes(32, 0x5b));
    expect(() => checkPiNKParams(p, own)).toThrow(SessionProtocolError);
  });

  it("rejects a different template, key placement, alphabet, length or header", () => {
    const tamper = (f: (p: ReturnType<typeof honest>["PiNK"]) => void) => {
      const p = honest();
      f(p.PiNK);
      return () => checkPiNKParams(p, own);
    };
    expect(tamper((p) => (p.template[0] = 0x47))).toThrow(SessionProtocolError);
    expect(tamper((p) => (p.key_offsets[0] = p.key_offsets[0]! - 1))).toThrow(SessionProtocolError);
    expect(tamper((p) => (p.key_alphabet = "[\\x00-\\xff]"))).toThrow(SessionProtocolError);
    expect(tamper((p) => (p.key_len = 3))).toThrow(SessionProtocolError);
    expect(tamper((p) => (p.head_len = p.head_len + 1))).toThrow(SessionProtocolError);
    expect(tamper((p) => (p.header[4] = p.header[4]! ^ 1))).toThrow(SessionProtocolError);
    expect(tamper((p) => (p.c_commit = []))).toThrow(SessionProtocolError);
    // Another body length (Content-Length) than ours.
    expect(() => checkPiNKParams(honest(), { ...own, bodyLen: 11 })).toThrow(SessionProtocolError);
    // v1 parameters in a v2 session.
    expect(() => checkPiNKParams({ PiN: honest().PiNK }, own)).toThrow(SessionProtocolError);
  });
});

describe("π_WIN / π_C3S parameter checks", () => {
  const suffix = new TextEncoder().encode(',"model":"m","max_tokens":8}');
  const payloadLen = 50 + suffix.length + 1 + 16; // header + (body + suffix + type byte + tag)
  const record = new Uint8Array(5 + payloadLen);
  record.set([0x17, 0x03, 0x03, payloadLen >> 8, payloadLen & 0xff]);
  for (let i = 5; i < record.length; i++) record[i] = (i * 31) & 0xff;
  const ctLen = payloadLen - 16;
  const w = Math.min(suffix.length + 1 + 13, ctLen);
  const off = ctLen - w;
  const h1 = bytes(32, 0x11);
  const h2 = bytes(32, 0x22);
  // Framing "1.1": the final record is the suffix alone (suffix ‖ 0x17 ‖ tag).
  const finalRecord = new Uint8Array(5 + suffix.length + 1 + 16);
  finalRecord.set([0x17, 0x03, 0x03, 0, suffix.length + 17]);
  for (let i = 5; i < finalRecord.length; i++) finalRecord[i] = (i * 17) & 0xff;
  const finalCt = finalRecord.subarray(5, finalRecord.length - 16);
  const honestWin = () => ({
    first_seq: 3,
    count: 1,
    params: {
      PiWin: {
        anchor: Array.from(h1),
        windows: [{ seq: 3, ct: Array.from(finalCt), expected: [...Array.from(suffix), 0x17] }] as Record<string, any>[],
      },
    },
  });
  const ownWin = { anchor: h1, seq: 3, wire: finalRecord, suffix };

  it("π_WIN (framing 1.1): one window, the whole of our own final record, anchored on our h1", () => {
    expect(checkPiWinFinalRecord(honestWin(), ownWin)).toEqual({ windows: 1, ctBytes: suffix.length + 1 });
  });

  it("π_WIN (framing 1.1): rejects another anchor, another record, a moved or partial window", () => {
    const otherAnchor = honestWin();
    otherAnchor.params.PiWin.anchor = Array.from(h2);
    expect(() => checkPiWinFinalRecord(otherAnchor, ownWin)).toThrow(SessionProtocolError);
    const earlier = honestWin();
    earlier.first_seq = 2;
    expect(() => checkPiWinFinalRecord(earlier, ownWin)).toThrow(SessionProtocolError);
    const otherSeq = honestWin();
    otherSeq.params.PiWin.windows[0]!.seq = 2;
    expect(() => checkPiWinFinalRecord(otherSeq, ownWin)).toThrow(SessionProtocolError);
    const two = honestWin();
    two.count = 2;
    expect(() => checkPiWinFinalRecord(two, ownWin)).toThrow(SessionProtocolError);
    const otherCt = honestWin();
    otherCt.params.PiWin.windows[0]!.ct[0] ^= 1;
    expect(() => checkPiWinFinalRecord(otherCt, ownWin)).toThrow(SessionProtocolError);
    const otherSuffix = honestWin();
    otherSuffix.params.PiWin.windows[0]!.expected[0] = 0x20;
    expect(() => checkPiWinFinalRecord(otherSuffix, ownWin)).toThrow(SessionProtocolError);
    const partial = honestWin();
    partial.params.PiWin.windows[0]!.expected = partial.params.PiWin.windows[0]!.expected.slice(0, -1);
    expect(() => checkPiWinFinalRecord(partial, ownWin)).toThrow(SessionProtocolError);
    const shifted = honestWin();
    shifted.params.PiWin.windows[0]!.sel_start = 1;
    expect(() => checkPiWinFinalRecord(shifted, ownWin)).toThrow(SessionProtocolError);
    const extra = honestWin();
    extra.params.PiWin.windows.push({ seq: 3, ct: Array.from(finalCt), expected: [0x17], sel_start: suffix.length });
    expect(() => checkPiWinFinalRecord(extra, ownWin)).toThrow(SessionProtocolError);
    // A π_C2S-shaped statement (protocol v2) is not a π_WIN one.
    expect(() => checkPiWinFinalRecord({ first_seq: 3, count: 1, params: { PiC2S: {} } }, ownWin)).toThrow(SessionProtocolError);
  });

  it("π_WIN (framing 1.1): our final record must be the suffix alone", () => {
    // A record that also carries private bytes cannot be proven as a whole.
    const longer = new Uint8Array(finalRecord.length + 8);
    longer.set(finalRecord);
    expect(() => checkPiWinFinalRecord(honestWin(), { ...ownWin, wire: longer })).toThrow(/not the suffix alone/);
  });

  it("π_C3S must cover exactly the final records we received, anchored on our h2", () => {
    const recs = [bytes(60, 1), bytes(80, 2), bytes(70, 3)];
    const r = bytes(40, 9);
    const params = (records: { seq: number; ct: number[]; off?: number }[], opts: { skip?: number; h2?: Uint8Array } = {}) => ({
      PiC3S: {
        h2: Array.from(opts.h2 ?? h2),
        records,
        expected: Array.from(r),
        skip: opts.skip ?? 0,
      },
    });
    // R (40 bytes) fits in the last record's 53 content bytes, so the first
    // covered record is decrypted only from its last block boundary (48).
    const tail: { seq: number; ct: number[]; off?: number }[] = [
      { seq: 1, ct: Array.from(recs[1]!.subarray(48, 64)), off: 48 },
      { seq: 2, ct: Array.from(recs[2]!.subarray(0, 54)) },
    ];
    // A two-record tail (the check follows the tail lengths we disclosed).
    const own = { h2, serverRecords: recs, r, skip: 0, tailLens: [54, 64] };
    expect(() => checkPiC3SParams(params(tail), own)).not.toThrow();
    // Any other offset (more or less of the record than the rule gives) is refused.
    for (const off of [0, 32]) {
      const other = [{ ...tail[0]!, off, ct: Array.from(recs[1]!.subarray(off, 64)) }, tail[1]!];
      expect(() => checkPiC3SParams(params(other), own)).toThrow(/offset/);
    }
    // A trailing close_notify-sized record is tolerated.
    expect(() =>
      checkPiC3SParams(params(tail), { ...own, serverRecords: [...recs, bytes(19, 4)] }),
    ).not.toThrow();
    expect(() => checkPiC3SParams(params(tail, { h2: h1 }), own)).toThrow(SessionProtocolError);
    expect(() =>
      checkPiC3SParams(params([{ seq: 0, ct: Array.from(recs[0]!.subarray(0, 44)) }]), own),
    ).toThrow(SessionProtocolError);
    expect(() => checkPiC3SParams(params(tail, { skip: 5 }), own)).toThrow(SessionProtocolError);
    const gap = [tail[0]!, { ...tail[1]!, seq: 3 }];
    expect(() => checkPiC3SParams(params(gap), own)).toThrow(SessionProtocolError);
    // Not enough coverage for the disclosure.
    expect(() =>
      checkPiC3SParams(params([tail[1]!]), { ...own, r: bytes(60, 9) }),
    ).toThrow(SessionProtocolError);
  });

  it("π_C3S after a server KeyUpdate: our epoch count and exact sequence numbers", () => {
    const recs = [bytes(60, 1), bytes(80, 2), bytes(70, 3), bytes(70, 4)];
    const r = bytes(40, 9);
    // The covered records' epoch starts at wire index 2: their seqs are 0, 1.
    const tail: { seq: number; ct: number[]; off?: number }[] = [
      { seq: 0, ct: Array.from(recs[2]!.subarray(48, 54)), off: 48 },
      { seq: 1, ct: Array.from(recs[3]!.subarray(0, 54)) },
    ];
    const params = (ku?: number, records = tail) => ({
      PiC3S: { h2: Array.from(h2), records, expected: Array.from(r), skip: 0, ...(ku ? { key_updates: ku } : {}) },
    });
    const own = { h2, serverRecords: recs, r, skip: 0, keyUpdates: 1, epochBase: 2, tailLens: [54, 54] };
    expect(() => checkPiC3SParams(params(1), own)).not.toThrow();
    // The node may not drop or invent a key epoch.
    expect(() => checkPiC3SParams(params(), own)).toThrow(/key epoch/);
    expect(() => checkPiC3SParams(params(2), own)).toThrow(/key epoch/);
    // Sequence numbers must be the records' offsets in that epoch.
    const shifted = tail.map((t) => ({ ...t, seq: t.seq + 2 }));
    expect(() => checkPiC3SParams(params(1, shifted), own)).toThrow(/sequence numbers/);
  });

  it("π_C3S with KeyUpdates and a close_notify after the usage event", () => {
    const D = { data: true, keyUpdates: 0 };
    const KU = { data: false, keyUpdates: 1 };
    const CN = { data: false, keyUpdates: 0 };
    // A KeyUpdate after the covered records leaves their epoch alone.
    expect(serverTailEpoch([D, D, D, KU, CN], 2)).toEqual({ trailing: 2, keyUpdates: 0, epochStart: 0 });
    // KeyUpdates before them count, coalesced ones too.
    expect(serverTailEpoch([D, KU, D, { data: false, keyUpdates: 2 }, D, D, KU], 2)).toEqual({
      trailing: 1,
      keyUpdates: 3,
      epochStart: 4,
    });
    // A key change inside the covered records cannot be proven.
    expect(() => serverTailEpoch([D, KU, D], 2)).toThrow(SessionProtocolError);
    expect(() => serverTailEpoch([D, KU], 2)).toThrow(SessionProtocolError);

    // The node's records must end before the trailing ones we counted.
    const recs = [bytes(60, 1), bytes(70, 3), bytes(22, 5), bytes(19, 4)];
    const r = bytes(40, 9);
    const tail = [{ seq: 1, ct: Array.from(recs[1]!.subarray(0, 54)) }];
    const params = (records = tail) => ({
      PiC3S: { h2: Array.from(h2), records, expected: Array.from(r), skip: 0 },
    });
    const own = { h2, serverRecords: recs, r, skip: 0, epochBase: 0, trailing: 2, tailLens: [54] };
    expect(() => checkPiC3SParams(params(), own)).not.toThrow();
    expect(() => checkPiC3SParams(params(), { ...own, trailing: 1 })).toThrow(SessionProtocolError);
  });

  it("π_C3S must name exactly the tail we disclosed, not a longer one", () => {
    const recs = [bytes(60, 1), bytes(80, 2), bytes(70, 3)];
    const r = bytes(40, 9);
    const params = (records: { seq: number; ct: number[]; off?: number }[]) => ({
      PiC3S: { h2: Array.from(h2), records, expected: Array.from(r), skip: 0 },
    });
    // R (40 bytes) fits in the last record: the minimal tail is that record.
    const minimal = [{ seq: 2, ct: Array.from(recs[2]!.subarray(0, 54)) }];
    const own = { h2, serverRecords: recs, r, skip: 0, epochBase: 0, trailing: 0, tailLens: [54] };
    expect(() => checkPiC3SParams(params(minimal), own)).not.toThrow();
    // Earlier genuine records prepended to it (more proof work) are refused.
    const padded = [{ seq: 1, ct: Array.from(recs[1]!.subarray(48, 64)), off: 48 }, ...minimal];
    expect(() => checkPiC3SParams(params(padded), own)).toThrow(/tail we disclosed/);
    const all = [
      { seq: 0, ct: Array.from(recs[0]!.subarray(32, 44)), off: 32 },
      { seq: 1, ct: Array.from(recs[1]!.subarray(0, 64)) },
      ...minimal,
    ];
    expect(() => checkPiC3SParams(params(all), own)).toThrow(/tail we disclosed/);
    // Record lengths must be the ones we sent, too.
    expect(() => checkPiC3SParams(params(minimal), { ...own, tailLens: [53] })).toThrow(/tail we disclosed/);
    // Without our tail lengths there is nothing to hold the node to.
    expect(() => checkPiC3SParams(params(minimal), { ...own, tailLens: [] })).toThrow(SessionProtocolError);
    expect(() =>
      checkPiC3SParams(params(minimal), { ...own, tailLens: undefined as unknown as number[] }),
    ).toThrow(SessionProtocolError);
  });

  it("π_C3S first-record offset keeps at least one content byte (same rule as the node)", () => {
    expect(firstTailOffset(100, 10, 30)).toBe(80);
    expect(firstTailOffset(100, 10, 110)).toBe(0);
    expect(firstTailOffset(32, 10, 11)).toBe(16);
    expect(firstTailOffset(63, 53, 40)).toBe(48);
    // Later records alone cover R + skip: the first record still keeps its
    // last content byte, so a content length that is a multiple of 16 backs
    // off one block.
    expect(firstTailOffset(32, 50, 40)).toBe(16);
    expect(firstTailOffset(4000, 50, 40)).toBe(3984);
    expect(firstTailOffset(16, 130, 130)).toBe(0);
    for (let content = 1; content < 100; content++) {
      const off = firstTailOffset(content, 50, 40);
      expect(off % 16).toBe(0);
      expect(content + 1 - off).toBeGreaterThanOrEqual(2);
    }
    // The check applies it: first record of 32 content bytes (+ type + tag).
    const recs = [bytes(49, 1), bytes(67, 2)];
    const r = bytes(40, 9);
    const params = (off: number) => ({
      PiC3S: {
        h2: Array.from(h2),
        records: [
          { seq: 0, ct: Array.from(recs[0]!.subarray(off, 33)), off },
          { seq: 1, ct: Array.from(recs[1]!.subarray(0, 51)) },
        ],
        expected: Array.from(r),
        skip: 0,
      },
    });
    const own = { h2, serverRecords: recs, r, skip: 0, epochBase: 0, trailing: 0, tailLens: [51, 33] };
    expect(() => checkPiC3SParams(params(16), own)).not.toThrow();
    expect(() => checkPiC3SParams(params(32), own)).toThrow(/offset/);
  });
});
