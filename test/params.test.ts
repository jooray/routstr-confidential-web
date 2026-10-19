import { describe, expect, it } from "vitest";
import { checkHeadTemplate, checkPiC2SParams, checkPiC3SParams, checkPiNKParams, firstTailOffset } from "../src/params.js";
import { SessionProtocolError } from "../src/errors.js";

describe("π_NK statement rebuilt from the signed offer", () => {
  const offer = {
    head_template:
      "POST /api/v1/chat/completions HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer {KEY:4}\r\nContent-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {LEN}\r\n\r\n",
    upstream_host: "api.example.com",
    key_length: 4,
    key_alphabet: "[A-Za-z0-9_-]",
  };
  const hk = new Uint8Array(32).fill(5);
  const bodyLen = 123;
  const filled = new TextEncoder().encode(offer.head_template.replace("{KEY:4}", "\0\0\0\0").replace("{LEN}", "123"));
  const offs = [...filled].flatMap((b, i) => (b === 0 ? [i] : []));
  const n = filled.length + 1;
  const honest = {
    PiNK: {
      template: [...filled],
      key_len: 4,
      key_offsets: offs,
      head_len: filled.length,
      hk: [...hk],
      header: [0x17, 0x03, 0x03, (n + 16) >> 8, (n + 16) & 0xff],
      c_commit: new Array(32).fill(1),
      key_alphabet: offer.key_alphabet,
    },
  };

  it("accepts the honest statement", () => {
    expect(() => checkPiNKParams(honest, { offer, hk, bodyLen })).not.toThrow();
  });

  it("rejects a changed template, key position, anchor or length", () => {
    const t = structuredClone(honest);
    t.PiNK.template[0] = 0x47;
    expect(() => checkPiNKParams(t, { offer, hk, bodyLen })).toThrow(SessionProtocolError);
    const k = structuredClone(honest);
    k.PiNK.key_offsets[0]! -= 1;
    expect(() => checkPiNKParams(k, { offer, hk, bodyLen })).toThrow(SessionProtocolError);
    expect(() => checkPiNKParams(honest, { offer, hk: new Uint8Array(32), bodyLen })).toThrow(/hk/);
    expect(() => checkPiNKParams(honest, { offer, hk, bodyLen: 124 })).toThrow(SessionProtocolError);
    const a = structuredClone(honest);
    a.PiNK.key_alphabet = "[0-9]";
    expect(() => checkPiNKParams(a, { offer, hk, bodyLen })).toThrow(/alphabet/);
  });
});

describe("head template", () => {
  const head = (path: string, headers: string[]) => `POST ${path} HTTP/1.1\r\n${headers.join("\r\n")}\r\n\r\n`;
  const STD = [
    "Host: api.example.com",
    "Authorization: Bearer {KEY:4}",
    "Content-Type: application/json",
    "Accept-Encoding: identity",
    "Connection: close",
    "Content-Length: {LEN}",
  ];

  it("takes exactly the expected headers on the kind's route", () => {
    expect(() => checkHeadTemplate(head("/api/v1/chat/completions", STD), "api.example.com")).not.toThrow();
    expect(() => checkHeadTemplate(head("/api/v1/image/generate", STD), "api.example.com", "images")).not.toThrow();
    expect(() => checkHeadTemplate(head("/v1/images/generations", [...STD].reverse()), "API.example.com", "images")).not.toThrow();
  });

  it("refuses another route, a query, another or a missing header", () => {
    const bad: [string, string[], "chat" | "images"][] = [
      ["/api/v1/image/generate", STD, "chat"],
      ["/api/v1/chat/completions", STD, "images"],
      ["/api/v1/chat/completions?store=true", STD, "chat"],
      ["/api/v1/chat/completions#x", STD, "chat"],
      ["/api/v1/chat/completions", [...STD, "Expect: 100-continue"], "chat"],
      ["/api/v1/chat/completions", [...STD, "X-Store: 1"], "chat"],
      ["/api/v1/chat/completions", STD.map((h) => (h.startsWith("Accept-Encoding") ? "Accept-Encoding: gzip" : h)), "chat"],
      ["/api/v1/chat/completions", STD.map((h) => (h.startsWith("Connection") ? "Connection: keep-alive" : h)), "chat"],
      ["/api/v1/chat/completions", STD.filter((h) => !h.startsWith("Connection")), "chat"],
      ["/api/v1/chat/completions", [...STD, "Connection: close"], "chat"],
    ];
    for (const [path, headers, kind] of bad) {
      expect(() => checkHeadTemplate(head(path, headers), "api.example.com", kind)).toThrow(SessionProtocolError);
    }
  });
});

describe("π_C2S / π_C3S windows are our own data", () => {
  const h1 = new Uint8Array(32).fill(1);
  const suffix = new TextEncoder().encode(',"model":"m","max_tokens":3}');
  const ctLen = 100;
  const record = new Uint8Array(5 + ctLen + 16).map((_, i) => (i * 7) & 0xff);
  const w = suffix.length + 14;
  const honest = {
    PiC2S: {
      h1: [...h1],
      seq: 2,
      ct_window: [...record.subarray(5 + ctLen - w, 5 + ctLen)],
      off: ctLen - w,
      w,
      sel_start: w - 1 - suffix.length,
      sel_len: suffix.length + 1,
      expected: [...suffix, 0x17],
    },
  };
  const own = { h1, seq: 2, record, suffix };

  it("accepts the window over our final record", () => {
    expect(() => checkPiC2SParams(honest, own)).not.toThrow();
  });

  it("rejects a moved window, another record or another anchor", () => {
    const moved = structuredClone(honest);
    moved.PiC2S.off = 0;
    expect(() => checkPiC2SParams(moved, own)).toThrow(SessionProtocolError);
    const earlier = structuredClone(honest);
    earlier.PiC2S.seq = 0;
    expect(() => checkPiC2SParams(earlier, own)).toThrow(SessionProtocolError);
    expect(() => checkPiC2SParams(honest, { ...own, h1: new Uint8Array(32) })).toThrow(/h1/);
    // The bare suffix, without the record's content type byte, is not enough.
    const bare = { PiC2S: { ...honest.PiC2S, sel_len: suffix.length, expected: [...suffix] } };
    expect(() => checkPiC2SParams(bare, own)).toThrow(SessionProtocolError);
  });

  it("π_C3S must cover exactly the final records we received", () => {
    const h2 = new Uint8Array(32).fill(2);
    const recs = [new Uint8Array(60).fill(1), new Uint8Array(80).fill(2), new Uint8Array(70).fill(3)];
    const r = new Uint8Array(40).fill(9);
    const params = (records: { seq: number; ct: number[]; off?: number }[], skip = 0, anchor = h2) => ({
      PiC3S: { h2: [...anchor], records, expected: [...r], skip },
    });
    // The first covered record is decrypted from its last block boundary that
    // still covers R (here 48: R fits in the last record).
    const tail = [
      { seq: 1, ct: [...recs[1]!.subarray(48, 64)], off: 48 },
      { seq: 2, ct: [...recs[2]!.subarray(0, 54)] },
    ];
    // A two-record tail (the check follows the tail lengths we disclosed).
    const ownC3 = { h2, serverRecords: recs, r, skip: 0, tailLens: [54, 64] };
    expect(() => checkPiC3SParams(params(tail), ownC3)).not.toThrow();
    const whole = [{ seq: 1, ct: [...recs[1]!.subarray(0, 64)] }, tail[1]!];
    expect(() => checkPiC3SParams(params(whole), ownC3)).toThrow(/offset/);
    expect(() => checkPiC3SParams(params([{ seq: 0, ct: [...recs[0]!.subarray(0, 44)] }]), ownC3)).toThrow(
      SessionProtocolError,
    );
    expect(() => checkPiC3SParams(params(tail, 5), ownC3)).toThrow(SessionProtocolError);
    expect(() => checkPiC3SParams(params(tail, 0, new Uint8Array(32)), ownC3)).toThrow(/h2/);
  });
  it("π_C3S must name exactly the tail we disclosed, not a longer one", () => {
    const h2 = new Uint8Array(32).fill(2);
    const recs = [new Uint8Array(60).fill(1), new Uint8Array(80).fill(2), new Uint8Array(70).fill(3)];
    const r = new Uint8Array(40).fill(9);
    const params = (records: { seq: number; ct: number[]; off?: number }[]) => ({
      PiC3S: { h2: [...h2], records, expected: [...r], skip: 0 },
    });
    // R (40 bytes) fits in the last record: the minimal tail is that record.
    const minimal = [{ seq: 2, ct: [...recs[2]!.subarray(0, 54)] }];
    const own = { h2, serverRecords: recs, r, skip: 0, epochBase: 0, trailing: 0, tailLens: [54] };
    expect(() => checkPiC3SParams(params(minimal), own)).not.toThrow();
    // Earlier genuine records prepended to it (more proof work) are refused.
    const padded = [{ seq: 1, ct: [...recs[1]!.subarray(48, 64)], off: 48 }, ...minimal];
    expect(() => checkPiC3SParams(params(padded), own)).toThrow(/tail we disclosed/);
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
    expect(firstTailOffset(32, 50, 40)).toBe(16);
    expect(firstTailOffset(4000, 50, 40)).toBe(3984);
    expect(firstTailOffset(16, 130, 130)).toBe(0);
    for (let content = 1; content < 100; content++) {
      const off = firstTailOffset(content, 50, 40);
      expect(off % 16).toBe(0);
      expect(content + 1 - off).toBeGreaterThanOrEqual(2);
    }
  });
});
