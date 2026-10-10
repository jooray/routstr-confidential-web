import { describe, expect, it } from "vitest";
import {
  aggregateChatCompletion,
  buildPinnedBody,
  chooseBucket,
  padPinnedBody,
  requestedMaxTokens,
  SseParser,
} from "../src/request.js";
import {
  canonicalSuffix,
  ChunkedDecoder,
  extractUsageDisclosure,
  IncrementalHttpResponse,
  parseHttpResponse,
  usageEventFromDisclosure,
} from "../src/suffix.js";
import { costMsat, modelPricing, promptLimit } from "../src/pricing.js";
import { verifyConfidentialOffer } from "../src/offer.js";
import { fromHex, hex } from "../src/bytes.js";
import prod from "./fixtures/cypherpunk-offer.json";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

describe("canonical suffix", () => {
  it("is byte-exact with the sidecar's reconstruction", () => {
    expect(canonicalSuffix("deepseek-v4-flash", 128)).toBe(
      ',"model":"deepseek-v4-flash","max_tokens":128,"max_completion_tokens":128,"n":1,"stream":true,' +
        '"stream_options":{"include_usage":true},' +
        '"venice_parameters":{"include_venice_system_prompt":false,"enable_web_search":"off"}}',
    );
  });
  it("JSON-escapes the model name", () => {
    expect(canonicalSuffix('a"b', 1)).toContain('"model":"a\\"b"');
  });
});

describe("pinned body", () => {
  it("strips caller-supplied pinned keys and ends with the suffix", () => {
    const body = buildPinnedBody(
      { model: "evil", max_tokens: 99999, n: 4, stream: false, messages: [{ role: "user", content: "hi" }] },
      "m",
      12,
    );
    const text = dec(body);
    const suffix = canonicalSuffix("m", 12);
    expect(text.endsWith(suffix)).toBe(true);
    expect(text.slice(0, -suffix.length)).toBe('{"messages":[{"role":"user","content":"hi"}]');
    const j = JSON.parse(text);
    expect(j).toMatchObject({ model: "m", max_tokens: 12, n: 1, stream: true });
  });

  it("builds valid JSON with only pinned keys", () => {
    expect(JSON.parse(dec(buildPinnedBody({ model: "m" }, "m", 3))).max_tokens).toBe(3);
  });

  it("caps max_tokens at the offer cap", () => {
    expect(requestedMaxTokens({ max_tokens: 100000 }, 4096)).toBe(4096);
    expect(requestedMaxTokens({ max_completion_tokens: 7.9 }, 4096)).toBe(7);
    expect(requestedMaxTokens({}, 4096)).toBe(4096);
  });

  it("pads with spaces before the suffix: same JSON, suffix still last", () => {
    const body = buildPinnedBody({ messages: [{ role: "user", content: "héllo" }] }, "m", 5);
    const suffix = canonicalSuffix("m", 5);
    const padded = padPinnedBody(body, 4096, suffix);
    expect(padded.length).toBe(4096);
    expect(dec(padded).endsWith(suffix)).toBe(true);
    expect(JSON.parse(dec(padded))).toEqual(JSON.parse(dec(body)));
    expect(padPinnedBody(body, body.length, suffix)).toBe(body);
    expect(() => padPinnedBody(body, body.length - 1, suffix)).toThrow(RangeError);
    expect(() => padPinnedBody(enc('{"x":1}'), 4096, suffix)).toThrow(/suffix/);
  });

  it("chooses power-of-two buckets with headroom", () => {
    expect(chooseBucket(0)).toBe(4096);
    expect(chooseBucket(3200)).toBe(4096);
    expect(chooseBucket(3400)).toBe(8192);
    expect(chooseBucket(1e9)).toBe(8 << 20);
  });
});

describe("streaming", () => {
  it("parses SSE split at arbitrary byte boundaries", () => {
    const raw =
      'data: {"id":"x","choices":[{"index":0,"delta":{"role":"assistant","content":"Hé"}}]}\n\n' +
      'data: {"id":"x","choices":[{"index":0,"delta":{"content":"llo"},"finish_reason":"stop"}]}\n\n' +
      'data: {"id":"x","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2}}\n\ndata: [DONE]\n\n';
    const bytes = enc(raw);
    const p = new SseParser();
    const evs: Record<string, any>[] = [];
    for (let i = 0; i < bytes.length; i += 3) evs.push(...p.push(bytes.subarray(i, i + 3)));
    expect(evs.length).toBe(3);
    expect(p.done).toBe(true);
    const agg = aggregateChatCompletion(evs) as any;
    expect(agg.choices[0].message.content).toBe("Héllo");
    expect(agg.choices[0].finish_reason).toBe("stop");
    expect(agg.usage).toEqual({ prompt_tokens: 3, completion_tokens: 2 });
  });

  it("de-chunks an HTTP/1.1 response incrementally", () => {
    const raw =
      "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n" +
      "6\r\ndata: \r\n" + '9\r\n{"x":1}\n\n\r\n' + "0\r\n\r\n";
    expect(parseHttpResponse(enc(raw)).bodyText).toBe('data: {"x":1}\n\n');
    const inc = new IncrementalHttpResponse();
    const out: Uint8Array[] = [];
    for (const b of enc(raw)) out.push(...inc.push(new Uint8Array([b])));
    expect(inc.head?.status).toBe(200);
    expect(out.map(dec).join("")).toBe('data: {"x":1}\n\n');
    expect(inc.complete).toBe(true);
    expect(() => new ChunkedDecoder().push(enc("zz\r\nhello\r\n"))).toThrow();
  });

  it("finds the usage disclosure in the response", () => {
    const usage = '{"id":"x","model":"m","choices":[],"usage":{"prompt_tokens":9,"completion_tokens":4}}';
    const body = `data: {"id":"x","choices":[{"index":0,"delta":{"content":"hi"}}]}\n\ndata: ${usage}\n\ndata: [DONE]\n\n`;
    const len = enc(body).length.toString(16);
    const raw = `HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n${len}\r\n${body}\r\n0\r\n\r\n`;
    const r = extractUsageDisclosure(enc(raw));
    expect(r).not.toBeNull();
    const ev = usageEventFromDisclosure(r!);
    expect(ev?.usage).toMatchObject({ prompt_tokens: 9, completion_tokens: 4 });
  });
});

describe("pricing", () => {
  const offer = verifyConfidentialOffer(prod, {
    pinnedPubkeys: ["2ca46ee98f3134c4e11a638663a45983b590bfdefd31588f9c2f03455fba15e7"],
    trustedHosts: ["api.venice.ai"],
  });

  it("prices usage like the node (cached input at the cached rate)", () => {
    const rates = { in: 1000, cached_in: 100, out: 2000 };
    expect(costMsat(rates, { prompt_tokens: 1000, completion_tokens: 500 })).toBe(2000);
    expect(costMsat(rates, { prompt_tokens: 1000, completion_tokens: 0, cached_tokens: 1000 })).toBe(100);
    expect(costMsat(rates, { prompt_tokens: 1, completion_tokens: 0 }, 2000)).toBe(2001);
  });

  it("estimates the reservation from the full context length (conservative)", () => {
    expect(promptLimit({ id: "a", top_provider: { context_length: 1000, max_completion_tokens: 100 } })).toBe(1000);
    expect(promptLimit({ id: "a", context_length: 500 })).toBe(500);
    expect(promptLimit(undefined)).toBeUndefined();
    const m = Object.keys(offer.price_list)[0]!;
    const [p] = modelPricing(offer, [{ id: m, context_length: 100_000 }], 1000).filter((x) => x.id === m);
    const r = offer.price_list[m]!;
    expect(p!.reservationMsat).toBe(Math.ceil((100_000 * r.in + 1000 * r.out) / 1000));
    expect(p!.sessionFeeMsat).toBe(0);
  });

  it("hex round-trips", () => {
    expect(hex(fromHex("00ff10"))).toBe("00ff10");
    expect(() => fromHex("abc")).toThrow();
  });
});
