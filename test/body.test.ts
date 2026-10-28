import { describe, expect, it } from "vitest";
import { VENICE_CHAT } from "./fixtures/chat.js";
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
import { offerReserveMarginTokens } from "../src/offer.js";
import { verifyConfidentialOffer } from "../src/offer.js";
import { fromHex, hex } from "../src/bytes.js";
import prod from "./fixtures/cypherpunk-offer.json";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

describe("canonical suffix", () => {
  it("is byte-exact with the sidecar's reconstruction", () => {
    expect(canonicalSuffix(VENICE_CHAT, "deepseek-v4-flash", 128)).toBe(
      ',"model":"deepseek-v4-flash","max_tokens":128,"max_completion_tokens":128,"n":1,"stream":true,' +
        '"stream_options":{"include_usage":true},' +
        '"venice_parameters":{"enable_web_search":"off","include_venice_system_prompt":false}}',
    );
  });
  it("JSON-escapes the model name", () => {
    expect(canonicalSuffix(VENICE_CHAT, 'a"b', 1)).toContain('"model":"a\\"b"');
  });
});

describe("pinned body", () => {
  it("strips caller-supplied pinned keys and ends with the suffix", () => {
    const body = buildPinnedBody(
      { model: "evil", max_tokens: 99999, n: 4, stream: false, messages: [{ role: "user", content: "hi" }] },
      "m",
      12,
      VENICE_CHAT,
    );
    const text = dec(body);
    const suffix = canonicalSuffix(VENICE_CHAT, "m", 12);
    expect(text.endsWith(suffix)).toBe(true);
    expect(text.slice(0, -suffix.length)).toBe('{"messages":[{"role":"user","content":"hi"}]');
    const j = JSON.parse(text);
    expect(j).toMatchObject({ model: "m", max_tokens: 12, n: 1, stream: true });
  });

  it("needs a private field before the exact suffix", () => {
    expect(() => buildPinnedBody({ model: "m" }, "m", 3, VENICE_CHAT)).toThrow(/messages/);
    const body = dec(buildPinnedBody({ model: "m", messages: [] }, "m", 3, VENICE_CHAT));
    expect(body.endsWith(canonicalSuffix(VENICE_CHAT, "m", 3))).toBe(true);
    expect(JSON.parse(body).max_tokens).toBe(3);
  });

  it("caps max_tokens at the offer cap", () => {
    expect(requestedMaxTokens({ max_tokens: 100000 }, 4096)).toBe(4096);
    expect(requestedMaxTokens({ max_completion_tokens: 7.9 }, 4096)).toBe(7);
    expect(requestedMaxTokens({}, 4096)).toBe(4096);
  });

  it("pads with spaces before the suffix: same JSON, suffix still last", () => {
    const body = buildPinnedBody({ messages: [{ role: "user", content: "héllo" }] }, "m", 5, VENICE_CHAT);
    const suffix = canonicalSuffix(VENICE_CHAT, "m", 5);
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

  it("keeps streamed tool calls when folding a completion", () => {
    const agg = aggregateChatCompletion([
      { id: "c", choices: [{ index: 0, delta: { role: "assistant", tool_calls: [{ index: 0, id: "t1", type: "function", function: { name: "get_", arguments: '{"a"' } }] } }] },
      { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { name: "time", arguments: ":1}" } }] }, finish_reason: "tool_calls" }] },
    ]) as any;
    expect(agg.choices[0].message.tool_calls).toEqual([
      { id: "t1", type: "function", function: { name: "get_time", arguments: '{"a":1}' } },
    ]);
    expect(agg.choices[0].finish_reason).toBe("tool_calls");
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

  it("skips interim 1xx heads, hides operator headers and reports framing", () => {
    const raw =
      "HTTP/1.1 100 Continue\r\n\r\n" +
      "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\nx-venice-balance-usd: 12.5\r\nx-ratelimit-remaining-requests: 3\r\n\r\n{\"a\":1}";
    const r = parseHttpResponse(enc(raw));
    expect(r.status).toBe(200);
    expect(r.bodyText).toBe('{"a":1}');
    expect(r.complete).toBe(true);
    expect(Object.keys(r.headers).sort()).toEqual(["content-length", "content-type"]);
    expect(parseHttpResponse(enc("HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort")).complete).toBe(false);
    expect(parseHttpResponse(enc("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")).complete).toBe(false);
    const inc = new IncrementalHttpResponse();
    for (const b of enc(raw)) inc.push(new Uint8Array([b]));
    expect(inc.head?.status).toBe(200);
    expect(inc.head?.headers["x-venice-balance-usd"]).toBeUndefined();
  });

  it("treats 101 Switching Protocols as the final status", () => {
    const raw = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    expect(parseHttpResponse(enc(raw)).status).toBe(101);
    const inc = new IncrementalHttpResponse();
    inc.push(enc(raw));
    expect(inc.head?.status).toBe(101);
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
  // The production offer without fees or a completion margin, so the expected
  // reservations below are the bare rate arithmetic.
  const plain = { ...offer, session_fee_msat: undefined, abandon_fee_msat: undefined, reserve_margin_tokens: undefined };

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
    const [p] = modelPricing(plain, [{ id: m, context_length: 100_000 }], 1000).filter((x) => x.id === m);
    const r = offer.price_list[m]!;
    expect(p!.reservationMsat).toBe(Math.ceil((100_000 * r.in + 1000 * r.out) / 1000));
    expect(p!.sessionFeeMsat).toBe(0);
    // The node reserves the offer's completion margin on top of max_tokens.
    const [q] = modelPricing({ ...plain, reserve_margin_tokens: 16 }, [{ id: m, context_length: 100_000 }], 1000).filter(
      (x) => x.id === m,
    );
    expect(q!.reservationMsat).toBe(Math.ceil((100_000 * r.in + 1016 * r.out) / 1000));
  });

  it("takes the context length in the node's order: top_provider first, then the model's", () => {
    // The first positive integer wins, not the larger one.
    expect(promptLimit({ id: "a", top_provider: { context_length: 1000 }, context_length: 5000 })).toBe(1000);
    expect(promptLimit({ id: "a", top_provider: { context_length: 0 }, context_length: 5000 })).toBe(5000);
    expect(promptLimit({ id: "a", top_provider: { context_length: null }, context_length: 5000 })).toBe(5000);
    expect(promptLimit({ id: "a", top_provider: { context_length: 1.5 }, context_length: 700 })).toBe(700);
    expect(promptLimit({ id: "a", top_provider: { context_length: -1 }, context_length: 0 })).toBeUndefined();
    expect(promptLimit({ id: "a" })).toBeUndefined();
  });

  it("without a context length, reserves the model's maximum cost like the node", () => {
    const m = Object.keys(offer.price_list)[0]!;
    const r = offer.price_list[m]!;
    const model = { id: m, sats_pricing: { max_cost: 12.3456 } };
    // ceil(ceil(max_cost·1000)·(1 + pct/100) + margin·out/1000) + max(session fee, abandon fee)
    const signed = { ...offer, reserve_margin_tokens: 16, rate_surcharge_pct: 10, session_fee_msat: 500, abandon_fee_msat: 2000 };
    const [p] = modelPricing(signed, [model], 1000).filter((x) => x.id === m);
    expect(p!.reservationMsat).toBe(Math.ceil(12346 * 1.1 + (16 * r.out) / 1000) + 2000);
    // No surcharge, margin or fees: just the maximum cost, rounded up to msat.
    const [q] = modelPricing(plain, [model], 1000).filter((x) => x.id === m);
    expect(q!.reservationMsat).toBe(12346 + Math.ceil((offerReserveMarginTokens(plain) * r.out) / 1000));
    // Neither a context length nor a maximum cost: unknown.
    const [u] = modelPricing(plain, [{ id: m }], 1000).filter((x) => x.id === m);
    expect(u!.reservationMsat).toBeUndefined();
    const [z] = modelPricing(plain, [{ id: m, sats_pricing: { max_cost: 0 } }], 1000).filter((x) => x.id === m);
    expect(z!.reservationMsat).toBeUndefined();
    // A context length takes precedence over the maximum cost.
    const [c] = modelPricing(plain, [{ ...model, context_length: 100_000 }], 1000).filter((x) => x.id === m);
    expect(c!.reservationMsat).toBe(
      Math.ceil((100_000 * r.in + (1000 + offerReserveMarginTokens(plain)) * r.out) / 1000),
    );
  });

  it("hex round-trips", () => {
    expect(hex(fromHex("00ff10"))).toBe("00ff10");
    expect(() => fromHex("abc")).toThrow();
  });
});
