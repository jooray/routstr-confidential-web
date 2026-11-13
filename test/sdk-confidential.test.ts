/**
 * Confidential-upstream SDK unit tests.
 *
 * Covers offer signature verification (good/bad), npub pinning, protocol
 * version negotiation, trusted-host matching, canonical suffix bytes,
 * receipt verification and the confidential transport's body handling. Fixtures are a real
 * v2 offer recorded from a production node (routstr-core branch `confidential-2pc`) and a
 * real offer from an older node running the retired protocol v1 (refused).
 */

import { describe, expect, it, vi } from "vitest";
import { VENICE_CHAT } from "./fixtures/chat.js";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { utf8ToBytes, bytesToHex } from "@noble/hashes/utils";

import {
  canonicalJson,
  npubToHex,
  verifySchnorrSignature,
} from "../src/canonical.js";
import {
  canonicalSuffix,
  chatSuffixKeys,
  effectiveModelFromText,
  extractUsageDisclosure,
  parseHttpResponse,
  usageEventFromDisclosure,
} from "../src/suffix.js";
import {
  verifyConfidentialOffer,
  verifyOfferSignature,
  supportedVersion,
} from "../src/offer.js";
import {
  checkUpstreamErrorReceipt,
  feeOnlyChargeOk,
  maxChargeMsats,
  checkAttestationBinding,
  parseSignedReceipt,
  verifyReceipt,
} from "../src/receipt.js";
import {
  offerAbandonFeeMsat,
  offerSessionFeeMsat,
  validateOfferShape,
} from "../src/offer.js";
import {
  ConfidentialError,
  ProverMissingError,
  ReceiptVerificationError,
  SessionRejectedError,
} from "../src/errors.js";
import { ConfidentialConnection } from "../src/connection.js";
import { NO_HOST } from "./fixtures/v3.js";
import { IncrementalHttpResponse, parseHttpResponse as parseHttp } from "../src/suffix.js";
import { fakeConnections } from "./fixtures/v3.js";
import {
  TrustedHostMatcher,
  matchHostname,
  normalizeHostname,
  parseTrustedHostPattern,
  encryptedNodeTransport,
} from "../src/hosts.js";
import {
  OfferBadSignatureError,
  OfferMalformedError,
  OfferPinMismatchError,
  OfferUnpinnedError,
  OfferUnsupportedVersionError,
  NodeProtocolOutdatedError,
  TrustedHostError,
} from "../src/errors.js";

import offerFixture from "./fixtures/sdk/venice-offer.json";
import offerFixtureV1 from "./fixtures/sdk/venice-offer-v1.json";

const OFFER = offerFixture as unknown as Record<string, unknown>;
/** A real offer from a node that still ran the retired protocol v1. */
const OFFER_V1 = offerFixtureV1 as unknown as Record<string, unknown>;

function makeKey() {
  const priv = new Uint8Array(32).fill(7);
  const pub = schnorr.getPublicKey(priv);
  return { priv, pubHex: bytesToHex(pub) };
}

/** Build an offer signed the way the node does: BIP-340 over sha256(canonical). */
function signedOffer(overrides: Record<string, unknown> = {}) {
  const { priv, pubHex } = makeKey();
  const offer: Record<string, unknown> = {
    v: 3,
    twopc: "split-public-1",
    upstream_host: "api.venice.ai",
    ws: "wss://node.example/v1/confidential/ws",
    notary_pubkey: pubHex,
    max_tokens_cap: 4096,
    key_length: 42,
    key_alphabet: "[A-Za-z0-9_-]",
    head_template:
      "POST /api/v1/chat/completions HTTP/1.1\r\nHost: api.venice.ai\r\nAuthorization: Bearer {KEY:42}\r\n" +
      "Content-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {LEN}\r\n\r\n",
    suffix_keys: ["model", "max_tokens", "max_completion_tokens", "n", "stream", "stream_options", "venice_parameters"],
    chat: VENICE_CHAT,
    price_list: {
      cheap: { in: 1000, cached_in: 1000, out: 1000 },
      dear: { in: 2000, cached_in: 2000, out: 4000 },
    },
    mints: ["https://mint.example/"],
    ...overrides,
  };
  const payload = canonicalJson(offer);
  const digest = sha256(utf8ToBytes(payload));
  const sig = bytesToHex(schnorr.sign(digest, priv));
  return { offer: { ...offer, sig, sig_payload: payload }, priv, pubHex };
}

describe("canonical JSON + Schnorr", () => {
  it("serializes with sorted keys and no whitespace", () => {
    expect(canonicalJson({ b: 1, a: [true, null, "x"] })).toBe('{"a":[true,null,"x"],"b":1}');
  });

  it("verifies a good signature", () => {
    const { offer } = signedOffer();
    expect(verifyOfferSignature(offer as never)).toBe(true);
  });

  it("rejects a tampered signed payload", () => {
    const { offer } = signedOffer();
    const payload = (offer as Record<string, unknown>).sig_payload as string;
    (offer as Record<string, unknown>).sig_payload = payload.replace("api.venice.ai", "evil.example");
    expect(verifyOfferSignature(offer as never)).toBe(false);
  });

  it("ignores tampering outside the signed payload", () => {
    // The client uses the signed payload's fields, so a mutated envelope cannot
    // change what the client trusts.
    const { offer } = signedOffer();
    const policy = { allowUnpinned: true, trustedHosts: ["*.venice.ai"] };
    const { offer: verified } = { offer: verifyConfidentialOffer(offer, policy) };
    (offer as Record<string, unknown>).upstream_host = "evil.example";
    const again = verifyConfidentialOffer(offer, policy);
    expect(verified.upstream_host).toBe("api.venice.ai");
    expect(again.upstream_host).toBe("api.venice.ai");
  });

  it("rejects a signature from the wrong key", () => {
    const { offer } = signedOffer();
    expect(
      verifySchnorrSignature(
        (offer as Record<string, unknown>).sig_payload as string,
        (offer as Record<string, unknown>).sig as string,
        bytesToHex(schnorr.getPublicKey(new Uint8Array(32).fill(9))),
      ),
    ).toBe(false);
  });
});

describe("npub decoding", () => {
  it("decodes a known npub and passes hex through", () => {
    // Well-known Nostr test identity (jack).
    expect(npubToHex("npub1sn0wdenkukak0d9dfczzeacvhkrgz92ak56egt7vdgzn8pv2wfqqhrjdv9")).toBe(
      "84dee6e676e5bb67b4ad4e042cf70cbd8681155db535942fcc6a0533858a7240",
    );
    const { pubHex } = makeKey();
    expect(npubToHex(pubHex)).toBe(pubHex);
    expect(npubToHex("npub1notvalid")).toBeNull();
  });
});

describe("offer verification + pinning", () => {
  it("accepts a v3 offer with the pin from its own key", () => {
    const { offer, pubHex } = signedOffer();
    const verified = verifyConfidentialOffer(offer, { pinnedPubkey: pubHex, trustedHosts: ["*.venice.ai"] });
    expect(verified.upstream_host).toBe("api.venice.ai");
    expect(verified.signedPayload.length).toBeGreaterThan(0);
    // Absent `http`: framing "1.1" only; absent deposit: none.
    expect(verified.http).toEqual(["1.1"]);
    expect(verified.connection_deposit_msat).toBe(0);
  });

  it("rejects an offer signed by a different key than the pin (npub pin mismatch)", () => {
    const { offer } = signedOffer();
    const otherPin = bytesToHex(schnorr.getPublicKey(new Uint8Array(32).fill(3)));
    expect(() => verifyConfidentialOffer(offer, { pinnedPubkey: otherPin })).toThrow(
      OfferPinMismatchError,
    );
  });

  it("refuses an unpinned offer by default (review #16)", () => {
    const { offer } = signedOffer();
    expect(() => verifyConfidentialOffer(offer, {})).toThrow(OfferUnpinnedError);
  });

  it("accepts an unpinned offer only with the dev flag", () => {
    const verified = verifyConfidentialOffer(signedOffer().offer, {
      allowUnpinned: true,
      trustedHosts: ["*.venice.ai"],
    });
    expect(verified.v).toBe(3);
  });

  it("rejects a bad signature even when pinned", () => {
    const { offer } = signedOffer();
    (offer as Record<string, unknown>).sig_payload = (
      (offer as Record<string, unknown>).sig_payload as string
    ).replace("4096", "9999");
    expect(() =>
      verifyConfidentialOffer(offer, { pinnedPubkey: offer.notary_pubkey as string }),
    ).toThrow(OfferBadSignatureError);
  });

  it("rejects a protocol version above its own", () => {
    const { offer } = signedOffer({ v: 4, min_v: 4, max_v: 4 });
    expect(() => verifyConfidentialOffer(offer, { allowUnpinned: true })).toThrow(
      OfferUnsupportedVersionError,
    );
    expect(supportedVersion({ v: 4, min_v: 4, max_v: 4 } as never)).toBe(false);
    // Only v3 is supported; an offer must run v3.
    expect(supportedVersion({ v: 3 } as never)).toBe(true);
    expect(supportedVersion({ v: 3, min_v: 2, max_v: 3 } as never)).toBe(true);
    expect(supportedVersion({ v: 2, min_v: 2, max_v: 3 } as never)).toBe(false);
  });

  it("a node that offers an older protocol is outdated (v2, and the retired v1)", () => {
    for (const v of [1, 2]) {
      const { offer } = signedOffer({ v, min_v: v, max_v: v });
      expect(() => verifyConfidentialOffer(offer, { allowUnpinned: true })).toThrow(/node_protocol_outdated/);
      expect(() => verifyConfidentialOffer(offer, { allowUnpinned: true })).toThrow(NodeProtocolOutdatedError);
    }
    // Real (correctly signed) offers recorded from a v1 node and from a v2 node.
    for (const recorded of [OFFER_V1, OFFER]) {
      expect(() =>
        verifyConfidentialOffer(recorded, {
          pinnedPubkey: recorded.notary_pubkey as string,
          trustedHosts: ["*.venice.ai"],
        }),
      ).toThrow(NodeProtocolOutdatedError);
    }
  });

  it("refuses to build a connection for an offer of another version", () => {
    for (const v of [1, 2, 4]) {
      expect(
        () =>
          new ConfidentialConnection({
            baseUrl: "http://127.0.0.1:8010",
            offer: { v, notary_pubkey: "00".repeat(32) },
            auth: "sk-x",
            host: NO_HOST,
          } as never),
      ).toThrow(/unsupported protocol version/);
    }
  });

  it("rejects an offer whose version lies outside its own min_v..max_v", () => {
    expect(supportedVersion({ v: 3, min_v: 4, max_v: 4 } as never)).toBe(false);
    expect(supportedVersion({ v: 3, min_v: 2, max_v: 2 } as never)).toBe(false);
    for (const bad of [
      { v: 3, min_v: 4, max_v: 4 },
      { v: 3, min_v: 2, max_v: 2 },
      { v: 3, min_v: 4 },
      { v: 3.5, min_v: 3, max_v: 4 },
      { v: 3, min_v: "1", max_v: 3 },
    ]) {
      const { offer } = signedOffer(bad as never);
      expect(() => verifyConfidentialOffer(offer, { allowUnpinned: true })).toThrow(OfferMalformedError);
    }
  });

  it("enforces the trusted-host list when provided", () => {
    expect(() =>
      verifyConfidentialOffer(signedOffer().offer, {
        allowUnpinned: true,
        trustedHosts: ["other.example"],
      }),
    ).toThrow(TrustedHostError);
    expect(
      verifyConfidentialOffer(signedOffer().offer, {
        allowUnpinned: true,
        trustedHosts: ["*.venice.ai"],
      }).upstream_host,
    ).toBe("api.venice.ai");
  });
});

describe("canonical suffix", () => {
  it("is byte-exact with the sidecar's reconstruction", () => {
    expect(canonicalSuffix(VENICE_CHAT, "deepseek-v4-flash", 12)).toBe(
      ',"model":"deepseek-v4-flash","max_tokens":12,"max_completion_tokens":12,"n":1,' +
        '"stream":true,"stream_options":{"include_usage":true},' +
        '"venice_parameters":{"enable_web_search":"off","include_venice_system_prompt":false}}',
    );
  });

  it("JSON-escapes the model name", () => {
    expect(canonicalSuffix(VENICE_CHAT, 'a"b', 1)).toContain('"model":"a\\"b"');
  });
});

describe("trusted API routes", () => {
  it("an entry may name the API base; a bare host allows /v1 and /api/v1", () => {
    const m = new TrustedHostMatcher(["api.venice.ai", "api.groq.com/openai/v1"]);
    expect(m.apiBases("api.venice.ai")).toEqual(["/v1", "/api/v1"]);
    expect(m.apiBases("api.groq.com")).toEqual(["/openai/v1"]);
    expect(m.apiBases("other.example")).toEqual([]);
    expect(matchHostname("api.groq.com", "api.groq.com/openai/v1")).toBe(true);
    for (const bad of ["api.x.com/", "api.x.com/v1/", "api.x.com//v1", "api.x.com/v1/../x", "api.x.com/v%31"]) {
      expect(() => new TrustedHostMatcher([bad])).toThrow(/not a canonical path/);
    }
  });

  it("refuses an offer whose head route is not the trusted base plus the endpoint", () => {
    const tpl = (path: string) =>
      `POST ${path} HTTP/1.1\r\nHost: api.venice.ai\r\nAuthorization: Bearer {KEY:42}\r\n` +
      `Content-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {LEN}\r\n\r\n`;
    const verify = (path: string, trustedHosts: string[]) => {
      const { offer } = signedOffer({ head_template: tpl(path) });
      return () => verifyConfidentialOffer(offer, { allowUnpinned: true, trustedHosts });
    };
    expect(verify("/api/v1/chat/completions", ["api.venice.ai"])).not.toThrow();
    expect(verify("/v1/chat/completions", ["api.venice.ai"])).not.toThrow();
    expect(verify("/api/v1/chat/completions", ["api.venice.ai/api/v1"])).not.toThrow();
    // Another route of the same provider that merely ends in the endpoint.
    expect(verify("/proxy/other-tenant/chat/completions", ["api.venice.ai"])).toThrow(TrustedHostError);
    expect(verify("/api/v2/chat/completions", ["api.venice.ai"])).toThrow(/not one the trusted host allows/);
    // An explicit base allows only itself.
    expect(verify("/v1/chat/completions", ["api.venice.ai/api/v1"])).toThrow(TrustedHostError);
  });
});

describe("trusted hostname matcher", () => {
  it("normalizes case and a trailing dot", () => {
    expect(normalizeHostname("API.Venice.AI.")).toBe("api.venice.ai");
  });

  it("exact match", () => {
    expect(matchHostname("api.venice.ai", "api.venice.ai")).toBe(true);
    expect(matchHostname("api.venice.ai", "venice.ai")).toBe(false);
    expect(matchHostname("api.venice.ai", "api.venice.ai.")).toBe(true);
  });

  it("`*` matches exactly one label", () => {
    expect(matchHostname("a.example.com", "*.example.com")).toBe(true);
    expect(matchHostname("a.b.example.com", "*.example.com")).toBe(false);
    expect(matchHostname("example.com", "*.example.com")).toBe(false);
  });

  it("`**` matches one or more labels", () => {
    expect(matchHostname("a.example.com", "**.example.com")).toBe(true);
    expect(matchHostname("a.b.example.com", "**.example.com")).toBe(true);
    expect(matchHostname("example.com", "**.example.com")).toBe(false);
    expect(matchHostname("x.a.b.c.example.com", "**.example.com")).toBe(true);
  });

  it("`**` works in the middle", () => {
    expect(matchHostname("a.b.c.example.com", "a.**.example.com")).toBe(true);
    expect(matchHostname("a.example.com", "a.**.example.com")).toBe(false);
  });

  it("is case-insensitive end to end", () => {
    expect(matchHostname("API.Venice.AI", "*.venice.ai")).toBe(true);
  });

  it("empty list rejects everything", () => {
    const m = new TrustedHostMatcher([]);
    expect(m.isEmpty).toBe(true);
    expect(m.matches("api.venice.ai")).toBe(false);
  });

  it("rejects unsafe patterns", () => {
    expect(() => parseTrustedHostPattern("")).toThrow();
    expect(() => parseTrustedHostPattern("   ")).toThrow();
    expect(() => parseTrustedHostPattern("*")).toThrow();
    expect(() => parseTrustedHostPattern("**")).toThrow();
    expect(() => parseTrustedHostPattern("*foo.com")).toThrow();
    expect(() => parseTrustedHostPattern("foo*.com")).toThrow();
    expect(() => parseTrustedHostPattern("a..b")).toThrow();
    expect(() => parseTrustedHostPattern("http://x.com")).toThrow();
    expect(() => parseTrustedHostPattern("x.com:443")).toThrow();
    expect(() => parseTrustedHostPattern("a@b.com")).toThrow();
  });

  it("accepts a whole-label wildcard in the middle or at the end", () => {
    expect(matchHostname("api.eu.example.com", "api.*.example.com")).toBe(true);
    expect(matchHostname("api.example.com", "api.*.example.com")).toBe(false);
    expect(matchHostname("foo.any", "foo.*")).toBe(true);
  });
});

describe("response parsing + usage disclosure", () => {
  const headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n";
  const sse =
    'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n' +
    'data: {"choices":[],"model":"deepseek-v4-flash","usage":{"prompt_tokens":9,"completion_tokens":1}}\n\n' +
    "data: [DONE]\n\n";

  function chunked(body: string): Uint8Array {
    const enc = new TextEncoder();
    const b = enc.encode(body);
    const hex = b.length.toString(16);
    return enc.encode(`${hex}\r\n${body}\r\n0\r\n\r\n`);
  }

  it("splits status/headers/body", () => {
    const raw = new TextEncoder().encode(headers + "hello");
    const parsed = parseHttpResponse(raw);
    expect(parsed.status).toBe(200);
    expect(parsed.contentType).toBe("text/event-stream");
    expect(parsed.bodyText).toBe("hello");
  });

  it("locates the π_C3 disclosure window and parses the usage event", () => {
    const raw = new TextEncoder().encode(headers).slice();
    const chunkedBytes = chunked(sse);
    const joined = new Uint8Array(raw.length + chunkedBytes.length);
    joined.set(raw, 0);
    joined.set(chunkedBytes, raw.length);
    const r = extractUsageDisclosure(joined);
    expect(r).not.toBeNull();
    const usage = usageEventFromDisclosure(r!);
    expect(usage?.model).toBe("deepseek-v4-flash");
    expect(usage?.usage.prompt_tokens).toBe(9);
    expect(effectiveModelFromText(sse)).toBe("deepseek-v4-flash");
  });
});

describe("receipt verification", () => {
  const ownUsage = {
    model: "deepseek-v4-flash",
    usage: { prompt_tokens: 9, completion_tokens: 1 },
  };
  const base = { sid: "abc", model: "deepseek-v4-flash", usage: { ...ownUsage }, reserved_msats: 20000 };

  function signReceipt(receipt: Record<string, unknown>) {
    const { priv, pubHex } = makeKey();
    const payload = canonicalJson(receipt);
    const sig = bytesToHex(schnorr.sign(sha256(utf8ToBytes(payload)), priv));
    return { payload, sig, pubHex };
  }

  it("accepts a signed receipt with matching usage and a fair cost", () => {
    const receipt = { ...base, cost_msats: 10, balance_msats: 90000 };
    const { payload, sig, pubHex } = signReceipt(receipt);
    const res = verifyReceipt({
      receipt: receipt as never,
      receiptJson: payload,
      sig,
      pubkey: pubHex,
      ownUsage,
      priceEntry: { in: 1000, out: 1000 },
    });
    expect(res).toEqual({ receiptSigOk: true, usageMatch: true, costWithinOffer: true });
  });

  it("flags a cost above the usage at the signed offer's rates", () => {
    // 1000 msats/1k in+out, 9+1 tokens -> at most 10 msats.
    const res = verifyReceipt({
      receipt: { ...base, cost_msats: 15000 } as never,
      ownUsage,
      priceEntry: { in: 1000, out: 1000 },
    });
    expect(res.costWithinOffer).toBe(false);
  });

  it("refuses a receipt without a whole, non-negative cost", () => {
    for (const cost_msats of [undefined, -1, 1.5, Number.NaN]) {
      const res = verifyReceipt({
        receipt: { ...base, cost_msats } as never,
        ownUsage,
        priceEntry: { in: 1000, out: 1000 },
      });
      expect(res.costWithinOffer, String(cost_msats)).toBe(false);
    }
    expect(() => checkUpstreamErrorReceipt({ ...base, usage: { error_status: 400 } } as never, 400)).toThrow(
      ReceiptVerificationError,
    );
  });

  it("matches the cached-token count of the usage we saw", () => {
    const cached = { ...ownUsage, usage: { ...ownUsage.usage, prompt_tokens_details: { cached_tokens: 4 } } };
    const res = verifyReceipt({
      receipt: { ...base, cost_msats: 1 } as never,
      ownUsage: cached,
      priceEntry: { in: 1000, out: 1000 },
    });
    expect(res.usageMatch).toBe(false);
    const same = verifyReceipt({
      receipt: { ...base, usage: cached, cost_msats: 1 } as never,
      ownUsage: cached,
      priceEntry: { in: 1000, out: 1000 },
    });
    expect(same.usageMatch).toBe(true);
  });

  it("never refuses the node's cached-input charge for float rounding", () => {
    // The node bills ceil((in·(p−c) + min(cached_in,in)·c + out·k)/1000). With
    // cached_in = in that equals the uncached price mathematically, but in
    // floating point 1.1·9999 + 1.1·1 rounds above 11000: the node charges 12.
    const priceEntry = { in: 1.1, cached_in: 1.1, out: 0 };
    const usage = { prompt_tokens: 10000, completion_tokens: 0, prompt_tokens_details: { cached_tokens: 1 } };
    const node = Math.ceil((1.1 * (10000 - 1) + 1.1 * 1 + 0 * 0) / 1000);
    expect(node).toBe(12);
    expect(maxChargeMsats(priceEntry, usage)).toBe(12);
    // Without cached tokens the bound is unchanged.
    expect(maxChargeMsats(priceEntry, { prompt_tokens: 10000, completion_tokens: 0 })).toBe(11);
    // A cached rate above `in` is not honoured beyond `in`.
    expect(maxChargeMsats({ in: 1, cached_in: 5, out: 0 }, { ...usage, prompt_tokens: 1000 })).toBe(1);
    const own = { model: "m", usage } as never;
    const r = verifyReceipt({
      receipt: { sid: "s", model: "m", usage: { usage }, cost_msats: 12 } as never,
      ownUsage: own,
      priceEntry,
    });
    expect(r.costWithinOffer).toBe(true);
    // Prompt-cache writes at the signed cache_write rate (same vectors as the node).
    const rates = { in: 10_000, cached_in: 2_500, cache_write: 12_500, out: 100_000 };
    const venice = {
      prompt_tokens: 1000,
      completion_tokens: 8,
      prompt_tokens_details: { cached_tokens: 200, cache_creation_input_tokens: 600 },
      cache_creation_input_tokens: 600,
    };
    expect(maxChargeMsats(rates, venice)).toBe(10_800);
    expect(maxChargeMsats(rates, { ...venice, prompt_tokens_details: { cached_tokens: 200, cache_write_tokens: 600 } })).toBe(10_800);
    expect(maxChargeMsats(rates, { ...venice, prompt_tokens_details: { cached_tokens: 200 } })).toBe(10_800);
    // Writes above the uncached bound: 1000·12.5 + 8·100.
    const allWritten = { ...venice, prompt_tokens_details: { cache_creation_input_tokens: 1000 } };
    expect(maxChargeMsats(rates, allWritten)).toBe(13_300);
    // Without a signed cache_write rate the writes bound at `in` (the uncached formula).
    const { cache_write: _cw, ...old } = rates;
    expect(maxChargeMsats(old, allWritten)).toBe(10_800);
  });

  it("bounds a cached session at the cached price, not the uncached one", () => {
    // The node bills cached reads at cached_in from the same disclosed usage,
    // so the uncached price is no bound for a usage that reports them.
    const priceEntry = { in: 1900, cached_in: 380, cache_write: 1900, out: 7500 };
    const usage = { prompt_tokens: 50_000, completion_tokens: 200, prompt_tokens_details: { cached_tokens: 48_000 } };
    const honest = Math.ceil((1900 * 2000 + 380 * 48_000 + 7500 * 200) / 1000);
    const uncached = Math.ceil((1900 * 50_000 + 7500 * 200) / 1000);
    expect(honest).toBe(23_540);
    expect(uncached).toBe(96_500);
    expect(maxChargeMsats(priceEntry, usage)).toBe(honest);
    expect(maxChargeMsats(priceEntry, usage, 2000)).toBe(honest + 2000);
    const own = { model: "m", usage } as never;
    const check = (cost_msats: number) =>
      verifyReceipt({
        receipt: { sid: "s", model: "m", usage: { usage }, cost_msats } as never,
        ownUsage: own,
        priceEntry,
      }).costWithinOffer;
    expect(check(honest)).toBe(true);
    expect(check(honest + 1)).toBe(false);
    // The uncached price for a cached session is an overcharge.
    expect(check(uncached)).toBe(false);
    // Cache writes dearer than `in` raise the bound, exactly as the node bills them.
    const dear = { ...priceEntry, cache_write: 2375 };
    const writes = { ...usage, prompt_tokens_details: { cached_tokens: 48_000, cache_write_tokens: 1500 } };
    expect(maxChargeMsats(dear, writes)).toBe(
      Math.ceil((1900 * 500 + 380 * 48_000 + 2375 * 1500 + 7500 * 200) / 1000),
    );
    // Writes cheaper than `in`: a node that did not read the write count bills
    // them at `in`, which stays within the bound (still below the uncached price).
    const cheap = { ...priceEntry, cache_write: 950 };
    expect(maxChargeMsats(cheap, writes)).toBe(honest);
    // A usage without cached reads is bounded by the uncached price, as before.
    expect(maxChargeMsats(priceEntry, { prompt_tokens: 50_000, completion_tokens: 200 })).toBe(uncached);
  });

  it("the bound is the node's own charge for any plain usage (cache_write ≥ in)", () => {
    // routstr-core frozen_cost_msats, same operation order.
    const node = (
      r: { in: number; cached_in: number; cache_write?: number; out: number },
      prompt: number,
      cached: number,
      written: number,
      completion: number,
    ) => {
      const c = Math.min(Math.max(cached, 0), prompt);
      const w = Math.min(written, prompt - c);
      const cachedRate = Math.min(r.cached_in, r.in);
      const writeRate = r.cache_write ?? r.in;
      return Math.ceil((r.in * (prompt - c - w) + cachedRate * c + writeRate * w + r.out * completion) / 1000);
    };
    let seed = 12345;
    const rnd = (n: number) => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    for (let i = 0; i < 2000; i++) {
      const inRate = (1 + rnd(50_000)) / 7;
      const rates = {
        in: inRate,
        cached_in: inRate * (rnd(13) / 10),
        cache_write: inRate * (1 + rnd(6) / 4),
        out: (1 + rnd(200_000)) / 3,
      };
      const prompt = rnd(200_000);
      const cached = rnd(3) === 0 ? 0 : rnd(prompt + 50);
      const written = rnd(3) === 0 ? 0 : rnd(prompt + 50);
      const completion = rnd(8000);
      const usage = {
        prompt_tokens: prompt,
        completion_tokens: completion,
        prompt_tokens_details: { cached_tokens: cached, cache_write_tokens: written },
      };
      expect(maxChargeMsats(rates, usage), JSON.stringify({ rates, usage })).toBe(
        node(rates, prompt, cached, written, completion),
      );
    }
  });

  it("allows the signed session fee on top of the usage, never more", () => {
    // 10 msats of usage at the (already surcharged) signed rates + 2000 fee.
    const priceEntry = { in: 1000, out: 1000 };
    expect(maxChargeMsats(priceEntry, ownUsage.usage, 2000)).toBe(2010);
    const ok = verifyReceipt({
      receipt: { ...base, cost_msats: 2010, session_fee_msat: 2000 } as never,
      ownUsage,
      priceEntry,
      sessionFeeMsat: 2000,
    });
    expect(ok.costWithinOffer).toBe(true);
    const over = verifyReceipt({
      receipt: { ...base, cost_msats: 2011, session_fee_msat: 2000 } as never,
      ownUsage,
      priceEntry,
      sessionFeeMsat: 2000,
    });
    expect(over.costWithinOffer).toBe(false);
    // Without a signed fee the same charge is refused.
    const noFee = verifyReceipt({ receipt: { ...base, cost_msats: 2010 } as never, ownUsage, priceEntry });
    expect(noFee.costWithinOffer).toBe(false);
    // A receipt naming a larger fee than the signed one is refused.
    const bigger = verifyReceipt({
      receipt: { ...base, cost_msats: 10, session_fee_msat: 5000 } as never,
      ownUsage,
      priceEntry,
      sessionFeeMsat: 2000,
    });
    expect(bigger.costWithinOffer).toBe(false);
    // The abandon fee never applies to a completed request.
    const abandonCharged = verifyReceipt({
      receipt: { ...base, cost_msats: 10_010, session_fee_msat: 2000, abandon_fee_msat: 10_000 } as never,
      ownUsage,
      priceEntry,
      sessionFeeMsat: 2000,
      abandonFeeMsat: 10_000,
    });
    expect(abandonCharged.costWithinOffer).toBe(false);
    const biggerAbandon = verifyReceipt({
      receipt: { ...base, cost_msats: 10, abandon_fee_msat: 20_000 } as never,
      ownUsage,
      priceEntry,
      sessionFeeMsat: 2000,
      abandonFeeMsat: 10_000,
    });
    expect(biggerAbandon.costWithinOffer).toBe(false);
  });

  it("refuses any cost when the signed offer has no rate for the model", () => {
    // Without a price entry there is no bound to check against: a node that
    // signs an offer without the served model's rates gets no cost accepted.
    const res = verifyReceipt({ receipt: { ...base, cost_msats: 1 } as never, ownUsage });
    expect(res.costWithinOffer).toBe(false);
    const free = verifyReceipt({ receipt: { ...base, cost_msats: 0 } as never, ownUsage });
    expect(free.costWithinOffer).toBe(false);
  });

  it("allows at most the fee for a charge without usage (4xx/503, abandoned)", () => {
    expect(feeOnlyChargeOk(0, 0)).toBe(true);
    expect(feeOnlyChargeOk(1, 0)).toBe(false);
    expect(feeOnlyChargeOk(2000, 2000)).toBe(true);
    expect(feeOnlyChargeOk(2001, 2000)).toBe(false);
  });

  it("bounds the charge for an upstream error receipt", () => {
    const err = (status: unknown, extra: Record<string, unknown> = {}) =>
      ({ sid: "s1", model: "m", usage: { error_status: status }, ...extra }) as never;
    // 4xx / 503: at most the session fee.
    expect(checkUpstreamErrorReceipt(err(429, { cost_msats: 0 }), 429, 0)).toBe(true);
    expect(checkUpstreamErrorReceipt(err(503, { cost_msats: 2000 }), 503, 2000)).toBe(true);
    expect(() => checkUpstreamErrorReceipt(err(503, { cost_msats: 2001, reserved_msats: 9000 }), 503, 2000)).toThrow(
      ReceiptVerificationError,
    );
    // Other 5xx: at most the reservation the receipt names, and a bound known before the release.
    const known = { reservationMsat: 9000 };
    expect(checkUpstreamErrorReceipt(err(500, { cost_msats: 9000, reserved_msats: 9000 }), 500, 0, known)).toBe(true);
    expect(() => checkUpstreamErrorReceipt(err(500, { cost_msats: 9000, reserved_msats: 9000 }), 500, 0)).toThrow(
      /no reservation bound/,
    );
    expect(() => checkUpstreamErrorReceipt(err(500, { cost_msats: 9001, reserved_msats: 9000 }), 500, 0, known)).toThrow(
      /reservation/,
    );
    expect(() => checkUpstreamErrorReceipt(err(502, { cost_msats: 1e12 }), 502, 0)).toThrow(/reservation/);
    expect(checkUpstreamErrorReceipt(err(504, { cost_msats: 500 }), 504, 500)).toBe(true);
    expect(() => checkUpstreamErrorReceipt(err(500, { cost_msats: -1, reserved_msats: 9000 }), 500, 0)).toThrow(
      ReceiptVerificationError,
    );
    expect(() =>
      checkUpstreamErrorReceipt(err(500, { cost_msats: 10, reserved_msats: 9000, session_fee_msat: 5 }), 500, 0),
    ).toThrow(/session fee/);
    // The status must be the one we saw, as a number.
    expect(checkUpstreamErrorReceipt(err("500", { cost_msats: 0 }), 500, 0)).toBe(false);
    expect(checkUpstreamErrorReceipt(err(502, { cost_msats: 0 }), 500, 0)).toBe(false);
  });

  it("flags a usage mismatch", () => {
    const receipt = {
      ...base,
      usage: { model: "deepseek-v4-flash", usage: { prompt_tokens: 999, completion_tokens: 1 } },
      cost_msats: 14,
    };
    const { payload, sig, pubHex } = signReceipt(receipt);
    const res = verifyReceipt({ receipt: receipt as never, receiptJson: payload, sig, pubkey: pubHex, ownUsage });
    expect(res.usageMatch).toBe(false);
    expect(res.receiptSigOk).toBe(true);
  });

  it("flags a bad receipt signature", () => {
    const receipt = { ...base, cost_msats: 14 };
    const res = verifyReceipt({
      receipt: receipt as never,
      receiptJson: canonicalJson(receipt),
      sig: "00".repeat(64),
      pubkey: bytesToHex(schnorr.getPublicKey(new Uint8Array(32).fill(7))),
      ownUsage,
    });
    expect(res.receiptSigOk).toBe(false);
  });
});

describe("usage disclosure window", () => {
  const usage = '{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":2},"model":"m"}';
  const head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
  const chunk = (d: string) => `${Buffer.byteLength(d).toString(16)}\r\n${d}\r\n`;

  it("starts at the usage event's line when the stream ends in one large chunk", () => {
    const events = Array.from({ length: 400 }, (_, i) => `data: {"choices":[{"delta":{"content":"tok${i}"}}]}\n\n`).join("");
    const big = chunk(`${events}data: ${usage}\n\ndata: [DONE]\n\n`);
    const resp = new TextEncoder().encode(`${head}${chunk("data: {}\n\n")}${big}0\r\n\r\n`);
    const r = extractUsageDisclosure(resp)!;
    const text = new TextDecoder().decode(r);
    expect(text.startsWith(`\ndata: ${usage}`)).toBe(true);
    expect(r.length).toBeLessThan(200);
    expect(usageEventFromDisclosure(r)?.usage.completion_tokens).toBe(2);
  });

  it("still uses a chunk boundary when the usage event starts its own chunk", () => {
    const resp = new TextEncoder().encode(
      `${head}${chunk("data: {}\n\n")}${chunk(`data: ${usage}\n\n`)}${chunk("data: [DONE]\n\n")}0\r\n\r\n`,
    );
    const r = extractUsageDisclosure(resp)!;
    expect(usageEventFromDisclosure(r)?.model).toBe("m");
    expect(r.length).toBeLessThan(140);
  });
});

describe("HTTP response decoding", () => {
  const enc = (s: string) => new TextEncoder().encode(s);
  const dec = (parts: Uint8Array[]) => parts.map((p) => new TextDecoder().decode(p)).join("");
  const raw =
    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n" +
    "6\r\ndata: \r\n" + "9\r\n{\"x\":1}\n\n\r\n" + "0\r\n\r\n";

  it("parseHttpResponse de-chunks a chunked body", () => {
    const r = parseHttp(enc(raw));
    expect(r.status).toBe(200);
    expect(r.bodyText).toBe('data: {"x":1}\n\n');
  });

  it("streams the same body byte by byte", () => {
    const inc = new IncrementalHttpResponse();
    const out: Uint8Array[] = [];
    for (const b of enc(raw)) out.push(...inc.push(new Uint8Array([b])));
    expect(inc.head?.status).toBe(200);
    expect(dec(out)).toBe('data: {"x":1}\n\n');
    expect(inc.complete).toBe(true);
  });

  it("rejects a malformed chunk size", () => {
    expect(() => new ChunkedDecoder().push(enc("zz\r\nhello\r\n"))).toThrow();
  });
});

describe("confidential session fee and surcharge in the offer", () => {
  const shape = {
    v: 3,
    upstream_host: "api.venice.ai",
    notary_pubkey: "ab".repeat(32),
    max_tokens_cap: 4096,
    key_length: 42,
    head_template: "POST /",
    suffix_keys: ["model", "max_tokens", "max_completion_tokens", "n", "stream", "stream_options", "venice_parameters"],
    chat: VENICE_CHAT,
    price_list: {},
  };

  it("refuses suffix_keys other than the ones the chat block pins", () => {
    for (const keys of [[], ["model", "max_tokens", "stream"], [...shape.suffix_keys].reverse()]) {
      expect(() => validateOfferShape({ ...shape, suffix_keys: keys })).toThrow(/suffix_keys/);
    }
  });

  it("refuses an offer without a chat block", () => {
    const { chat: _chat, ...noChat } = shape;
    expect(() => validateOfferShape(noChat)).toThrow(/chat/);
  });

  it("accepts absent or valid pricing fields and reads the fee", () => {
    validateOfferShape({ ...shape });
    validateOfferShape({ ...shape, session_fee_msat: 2000, abandon_fee_msat: 10000, rate_surcharge_pct: 20 });
    expect(offerSessionFeeMsat({})).toBe(0);
    expect(offerSessionFeeMsat({ session_fee_msat: 2000 })).toBe(2000);
    // The abandon fee is never below the session fee.
    expect(offerAbandonFeeMsat({})).toBe(0);
    expect(offerAbandonFeeMsat({ session_fee_msat: 2000 })).toBe(2000);
    expect(offerAbandonFeeMsat({ session_fee_msat: 2000, abandon_fee_msat: 10000 })).toBe(10000);
    expect(offerAbandonFeeMsat({ session_fee_msat: 2000, abandon_fee_msat: 500 })).toBe(2000);
  });

  it("rejects malformed pricing fields", () => {
    for (const bad of [-1, 1.5, "2000", Number.NaN]) {
      expect(() => validateOfferShape({ ...shape, session_fee_msat: bad })).toThrow();
    }
    for (const bad of [-1, 2.5, "10"]) {
      expect(() => validateOfferShape({ ...shape, abandon_fee_msat: bad })).toThrow();
    }
    for (const bad of [-1, "20", Number.POSITIVE_INFINITY]) {
      expect(() => validateOfferShape({ ...shape, rate_surcharge_pct: bad })).toThrow();
    }
  });

  it("rejects a malformed token cap or price entry", () => {
    for (const bad of [0, -5, 1.5, Number.NaN, "4096"]) {
      expect(() => validateOfferShape({ ...shape, max_tokens_cap: bad })).toThrow(/max_tokens_cap/);
    }
    validateOfferShape({ ...shape, price_list: { m: { in: 1.1, out: 2, cached_in: 0.5 } } });
    for (const bad of [null, 5, { in: 1 }, { in: "1", out: 1 }, { in: 1, out: -1 }, { in: 1, out: 1, cached_in: "x" }]) {
      expect(() => validateOfferShape({ ...shape, price_list: { m: bad } })).toThrow(/price_list/);
    }
  });
});

describe("connection construction guards", () => {
  const opts = (extra: Record<string, unknown> = {}) =>
    ({
      baseUrl: "http://127.0.0.1:8010",
      offer: { v: 3, notary_pubkey: "00".repeat(32), chat: VENICE_CHAT, suffix_keys: chatSuffixKeys(VENICE_CHAT) },
      auth: "sk-x",
      host: NO_HOST,
      ...extra,
    }) as never;

  it("refuses a session announced under another key before the 2PC starts", async () => {
    const realWs = (globalThis as any).WebSocket;
    (globalThis as any).WebSocket = class {
      onopen?: () => void;
      onmessage?: (ev: { data: string }) => void;
      onclose?: () => void;
      onerror?: () => void;
      constructor() {
        setTimeout(() => this.onopen?.(), 0);
      }
      send() {
        setTimeout(() => this.onmessage?.({ data: JSON.stringify({ type: "ready", v: 3, http: "1.1", sid: "ab".repeat(32), pubkey: "11".repeat(32) }) }), 0);
      }
      close() {}
    };
    let twoPcStarted = 0;
    try {
      const session = new ConfidentialConnection(
        opts({
          host: NO_HOST,
          twoPcFactory: () => {
            twoPcStarted++;
            throw new Error("2PC started");
          },
        }),
      );
      await expect(session.arm()).rejects.toThrow(/differs from the signed offer key/);
      expect(twoPcStarted).toBe(0);
    } finally {
      (globalThis as any).WebSocket = realWs;
    }
  });

  it("refuses a plain-http remote node", () => {
    expect(() => new ConfidentialConnection(opts({ baseUrl: "http://node.example" }))).toThrow(/plain http/);
    expect(() =>
      new ConfidentialConnection(opts({ baseUrl: "http://node.example", allowInsecureTransport: true })),
    ).not.toThrow();
  });
});
