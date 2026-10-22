import { describe, expect, it } from "vitest";
import { canonicalJson, npubToHex, verifySchnorrSignature } from "../src/canonical.js";
import {
  OfferBadSignatureError,
  OfferMalformedError,
  OfferPinMismatchError,
  OfferUnpinnedError,
  OfferUnsupportedVersionError,
  TrustedHostError,
} from "../src/errors.js";
import {
  fetchConfidentialOffer,
  offerAbandonFeeMsat,
  offerSessionFeeMsat,
  validateOfferShape,
  verifyConfidentialOffer,
} from "../src/offer.js";
import { makeKey, sign, signedOffer } from "./helpers.js";
import prod from "./fixtures/cypherpunk-offer.json";

const PROD_PUBKEY = "2ca46ee98f3134c4e11a638663a45983b590bfdefd31588f9c2f03455fba15e7";
const HOSTS = ["api.venice.ai"];

describe("canonical JSON + BIP-340", () => {
  it("serializes with sorted keys and no whitespace", () => {
    expect(canonicalJson({ b: 1, a: [2, { d: 1, c: "x" }] })).toBe('{"a":[2,{"c":"x","d":1}],"b":1}');
  });
  it("verifies a good signature and rejects tampering / wrong key", () => {
    const { priv, pubHex } = makeKey();
    const sig = sign('{"x":1}', priv);
    expect(verifySchnorrSignature('{"x":1}', sig, pubHex)).toBe(true);
    expect(verifySchnorrSignature('{"x":2}', sig, pubHex)).toBe(false);
    expect(verifySchnorrSignature('{"x":1}', sig, makeKey(9).pubHex)).toBe(false);
    expect(verifySchnorrSignature('{"x":1}', undefined, pubHex)).toBe(false);
  });
  it("decodes npub and passes hex through", () => {
    expect(npubToHex(PROD_PUBKEY)).toBe(PROD_PUBKEY);
    expect(npubToHex("not-a-key")).toBeNull();
  });
});

describe("offer verification", () => {
  it("accepts the production node's signed offer under its pinned key", () => {
    const o = verifyConfidentialOffer(prod, { pinnedPubkeys: [PROD_PUBKEY], trustedHosts: HOSTS });
    expect(o.v).toBe(2);
    expect(o.upstream_host).toBe("api.venice.ai");
    expect(Object.keys(o.price_list).length).toBeGreaterThan(0);
  });

  it("rejects the production offer under another pin or untrusted host", () => {
    expect(() =>
      verifyConfidentialOffer(prod, { pinnedPubkeys: [makeKey().pubHex], trustedHosts: HOSTS }),
    ).toThrow(OfferPinMismatchError);
    expect(() =>
      verifyConfidentialOffer(prod, { pinnedPubkeys: [PROD_PUBKEY], trustedHosts: ["api.openai.com"] }),
    ).toThrow(TrustedHostError);
    expect(() => verifyConfidentialOffer(prod, { pinnedPubkeys: [PROD_PUBKEY] })).toThrow(TrustedHostError);
  });

  it("uses the signed payload, not the envelope", () => {
    const tampered = { ...(prod as Record<string, unknown>), upstream_host: "evil.example", price_list: {} };
    const o = verifyConfidentialOffer(tampered, { pinnedPubkeys: [PROD_PUBKEY], trustedHosts: HOSTS });
    expect(o.upstream_host).toBe("api.venice.ai");
    expect(Object.keys(o.price_list).length).toBeGreaterThan(0);
  });

  it("rejects a tampered signed payload", () => {
    const p = prod as Record<string, unknown>;
    const bad = { ...p, sig_payload: String(p.sig_payload).replace('"in":', '"in":0.5+') };
    expect(() => verifyConfidentialOffer(bad, { pinnedPubkeys: [PROD_PUBKEY], trustedHosts: HOSTS })).toThrow();
    const { offer, pubHex } = signedOffer();
    const forged = { ...offer, sig_payload: (offer.sig_payload as string).replace('"cheap"', '"cheaper"') };
    expect(() => verifyConfidentialOffer(forged, { pinnedPubkeys: [pubHex], trustedHosts: HOSTS })).toThrow(
      OfferBadSignatureError,
    );
  });

  it("refuses unpinned offers", () => {
    const { offer } = signedOffer();
    expect(() => verifyConfidentialOffer(offer, { trustedHosts: HOSTS })).toThrow(OfferUnpinnedError);
  });

  it("speaks v2 only (the browser has no v1 path)", () => {
    const { offer, pubHex } = signedOffer({ v: 1, min_v: 1, max_v: 1 });
    expect(() => verifyConfidentialOffer(offer, { pinnedPubkeys: [pubHex], trustedHosts: HOSTS })).toThrow(
      OfferUnsupportedVersionError,
    );
  });

  it("rejects an offer whose version lies outside its own min_v..max_v", () => {
    for (const bad of [
      { v: 2, min_v: 3, max_v: 3 },
      { v: 2, min_v: 1, max_v: 1 },
      { v: 2.5, min_v: 2, max_v: 3 },
    ]) {
      const { offer, pubHex } = signedOffer(bad);
      expect(() => verifyConfidentialOffer(offer, { pinnedPubkeys: [pubHex], trustedHosts: HOSTS })).toThrow(
        OfferMalformedError,
      );
    }
  });

  it("reads optional fee fields and rejects malformed ones", () => {
    const { offer, pubHex } = signedOffer({ session_fee_msat: 2000, abandon_fee_msat: 5000, rate_surcharge_pct: 10 });
    const o = verifyConfidentialOffer(offer, { pinnedPubkeys: [pubHex], trustedHosts: HOSTS });
    expect(offerSessionFeeMsat(o)).toBe(2000);
    expect(offerAbandonFeeMsat(o)).toBe(5000);
    expect(offerAbandonFeeMsat({ session_fee_msat: 2000, abandon_fee_msat: 1 })).toBe(2000);
    const shape = { ...offer };
    for (const bad of [-1, 1.5, "10"]) {
      expect(() => validateOfferShape({ ...shape, session_fee_msat: bad })).toThrow(OfferMalformedError);
    }
    // suffix_keys must be exactly the keys the chat block pins, and the block is required.
    const { chat: _chat, ...noChat } = shape as Record<string, unknown>;
    expect(() => validateOfferShape(noChat)).toThrow(/chat/);
    for (const keys of [[], ["model", "max_tokens", "stream"], ["venice_parameters", "stream_options", "stream", "n", "max_completion_tokens", "max_tokens", "model"]]) {
      expect(() => validateOfferShape({ ...shape, suffix_keys: keys })).toThrow(/suffix_keys/);
    }
    // Unknown extra fields are tolerated.
    const extra = signedOffer({ some_future_field: { x: 1 } });
    expect(() =>
      verifyConfidentialOffer(extra.offer, { pinnedPubkeys: [extra.pubHex], trustedHosts: HOSTS }),
    ).not.toThrow();
  });

  it("fetches through an injected fetch", async () => {
    const o = await fetchConfidentialOffer("https://node.example/", {
      pinnedPubkeys: [PROD_PUBKEY],
      trustedHosts: HOSTS,
      fetchImpl: (async (url: string) => {
        expect(url).toBe("https://node.example/v1/confidential/offer");
        return new Response(JSON.stringify(prod));
      }) as unknown as typeof fetch,
    });
    expect(o.notary_pubkey).toBe(PROD_PUBKEY);
  });
});

describe("trusted API routes", () => {
  const tpl = (path: string) =>
    `POST ${path} HTTP/1.1\r\nHost: api.venice.ai\r\nAuthorization: Bearer {KEY:63}\r\n` +
    `Content-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {LEN}\r\n\r\n`;
  const verify = (path: string, trustedHosts: string[], extra: Record<string, unknown> = {}) => {
    const { offer, pubHex } = signedOffer({ head_template: tpl(path), ...extra });
    return () => verifyConfidentialOffer(offer, { pinnedPubkeys: [pubHex], trustedHosts });
  };

  it("takes the trusted base plus the endpoint, nothing else", () => {
    expect(verify("/api/v1/chat/completions", HOSTS)).not.toThrow();
    expect(verify("/v1/chat/completions", HOSTS)).not.toThrow();
    expect(verify("/api/v1/chat/completions", ["api.venice.ai/api/v1"])).not.toThrow();
    expect(verify("/proxy/other-tenant/chat/completions", HOSTS)).toThrow(TrustedHostError);
    expect(verify("/v1/chat/completions", ["api.venice.ai/api/v1"])).toThrow(/not one the trusted host allows/);
  });

  it("refuses a chat head template outside the head syntax before any setup", () => {
    const head = (headers: string) => `POST /api/v1/chat/completions HTTP/1.1\r\n${headers}\r\n\r\n`;
    const std = [
      "Host: api.venice.ai",
      "Authorization: Bearer {KEY:63}",
      "Content-Type: application/json",
      "Accept-Encoding: identity",
      "Connection: close",
      "Content-Length: {LEN}",
    ];
    const check = (headers: string[]) => {
      const { offer, pubHex } = signedOffer({ head_template: head(headers.join("\r\n")) });
      return () => verifyConfidentialOffer(offer, { pinnedPubkeys: [pubHex], trustedHosts: HOSTS });
    };
    expect(check(std)).not.toThrow();
    for (const bad of [
      std.filter((h) => !h.startsWith("Content-Type")),
      [...std, "X-Store: 1"],
      std.map((h) => (h.startsWith("Connection") ? "Connection : close" : h)),
      std.map((h) => (h.startsWith("Connection") ? "Connection: close\nX-Store: 1" : h)),
      std.map((h) => (h.startsWith("Authorization") ? "Authorization: Token {KEY:63}" : h)),
      std.map((h) => (h.startsWith("Host") ? "Host: api.other.example" : h)),
    ]) {
      expect(check(bad)).toThrow(OfferMalformedError);
    }
  });

  it("turns images off when only their route is not trusted", () => {
    const images = { ...(prod as never as { images?: Record<string, unknown> }).images, head_template: tpl("/x/image/generate") };
    const o = verify("/api/v1/chat/completions", HOSTS, { capabilities: ["chat", "images"], images })();
    expect(o.images).toBeUndefined();
  });
});

