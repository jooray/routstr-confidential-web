import { describe, expect, it } from "vitest";
import { canonicalJson, npubToHex, verifySchnorrSignature } from "../src/canonical";
import {
  OfferBadSignatureError,
  OfferMalformedError,
  OfferPinMismatchError,
  OfferUnpinnedError,
  OfferUnsupportedVersionError,
  TrustedHostError,
} from "../src/errors";
import {
  fetchConfidentialOffer,
  offerAbandonFeeMsat,
  offerSessionFeeMsat,
  validateOfferShape,
  verifyConfidentialOffer,
} from "../src/offer";
import { makeKey, sign, signedOffer } from "./helpers";
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
