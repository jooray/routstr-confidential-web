/**
 * The prompt limit a node signs per model (`context_lengths`): the reservation
 * ceiling is sized only by it, the reservation shown and checked before a
 * request prefers it over the model list's row (which may be another
 * upstream's), and the offer check refuses a malformed one (ported from
 * routstr-sdk tests/unit/confidential-context-lengths.test.ts).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { contextLengthsProblem, validateOfferShape, verifyConfidentialOffer, type VerifiedOffer } from "../src/offer.js";
import type { NodeModel } from "../src/node-api.js";
import { modelPricing, reservationCeilingMsat, reservationMsat } from "../src/pricing.js";
import { BOTH, NODE_PUB, restoreFetch, signedV3Offer, v3OfferFields } from "./fixtures/v3.js";

const verified = (extra: Record<string, unknown> = {}): VerifiedOffer =>
  verifyConfidentialOffer(signedV3Offer(extra), { pinnedPubkeys: [NODE_PUB], trustedHosts: ["*.venice.ai"] });
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
  ({ id: "m", context_length: 131072, sats_pricing: { max_cost: 20 }, ...extra }) as unknown as NodeModel;
// What the node reserves for 100 completion tokens with a prompt limit of `limit`.
const nodeReserves = (limit: number) => Math.ceil((limit * 1000 + 116 * 2000) / 1000) + 300;

afterEach(() => {
  vi.restoreAllMocks();
  restoreFetch();
});

describe("the signed context length", () => {
  it("sizes the ceiling, not the model list's row (another upstream's, smaller)", () => {
    const o = offer({ context_lengths: { m: 262144 } });
    expect(reservationCeilingMsat(o, "m", model(), 100)).toBe(nodeReserves(262144));
    // Without the model list at all.
    expect(reservationCeilingMsat(o, "m", undefined, 100)).toBe(nodeReserves(262144));
  });

  it("without it there is no ceiling, whatever the model list says", () => {
    expect(reservationCeilingMsat(offer(), "m", model(), 100)).toBeUndefined();
  });

  it("is preferred for the reservation and the balance a request needs; the list's row is the fallback", () => {
    const o = offer({ context_lengths: { m: 262144 } });
    expect(reservationMsat(o, o.price_list.m!, model(), 100)).toBe(nodeReserves(262144));
    expect(reservationMsat(offer(), offer().price_list.m!, model(), 100)).toBe(nodeReserves(131072));
    const [p] = modelPricing(o, [model()], 100);
    expect(p!.promptLimit).toBe(262144);
    expect(p!.reservationMsat).toBe(nodeReserves(262144));
    expect(p!.requiredMsat).toBe(nodeReserves(262144) + 2000);
  });

  it("is validated with the offer: optional, else positive safe integers for priced ids", () => {
    const priced = { ...BOTH, price_list: { cheap: { in: 1000, cached_in: 1000, out: 1000 } } };
    expect(() => validateOfferShape(v3OfferFields(priced))).not.toThrow();
    expect(() => validateOfferShape(v3OfferFields({ ...priced, context_lengths: { cheap: 131072 } }))).not.toThrow();
    expect(() => validateOfferShape(v3OfferFields({ ...priced, context_lengths: {} }))).not.toThrow();
    for (const bad of [[], "x", null, 7, [131072], { cheap: 0 }, { cheap: -1 }, { cheap: 1.5 }, { cheap: "131072" }, { cheap: 2 ** 53 }, { cheap: null }, { other: 131072 }]) {
      expect(contextLengthsProblem({ price_list: priced.price_list, context_lengths: bad })).toBeDefined();
      expect(() => validateOfferShape(v3OfferFields({ ...priced, context_lengths: bad }))).toThrow(/context_lengths/);
    }
  });
});
