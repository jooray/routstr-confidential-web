/**
 * Price display and checks from the *signed* offer (msat per 1k tokens) and
 * the node's model list (context length). Tolerant of extra offer fields: a
 * node may add a flat `session_fee_msat` and a `rate_surcharge_pct` (already
 * folded into the price list); both are read when present.
 */

import { offerAbandonFeeMsat, offerSessionFeeMsat, type ConfidentialPriceEntry, type VerifiedOffer } from "./offer.js";
import type { NodeModel } from "./node-api.js";

export interface ModelPricing {
  id: string;
  name?: string;
  contextLength?: number;
  /** The prompt limit the node reserves for (context − max completion), when known. */
  promptLimit?: number;
  rates: ConfidentialPriceEntry;
  sessionFeeMsat: number;
  /** Kept by the node when an armed (pre-warmed) session is never used. */
  abandonFeeMsat: number;
  rateSurchargePct: number;
  /**
   * Reservation the node holds while a session for `maxTokens` is open (msat):
   * a full-context prompt plus `maxTokens` at the signed rates, plus the
   * larger of the session and abandon fees. The key needs at least this
   * available balance; the unused part is released at settlement.
   */
  reservationMsat?: number;
  maxTokens: number;
}

/**
 * The prompt size the node reserves for. Conservative: the model's full
 * context length. (routstr-core's `prompt_token_limit` may subtract the
 * provider's max completion tokens, but deployed nodes have been seen to
 * reserve on the full context; over-estimating only shows a higher required
 * balance, under-estimating would surprise the user with a 402.)
 */
export function promptLimit(m: NodeModel | undefined): number | undefined {
  if (!m) return undefined;
  const cl = Math.max(m.top_provider?.context_length ?? 0, m.context_length ?? 0);
  return cl > 0 ? cl : undefined;
}

export function sessionFeeMsat(offer: VerifiedOffer): number {
  return offerSessionFeeMsat(offer);
}

/** msat for a usage at the signed rates (+ the session fee), as the node computes it. */
export function costMsat(
  rates: ConfidentialPriceEntry,
  usage: { prompt_tokens: number; completion_tokens: number; cached_tokens?: number },
  feeMsat = 0,
): number {
  const cached = Math.min(Math.max(usage.cached_tokens ?? 0, 0), usage.prompt_tokens);
  const cachedRate = Math.min(rates.cached_in ?? rates.in, rates.in);
  return (
    Math.ceil(
      (rates.in * (usage.prompt_tokens - cached) + cachedRate * cached + rates.out * usage.completion_tokens) / 1000,
    ) + feeMsat
  );
}

export function modelPricing(offer: VerifiedOffer, models: NodeModel[], maxTokens: number): ModelPricing[] {
  const byId = new Map(models.map((m) => [m.id, m]));
  const fee = sessionFeeMsat(offer);
  const pct = typeof offer.rate_surcharge_pct === "number" ? offer.rate_surcharge_pct : 0;
  return Object.entries(offer.price_list)
    .map(([id, rates]) => {
      const m = byId.get(id);
      const limit = promptLimit(m);
      const mt = Math.min(maxTokens, offer.max_tokens_cap);
      return {
        id,
        name: m?.name,
        contextLength: m?.context_length,
        promptLimit: limit,
        rates,
        sessionFeeMsat: fee,
        abandonFeeMsat: offerAbandonFeeMsat(offer),
        rateSurchargePct: pct,
        maxTokens: mt,
        reservationMsat:
          limit !== undefined
            ? Math.ceil((limit * rates.in + mt * rates.out) / 1000) + Math.max(fee, offerAbandonFeeMsat(offer))
            : undefined,
      };
    })
    .sort((a, b) => a.id.localeCompare(b.id));
}

/** Rough token count of a text for estimates (~4 characters per token). */
export function roughTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

export function formatSats(msat: number): string {
  const sats = msat / 1000;
  if (sats >= 100) return `${Math.round(sats).toLocaleString()} sat`;
  if (sats >= 1) return `${sats.toFixed(1)} sat`;
  return `${sats.toFixed(3)} sat`;
}
