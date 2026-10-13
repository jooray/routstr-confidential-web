/**
 * Price display and checks from the *signed* offer (msat per 1k tokens) and
 * the node's model list (context length). Tolerant of extra offer fields: a
 * node may add a flat `session_fee_msat` and a `rate_surcharge_pct` (already
 * folded into the price list); both are read when present.
 */

import {
  offerAbandonFeeMsat,
  offerReserveMarginTokens,
  offerSessionFeeMsat,
  type ConfidentialPriceEntry, type VerifiedOffer } from "./offer.js";
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
   * a full-context prompt plus `maxTokens` and the offer's
   * `reserve_margin_tokens` at the signed rates, plus the larger of the
   * session and abandon fees. Without a context length: the model's maximum
   * cost (`sats_pricing.max_cost`) raised by the rate surcharge, plus the
   * margin at the signed completion rate, plus the same fee. Undefined when
   * neither is known. The key needs at least this available balance; the
   * unused part is released at settlement.
   */
  reservationMsat?: number;
  maxTokens: number;
}

/**
 * The prompt size the node reserves for: the model's full context length,
 * taken as the node does, the first positive integer of
 * `top_provider.context_length` and `context_length`, in that order.
 * Undefined when neither is one (the node then reserves the model's maximum
 * cost instead).
 */
export function promptLimit(m: NodeModel | undefined): number | undefined {
  if (!m) return undefined;
  return [m.top_provider?.context_length, m.context_length].find(
    (cl): cl is number => typeof cl === "number" && Number.isSafeInteger(cl) && cl > 0,
  );
}

/** The model's undiscounted maximum cost in sats, from the node's model list. */
function maxCostSats(m: NodeModel | undefined): number | undefined {
  const v: unknown = m?.sats_pricing?.max_cost;
  return typeof v === "number" && Number.isFinite(v) && v > 0 ? v : undefined;
}

/**
 * The reservation (msat) the node holds for a session on `m` with a pinned
 * completion cap of `maxTokens`, as routstr-core's confidential `reserve()`
 * computes it. See `ModelPricing.reservationMsat`.
 */
export function reservationMsat(
  offer: VerifiedOffer,
  rates: ConfidentialPriceEntry,
  m: NodeModel | undefined,
  maxTokens: number,
): number | undefined {
  const fee = Math.max(sessionFeeMsat(offer), offerAbandonFeeMsat(offer));
  const margin = offerReserveMarginTokens(offer);
  const limit = promptLimit(m);
  if (limit !== undefined) {
    return Math.ceil((limit * rates.in + (maxTokens + margin) * rates.out) / 1000) + fee;
  }
  const maxCost = maxCostSats(m);
  if (maxCost === undefined) return undefined;
  const pct = surchargePct(offer);
  return Math.ceil(Math.ceil(maxCost * 1000) * (1 + pct / 100) + (margin * rates.out) / 1000) + fee;
}

function surchargePct(offer: VerifiedOffer): number {
  const v = offer.rate_surcharge_pct;
  return typeof v === "number" && Number.isFinite(v) && v > 0 ? v : 0;
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
  const pct = surchargePct(offer);
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
        reservationMsat: reservationMsat(offer, rates, m, mt),
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
