/**
 * The node's confidential-upstream offer: fetch, signature + pin verification,
 * version negotiation.
 *
 * Security model (review #16): a signature is only authenticity if the verifier
 * pins *who* may sign. `verifyConfidentialOffer` therefore requires either an
 * explicit `pinnedPubkey` (hex or npub, e.g. the node's Nostr key from its
 * NIP-91 announcement, which routstrd discovery already resolved) or the
 * explicit dev flag `allowUnpinned`. Without either, the offer is rejected —
 * self-consistency is not trust.
 */

import {
  canonicalJson,
  npubToHex,
  verifySchnorrSignature,
} from "./canonical.js";
import { TrustedHostMatcher } from "./hosts.js";
import { checkHeadTemplate, headRouteProblem } from "./params.js";
import {
  OfferBadSignatureError,
  OfferMalformedError,
  OfferPinMismatchError,
  OfferUnavailableError,
  OfferUnpinnedError,
  OfferUnsupportedVersionError,
  TrustedHostError,
} from "./errors.js";
import { type ChatSuffixSpec, pinKeyProblem, validateChatSuffix } from "./suffix.js";

/** Protocol versions this client speaks. */
/** The browser client implements only protocol v2 (two-party handshake). */
export const CONFIDENTIAL_VERSION_MIN = 2;
export const CONFIDENTIAL_VERSION_MAX = 2;

export interface ConfidentialPriceEntry {
  /** msats per 1k input tokens. */
  in: number;
  /** msats per 1k cached input tokens. */
  cached_in?: number;
  /** msats per 1k prompt tokens written to the provider's prompt cache. */
  cache_write?: number;
  /** msats per 1k output tokens. */
  out: number;
}

/** A JSON key/value pinned in the image suffix, as `[key, value]`. */
export type ImagePin = [string, unknown];

/** One priced variant of an image model (its pins choose the price tier). */
export interface ConfidentialImageVariant {
  id: string;
  pins: ImagePin[];
  /** Flat price per image, msats, from the signed offer. */
  msat_per_image: number;
  /** Most images per request for this variant (below the block's `max_count`). */
  max_count?: number;
}

/** The signed offer's image block (capability `images`). */
export interface ConfidentialImagesOffer {
  /** Request head of the image route, `{KEY:n}` and `{LEN}` tokens as for chat. */
  head_template: string;
  /** Response JSON shape: `venice` (`{images:[base64]}`) or `openai` (`{data:[{b64_json}]}`). */
  response_shape: "venice" | "openai";
  /** Seconds the provider may stay silent before the response (default 300). */
  response_idle_s?: number;
  /** Most images per request. */
  max_count: number;
  /** The request key that carries the count (default `variants`, Venice's). */
  count_key: string;
  /** Pins every request carries, after the model and the count. */
  fixed_pins: ImagePin[];
  price_list: Record<string, ConfidentialImageVariant[]>;
  /** The relay's parameter space and response cap (informational for the client). */
  param_space?: Record<string, unknown[]>;
  max_response_bytes?: number;
}

export interface ConfidentialOffer {
  v: number;
  min_v?: number;
  max_v?: number;
  upstream_host: string;
  ws?: string;
  notary_pubkey: string;
  notary_pubkey_curve?: string;
  max_tokens_cap: number;
  key_length: number;
  key_alphabet?: string;
  head_template: string;
  /** The keys the chat suffix pins, in order (derived from `chat`). */
  suffix_keys: string[];
  /** How the pinned chat suffix is built (`validateChatSuffix`). */
  chat: ChatSuffixSpec;
  price_list: Record<string, ConfidentialPriceEntry>;
  /** What the node serves confidentially (absent: chat only). */
  capabilities?: string[];
  images?: ConfidentialImagesOffer;
  mints?: string[];
  prewarm?: boolean;
  /**
   * Flat fee (msats) on top of the usage of a completed request, and the
   * charge for a request the provider refused (4xx/503). The client accepts it
   * by echoing it in setup.
   */
  session_fee_msat?: number;
  /**
   * Fee (msats, ≥ session_fee_msat) for a session that ends without a request
   * reaching the provider: armed and never used, aborted before the body, the
   * client gone. The node's anti-DoS deposit; it is reserved at setup and the
   * client accepts it by echoing it in setup.
   */
  abandon_fee_msat?: number;
  /**
   * Informational: the surcharge (percent) the node applies to its per-token
   * rates for confidential sessions. `price_list` already includes it.
   */
  rate_surcharge_pct?: number;
  /**
   * Completion tokens the node reserves beyond `max_tokens` (a provider may
   * bill a few past the cap). Only the reservation grows; the charge is still
   * the usage.
   */
  reserve_margin_tokens?: number;
  /** BIP-340 Schnorr signature (hex) over `sig_payload`. */
  sig?: string;
  /** Exact bytes that were signed. */
  sig_payload?: string;
  [key: string]: unknown;
}

export interface VerifyOfferOptions {
  /**
   * Expected notary pubkey (64-hex or npub). When set, a mismatch is fatal.
   * routstrd passes the node's Nostr announcement key here.
   */
  pinnedPubkey?: string;
  /**
   * A set of accepted notary pubkeys (hex or npub). The offer's notary must be
   * a member. Used when the operator pins several trusted nodes.
   */
  pinnedPubkeys?: readonly string[];
  /**
   * Dev-only escape hatch: accept an offer with no pin. NEVER set in
   * production; the review flagged self-signed offers as not authentic.
   */
  allowUnpinned?: boolean;
  /** Trusted upstream hostnames (exact or wildcard). Empty ⇒ reject. */
  trustedHosts?: readonly string[] | TrustedHostMatcher;
}

export interface VerifiedOffer extends ConfidentialOffer {
  /** The exact payload whose signature verified. */
  signedPayload: string;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Structural validation. Throws `OfferMalformedError`. */
export function validateOfferShape(offer: unknown): asserts offer is ConfidentialOffer {
  if (!isObject(offer)) throw new OfferMalformedError("offer is not an object");
  const required = [
    "v",
    "upstream_host",
    "notary_pubkey",
    "max_tokens_cap",
    "key_length",
    "head_template",
    "suffix_keys",
    "price_list",
  ] as const;
  for (const key of required) {
    if (!(key in offer)) {
      throw new OfferMalformedError(`offer is missing required field '${key}'`);
    }
  }
  if (typeof offer.v !== "number" || !Number.isSafeInteger(offer.v)) {
    throw new OfferMalformedError("offer.v is not an integer");
  }
  for (const key of ["min_v", "max_v"] as const) {
    const bound = offer[key];
    if (bound !== undefined && (typeof bound !== "number" || !Number.isSafeInteger(bound))) {
      throw new OfferMalformedError(`offer.${key} is not an integer`);
    }
  }
  // The offered range must contain the version the offer itself runs.
  const minV = (offer.min_v ?? offer.v) as number;
  const maxV = (offer.max_v ?? offer.v) as number;
  if (!(minV <= offer.v && offer.v <= maxV)) {
    throw new OfferMalformedError(
      `offer version v=${offer.v} lies outside its own range min_v=${minV} max_v=${maxV}`,
    );
  }
  if (typeof offer.upstream_host !== "string" || !offer.upstream_host) {
    throw new OfferMalformedError("offer.upstream_host is not a non-empty string");
  }
  if (typeof offer.notary_pubkey !== "string" || !offer.notary_pubkey) {
    throw new OfferMalformedError("offer.notary_pubkey is not a non-empty string");
  }
  if (typeof offer.head_template !== "string" || !offer.head_template) {
    throw new OfferMalformedError("offer.head_template is not a non-empty string");
  }
  // The node chooses every pinned value of the chat suffix: only a block
  // within the policy is accepted, and suffix_keys must list its keys. (An
  // offer for a version this client does not speak is refused as such.)
  if (supportedVersion(offer as ConfidentialOffer)) validateChatSuffix(offer.chat, offer.suffix_keys);
  if (!isObject(offer.price_list)) {
    throw new OfferMalformedError("offer.price_list is not an object");
  }
  for (const [model, entry] of Object.entries(offer.price_list)) {
    const rate = (v: unknown) => typeof v === "number" && Number.isFinite(v) && v >= 0;
    const optional = (v: unknown) => v === undefined || rate(v);
    if (!isObject(entry) || !rate(entry.in) || !rate(entry.out) || !optional(entry.cached_in) || !optional(entry.cache_write)) {
      throw new OfferMalformedError(`offer.price_list[${JSON.stringify(model)}] is not a set of non-negative rates`);
    }
  }
  if (
    typeof offer.max_tokens_cap !== "number" ||
    !Number.isSafeInteger(offer.max_tokens_cap) ||
    offer.max_tokens_cap <= 0
  ) {
    throw new OfferMalformedError("offer.max_tokens_cap is not a positive integer");
  }
  if (
    offer.session_fee_msat !== undefined &&
    (typeof offer.session_fee_msat !== "number" ||
      !Number.isSafeInteger(offer.session_fee_msat) ||
      offer.session_fee_msat < 0)
  ) {
    throw new OfferMalformedError("offer.session_fee_msat is not a non-negative integer");
  }
  if (
    offer.abandon_fee_msat !== undefined &&
    (typeof offer.abandon_fee_msat !== "number" ||
      !Number.isSafeInteger(offer.abandon_fee_msat) ||
      offer.abandon_fee_msat < 0)
  ) {
    throw new OfferMalformedError("offer.abandon_fee_msat is not a non-negative integer");
  }
  if (offer.capabilities !== undefined) {
    if (!Array.isArray(offer.capabilities) || !offer.capabilities.every((c) => typeof c === "string")) {
      throw new OfferMalformedError("offer.capabilities is not a list of strings");
    }
  }
  // The image block is checked when an image request uses it (`offerImages`):
  // a malformed one refuses images, never the chat the offer also serves.
  if (
    offer.rate_surcharge_pct !== undefined &&
    (typeof offer.rate_surcharge_pct !== "number" ||
      !Number.isFinite(offer.rate_surcharge_pct) ||
      offer.rate_surcharge_pct < 0)
  ) {
    throw new OfferMalformedError("offer.rate_surcharge_pct is not a non-negative number");
  }
}

function isPin(p: unknown): p is ImagePin {
  return Array.isArray(p) && p.length === 2 && typeof p[0] === "string" && p[0].length > 0;
}

/** Most images per request any offer may ask for. */
export const IMAGE_MAX_COUNT = 4;
/** The variant pins a client lets the node choose: price tiers and the format. */
export const IMAGE_VARIANT_PIN_KEYS = ["resolution", "quality", "format"] as const;

/** A fixed pin switches a provider extra off: `false` or an empty list. */
function isOffValue(v: unknown): boolean {
  return v === false || (Array.isArray(v) && v.length === 0);
}

/**
 * The signed image block, checked before any image request uses it. The node
 * chooses what the suffix pins, and the provider obeys the suffix, so only
 * pins that switch extras off (under no key that negates a feature or names
 * a protection) and pins that select a priced tier are taken: anything else
 * could switch on a feature that sends the prompt elsewhere.
 */
export function validateImagesBlock(images: unknown, upstreamHost?: string): void {
  const bad = (what: string): never => {
    throw new OfferMalformedError(`offer.images: ${what}`);
  };
  if (!isObject(images)) bad("not an object");
  const im = images as Record<string, unknown>;
  if (typeof im.head_template !== "string" || !im.head_template) bad("head_template is not a non-empty string");
  if (upstreamHost !== undefined) {
    try {
      checkHeadTemplate(im.head_template as string, upstreamHost, "images");
    } catch (e) {
      bad(`head_template: ${(e as Error).message}`);
    }
  }
  if (im.response_shape !== "venice" && im.response_shape !== "openai") bad("unknown response_shape");
  if (
    im.response_idle_s !== undefined &&
    (typeof im.response_idle_s !== "number" ||
      !Number.isSafeInteger(im.response_idle_s) ||
      im.response_idle_s < 30 ||
      im.response_idle_s > 600)
  ) {
    bad("response_idle_s is not an integer of 30 to 600");
  }
  if (
    typeof im.max_count !== "number" ||
    !Number.isSafeInteger(im.max_count) ||
    im.max_count < 1 ||
    im.max_count > IMAGE_MAX_COUNT
  ) {
    bad(`max_count is not an integer of 1 to ${IMAGE_MAX_COUNT}`);
  }
  const countKey = im.count_key ?? "variants";
  if (typeof countKey !== "string" || !countKey || countKey === "model") bad("count_key is invalid");
  if (!Array.isArray(im.fixed_pins) || !im.fixed_pins.every(isPin)) bad("fixed_pins is not a list of [key, value]");
  const fixed = im.fixed_pins as ImagePin[];
  for (const [k, v] of fixed) {
    if (!isOffValue(v)) bad(`fixed pin ${JSON.stringify(k)} does not switch an extra off`);
    const keyProblem = pinKeyProblem(k, v);
    if (keyProblem) bad(`fixed pin ${JSON.stringify(k)}: ${keyProblem}`);
  }
  const fixedKeys = fixed.map(([k]) => k);
  const reserved = ["model", countKey as string, ...fixedKeys];
  if (new Set(reserved).size !== reserved.length) bad("a fixed pin repeats the model, the count or another pin");
  if (!isObject(im.param_space)) bad("param_space is not an object");
  const space = im.param_space as Record<string, unknown>;
  for (const [k, vals] of Object.entries(space)) {
    if (!Array.isArray(vals) || !vals.every((x) => typeof x === "string")) bad(`param_space[${JSON.stringify(k)}] is not a list of strings`);
  }
  if (!isObject(im.price_list)) bad("price_list is not an object");
  for (const [model, variants] of Object.entries(im.price_list as Record<string, unknown>)) {
    const at = `price_list[${JSON.stringify(model)}]`;
    if (!Array.isArray(variants) || variants.length === 0) bad(`${at} has no variants`);
    const ids = new Set<string>();
    for (const v of variants as unknown[]) {
      if (!isObject(v) || typeof v.id !== "string" || !v.id || !Array.isArray(v.pins) || !v.pins.every(isPin)) {
        bad(`${at} has a malformed variant`);
      }
      const vr = v as Record<string, unknown>;
      if (ids.has(vr.id as string)) bad(`${at} repeats the variant id ${JSON.stringify(vr.id)}`);
      ids.add(vr.id as string);
      const price = vr.msat_per_image;
      if (typeof price !== "number" || !Number.isSafeInteger(price) || price <= 0) {
        bad(`${at} variant ${JSON.stringify(vr.id)} has no positive integer price`);
      }
      if (
        vr.max_count !== undefined &&
        (typeof vr.max_count !== "number" ||
          !Number.isSafeInteger(vr.max_count) ||
          vr.max_count < 1 ||
          vr.max_count > (im.max_count as number))
      ) {
        bad(`${at} variant ${JSON.stringify(vr.id)} has an invalid max_count`);
      }
      const keys = new Set<string>();
      for (const [k, val] of vr.pins as ImagePin[]) {
        if (!(IMAGE_VARIANT_PIN_KEYS as readonly string[]).includes(k)) bad(`${at} pins ${JSON.stringify(k)}, not a price tier`);
        if (keys.has(k) || reserved.includes(k)) bad(`${at} pins ${JSON.stringify(k)} twice`);
        keys.add(k);
        const allowed = space[k];
        if (typeof val !== "string" || !Array.isArray(allowed) || !allowed.includes(val)) {
          bad(`${at} pins ${JSON.stringify(k)}=${JSON.stringify(val)} outside param_space`);
        }
      }
    }
  }
}

/**
 * The offer's image block when the node serves images confidentially: only
 * with `capabilities` naming `images` (an offer without the field is chat
 * only). Defaults filled in: `count_key` "variants", `response_idle_s` 300.
 * A malformed block throws `OfferMalformedError`: images are refused, the
 * offer's chat is not affected.
 */
export function offerImages(
  offer: Pick<ConfidentialOffer, "capabilities" | "images"> & { upstream_host?: string },
): ConfidentialImagesOffer | undefined {
  if (!offer.images || !offer.capabilities?.includes("images")) return undefined;
  validateImagesBlock(offer.images, offer.upstream_host);
  return { ...offer.images, count_key: offer.images.count_key ?? "variants", response_idle_s: offer.images.response_idle_s ?? 300 };
}

function feeValue(fee: unknown): number {
  return typeof fee === "number" && Number.isSafeInteger(fee) && fee > 0 ? fee : 0;
}

/** The signed offer's completion-token margin on the reservation (0 when none). */
export function offerReserveMarginTokens(offer: Pick<ConfidentialOffer, "reserve_margin_tokens">): number {
  return feeValue(offer.reserve_margin_tokens);
}

/** The signed offer's session fee in msats (0 when the node charges none). */
export function offerSessionFeeMsat(offer: Pick<ConfidentialOffer, "session_fee_msat">): number {
  return feeValue(offer.session_fee_msat);
}

/**
 * The signed offer's abandon fee in msats: what a session that ends without a
 * request reaching the provider costs. Never below the session fee (the node
 * uses the session fee when it sets none).
 */
export function offerAbandonFeeMsat(
  offer: Pick<ConfidentialOffer, "session_fee_msat" | "abandon_fee_msat">,
): number {
  return Math.max(feeValue(offer.abandon_fee_msat), offerSessionFeeMsat(offer));
}

/** The exact bytes the node signed, or a canonical reconstruction. */
export function offerSignedPayload(offer: ConfidentialOffer): string {
  if (typeof offer.sig_payload === "string" && offer.sig_payload.length > 0) {
    return offer.sig_payload;
  }
  const { sig: _sig, sig_payload: _sp, ...unsigned } = offer;
  return canonicalJson(unsigned);
}

/** Verify only the BIP-340 signature; no pin check. */
export function verifyOfferSignature(offer: ConfidentialOffer): boolean {
  const payload = offerSignedPayload(offer);
  return verifySchnorrSignature(payload, offer.sig, offer.notary_pubkey);
}

/** Supported-version check against the offer's `min_v`/`max_v` and `v`. */
export function supportedVersion(offer: ConfidentialOffer): boolean {
  const min = offer.min_v ?? offer.v;
  const max = offer.max_v ?? offer.v;
  return (
    min <= offer.v &&
    offer.v <= max &&
    offer.v >= CONFIDENTIAL_VERSION_MIN &&
    offer.v <= CONFIDENTIAL_VERSION_MAX &&
    min <= CONFIDENTIAL_VERSION_MAX &&
    max >= CONFIDENTIAL_VERSION_MIN
  );
}

/**
 * Full verification: shape → version → signature → pin → trusted host.
 * Returns the offer with `signedPayload` filled in. Every failure is typed.
 */
export function verifyConfidentialOffer(
  raw: unknown,
  options: VerifyOfferOptions = {},
): VerifiedOffer {
  validateOfferShape(raw);
  // The signed bytes are authoritative: when the node ships `sig_payload`, the
  // fields the client uses MUST come from it, not from the outer (mutable)
  // envelope, or a tampered envelope would verify against an unchanged payload.
  let offer: ConfidentialOffer = raw;
  const payload = offerSignedPayload(raw);
  if (typeof raw.sig_payload === "string" && raw.sig_payload.length > 0) {
    let signed: unknown;
    try {
      signed = JSON.parse(raw.sig_payload);
    } catch (error) {
      throw new OfferMalformedError(
        "offer.sig_payload is not valid JSON",
        error instanceof Error ? error.message : String(error),
      );
    }
    validateOfferShape(signed);
    offer = { ...signed, sig: raw.sig, sig_payload: raw.sig_payload };
  }

  if (!supportedVersion(offer)) {
    throw new OfferUnsupportedVersionError(
      `offer version v=${offer.v} min_v=${offer.min_v ?? offer.v} max_v=${offer.max_v ?? offer.v} ` +
        `outside supported range ${CONFIDENTIAL_VERSION_MIN}-${CONFIDENTIAL_VERSION_MAX}`,
    );
  }

  if (!offer.sig) {
    if (!options.allowUnpinned) {
      throw new OfferUnpinnedError(
        "offer is unsigned and allowUnpinned is not set (self-consistency is not authenticity)",
      );
    }
  } else if (!verifySchnorrSignature(payload, offer.sig, offer.notary_pubkey)) {
    throw new OfferBadSignatureError();
  }

  if (options.pinnedPubkey) {
    const pin = npubToHex(options.pinnedPubkey);
    if (!pin) {
      throw new OfferPinMismatchError(
        `configured pinned pubkey is not a valid hex pubkey or npub: ${options.pinnedPubkey}`,
      );
    }
    const notary = npubToHex(offer.notary_pubkey);
    if (!notary || notary !== pin) {
      throw new OfferPinMismatchError(
        `offer notary ${offer.notary_pubkey} != pinned ${pin}`,
      );
    }
  } else if (options.pinnedPubkeys && options.pinnedPubkeys.length > 0) {
    const allowed = options.pinnedPubkeys
      .map((p) => npubToHex(p))
      .filter((p): p is string => p !== null);
    if (allowed.length === 0) {
      throw new OfferPinMismatchError("configured pinnedPubkeys contains no valid pubkey");
    }
    const notary = npubToHex(offer.notary_pubkey);
    if (!notary || !allowed.includes(notary)) {
      throw new OfferPinMismatchError(
        `offer notary ${offer.notary_pubkey} is not among the pinned node keys`,
      );
    }
  } else if (!options.allowUnpinned) {
    throw new OfferUnpinnedError(
      "no pinnedPubkey configured and allowUnpinned is not set",
    );
  }

  // The node writes the chat request head too: the same syntax as the image
  // head, checked before any setup (π_NK checks it again per session).
  try {
    checkHeadTemplate(offer.head_template, offer.upstream_host, "chat");
  } catch (e) {
    throw new OfferMalformedError(`offer.head_template: ${(e as Error).message}`);
  }

  // Fail closed at runtime too (plain-JS callers bypass the TS type): an
  // offer is only usable for an upstream host the caller trusts.
  if (options.trustedHosts === undefined) {
    throw new TrustedHostError("no trusted upstream hosts configured; refusing the offer");
  }
  {
    const matcher =
      options.trustedHosts instanceof TrustedHostMatcher
        ? options.trustedHosts
        : new TrustedHostMatcher(options.trustedHosts as readonly string[]);
    if (!matcher.matches(offer.upstream_host)) {
      throw new TrustedHostError(
        `offer upstream_host not trusted: ${matcher.describe(offer.upstream_host)}`,
      );
    }
    // The node writes the request head: hold its route to the API base the
    // caller trusts for that host, so it cannot pick another route of the
    // same provider that merely ends in the endpoint.
    const bases = matcher.apiBases(offer.upstream_host);
    const route = headRouteProblem(offer.head_template, bases, "chat");
    if (route) throw new TrustedHostError(`offer head_template: ${route}`);
    if (offer.images && headRouteProblem(String(offer.images.head_template), bases, "images")) {
      // Images off for this offer; chat on the same signed terms still works.
      const { images: _refused, ...rest } = offer;
      return { ...rest, signedPayload: payload };
    }
  }

  return { ...offer, signedPayload: payload };
}

/**
 * Fetch + verify the node's offer. `baseUrl` is the node HTTP(S) base (e.g.
 * `http://127.0.0.1:8000`) — the offer lives at `/v1/confidential/offer`.
 */
export async function fetchConfidentialOffer(
  baseUrl: string,
  options: VerifyOfferOptions & { fetchImpl?: typeof fetch } = {},
): Promise<VerifiedOffer> {
  const base = baseUrl.replace(/\/$/, "");
  const url = `${base}/v1/confidential/offer`;
  const doFetch = options.fetchImpl ?? fetch;
  let resp: Response;
  try {
    resp = await doFetch(url);
  } catch (error) {
    throw new OfferUnavailableError(
      `could not reach ${url}`,
      error instanceof Error ? error.message : String(error),
    );
  }
  if (!resp.ok) {
    throw new OfferUnavailableError(`${url} returned HTTP ${resp.status}`);
  }
  let json: unknown;
  try {
    json = await resp.json();
  } catch (error) {
    throw new OfferMalformedError(
      "offer is not valid JSON",
      error instanceof Error ? error.message : String(error),
    );
  }
  return verifyConfidentialOffer(json, options);
}
