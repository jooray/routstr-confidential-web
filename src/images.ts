/**
 * Confidential image generation: the pinned suffix, variant choice and the
 * response conversion.
 *
 * The node prices an image request flat (`msat_per_image × count`), so every
 * request parameter that changes the price is pinned in the JSON suffix that
 * π_C2S proves: the model, the count and the variant's tier keys, plus the
 * offer's fixed pins (the provider's paid extras switched off). Everything
 * else (the prompt, aspect ratio, seed, safe mode, ...) stays in the private
 * prefix the node never sees. Duplicate keys resolve to the last value at the
 * provider, so a prefix value of a pinned key is overridden by the suffix.
 */

import { OfferMalformedError, SessionProtocolError } from "./errors.js";
import type { ConfidentialImagesOffer, ConfidentialImageVariant, ImagePin } from "./offer.js";

/**
 * The suffix for (model, count, variant), byte-exact with the sidecar and the
 * SDK:
 *
 *   "," + join(",", ["\"model\":" + json(M), json(count_key) + ":" + json(count)]
 *                   ++ [json(k) + ":" + json(v) for (k, v) in fixed_pins ++ pins]) + "}"
 *
 * with compact JSON. A key that appears twice is refused.
 */
export function renderImageSuffix(
  model: string,
  countKey: string,
  count: number,
  fixedPins: readonly ImagePin[],
  variantPins: readonly ImagePin[],
): string {
  if (!Number.isSafeInteger(count) || count < 1) throw new SessionProtocolError(`invalid image count ${count}`);
  const pairs: ImagePin[] = [["model", model], [countKey, count], ...fixedPins, ...variantPins];
  const seen = new Set<string>();
  const parts: string[] = [];
  for (const [k, v] of pairs) {
    if (seen.has(k)) throw new OfferMalformedError(`image suffix pins ${JSON.stringify(k)} twice`);
    seen.add(k);
    const value = JSON.stringify(v);
    if (value === undefined) throw new OfferMalformedError(`image pin ${JSON.stringify(k)} has no JSON value`);
    parts.push(`${JSON.stringify(k)}:${value}`);
  }
  return `,${parts.join(",")}}`;
}

/** The suffix for a request from the signed offer's image block. */
export function imageSuffix(images: ConfidentialImagesOffer, model: string, variant: ConfidentialImageVariant, count: number): string {
  return renderImageSuffix(model, images.count_key, count, images.fixed_pins, variant.pins);
}

/** Keys the suffix pins (a private option may not use them). */
export function pinnedImageKeys(images: ConfidentialImagesOffer, variant: ConfidentialImageVariant): Set<string> {
  return new Set(["model", images.count_key, ...images.fixed_pins.map((p) => p[0]), ...variant.pins.map((p) => p[0])]);
}

/**
 * The offered variant a request asks for: `variant` by id, or the one whose
 * pins match every price parameter the caller gave (e.g. `{resolution: "2K"}`).
 * With no parameters, the model's only variant, else its first one (the
 * default tier). Never a silent substitute: a parameter no variant pins to
 * that value is refused.
 */
export function chooseImageVariant(
  images: ConfidentialImagesOffer,
  model: string,
  want: { variant?: string; params?: Record<string, unknown> } = {},
): ConfidentialImageVariant {
  const variants = images.price_list[model];
  if (!variants || variants.length === 0) {
    throw new SessionProtocolError(`the node does not serve ${model} for confidential images`);
  }
  if (want.variant !== undefined) {
    const v = variants.find((x) => x.id === want.variant);
    if (!v) throw new SessionProtocolError(`${model} has no image variant ${JSON.stringify(want.variant)}`);
    return v;
  }
  const params = Object.entries(want.params ?? {}).filter(([, v]) => v !== undefined);
  if (params.length === 0) return variants[0]!;
  const match = variants.find((v) =>
    params.every(([k, val]) => v.pins.some(([pk, pv]) => pk === k && JSON.stringify(pv) === JSON.stringify(val))),
  );
  if (!match) {
    throw new SessionProtocolError(
      `${model} has no image variant with ${params.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ")}`,
    );
  }
  return match;
}

/** Keys that choose the variant and the count; never sent as private options. */
export const IMAGE_SELECTOR_KEYS = [
  "model",
  "n",
  "variants",
  "count",
  "resolution",
  "quality",
  "format",
  "size",
  "response_format",
  "output_format",
] as const;

/** An image request the client refuses before any session is opened. */
export class ImageRequestError extends SessionProtocolError {}

/** An OpenAI `size` ("WxH") as the node's resolution class, by area. */
export function resolutionFromSize(size: string): string {
  const m = /^(\d+)x(\d+)$/.exec(size);
  if (!m) throw new ImageRequestError(`size ${JSON.stringify(size)} is not WIDTHxHEIGHT`);
  const area = Number(m[1]) * Number(m[2]);
  return area < 2 * 1024 * 1024 ? "1K" : area < 2 * 2048 * 2048 ? "2K" : "4K";
}

export interface PlannedImageRequest {
  model: string;
  variant: ConfidentialImageVariant;
  count: number;
  /** The private options (the prompt among them), never the selectors. */
  privateOptions: Record<string, unknown>;
}

const pinOf = (v: ConfidentialImageVariant, key: string): unknown => v.pins.find(([k]) => k === key)?.[1];

/**
 * Split a request (OpenAI or provider shaped) into the signed variant, the
 * count and the private options. The rules match the SDK's request planner:
 * every key that chooses the price is a selector and never private; a
 * selector the model's variants cannot satisfy is refused, never dropped
 * silently; among matching variants the cheapest wins; a tiered model refuses
 * private `width`/`height`, which could pick a dearer size than the pinned tier.
 */
export function planImageRequest(
  images: ConfidentialImagesOffer,
  body: Record<string, unknown>,
  variantId?: string,
): PlannedImageRequest {
  const model = body.model;
  if (typeof model !== "string" || !model) throw new ImageRequestError("an image request needs a model");
  const variants = images.price_list[model];
  if (!variants || variants.length === 0) {
    throw new ImageRequestError(`the node does not serve ${model} for confidential images`);
  }
  const rawCount = body[images.count_key] ?? body.n ?? body.variants ?? body.count ?? 1;
  if (typeof rawCount !== "number" || !Number.isSafeInteger(rawCount) || rawCount < 1 || rawCount > images.max_count) {
    throw new ImageRequestError(`count must be 1..${images.max_count}`);
  }
  for (const key of ["format", "output_format"]) {
    const f = body[key];
    if (f !== undefined && f !== "webp") throw new ImageRequestError(`only webp images are offered (${key}=${JSON.stringify(f)})`);
  }
  const hasAxis = (key: string) => variants.some((v) => pinOf(v, key) !== undefined);
  let candidates = variants;
  if (variantId !== undefined) {
    const v = variants.find((x) => x.id === variantId);
    if (!v) throw new ImageRequestError(`${model} has no image variant ${JSON.stringify(variantId)}`);
    candidates = [v];
  }
  let resolution: unknown = typeof body.resolution === "string" ? body.resolution.toUpperCase() : body.resolution;
  if (resolution === undefined && body.size !== undefined && body.size !== "auto") {
    if (typeof body.size !== "string") throw new ImageRequestError("size must be a string");
    const r = resolutionFromSize(body.size);
    // Without a resolution axis a size only carries aspect intent: ignored.
    if (hasAxis("resolution")) resolution = r;
  }
  const want: [string, unknown][] = [];
  if (resolution !== undefined) {
    if (!hasAxis("resolution")) throw new ImageRequestError(`${model} has no resolution tiers`);
    want.push(["resolution", resolution]);
  }
  if (body.quality !== undefined) {
    if (!hasAxis("quality")) throw new ImageRequestError(`${model} has no quality tiers`);
    want.push(["quality", body.quality]);
  }
  if (hasAxis("format")) want.push(["format", "webp"]);
  const matching = candidates.filter((v) => want.every(([k, val]) => JSON.stringify(pinOf(v, k)) === JSON.stringify(val)));
  if (matching.length === 0) {
    throw new ImageRequestError(`${model} has no image variant with ${want.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ")}`);
  }
  const variant = matching.reduce((a, b) => (b.msat_per_image < a.msat_per_image ? b : a));
  if (hasAxis("resolution") && (body.width !== undefined || body.height !== undefined)) {
    throw new ImageRequestError(`${model} is priced by resolution tier: width/height cannot be private options`);
  }
  const selectors = new Set<string>([...IMAGE_SELECTOR_KEYS, images.count_key]);
  const privateOptions: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(body)) {
    if (!selectors.has(k) && v !== undefined) privateOptions[k] = v;
  }
  return { model, variant, count: rawCount, privateOptions };
}

/**
 * The request body: the private options as a JSON object without its closing
 * brace, then the suffix. The private part must not carry the model, the count
 * or any pinned key (the suffix would override it anyway; refusing makes a
 * caller's mistake visible).
 */
export function buildImageBody(privateOptions: Record<string, unknown>, suffix: string, pinned: Set<string>): Uint8Array {
  for (const k of Object.keys(privateOptions)) {
    if (pinned.has(k)) throw new SessionProtocolError(`${JSON.stringify(k)} is pinned by the offer; it cannot be a private option`);
  }
  if (typeof privateOptions.prompt !== "string" || !privateOptions.prompt) {
    throw new SessionProtocolError("an image request needs a prompt");
  }
  const prefix = JSON.stringify(privateOptions);
  return new TextEncoder().encode(prefix.slice(0, -1) + suffix);
}

/** Base64 (standard alphabet, padded or not) to bytes. */
export function base64ToBytes(b64: string): Uint8Array {
  // Decoded straight into bytes: atob would hold a second, binary-string copy
  // of a multi-megabyte image.
  const out = new Uint8Array(Math.floor((b64.length * 3) / 4) + 3);
  let n = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < b64.length; i++) {
    const c = b64.charCodeAt(i);
    const v = c < 128 ? B64[c]! : -1;
    if (v === -2) continue; // whitespace
    if (v === -3) break; // padding
    if (v < 0) throw new SessionProtocolError("image response is not valid base64");
    acc = ((acc << 6) | v) & 0x3fff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[n++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, n);
}

const B64 = (() => {
  const t = new Int8Array(128).fill(-1);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (let i = 0; i < alphabet.length; i++) t[alphabet.charCodeAt(i)] = i;
  for (const ws of [9, 10, 13, 32]) t[ws] = -2;
  t[61] = -3; // "="
  return t;
})();

/** The base64 images of a provider response, in either shape. */
export function responseImages(body: unknown, shape: ConfidentialImagesOffer["response_shape"]): string[] {
  const b = body as { images?: unknown; data?: unknown } | null;
  if (shape === "venice") {
    if (!Array.isArray(b?.images) || !b.images.every((x) => typeof x === "string")) {
      throw new SessionProtocolError("image response has no images[]");
    }
    return b.images as string[];
  }
  if (!Array.isArray(b?.data)) throw new SessionProtocolError("image response has no data[]");
  return (b.data as { b64_json?: unknown }[]).map((d) => {
    if (typeof d?.b64_json !== "string") throw new SessionProtocolError("image response item has no b64_json");
    return d.b64_json;
  });
}

/** The response in the OpenAI shape: `{created, data: [{b64_json}]}`. */
export function toOpenAiImages(body: unknown, shape: ConfidentialImagesOffer["response_shape"]): {
  created: number;
  data: { b64_json: string }[];
} {
  const created = Number((body as { created?: unknown } | null)?.created) || Math.floor(Date.now() / 1000);
  return { created, data: responseImages(body, shape).map((b64_json) => ({ b64_json })) };
}

/** The MIME type the pins ask for (`format`/`output_format`), default WebP. */
export function imageMimeType(pins: readonly ImagePin[]): string {
  const f = pins.find(([k]) => k === "format" || k === "output_format")?.[1];
  return f === "png" ? "image/png" : f === "jpeg" || f === "jpg" ? "image/jpeg" : "image/webp";
}
