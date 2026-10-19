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
  const bin = atob(b64.replace(/\s+/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

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
