import { afterEach, describe, expect, it, vi } from "vitest";
import { ConfidentialClient, imageRequestCostMsat } from "../src/client.js";
import {
  buildImageBody,
  chooseImageVariant,
  imageMimeType,
  imageSuffix,
  pinnedImageKeys,
  renderImageSuffix,
  responseImages,
  toOpenAiImages,
} from "../src/images.js";
import {
  imagesOfferProblem,
  offerImages,
  validateOfferShape,
  verifyConfidentialOffer,
  type ConfidentialImagesOffer,
  type VerifiedOffer,
} from "../src/offer.js";
import { NODE_PUB, signedV3Offer } from "./fixtures/v3.js";
import { verifyFlatReceipt } from "../src/receipt.js";
import { base64ToBytes, planImageRequest } from "../src/images.js";
import { checkImageResponse, imageOutcome } from "../src/wire.js";
import { parseHttpResponse } from "../src/suffix.js";
import { ProofChannel } from "../src/zkchan.js";
import requestVectors from "./fixtures/image-request-vectors.json";
import prod from "./fixtures/v3-node-offer.json";

const FIXED: [string, unknown][] = [
  ["return_binary", false],
  ["enhance_prompt", false],
  ["enable_web_search", false],
  ["style_references", []],
];

const IMAGES: ConfidentialImagesOffer = {
  head_template:
    "POST /api/v1/image/generate HTTP/1.1\r\nHost: api.venice.ai\r\nAuthorization: Bearer {KEY:42}\r\nContent-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {LEN}\r\n\r\n",
  response_shape: "venice",
  response_idle_s: 300,
  max_count: 4,
  count_key: "variants",
  fixed_pins: FIXED,
  param_space: { resolution: ["1K", "2K", "4K"], quality: ["low", "medium", "high"], format: ["webp"] },
  price_list: {
    "z-image-turbo": [{ id: "webp", pins: [["format", "webp"]], msat_per_image: 12164 }],
    "nano-banana-pro": [
      { id: "1K-webp", pins: [["resolution", "1K"], ["format", "webp"]], msat_per_image: 218000 },
      { id: "2K-webp", pins: [["resolution", "2K"], ["format", "webp"]], msat_per_image: 290000 },
    ],
  },
};

function offerWithImages(extra: Partial<VerifiedOffer> = {}): VerifiedOffer {
  return { ...(prod as never as VerifiedOffer), capabilities: ["chat", "images"], images: IMAGES, signedPayload: "", ...extra };
}

describe("image suffix", () => {
  it("matches the shared test vector byte for byte", () => {
    expect(renderImageSuffix("z-image-turbo", "variants", 2, FIXED, [["format", "webp"]])).toBe(
      ',"model":"z-image-turbo","variants":2,"return_binary":false,"enhance_prompt":false,"enable_web_search":false,"style_references":[],"format":"webp"}',
    );
  });

  it("refuses a key pinned twice and a bad count", () => {
    expect(() => renderImageSuffix("m", "variants", 1, [["format", "png"]], [["format", "webp"]])).toThrow(/twice/);
    expect(() => renderImageSuffix("m", "model", 1, [], [])).toThrow(/twice/);
    expect(() => renderImageSuffix("m", "variants", 0, [], [])).toThrow(/count/);
  });

  it("gives a body whose effective values are the pinned ones", () => {
    const v = IMAGES.price_list["nano-banana-pro"]![1]!;
    const suffix = imageSuffix(IMAGES, "nano-banana-pro", v, 3);
    const body = buildImageBody({ prompt: "a \"quoted\" cat", aspect_ratio: "16:9" }, suffix, pinnedImageKeys(IMAGES, v));
    const text = new TextDecoder().decode(body);
    expect(text.endsWith(suffix)).toBe(true);
    const parsed = JSON.parse(text);
    expect(parsed).toMatchObject({ prompt: 'a "quoted" cat', aspect_ratio: "16:9", model: "nano-banana-pro", variants: 3, resolution: "2K", format: "webp" });
  });

  it("refuses pinned keys among the private options and a missing prompt", () => {
    const v = IMAGES.price_list["z-image-turbo"]![0]!;
    const pinned = pinnedImageKeys(IMAGES, v);
    expect(() => buildImageBody({ prompt: "x", enhance_prompt: true }, ",}", pinned)).toThrow(/pinned/);
    expect(() => buildImageBody({ prompt: "x", variants: 4 }, ",}", pinned)).toThrow(/pinned/);
    expect(() => buildImageBody({ prompt: "" }, ",}", pinned)).toThrow(/prompt/);
  });
});

describe("variant choice", () => {
  it("takes an id, matching params, or the first variant; never substitutes", () => {
    expect(chooseImageVariant(IMAGES, "nano-banana-pro").id).toBe("1K-webp");
    expect(chooseImageVariant(IMAGES, "nano-banana-pro", { variant: "2K-webp" }).id).toBe("2K-webp");
    expect(chooseImageVariant(IMAGES, "nano-banana-pro", { params: { resolution: "2K" } }).id).toBe("2K-webp");
    expect(() => chooseImageVariant(IMAGES, "nano-banana-pro", { params: { resolution: "4K" } })).toThrow(/no image variant/);
    expect(() => chooseImageVariant(IMAGES, "z-image-turbo", { params: { format: "png" } })).toThrow(/no image variant/);
    expect(() => chooseImageVariant(IMAGES, "nope")).toThrow(/does not serve/);
  });

  it("prices a request at the signed per-image price plus the session fee", () => {
    const v = IMAGES.price_list["z-image-turbo"]![0]!;
    expect(imageRequestCostMsat(offerWithImages({ session_fee_msat: 100 }), v, 3)).toBe(3 * 12164 + 100);
  });
});

const policy = { pinnedPubkeys: [NODE_PUB], trustedHosts: ["api.venice.ai"] };
const signed = (extra: Record<string, unknown>) => signedV3Offer(JSON.parse(JSON.stringify(extra)));

describe("offer image block", () => {
  it("validates the block and honours the capability list", () => {
    const base = { ...(prod as object) } as Record<string, unknown>;
    expect(() => validateOfferShape({ ...base, capabilities: ["chat", "images"], images: IMAGES })).not.toThrow();
    const variant = (v: Record<string, unknown>) => ({ ...IMAGES, price_list: { m: [{ id: "a", pins: [["format", "webp"]], msat_per_image: 1000, ...v }] } });
    for (const bad of [
      { ...IMAGES, response_shape: "png" },
      { ...IMAGES, max_count: 0 },
      { ...IMAGES, max_count: 5 },
      { ...IMAGES, max_count: 1.5 },
      { ...IMAGES, response_idle_s: 1 },
      { ...IMAGES, response_idle_s: 601 },
      { ...IMAGES, count_key: "model" },
      { ...IMAGES, fixed_pins: [["x"]] },
      // Fixed pins only switch extras off: anything else could turn a feature on.
      { ...IMAGES, fixed_pins: [["enable_web_search", true]] },
      { ...IMAGES, fixed_pins: [["embed_exif_metadata", "yes"]] },
      { ...IMAGES, fixed_pins: [["seed", 1]] },
      { ...IMAGES, fixed_pins: [["style_references", ["https://x"]]] },
      { ...IMAGES, fixed_pins: [["variants", false]] },
      // No key that negates a feature (false under it switches it on) or names a protection.
      { ...IMAGES, fixed_pins: [["disable_watermark", false]] },
      { ...IMAGES, fixed_pins: [["No_Logo", false]] },
      { ...IMAGES, fixed_pins: [["hide_watermark", false]] },
      { ...IMAGES, fixed_pins: [["safe_mode", false]] },
      { ...IMAGES, fixed_pins: [["content_filter", []]] },
      { ...IMAGES, fixed_pins: [["nsfw", false]] },
      { ...IMAGES, param_space: undefined },
      { ...IMAGES, param_space: { format: [1] } },
      { ...IMAGES, price_list: { m: [] } },
      variant({ msat_per_image: -1 }),
      variant({ msat_per_image: Number.NaN }),
      variant({ msat_per_image: 0 }),
      variant({ msat_per_image: 1.5 }),
      variant({ max_count: 5 }),
      variant({ pins: [["safe_mode", "false"]] }),
      variant({ pins: [["aspect_ratio", "16:9"]] }),
      variant({ pins: [["format", "png"]] }),
      variant({ pins: [["resolution", 2]] }),
      variant({ pins: [["format", "webp"], ["format", "webp"]] }),
      variant({ pins: [["return_binary", false]] }),
      { ...IMAGES, price_list: { m: [{ id: "a", pins: [], msat_per_image: 1 }, { id: "a", pins: [], msat_per_image: 2 }] } },
    ]) {
      // A malformed image block refuses images, not the offer's chat.
      expect(() => validateOfferShape({ ...base, capabilities: ["chat", "images"], images: bad })).not.toThrow();
      expect(imagesOfferProblem(bad, "api.venice.ai")).toMatch(/offer\.images/);
      // A verified offer drops a refused block (chat still works) and says why.
      const v = verifyConfidentialOffer(signed({ capabilities: ["chat", "images"], images: bad }), policy);
      expect(v.images).toBeUndefined();
      expect(v.imagesRefused).toMatch(/offer\.images/);
      expect(() => offerImages(v)).toThrow(/image offer is refused/);
    }
    expect(imagesOfferProblem(IMAGES, "api.venice.ai")).toBeUndefined();
    expect(offerImages(verifyConfidentialOffer(signed({ capabilities: ["chat", "images"], images: IMAGES }), policy))).toEqual(IMAGES);
    // The head template is checked against the upstream host and the image route.
    expect(imagesOfferProblem(IMAGES, "api.other.example")).toMatch(/head_template/);
    const chatRoute = { ...IMAGES, head_template: IMAGES.head_template.replace("/api/v1/image/generate", "/api/v1/chat/completions") };
    expect(imagesOfferProblem(chatRoute, "api.venice.ai")).toMatch(/head_template/);
    // The count key must be the one the route reads (variants for /image/generate, n for /images/generations).
    expect(imagesOfferProblem({ ...IMAGES, count_key: "n" }, "api.venice.ai")).toMatch(/count_key/);
    const openaiRoute = { ...IMAGES, count_key: "n", head_template: IMAGES.head_template.replace("/api/v1/image/generate", "/api/v1/images/generations") };
    expect(imagesOfferProblem(openaiRoute, "api.venice.ai")).toBeUndefined();
    // No capability list: a chat-only offer, whatever else it carries.
    expect(offerImages({ images: IMAGES })).toBeUndefined();
    expect(offerImages({ capabilities: ["chat"], images: IMAGES })).toBeUndefined();
    expect(offerImages({ capabilities: ["chat"] })).toBeUndefined();
  });
});

describe("flat receipt", () => {
  const own = { model: "z-image-turbo", variant: "webp", count: 2, msatPerImage: 12164, sessionFeeMsat: 100 };
  const good = { sid: "s", model: "z-image-turbo", kind: "images", variant: "webp", count: 2, msat_per_image: 12164, cost_msats: 24428, usage: { flat: true } } as never;

  it("accepts exactly price × count + session fee", () => {
    expect(() => verifyFlatReceipt(good, own)).not.toThrow();
  });

  it("rounds a fractional price up, as the node charges it", () => {
    const frac = { ...own, msatPerImage: 12164.4 };
    expect(() => verifyFlatReceipt({ ...(good as object), msat_per_image: 12164.4, cost_msats: 24429 } as never, frac)).not.toThrow();
    expect(() => verifyFlatReceipt({ ...(good as object), msat_per_image: 12164.4, cost_msats: 24428 } as never, frac)).toThrow();
  });

  it("refuses any other charge or terms", () => {
    const r = good as Record<string, unknown>;
    for (const bad of [
      { ...r, cost_msats: 24429 },
      { ...r, cost_msats: 24427 },
      { ...r, cost_msats: undefined },
      { ...r, model: "other" },
      { ...r, kind: "chat" },
      { ...r, variant: "2K" },
      { ...r, count: 3 },
      { ...r, msat_per_image: 1 },
      { ...r, session_fee_msat: 101 },
    ]) {
      expect(() => verifyFlatReceipt(bad as never, own)).toThrow();
    }
  });
});

describe("image response", () => {
  it("reads both shapes and converts to the OpenAI one", () => {
    expect(responseImages({ images: ["AAAA"] }, "venice")).toEqual(["AAAA"]);
    expect(responseImages({ data: [{ b64_json: "BBBB" }] }, "openai")).toEqual(["BBBB"]);
    expect(() => responseImages({ data: [] }, "venice")).toThrow();
    expect(toOpenAiImages({ created: 5, images: ["AAAA"] }, "venice")).toEqual({ created: 5, data: [{ b64_json: "AAAA" }] });
    expect(imageMimeType([["format", "webp"]])).toBe("image/webp");
    expect(imageMimeType([["format", "png"]])).toBe("image/png");
  });
});

describe("image request planning (shared vectors with the SDK)", () => {
  const images = requestVectors.images as never as Parameters<typeof planImageRequest>[0];
  for (const v of requestVectors.cases) {
    it(v.name, () => {
      const run = () => {
        const p = planImageRequest(images, { ...(v.body as Record<string, unknown>) });
        // The body builder refuses pinned keys among the private options.
        buildImageBody(p.privateOptions, imageSuffix(images, p.model, p.variant, p.count), pinnedImageKeys(images, p.variant));
        return { variant: p.variant.id, count: p.count, private: Object.keys(p.privateOptions).sort() };
      };
      if ("error" in v.expect) expect(run).toThrow();
      else expect(run()).toEqual(v.expect);
    });
  }
});

describe("an accepted image answer", () => {
  const want = { model: "z-image-turbo", count: 2, countKey: "variants" };
  const http = (json: string, declared?: number) =>
    parseHttpResponse(
      new TextEncoder().encode(
        `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${declared ?? new TextEncoder().encode(json).length}\r\n\r\n${json}`,
      ),
    );

  it("has no warnings when it is what was pinned", () => {
    const r = checkImageResponse(http('{"images":["AAAA","AAAA"],"request":{"model":"z-image-turbo","variants":2}}'), "venice", want);
    expect(r.image.data).toHaveLength(2);
    expect(r.warnings).toEqual([]);
  });

  it("reports a short count, another echoed model or count, a cut body, never throws", () => {
    const short = checkImageResponse(http('{"images":["AAAA"],"request":{"model":"other","variants":1}}'), "venice", want);
    expect(short.image.data).toHaveLength(1);
    expect(short.warnings.join(" ")).toMatch(/1 of 2/);
    expect(short.warnings.join(" ")).toMatch(/model other/);
    expect(short.warnings.join(" ")).toMatch(/variants=1/);
    const cut = checkImageResponse(http('{"images":["AA', 9999), "venice", want);
    expect(cut.image.data).toEqual([]);
    expect(cut.warnings.join(" ")).toMatch(/incomplete/);
    expect(cut.warnings.join(" ")).toMatch(/not JSON/);
  });
});
describe("proof channel verification", () => {
  it("refuses a verification that reports no checks", async () => {
    const ch = new ProofChannel({} as never);
    const run = ch.run("verify", "pi_nk", {}, undefined, 1000);
    (ch as unknown as { onControl(m: Record<string, unknown>): void }).onControl({ ev: "done", id: 1, ok: true, checks: [] });
    await expect(run).rejects.toThrow(/checks failed/);
    const ok = ch.run("verify", "pi_nk", {}, undefined, 1000);
    (ch as unknown as { onControl(m: Record<string, unknown>): void }).onControl({ ev: "done", id: 2, ok: true, checks: [{ label: "x", ok: true }] });
    await expect(ok).resolves.toBeTruthy();
  });
});

describe("image response handling", () => {
  it("accepts only a 2xx; discloses an error; neither for anything else", () => {
    expect(imageOutcome(200)).toBe("accept");
    expect(imageOutcome(204)).toBe("accept");
    expect(imageOutcome(302)).toBe("refuse");
    expect(imageOutcome(0)).toBe("refuse");
    expect(imageOutcome(100)).toBe("refuse");
    expect(imageOutcome(400)).toBe("disclose");
    expect(imageOutcome(503)).toBe("disclose");
  });

  it("decodes base64 straight to bytes, padded or not, with whitespace", () => {
    const bytes = new Uint8Array(1000).map((_, i) => (i * 37) % 256);
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    const b64 = btoa(bin);
    expect(Array.from(base64ToBytes(b64))).toEqual(Array.from(bytes));
    expect(Array.from(base64ToBytes(b64.replace(/=+$/, "")))).toEqual(Array.from(bytes));
    expect(Array.from(base64ToBytes(b64.slice(0, 40) + "\n" + b64.slice(40)))).toEqual(Array.from(bytes));
    expect(Array.from(base64ToBytes("TWFu"))).toEqual([77, 97, 110]);
    expect(Array.from(base64ToBytes("TWE="))).toEqual([77, 97]);
    expect(() => base64ToBytes("TW*u")).toThrow();
  });
});
