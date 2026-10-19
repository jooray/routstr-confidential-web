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
import { validateOfferShape, offerImages, type ConfidentialImagesOffer, type VerifiedOffer } from "../src/offer.js";
import { verifyFlatReceipt } from "../src/receipt.js";
import { ConfidentialSession } from "../src/session.js";
import prod from "./fixtures/cypherpunk-offer.json";

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

describe("offer image block", () => {
  it("validates the block and honours the capability list", () => {
    const base = { ...(prod as object) } as Record<string, unknown>;
    expect(() => validateOfferShape({ ...base, capabilities: ["chat", "images"], images: IMAGES })).not.toThrow();
    for (const bad of [
      { ...IMAGES, response_shape: "png" },
      { ...IMAGES, max_count: 0 },
      { ...IMAGES, count_key: "model" },
      { ...IMAGES, fixed_pins: [["x"]] },
      { ...IMAGES, price_list: { m: [] } },
      { ...IMAGES, price_list: { m: [{ id: "a", pins: [], msat_per_image: -1 }] } },
      { ...IMAGES, price_list: { m: [{ id: "a", pins: [], msat_per_image: Number.NaN }] } },
    ]) {
      expect(() => validateOfferShape({ ...base, images: bad })).toThrow(/offer\.images/);
    }
    expect(offerImages({ capabilities: ["chat", "images"], images: IMAGES })).toEqual(IMAGES);
    // No capability list: a chat-only offer, whatever else it carries.
    expect(offerImages({ images: IMAGES })).toBeUndefined();
    expect(offerImages({ capabilities: ["chat"], images: IMAGES })).toBeUndefined();
    const { count_key: _k, response_idle_s: _r, ...bare } = IMAGES;
    expect(offerImages({ capabilities: ["images"], images: bare as never })).toMatchObject({ count_key: "variants", response_idle_s: 300 });
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

describe("image sessions", () => {
  const base = {
    baseUrl: "https://node.example",
    auth: "sk-test",
    model: "z-image-turbo",
    maxTokens: 0,
    bodyLength: 300,
    host: {} as never,
  };

  it("need an offer that serves images, a valid variant and count", () => {
    const variant = IMAGES.price_list["z-image-turbo"]![0]!;
    expect(() => new ConfidentialSession({ ...base, offer: { ...offerWithImages(), images: undefined }, kind: "images", image: { variant, count: 1 } })).toThrow(/no confidential images/);
    expect(() => new ConfidentialSession({ ...base, offer: offerWithImages(), kind: "images", image: { variant, count: 5 } })).toThrow(/outside/);
    expect(() =>
      new ConfidentialSession({ ...base, offer: offerWithImages(), kind: "images", image: { variant: { ...variant, id: "x" }, count: 1 } }),
    ).toThrow(/no variant/);
    const s = new ConfidentialSession({ ...base, offer: offerWithImages(), kind: "images", image: { variant, count: 2 } });
    expect(s.suffix).toBe(imageSuffix(IMAGES, "z-image-turbo", variant, 2));
  });

  it("are never armed ahead or claimed", async () => {
    const variant = IMAGES.price_list["z-image-turbo"]![0]!;
    const s = new ConfidentialSession({ ...base, offer: offerWithImages(), kind: "images", image: { variant, count: 1 } });
    await expect(s.arm()).rejects.toThrow(/never armed/);
    await expect(s.claim(new Uint8Array(300))).rejects.toThrow(/never claimed/);
  });
});

describe("client.images.generate", () => {
  afterEach(() => vi.restoreAllMocks());

  function client() {
    const c = new ConfidentialClient({
      node: "https://node.example",
      nodePubkeys: ["00".repeat(32)],
      trustedHosts: ["api.venice.ai"],
      credential: "sk-test",
      host: {} as never,
      prewarm: { onlyWhenVisible: false },
    });
    vi.spyOn(c, "offer").mockResolvedValue(offerWithImages());
    return c;
  }

  it("runs one cold image session and never touches the pre-warm pool", async () => {
    const c = client();
    const pw = c.prewarmer!;
    const spies = [vi.spyOn(pw, "setTarget"), vi.spyOn(pw, "take"), vi.spyOn(pw, "activity"), vi.spyOn(pw, "beginPreparing")];
    let seen: ConfidentialSession | undefined;
    let body = "";
    vi.spyOn(ConfidentialSession.prototype, "run").mockImplementation(async function (this: ConfidentialSession, b: Uint8Array) {
      seen = this;
      body = new TextDecoder().decode(b);
      return {
        http: { status: 200, statusText: "OK" },
        images: [new Blob([new Uint8Array([1, 2])], { type: "image/webp" })],
        receipt: { cost_msats: 2 * 218000 },
      } as never;
    });
    const out = await c.images.generate({ model: "nano-banana-pro", prompt: "a cat", count: 2, aspectRatio: "16:9", seed: 7 });
    expect(seen?.kind).toBe("images");
    expect(JSON.parse(body)).toMatchObject({ prompt: "a cat", aspect_ratio: "16:9", seed: 7, model: "nano-banana-pro", variants: 2, resolution: "1K" });
    expect(out).toMatchObject({ variant: "1K-webp", count: 2, msatPerImage: 218000, costMsats: 436000 });
    expect(out.images).toHaveLength(1);
    for (const s of spies) expect(s).not.toHaveBeenCalled();
    pw.stop();
  });

  it("refuses a node without images and reports an upstream error with its result", async () => {
    const c = client();
    vi.spyOn(c, "offer").mockResolvedValue({ ...offerWithImages(), images: undefined });
    await expect(c.images.generate({ model: "z-image-turbo", prompt: "x" })).rejects.toMatchObject({ code: "offer_no_images" });
    vi.spyOn(c, "offer").mockResolvedValue(offerWithImages());
    vi.spyOn(ConfidentialSession.prototype, "run").mockResolvedValue({
      http: { status: 400, statusText: "Bad Request" },
      images: [],
      receipt: { cost_msats: 0 },
    } as never);
    await expect(c.images.generate({ model: "z-image-turbo", prompt: "x" })).rejects.toMatchObject({ code: "upstream_error", status: 400 });
    c.prewarmer!.stop();
  });
});
