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
import { base64ToBytes, planImageRequest } from "../src/images.js";
import { decodeImageResponse, imageOutcome } from "../src/session.js";
import { parseHttpResponse } from "../src/suffix.js";
import { ProofChannel } from "../src/zkchan.js";
import requestVectors from "./fixtures/image-request-vectors.json";
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
      expect(() => offerImages({ capabilities: ["chat", "images"], images: bad as never })).toThrow(/offer\.images/);
    }
    expect(offerImages({ capabilities: ["chat", "images"], images: IMAGES })).toEqual(IMAGES);
    // The head template is checked against the upstream host and the image route.
    expect(offerImages({ capabilities: ["images"], images: IMAGES, upstream_host: "api.venice.ai" })).toEqual(IMAGES);
    expect(() => offerImages({ capabilities: ["images"], images: IMAGES, upstream_host: "api.other.example" })).toThrow(/head_template/);
    const chatRoute = { ...IMAGES, head_template: IMAGES.head_template.replace("/api/v1/image/generate", "/api/v1/chat/completions") };
    expect(() => offerImages({ capabilities: ["images"], images: chatRoute, upstream_host: "api.venice.ai" })).toThrow(/head_template/);
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
    // A caller's doctored copy of the variant does not reach the suffix.
    const doctored = { ...variant, pins: [["resolution", "4K"]] as [string, string][], msat_per_image: 1 };
    const d = new ConfidentialSession({ ...base, offer: offerWithImages(), kind: "images", image: { variant: doctored, count: 2 } });
    expect(d.suffix).toBe(imageSuffix(IMAGES, "z-image-turbo", variant, 2));
    // A variant's own count cap is below the block's.
    const capped = { ...variant, max_count: 1 };
    const cappedOffer = offerWithImages({ images: { ...IMAGES, price_list: { ...IMAGES.price_list, "z-image-turbo": [capped] } } });
    expect(() => new ConfidentialSession({ ...base, offer: cappedOffer, kind: "images", image: { variant: capped, count: 2 } })).toThrow(/outside 1\.\.1/);
    // A node-chosen fixed pin that switches a feature on refuses the session.
    const hostile = offerWithImages({ images: { ...IMAGES, fixed_pins: [["enable_web_search", true]] } });
    expect(() => new ConfidentialSession({ ...base, offer: hostile, kind: "images", image: { variant, count: 1 } })).toThrow(/switch an extra off/);
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
    const spies = [vi.spyOn(pw, "setTarget"), vi.spyOn(pw, "take"), vi.spyOn(pw, "activity")];
    const begin = vi.spyOn(pw, "beginPreparing");
    const end = vi.spyOn(pw, "endPreparing");
    let preparingDuringRun = -1;
    let seen: ConfidentialSession | undefined;
    let body = "";
    vi.spyOn(ConfidentialSession.prototype, "run").mockImplementation(async function (this: ConfidentialSession, b: Uint8Array) {
      seen = this;
      body = new TextDecoder().decode(b);
      preparingDuringRun = (pw as unknown as { preparing: number }).preparing;
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
    // The chat pool is held back while the image's own 2PC runs, and the
    // image does not count as chat activity when it ends.
    expect(begin).toHaveBeenCalledTimes(1);
    expect(preparingDuringRun).toBe(1);
    expect(end).toHaveBeenCalledWith(false);
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
  const terms = { model: "z-image-turbo", count: 2, countKey: "variants", shape: "venice" as const, pins: [["format", "webp"]] as [string, unknown][] };
  const http = (json: string, declared?: number) =>
    parseHttpResponse(
      new TextEncoder().encode(
        `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${declared ?? new TextEncoder().encode(json).length}\r\n\r\n${json}`,
      ),
    );

  it("has no warnings when it is what was pinned", () => {
    const r = decodeImageResponse(http('{"images":["AAAA","AAAA"],"request":{"data":{"model":"z-image-turbo","variants":2}}}'), terms);
    expect(r.images).toHaveLength(2);
    expect(r.warnings).toEqual([]);
  });

  it("reports a short count, another echoed model or count, a cut body, never throws", () => {
    const short = decodeImageResponse(http('{"images":["AAAA"],"request":{"model":"other","variants":1}}'), terms);
    expect(short.images).toHaveLength(1);
    expect(short.warnings.join(" ")).toMatch(/1 of 2/);
    expect(short.warnings.join(" ")).toMatch(/model "other"/);
    expect(short.warnings.join(" ")).toMatch(/count 1/);
    const cut = decodeImageResponse(http('{"images":["AA', 9999), terms);
    expect(cut.images).toEqual([]);
    expect(cut.warnings.join(" ")).toMatch(/declared length/);
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
    expect(imageOutcome(302)).toBe("invalid");
    expect(imageOutcome(0)).toBe("invalid");
    expect(imageOutcome(100)).toBe("invalid");
    expect(imageOutcome(400)).toBe("error");
    expect(imageOutcome(503)).toBe("error");
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
