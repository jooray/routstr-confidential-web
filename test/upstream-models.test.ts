/**
 * Models whose public id is not the provider's own (an `org/` prefix): the
 * signed offer lists the pair in `upstream_models`, the request and the price
 * list name the public id, the chat suffix pins the provider's id, and the
 * receipt names both (PROTOCOL-V3.md §12.1, §12.8).
 */
import { describe, expect, it } from "vitest";
import { ConfidentialConnection } from "../src/connection.js";
import { ReceiptVerificationError } from "../src/errors.js";
import { pinnedModelId, upstreamModelsProblem, validateOfferShape } from "../src/offer.js";
import { buildPinnedBody } from "../src/request.js";
import { canonicalSuffix } from "../src/suffix.js";
import { VENICE_CHAT } from "./fixtures/chat.js";
import { BOTH, v3OfferFields } from "./fixtures/v3.js";

const PUBLIC = "kimi-k3.1-pro";
const PROVIDER = "moonshotai/kimi-k3.1-pro";
const RATES = { in: 1000, cached_in: 1000, out: 1000 };
const MAPPED = { ...BOTH, price_list: { cheap: RATES, [PUBLIC]: RATES }, upstream_models: { [PUBLIC]: PROVIDER } };

describe("upstream_models", () => {
  it("maps a public id to the provider's and leaves the others", () => {
    expect(pinnedModelId(MAPPED, PUBLIC)).toBe(PROVIDER);
    expect(pinnedModelId(MAPPED, "cheap")).toBe("cheap");
    expect(pinnedModelId({}, "x")).toBe("x");
  });

  it("is validated with the offer", () => {
    const fields = v3OfferFields(MAPPED);
    expect(() => validateOfferShape(fields)).not.toThrow();
    expect(() => validateOfferShape(v3OfferFields(BOTH))).not.toThrow();
    for (const bad of [[], "x", { other: "a/b" }, { cheap: "cheap" }, { cheap: 'a"b' }, { cheap: "a\\b" }, { cheap: "" }, { cheap: "a b" }, { cheap: 7 }]) {
      expect(upstreamModelsProblem({ price_list: MAPPED.price_list, upstream_models: bad })).toBeDefined();
      expect(() => validateOfferShape({ ...fields, upstream_models: bad })).toThrow(/upstream_models/);
    }
  });

  it("the body ends with the suffix pinning the provider's id", () => {
    const params = { model: PUBLIC, messages: [{ role: "user" as const, content: "x" }] };
    const body = new TextDecoder().decode(buildPinnedBody(params as never, pinnedModelId(MAPPED, PUBLIC), 20, VENICE_CHAT));
    expect(body.endsWith(canonicalSuffix(VENICE_CHAT, PROVIDER, 20))).toBe(true);
    expect(body).not.toContain(`"model":"${PUBLIC}"`);
  });

  it("a receipt must name the public id and the pinned provider id", () => {
    const check = (ConfidentialConnection.prototype as any).checkPinnedModel as (cur: unknown, receipt: unknown) => void;
    const cur = { model: PUBLIC, offer: MAPPED };
    expect(() => check.call({}, cur, { model: PUBLIC, upstream_model: PROVIDER })).not.toThrow();
    expect(() => check.call({}, cur, { model: PUBLIC })).toThrow(ReceiptVerificationError);
    expect(() => check.call({}, cur, { model: PUBLIC, upstream_model: "moonshotai/other" })).toThrow(ReceiptVerificationError);
    expect(() => check.call({}, cur, { model: PROVIDER, upstream_model: PROVIDER })).toThrow(ReceiptVerificationError);
    expect(() => check.call({}, { model: "cheap", offer: MAPPED }, { model: "cheap" })).not.toThrow();
    expect(() => check.call({}, { model: PUBLIC, offer: MAPPED, image: {} }, { model: PUBLIC })).not.toThrow();
  });
});
