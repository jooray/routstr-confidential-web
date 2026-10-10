import { describe, expect, it } from "vitest";
import { canonicalJson } from "../src/canonical.js";
import { bytesToHex } from "@noble/hashes/utils";
import { ReceiptVerificationError } from "../src/errors.js";
import { feeOnlyChargeOk, maxChargeMsats, parseSignedReceipt, verifyReceipt } from "../src/receipt.js";
import { hex, sha256 } from "../src/bytes.js";
import { makeKey, sign } from "./helpers.js";

const ownUsage = { model: "m", usage: { prompt_tokens: 9, completion_tokens: 1 } };
const base = { sid: "abc", model: "m", usage: { ...ownUsage }, reserved_msats: 20000 };

describe("receipt verification", () => {
  it("accepts a signed receipt with matching usage and a fair cost", () => {
    const { priv, pubHex } = makeKey();
    const receipt = { ...base, cost_msats: 10 };
    const json = canonicalJson(receipt);
    const r = verifyReceipt({
      receipt: receipt as never,
      receiptJson: json,
      sig: sign(json, priv),
      pubkey: pubHex,
      ownUsage,
      priceEntry: { in: 1000, out: 1000 },
    });
    expect(r).toEqual({ receiptSigOk: true, usageMatch: true, costWithinOffer: true });
  });

  it("flags a cost above the signed rates, a usage mismatch and a bad signature", () => {
    expect(
      verifyReceipt({ receipt: { ...base, cost_msats: 11 } as never, ownUsage, priceEntry: { in: 1000, out: 1000 } })
        .costWithinOffer,
    ).toBe(false);
    const other = { ...base, usage: { model: "m", usage: { prompt_tokens: 99, completion_tokens: 1 } } };
    expect(verifyReceipt({ receipt: other as never, ownUsage }).usageMatch).toBe(false);
    const json = canonicalJson(base);
    expect(
      verifyReceipt({ receipt: base as never, receiptJson: json, sig: "00".repeat(64), pubkey: makeKey().pubHex, ownUsage })
        .receiptSigOk,
    ).toBe(false);
  });

  it("allows the signed session fee on top of the usage, never more", () => {
    const priceEntry = { in: 1000, out: 1000 };
    expect(maxChargeMsats(priceEntry, ownUsage.usage, 2000)).toBe(2010);
    const v = (cost: number, fee?: number, named?: number) =>
      verifyReceipt({
        receipt: { ...base, cost_msats: cost, ...(named !== undefined ? { session_fee_msat: named } : {}) } as never,
        ownUsage,
        priceEntry,
        sessionFeeMsat: fee,
      }).costWithinOffer;
    expect(v(2010, 2000, 2000)).toBe(true);
    expect(v(2011, 2000, 2000)).toBe(false);
    expect(v(2010)).toBe(false);
    expect(v(10, 2000, 5000)).toBe(false);
    expect(feeOnlyChargeOk(0, 0)).toBe(true);
    expect(feeOnlyChargeOk(1, 0)).toBe(false);
    expect(feeOnlyChargeOk(2000, 2000)).toBe(true);
  });

  it("accepts only a receipt signed for this session and attestation", () => {
    const { priv, pubHex } = makeKey();
    const aJson = '{"sid":"s1","x":1}';
    const receipt = { sid: "s1", model: "m", cost_msats: 5, attestation_hash: hex(sha256(new TextEncoder().encode(aJson))) };
    const receiptJson = canonicalJson(receipt);
    const sig = sign(receiptJson, priv);
    expect(parseSignedReceipt({ receiptJson, sig, pubkey: pubHex, sid: "s1", attestationJson: aJson }).cost_msats).toBe(5);
    expect(() => parseSignedReceipt({ receiptJson, sig: undefined, pubkey: pubHex, sid: "s1" })).toThrow(
      ReceiptVerificationError,
    );
    expect(() =>
      parseSignedReceipt({ receiptJson: receiptJson.replace('"cost_msats":5', '"cost_msats":1'), sig, pubkey: pubHex, sid: "s1" }),
    ).toThrow(ReceiptVerificationError);
    expect(() => parseSignedReceipt({ receiptJson, sig, pubkey: pubHex, sid: "s2" })).toThrow(/not s2/);
    expect(() => parseSignedReceipt({ receiptJson, sig, pubkey: pubHex, sid: "s1", attestationJson: "{}" })).toThrow(
      /attestation/,
    );
    expect(bytesToHex(new Uint8Array([1, 255]))).toBe(hex(new Uint8Array([1, 255])));
  });
});
