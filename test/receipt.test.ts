import { describe, expect, it } from "vitest";
import { canonicalJson } from "../src/canonical.js";
import { bytesToHex } from "@noble/hashes/utils";
import { ReceiptVerificationError } from "../src/errors.js";
import {
  checkAttestationBinding,
  checkUpstreamErrorReceipt,
  feeOnlyChargeOk,
  maxChargeMsats,
  errorStatusChargeMsat,
  parseSignedReceipt,
  verifyReceipt,
} from "../src/receipt.js";
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

  it("bounds the charge for an upstream error receipt", () => {
    const err = (status: unknown, extra: Record<string, unknown> = {}) =>
      ({ sid: "s1", model: "m", usage: { error_status: status }, ...extra }) as never;
    // 4xx / 503: at most the session fee.
    expect(checkUpstreamErrorReceipt(err(429, { cost_msats: 0 }), 429, 0)).toBe(true);
    expect(checkUpstreamErrorReceipt(err(503, { cost_msats: 2000 }), 503, 2000)).toBe(true);
    expect(() => checkUpstreamErrorReceipt(err(503, { cost_msats: 2001, reserved_msats: 9000 }), 503, 2000)).toThrow(
      ReceiptVerificationError,
    );
    // Other 5xx: at most the reservation the receipt names.
    expect(checkUpstreamErrorReceipt(err(500, { cost_msats: 9000, reserved_msats: 9000 }), 500, 0)).toBe(true);
    expect(() => checkUpstreamErrorReceipt(err(500, { cost_msats: 9001, reserved_msats: 9000 }), 500, 0)).toThrow(
      /reservation/,
    );
    expect(() => checkUpstreamErrorReceipt(err(502, { cost_msats: 1e12 }), 502, 0)).toThrow(/reservation/);
    expect(checkUpstreamErrorReceipt(err(504, { cost_msats: 500 }), 504, 500)).toBe(true);
    expect(() => checkUpstreamErrorReceipt(err(500, { cost_msats: -1, reserved_msats: 9000 }), 500, 0)).toThrow(
      ReceiptVerificationError,
    );
    expect(() =>
      checkUpstreamErrorReceipt(err(500, { cost_msats: 10, reserved_msats: 9000, session_fee_msat: 5 }), 500, 0),
    ).toThrow(/session fee/);
    // The abandon fee it names is bounded by the signed one, as in the SDK.
    expect(() =>
      checkUpstreamErrorReceipt(err(400, { cost_msats: 10, abandon_fee_msat: 2001 }), 400, 100, 2000),
    ).toThrow(/abandon fee/);
    expect(checkUpstreamErrorReceipt(err(400, { cost_msats: 10, abandon_fee_msat: 2000 }), 400, 100, 2000)).toBe(true);
    // The status must be the one we saw, as a number.
    expect(checkUpstreamErrorReceipt(err("500", { cost_msats: 0 }), 500, 0)).toBe(false);
    expect(checkUpstreamErrorReceipt(err(502, { cost_msats: 0 }), 500, 0)).toBe(false);
  });

  it("bounds a rejected request by the abandon fee, a 429/503 by the session fee", () => {
    const err = (status: number, cost: number) => ({ sid: "s1", model: "m", usage: { error_status: status }, cost_msats: cost }) as never;
    // session fee 100, abandon fee 2000
    expect(checkUpstreamErrorReceipt(err(400, 2000), 400, 100, 2000)).toBe(true);
    expect(checkUpstreamErrorReceipt(err(404, 2000), 404, 100, 2000)).toBe(true);
    // Less than the rule allows only favours the client (and a node not yet
    // charging the abandon fee stays usable).
    expect(checkUpstreamErrorReceipt(err(400, 100), 400, 100, 2000)).toBe(true);
    expect(() => checkUpstreamErrorReceipt(err(400, 2001), 400, 100, 2000)).toThrow(ReceiptVerificationError);
    expect(checkUpstreamErrorReceipt(err(429, 100), 429, 100, 2000)).toBe(true);
    expect(checkUpstreamErrorReceipt(err(503, 100), 503, 100, 2000)).toBe(true);
    expect(() => checkUpstreamErrorReceipt(err(429, 2000), 429, 100, 2000)).toThrow(ReceiptVerificationError);
    expect(checkUpstreamErrorReceipt(err(503, 0), 503, 100, 2000)).toBe(true);
    // An abandon fee below the session fee counts as the session fee.
    expect(checkUpstreamErrorReceipt(err(400, 100), 400, 100, 0)).toBe(true);
  });

  it("holds an image session's error receipt to its terms", () => {
    const image = { model: "z", variant: "webp", count: 2, msatPerImage: 12000 };
    const err = (status: number, extra: Record<string, unknown>) =>
      ({ sid: "s1", model: "z", kind: "images", variant: "webp", count: 2, usage: { error_status: status }, ...extra }) as never;
    expect(checkUpstreamErrorReceipt(err(400, { cost_msats: 2000 }), 400, 0, 2000, image)).toBe(true);
    // Another kind, model, variant or count: refused.
    for (const other of [{ kind: undefined }, { model: "y" }, { variant: "1K-webp" }, { count: 1 }]) {
      expect(() => checkUpstreamErrorReceipt(err(400, { cost_msats: 2000, ...other }), 400, 0, 2000, image)).toThrow(/image session/);
    }
    // Other 5xx: at most price × count + abandon fee, even under a larger named reservation.
    expect(checkUpstreamErrorReceipt(err(500, { cost_msats: 26000, reserved_msats: 1e12 }), 500, 0, 2000, image)).toBe(true);
    expect(() => checkUpstreamErrorReceipt(err(500, { cost_msats: 26001, reserved_msats: 1e12 }), 500, 0, 2000, image)).toThrow(
      /image session/,
    );
  });

  it("accepts only a receipt signed for this session and attestation", () => {
    const { priv, pubHex } = makeKey();
    const aJson = '{"sid":"s1","x":1}';
    const receipt = { sid: "s1", model: "m", cost_msats: 5, attestation_hash: hex(sha256(new TextEncoder().encode(aJson))) };
    const receiptJson = canonicalJson(receipt);
    const sig = sign(receiptJson, priv);
    expect(parseSignedReceipt({ receiptJson, sig, pubkey: pubHex, sid: "s1", attestationJson: aJson }).cost_msats).toBe(5);
    expect(() => parseSignedReceipt({ receiptJson, sig: undefined, pubkey: pubHex, sid: "s1", attestationJson: aJson })).toThrow(
      ReceiptVerificationError,
    );
    expect(() =>
      parseSignedReceipt({ receiptJson: receiptJson.replace('"cost_msats":5', '"cost_msats":1'), sig, pubkey: pubHex, sid: "s1", attestationJson: aJson }),
    ).toThrow(ReceiptVerificationError);
    expect(() => parseSignedReceipt({ receiptJson, sig, pubkey: pubHex, sid: "s2", attestationJson: aJson })).toThrow(/not s2/);
    // A signed receipt without an attestation hash is bound to nothing.
    const unbound = canonicalJson({ sid: "s1", model: "m", cost_msats: 5 });
    expect(() =>
      parseSignedReceipt({ receiptJson: unbound, sig: sign(unbound, priv), pubkey: pubHex, sid: "s1", attestationJson: aJson }),
    ).toThrow(/attestation/);
    // No signed rate for the model: no cost is accepted.
    expect(verifyReceipt({ receipt: { sid: "s1", model: "m", cost_msats: 0 } as never, ownUsage: { model: "m", usage: { prompt_tokens: 1, completion_tokens: 1 } } as never }).costWithinOffer).toBe(false);
    expect(() => parseSignedReceipt({ receiptJson, sig, pubkey: pubHex, sid: "s1", attestationJson: "{}" })).toThrow(
      /attestation/,
    );
    expect(bytesToHex(new Uint8Array([1, 255]))).toBe(hex(new Uint8Array([1, 255])));
  });

  it("accepts only an attestation naming this session and handshake", () => {
    const thSH = new Uint8Array(32).fill(7);
    const thSF = new Uint8Array(32).fill(9);
    const own = { sid: "s1", thSH, thSF, cCommit: "ab".repeat(32) };
    const att = (o: Record<string, unknown>) =>
      canonicalJson({ sid: "s1", th_sh: hex(thSH), th_sf: hex(thSF), c_commit: "ab".repeat(32), ...o });
    expect(() => checkAttestationBinding(att({}), own)).not.toThrow();
    // The commitment is always checked: without ours there is nothing to compare.
    expect(() => checkAttestationBinding(att({}), { sid: "s1", thSH, thSF })).toThrow(/commitment/);
    expect(() => checkAttestationBinding(att({ c_commit: null }), own)).toThrow(/commitment/);
    expect(() => checkAttestationBinding(att({ sid: "s2" }), own)).toThrow(/not s1/);
    expect(() => checkAttestationBinding(att({ th_sh: "00".repeat(32) }), own)).toThrow(/handshake/);
    expect(() => checkAttestationBinding(att({ th_sf: null }), own)).toThrow(/handshake/);
    expect(() => checkAttestationBinding(att({}), { sid: "s1" })).toThrow(ReceiptVerificationError);
    expect(() => checkAttestationBinding("null", own)).toThrow(ReceiptVerificationError);
    expect(() => checkAttestationBinding("{", own)).toThrow(/JSON/);
  });

  it("checks the attestation's commitment, certificate hash and upstream byte record against ours", () => {
    const thSH = new Uint8Array(32).fill(7);
    const thSF = new Uint8Array(32).fill(9);
    const chain = new Uint8Array(32).fill(3);
    const recv = new Uint8Array(32).fill(4);
    const own = { sid: "s1", thSH, thSF, cCommit: "ab".repeat(32), certChainHash: chain, serverRecords: 9, recvSha256: recv };
    const att = (o: Record<string, unknown>) =>
      canonicalJson({
        sid: "s1",
        th_sh: bytesToHex(thSH),
        th_sf: bytesToHex(thSF),
        c_commit: "ab".repeat(32),
        cert_chain_hash: bytesToHex(chain),
        server_records: 9,
        sha256_recv: bytesToHex(recv),
        ...o,
      });
    expect(() => checkAttestationBinding(att({}), own)).not.toThrow();
    expect(() => checkAttestationBinding(att({ c_commit: null }), own)).toThrow(/commitment/);
    expect(() => checkAttestationBinding(att({ cert_chain_hash: "00".repeat(32) }), own)).toThrow(/certificate/);
    expect(() => checkAttestationBinding(att({ server_records: 8 }), own)).toThrow(/upstream records/);
    expect(() => checkAttestationBinding(att({ sha256_recv: "00".repeat(32) }), own)).toThrow(/upstream bytes/);
  });

  it("never refuses the node's cached-input charge for float rounding", () => {
    const usage = { prompt_tokens: 10000, completion_tokens: 0, prompt_tokens_details: { cached_tokens: 1 } };
    expect(Math.ceil((1.1 * 9999 + 1.1 * 1) / 1000)).toBe(12); // what the node charges
    expect(maxChargeMsats({ in: 1.1, cached_in: 1.1, out: 0 }, usage)).toBe(12);
    expect(maxChargeMsats({ in: 1.1, out: 0 }, { prompt_tokens: 10000, completion_tokens: 0 })).toBe(11);
  });

  it("bounds prompt-cache writes at the signed cache_write rate (the node's vectors)", () => {
    const rates = { in: 10_000, cached_in: 2_500, cache_write: 12_500, out: 100_000 };
    const venice = {
      prompt_tokens: 1000,
      completion_tokens: 8,
      prompt_tokens_details: { cached_tokens: 200, cache_creation_input_tokens: 600 },
      cache_creation_input_tokens: 600,
    };
    expect(maxChargeMsats(rates, venice)).toBe(10_800);
    const allWritten = { ...venice, prompt_tokens_details: { cache_creation_input_tokens: 1000 } };
    expect(maxChargeMsats(rates, allWritten)).toBe(13_300);
    const { cache_write: _cw, ...old } = rates;
    expect(maxChargeMsats(old, allWritten)).toBe(10_800);
  });

  it("charges the node's own provider-key errors the session fee", () => {
    for (const s of [401, 402, 403, 429, 503]) expect(errorStatusChargeMsat(s, 2000, 5000)).toBe(2000);
    expect(errorStatusChargeMsat(400, 2000, 5000)).toBe(5000);
    expect(errorStatusChargeMsat(500, 2000, 5000)).toBeUndefined();
  });
});
