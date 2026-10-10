import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import { canonicalJson } from "../src/canonical.js";

export function makeKey(fill = 7) {
  const priv = new Uint8Array(32).fill(fill);
  return { priv, pubHex: bytesToHex(schnorr.getPublicKey(priv)) };
}

export function sign(payload: string, priv: Uint8Array): string {
  return bytesToHex(schnorr.sign(sha256(utf8ToBytes(payload)), priv));
}

/** An offer signed the way the node signs it: BIP-340 over sha256(canonical JSON). */
export function signedOffer(overrides: Record<string, unknown> = {}, keyFill = 7) {
  const { priv, pubHex } = makeKey(keyFill);
  const offer: Record<string, unknown> = {
    v: 2,
    min_v: 2,
    max_v: 2,
    upstream_host: "api.venice.ai",
    ws: "wss://node.example/v1/confidential/ws",
    notary_pubkey: pubHex,
    max_tokens_cap: 4096,
    key_length: 63,
    key_alphabet: "[A-Za-z0-9_-]",
    head_template:
      "POST /api/v1/chat/completions HTTP/1.1\r\nHost: api.venice.ai\r\nAuthorization: Bearer {KEY:63}\r\nContent-Length: {LEN}\r\n\r\n",
    suffix_keys: ["model", "max_tokens", "stream"],
    price_list: {
      cheap: { in: 1000, cached_in: 100, out: 2000 },
      dear: { in: 2000, cached_in: 2000, out: 4000 },
    },
    ...overrides,
  };
  const payload = canonicalJson(offer);
  return { offer: { ...offer, sig_payload: payload, sig: sign(payload, priv) }, priv, pubHex };
}
