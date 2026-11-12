/**
 * The small part of `node:crypto` the connection and the pool use, for the
 * browser: an incremental SHA-256 with Node's `update` / `digest` / `copy`
 * shape, and a random UUID.
 */

import { sha256 } from "@noble/hashes/sha2";
import { hex } from "./bytes.js";

export interface Sha256Hash {
  update(data: Uint8Array | string): Sha256Hash;
  digest(): Uint8Array;
  digest(encoding: "hex"): string;
  /** An independent copy of the running state. */
  copy(): Sha256Hash;
}

type NobleHash = ReturnType<typeof sha256.create>;

class Hash implements Sha256Hash {
  constructor(private readonly h: NobleHash = sha256.create()) {}

  update(data: Uint8Array | string): Sha256Hash {
    this.h.update(typeof data === "string" ? new TextEncoder().encode(data) : data);
    return this;
  }

  digest(): Uint8Array;
  digest(encoding: "hex"): string;
  digest(encoding?: "hex"): Uint8Array | string {
    const d = this.h.digest();
    return encoding === "hex" ? hex(d) : d;
  }

  copy(): Sha256Hash {
    return new Hash(this.h.clone());
  }
}

/** `createHash("sha256")` as in Node (only SHA-256). */
export function createHash(algorithm: "sha256"): Sha256Hash {
  if (algorithm !== "sha256") throw new Error(`unsupported hash ${String(algorithm)}`);
  return new Hash();
}

export function randomUUID(): string {
  return globalThis.crypto.randomUUID();
}
