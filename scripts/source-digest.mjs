#!/usr/bin/env node
// Recomputes the source digest that crates/client-wasm/build.rs embeds in the
// wasm's buildInfo() ("src:<digest>"), from the files in this checkout.
//   node scripts/source-digest.mjs           print the digest
//   node scripts/source-digest.mjs --check   exit 1 unless wasm/pkg was built from this tree
// Keep SOURCES and the hashing in step with build.rs.
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

export const SOURCES = [
  ".cargo/config.toml",
  "Cargo.lock",
  "Cargo.toml",
  "rust-toolchain.toml",
  "crates/client-wasm/Cargo.toml",
  "crates/client-wasm/build.rs",
  "crates/client-wasm/src",
  "crates/vendor/UPSTREAM",
  "crates/vendor/cu-crypto",
  "crates/vendor/twopc",
  "crates/vendor/zkbench",
];

function walk(root, rel, out) {
  const p = join(root, rel);
  if (!existsSync(p)) return;
  const st = statSync(p);
  if (st.isDirectory()) {
    const names = readdirSync(p)
      .filter((n) => !n.startsWith(".") && n !== "target")
      .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    for (const n of names) walk(root, `${rel}/${n}`, out);
  } else if (st.isFile()) {
    out.push(rel);
  }
}

/** The 16-hex-digit source digest of the tree at `root`. */
export function sourceDigest(root = ROOT) {
  const files = [];
  for (const s of SOURCES) walk(root, s, files);
  const uniq = [...new Set(files)].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const h = createHash("sha256");
  for (const f of uniq) {
    const data = readFileSync(join(root, f));
    const len = Buffer.alloc(8);
    len.writeBigUInt64BE(BigInt(data.length));
    h.update(Buffer.from(f, "utf8"));
    h.update(Buffer.from([0]));
    h.update(len);
    h.update(data);
  }
  return h.digest("hex").slice(0, 16);
}

/** The buildInfo string embedded in a wasm binary, if any. */
export function embeddedBuildInfo(wasm) {
  const m = /client-wasm [0-9.]+ \(protocol v2; routstr-confidential@[^,]*, mpz2@[^,]*, src:[0-9a-f]{16}\)/.exec(
    Buffer.from(wasm).toString("latin1"),
  );
  return m?.[0];
}

/** The buildInfo string embedded in the committed wasm/pkg binary, if any. */
export function committedBuildInfo(root = ROOT) {
  return embeddedBuildInfo(readFileSync(join(root, "wasm/pkg/client_wasm_bg.wasm")));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const digest = sourceDigest();
  if (process.argv.includes("--check")) {
    const info = committedBuildInfo();
    if (!info?.endsWith(`src:${digest})`)) {
      console.error(`wasm/pkg was not built from this tree: source digest ${digest}, wasm says ${info ?? "nothing"}`);
      process.exit(1);
    }
    console.log(info);
  } else {
    console.log(digest);
  }
}
