#!/usr/bin/env node
// Checks that crates/vendor is upstream + patches/routstr-confidential-wasm32.patch,
// byte for byte, for every vendored crate, at the upstream commit named in
// crates/vendor/UPSTREAM. Any other difference fails.
//
//   node scripts/vendor-check.mjs <routstr-confidential checkout>
//   CU_UPSTREAM_DIR=<checkout> npm run check:vendor
//
// The checkout must contain the commit (a blobless clone is enough: git
// archive fetches what it needs). What is compared:
//   crates/vendor/{cu-crypto,twopc,zkbench}  with  crypto/{cu-crypto,twopc,zkbench}
//     after `git apply` of the patch (target/ and zkbench/Cargo.lock left out:
//     the workspace's Cargo.lock is this repository's);
//   test/fixtures/twopc-hash-vectors.json (crates/vendor/conformance links to it)
//     with crypto/conformance/twopc-hash-vectors.json.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, lstatSync, rmSync, existsSync, readlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CRATES = ["cu-crypto", "twopc", "zkbench"];
const IGNORED = new Set(["zkbench/Cargo.lock"]);
const PATCH = join(ROOT, "patches", "routstr-confidential-wasm32.patch");

const upstream = process.argv[2] ?? process.env.CU_UPSTREAM_DIR;
if (!upstream) {
  console.error("usage: node scripts/vendor-check.mjs <routstr-confidential checkout> (or CU_UPSTREAM_DIR)");
  process.exit(2);
}
const commit = readFileSync(join(ROOT, "crates", "vendor", "UPSTREAM"), "utf8").trim();
if (!/^[0-9a-f]{7,40}$/.test(commit)) {
  console.error(`crates/vendor/UPSTREAM does not name a commit: ${JSON.stringify(commit)}`);
  process.exit(2);
}

/** Files of `crate` under `dir` (relative paths with "/"), symlinks as links. */
function files(dir, crate, rel = "", out = new Map()) {
  for (const name of readdirSync(join(dir, rel)).sort()) {
    const r = rel ? `${rel}/${name}` : name;
    const p = join(dir, r);
    const st = lstatSync(p);
    if (name === "target" || IGNORED.has(`${crate}/${r}`)) continue;
    if (st.isDirectory()) files(dir, crate, r, out);
    else if (st.isSymbolicLink()) out.set(r, `symlink:${readlinkSync(p)}`);
    else out.set(r, readFileSync(p));
  }
  return out;
}

function same(a, b) {
  return typeof a === "string" || typeof b === "string" ? a === b : Buffer.compare(a, b) === 0;
}

const tmp = mkdtempSync(join(tmpdir(), "vendor-check-"));
let problems = 0;
try {
  const up = resolve(upstream);
  const tar = execFileSync("git", ["-C", up, "archive", "--format=tar", commit, "crypto/cu-crypto", "crypto/twopc", "crypto/zkbench", "crypto/conformance"], {
    maxBuffer: 1 << 30,
  });
  execFileSync("tar", ["-x", "-C", tmp], { input: tar });
  // `git apply` outside a repository applies to the working directory.
  execFileSync("git", ["apply", "-p1", "--whitespace=nowarn", PATCH], { cwd: tmp });
  for (const crate of CRATES) {
    const before = problems;
    const want = files(join(tmp, "crypto", crate), crate);
    const have = files(join(ROOT, "crates", "vendor", crate), crate);
    for (const [f, data] of want) {
      if (!have.has(f)) {
        console.error(`MISSING crates/vendor/${crate}/${f} (upstream ${commit} + patch has it)`);
        problems++;
      } else if (!same(have.get(f), data)) {
        console.error(`DIFFERS crates/vendor/${crate}/${f} from upstream ${commit} + patch`);
        problems++;
      }
    }
    for (const f of have.keys()) {
      if (!want.has(f)) {
        console.error(`EXTRA   crates/vendor/${crate}/${f} (not in upstream ${commit} + patch)`);
        problems++;
      }
    }
    if (problems === before) console.log(`same    crates/vendor/${crate} = upstream ${commit} crypto/${crate} + patch (${want.size} files)`);
  }
  const vectors = join(ROOT, "test", "fixtures", "twopc-hash-vectors.json");
  const upVectors = join(tmp, "crypto", "conformance", "twopc-hash-vectors.json");
  if (!existsSync(upVectors) || !existsSync(vectors) || !same(readFileSync(vectors), readFileSync(upVectors))) {
    console.error(`DIFFERS test/fixtures/twopc-hash-vectors.json from upstream ${commit} crypto/conformance`);
    problems++;
  } else {
    console.log(`same    test/fixtures/twopc-hash-vectors.json = upstream ${commit} crypto/conformance`);
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
if (problems) {
  console.error(`vendor-check: ${problems} undeclared difference(s); re-vendor (patches/README.md) or declare them in the patch`);
  process.exit(1);
}
console.log("vendor-check: crates/vendor is upstream + patch, byte for byte");
