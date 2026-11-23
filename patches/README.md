# Patches for routstr-confidential (wasm32 support)

`routstr-confidential-wasm32.patch` makes the `twopc` and `zkbench` crates
build and run on `wasm32-unknown-unknown` (single-threaded, browser event
loop) without changing their behaviour natively. It applies to
`jooray/routstr-confidential` at 401d21f (branch `main`, protocol v3
with the key schedule `split-public-2`; the base is recorded in
`crates/vendor/UPSTREAM`), and `git apply` of it there reproduces
`crates/vendor/twopc` byte for byte:

```bash
cd routstr-confidential && git checkout 401d21f && git apply -p1 ../routstr-confidential-web/patches/routstr-confidential-wasm32.patch
cargo test --release -p twopc -p zkbench        # unchanged natively
cargo check --target wasm32-unknown-unknown -p twopc -p zkbench   # needs the getrandom cfg below
```

All three crates are vendored from 401d21f: `cu-crypto` is a plain copy (it
needs no change), and `twopc` and `zkbench` are 401d21f's with this patch (the
mpz2 pin `eaca5f9` is upstream's). There are no other differences.
`node scripts/vendor-check.mjs <routstr-confidential checkout>` (`npm run
check:vendor` with `CU_UPSTREAM_DIR`) checks that, byte for byte, and CI runs it
against a clone of `jooray/routstr-confidential`. `zkbench`'s `build.rs` (it
records a commit for `cu-prover --version`, a binary the wasm does not contain)
is built with `CU_BUILD_COMMIT=client-wasm` (`scripts/build-wasm.sh`), so the
wasm does not depend on this checkout's HEAD.

`cu-crypto`'s software GHASH (`aesgcm::gfmul`) runs in the wasm only in
`fixturesV2()` (zkbench's proof fixtures for benchmarks, built from fixed test
keys). The client's TLS records are sealed and opened by the TLS fork in
JavaScript (WebCrypto AES-GCM), the proof statements recompute no GCM tag
(`zkbench/src/statements.rs`, CTR keystream only), and `twopc` uses
`cu-crypto` for HKDF in the circuits and AES-GCM only in its native tests. The branch-free multiply (upstream c1ec95a) is vendored
all the same.

This repository vendors the patched crates in `crates/vendor/`. To re-vendor
after a change upstream: copy `crypto/{cu-crypto,twopc,zkbench}` (without
`target/` and `zkbench/Cargo.lock`) from a tree with this patch applied, or
regenerate the patch from the merged result with
`git diff --no-index` against the pristine crates, and check that applying it
to the new base reproduces `crates/vendor/` exactly.

What it changes:

1. **`src/rt.rs`** (new, same file in both crates): `spawn`, `spawn_blocking`,
   `sleep`, `timeout`, `JoinHandle`, `Instant`. Natively these are tokio's;
   on wasm32 `spawn` is `wasm_bindgen_futures::spawn_local` (abortable, with a
   oneshot for the result), `spawn_blocking` runs inline, timers are
   `gloo-timers`, and `Instant` is `web_time::Instant` (`std::time::Instant`
   panics on wasm32-unknown-unknown).
2. **`mux.rs`** (both crates): `tokio::spawn`/`tokio::time::timeout` → `rt::`.
   tokio's `duplex`, `mpsc`, `split` and `select!` stay: they are
   executor-agnostic.
3. **`twopc/src/lib.rs`**: `tokio::task::spawn_blocking` → `rt::spawn_blocking`
   (4×), `tokio::spawn`/`sleep` → `rt::`, `std::time::Instant` → `rt::Instant`,
   and the node-side `std::thread::scope` for the per-stage check rows
   (five stages) becomes `scope_n` (threads natively, sequential on wasm).
   `testutil` is native-only. (`gc.rs`'s check-row tweak range check, which
   an earlier patch made compile on 32-bit targets, is upstream since 9842a20.)
4. **`zkbench`**: `channel.rs` uses `rt::Instant` and `rt::timeout` (the
   hello timeout); `proofs.rs` spawns with
   `rt::spawn`; the emulated `transport` module and `run_pair_transport`
   (benchmarks, need tokio timers) are native-only.
5. **Cargo.toml** (both): tokio is `["sync","macros","io-util"]` everywhere and
   `["full"]` only on non-wasm targets; wasm32 adds `wasm-bindgen-futures`,
   `gloo-timers` (and `getrandom` 0.3 `wasm_js` in twopc); `web-time` for all.

A wasm consumer must also select the getrandom backend for 0.3/0.4 with
`--cfg getrandom_backend="wasm_js"` (see `.cargo/config.toml` here) and enable
`getrandom` 0.2 `js`, 0.3/0.4 `wasm_js` (see `crates/client-wasm/Cargo.toml`).
mpz2 at rev eaca5f9 needs no change.

The vendored `twopc`'s test `hash_vectors_match_conformance_file` reads
`crates/vendor/conformance/twopc-hash-vectors.json`, a symlink to the shared
vector file `test/fixtures/twopc-hash-vectors.json` (a byte-identical copy of
`crypto/conformance/twopc-hash-vectors.json`); `crates/client-wasm/tests/twopc_vectors.rs`
checks the same vectors natively and on wasm32.
