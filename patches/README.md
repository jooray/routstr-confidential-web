# Patches for routstr-confidential (wasm32 support)

`routstr-confidential-wasm32.patch` makes the `twopc` and `zkbench` crates
build and run on `wasm32-unknown-unknown` (single-threaded, browser event
loop) without changing their behaviour natively. It applies to
`jooray/routstr-confidential` at bc3a3d4 (branch `twopc-v2`, the
commit after `5abd8c9`), and `git apply` of it there reproduces
`crates/vendor/` byte for byte (`cu-crypto` needs no change and is a plain
copy):

```bash
cd routstr-confidential && git apply -p1 ../routstr-confidential-web/patches/routstr-confidential-wasm32.patch
cargo test --release -p twopc -p zkbench        # unchanged natively
cargo check --target wasm32-unknown-unknown -p twopc -p zkbench   # needs the getrandom cfg below
```

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
   and the node-side `std::thread::scope` for the two phases' check rows
   becomes `scope2` (threads natively, sequential on wasm). `testutil` is
   native-only.
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
mpz2 at rev 8f89783 needed no change.
