# Patches for routstr-confidential (wasm32 support)

`routstr-confidential-wasm32.patch` makes the `twopc` and `zkbench` crates
build and run on `wasm32-unknown-unknown` (single-threaded, browser event
loop) without changing their behaviour natively. It applies to
`jooray/routstr-confidential` at `0903e77` (branch `twopc-v2`):

```bash
cd routstr-confidential && git apply -p1 ../routstr-confidential-web/patches/routstr-confidential-wasm32.patch
cargo test --release -p twopc -p zkbench        # unchanged natively
cargo check --target wasm32-unknown-unknown -p twopc -p zkbench   # needs the getrandom cfg below
```

This repository vendors the patched crates in `crates/vendor/` (first commit:
pristine copy; second commit: this patch), so the diff is reviewable in git.

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
4. **`zkbench`**: `channel.rs` uses `rt::Instant`; `proofs.rs` spawns with
   `rt::spawn`; the emulated `transport` module and `run_pair_transport`
   (benchmarks, need tokio timers) are native-only.
5. **Cargo.toml** (both): tokio is `["sync","macros","io-util"]` everywhere and
   `["full"]` only on non-wasm targets; wasm32 adds `wasm-bindgen-futures`,
   `gloo-timers` (and `getrandom` 0.3 `wasm_js` in twopc); `web-time` for all.

A wasm consumer must also select the getrandom backend for 0.3/0.4 with
`--cfg getrandom_backend="wasm_js"` (see `.cargo/config.toml` here) and enable
`getrandom` 0.2 `js`, 0.3/0.4 `wasm_js` (see `crates/client-wasm/Cargo.toml`).
mpz2 at rev 8f89783 needed no change.
