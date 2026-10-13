#!/usr/bin/env bash
# Build crates/client-wasm for the browser into wasm/pkg.
# Needs: rustup (toolchain from rust-toolchain.toml, wasm32 target),
# wasm-bindgen-cli matching Cargo.lock (cargo install wasm-bindgen-cli --version 0.2.129 --locked)
# and `npm ci` (wasm-opt from the pinned binaryen devDependency).
#
# The output is meant to be byte-reproducible from the same sources and tool
# versions on the same host platform (the reference is x86_64-linux, CI's
# ubuntu-24.04; rustc's crate hashes and codegen depend on the host): host
# paths (the checkout, CARGO_HOME) are remapped out of the binary, the
# lockfile is enforced, and wasm-opt is the pinned one.
# CI (.github/workflows/wasm.yml) rebuilds and compares with the committed
# wasm/pkg. Set WASM_OPT to override the optimizer (the result then differs).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/wasm/pkg"
export PATH="$HOME/.cargo/bin:$PATH"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
cd "$ROOT"
# Arrays given with --config are appended to .cargo/config.toml's rustflags.
cargo build --locked --release --target wasm32-unknown-unknown -p client-wasm \
  --config "target.wasm32-unknown-unknown.rustflags=[\"--remap-path-prefix=$CARGO_HOME_DIR=/cargo\", \"--remap-path-prefix=$ROOT=/build\"]"
WB_VER=$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | sed -n 's/version = "\(.*\)"/\1/p')
if ! wasm-bindgen --version 2>/dev/null | grep -q "$WB_VER"; then
  echo "wasm-bindgen-cli $WB_VER required: cargo install wasm-bindgen-cli --version $WB_VER --locked" >&2
  exit 1
fi
rm -rf "$OUT"; mkdir -p "$OUT"
wasm-bindgen --target web --out-dir "$OUT" --out-name client_wasm \
  target/wasm32-unknown-unknown/release/client_wasm.wasm
WASM_OPT="${WASM_OPT:-}"
if [ -z "$WASM_OPT" ] && [ -x "$ROOT/node_modules/.bin/wasm-opt" ]; then WASM_OPT="$ROOT/node_modules/.bin/wasm-opt"; fi
if [ -n "$WASM_OPT" ]; then
  "$WASM_OPT" -O3 --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext --enable-mutable-globals --enable-simd \
    "$OUT/client_wasm_bg.wasm" -o "$OUT/client_wasm_bg.opt.wasm" && mv "$OUT/client_wasm_bg.opt.wasm" "$OUT/client_wasm_bg.wasm"
else
  echo "warning: wasm-opt not found (run npm ci); the output is not the release build" >&2
fi
ls -la "$OUT"
shasum -a 256 "$OUT"/* 2>/dev/null || sha256sum "$OUT"/*
