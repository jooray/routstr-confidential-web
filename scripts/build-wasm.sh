#!/usr/bin/env bash
# Build crates/client-wasm for the browser into packages/confidential-web/wasm/pkg.
# Needs: rustup (toolchain from rust-toolchain.toml, wasm32 target) and
# wasm-bindgen-cli matching Cargo.lock (cargo install wasm-bindgen-cli --version 0.2.129 --locked).
# wasm-opt (binaryen) is used when available (npm i -g binaryen, or brew).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/packages/confidential-web/wasm/pkg"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
cargo build --release --target wasm32-unknown-unknown -p client-wasm
WB_VER=$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | sed -n 's/version = "\(.*\)"/\1/p')
if ! wasm-bindgen --version 2>/dev/null | grep -q "$WB_VER"; then
  echo "wasm-bindgen-cli $WB_VER required: cargo install wasm-bindgen-cli --version $WB_VER --locked" >&2
  exit 1
fi
rm -rf "$OUT"; mkdir -p "$OUT"
wasm-bindgen --target web --out-dir "$OUT" --out-name client_wasm \
  target/wasm32-unknown-unknown/release/client_wasm.wasm
WASM_OPT="${WASM_OPT:-$(command -v wasm-opt || true)}"
if [ -z "$WASM_OPT" ] && [ -x "$ROOT/node_modules/.bin/wasm-opt" ]; then WASM_OPT="$ROOT/node_modules/.bin/wasm-opt"; fi
if [ -n "$WASM_OPT" ]; then
  "$WASM_OPT" -O3 --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext --enable-mutable-globals --enable-simd \
    "$OUT/client_wasm_bg.wasm" -o "$OUT/client_wasm_bg.opt.wasm" && mv "$OUT/client_wasm_bg.opt.wasm" "$OUT/client_wasm_bg.wasm"
else
  echo "note: wasm-opt not found; skipping size/speed optimisation" >&2
fi
ls -la "$OUT"
