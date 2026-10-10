// Build the library for consumers: tsc (JS + .d.ts) into dist/, plus the
// vendored TLS client (plain JS with .d.ts) copied as is. The wasm stays in
// wasm/pkg/ (committed; rebuild with `npm run build:wasm`), which
// dist/wasm/host.js imports as ../../wasm/pkg/client_wasm.js.
import { cpSync, existsSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";

const root = new URL("../", import.meta.url).pathname;
if (!existsSync(`${root}wasm/pkg/client_wasm_bg.wasm`)) {
  console.error("wasm/pkg is missing: run `npm run build:wasm` (Rust toolchain + wasm-bindgen-cli)");
  process.exit(1);
}
rmSync(`${root}dist`, { recursive: true, force: true });
const tsc = createRequire(import.meta.url).resolve("typescript/bin/tsc");
execFileSync(process.execPath, [tsc, "-p", `${root}tsconfig.build.json`], { stdio: "inherit" });
cpSync(`${root}src/tls-fork`, `${root}dist/tls-fork`, { recursive: true });
console.log("built dist/");
