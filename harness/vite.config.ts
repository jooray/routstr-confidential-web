// Test harness (not shipped): the library's wasm benchmark against a local
// bench-node and the TLS diagnostic, built from the library's dist/.
import { defineConfig } from "vite";

export default defineConfig({
  root: new URL(".", import.meta.url).pathname,
  base: "./",
  worker: { format: "es" },
  build: { target: "es2022", outDir: "dist", emptyOutDir: true, assetsInlineLimit: 0, chunkSizeWarningLimit: 2000 },
});
