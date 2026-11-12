// Test harness (not shipped): the library's wasm benchmark against a local
// bench-node, the TLS diagnostic, and the protocol-v3 live check
// (live.html), built from the library's dist/.
import { defineConfig } from "vite";

export default defineConfig({
  root: new URL(".", import.meta.url).pathname,
  base: "./",
  worker: { format: "es" },
  build: {
    target: "es2022",
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 2000,
    rollupOptions: {
      input: {
        index: new URL("index.html", import.meta.url).pathname,
        live: new URL("live.html", import.meta.url).pathname,
      },
    },
  },
});
