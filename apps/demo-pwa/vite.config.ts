import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { createHash } from "node:crypto";
import { defineConfig, type Plugin } from "vite";

const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")) as { version: string };
const VERSION = pkg.version;
const BUILD = new Date().toISOString();

/**
 * Release versioning for the PWA (house rule: every release is versioned and
 * the app refreshes itself, never relying on a hard refresh):
 *  - `version.json` {version, build, assets_sha256} is fetched (no-store) on load,
 *    on focus and every 5 minutes; a different version triggers an update;
 *  - `sw.js` is regenerated per build with the version in its cache name and
 *    the exact asset list; it installs with skipWaiting + clients.claim and
 *    the page reloads on `controllerchange`.
 */
function pwaRelease(): Plugin {
  let outDir = "dist";
  return {
    name: "pwa-release",
    configResolved(c) {
      outDir = c.build.outDir;
    },
    closeBundle() {
      const files: string[] = [];
      const walk = (d: string) => {
        for (const f of readdirSync(d)) {
          const p = join(d, f);
          if (statSync(p).isDirectory()) walk(p);
          else files.push(relative(outDir, p).split("\\").join("/"));
        }
      };
      walk(outDir);
      const assets = files.filter((f) => f !== "sw.js" && f !== "version.json").sort();
      const h = createHash("sha256");
      for (const f of assets) h.update(f).update(readFileSync(join(outDir, f)));
      const digest = h.digest("hex");
      writeFileSync(
        join(outDir, "version.json"),
        JSON.stringify({ version: VERSION, build: BUILD, assets_sha256: digest }, null, 2) + "\n",
      );
      const sw = readFileSync(new URL("./src/sw-template.js", import.meta.url), "utf8")
        .replace("__VERSION__", JSON.stringify(VERSION))
        .replace("__BUILD__", JSON.stringify(digest.slice(0, 16)))
        .replace("__ASSETS__", JSON.stringify(["./", ...assets.map((a) => `./${a}`)]));
      writeFileSync(join(outDir, "sw.js"), sw);
    },
  };
}

export default defineConfig({
  base: "./",
  define: {
    __APP_VERSION__: JSON.stringify(VERSION),
    __APP_BUILD__: JSON.stringify(BUILD),
  },
  worker: { format: "es" },
  optimizeDeps: { exclude: ["@routstr/confidential-web"] },
  build: {
    target: "es2022",
    outDir: "dist",
    assetsInlineLimit: 0,
    sourcemap: false,
    chunkSizeWarningLimit: 1500,
    rollupOptions: { input: { main: "index.html", bench: "bench.html" } },
  },
  server: { port: 5173 },
  plugins: [pwaRelease()],
});
