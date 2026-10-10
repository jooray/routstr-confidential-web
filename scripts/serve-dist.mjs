// Minimal static server for apps/demo-pwa/dist (used by the browser tests).
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../apps/demo-pwa/dist/", import.meta.url));
const types = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".wasm": "application/wasm",
  ".json": "application/json",
  ".webmanifest": "application/manifest+json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
};

export function serveDist(port = 4173) {
  const server = createServer(async (req, res) => {
    try {
      let p = decodeURIComponent(new URL(req.url ?? "/", "http://x").pathname);
      if (p.endsWith("/")) p += "index.html";
      const file = normalize(join(root, p));
      if (!file.startsWith(root)) throw new Error("outside root");
      await stat(file);
      res.writeHead(200, {
        "content-type": types[extname(file)] ?? "application/octet-stream",
        "cache-control": p.endsWith("version.json") || p.endsWith("sw.js") ? "no-store" : "no-cache",
      });
      res.end(await readFile(file));
    } catch {
      res.writeHead(404);
      res.end("not found");
    }
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve(server)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.argv[2] ?? 4173);
  await serveDist(port);
  console.log(`serving apps/demo-pwa/dist on http://127.0.0.1:${port}/`);
}
