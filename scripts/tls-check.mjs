// The browser TLS stack against the real provider (cert chain, hostname,
// TLS 1.3 records) through the test-only relay (node scripts/ws-tcp-relay.mjs).
//   node scripts/tls-check.mjs [chromium,firefox,webkit]
import { chromium, firefox, webkit } from "playwright";
import { serveDist } from "./serve-dist.mjs";
const server = await serveDist(4175);
let bad = false;
for (const name of (process.argv[2] ?? "chromium,firefox,webkit").split(",")) {
  const b = await { chromium, firefox, webkit }[name].launch();
  const p = await b.newPage();
  await p.goto("http://127.0.0.1:4175/bench.html?tls=ws://127.0.0.1:7451&host=api.venice.ai");
  await p.waitForFunction(() => window.__tls, null, { timeout: 30_000 });
  const r = await p.evaluate(() => window.__tls);
  if (!r.ok) bad = true;
  console.log(JSON.stringify({ engine: name, ...r }));
  await b.close();
}
server.close();
process.exit(bad ? 1 : 0);
