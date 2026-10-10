// wasm vs native timings in real browsers (headless), against a local
// bench-node (start it first: target/release/bench-node serve --port 7450).
//   node scripts/browser-bench.mjs [chromium,firefox,webkit] [runs]
import { chromium, firefox, webkit } from "playwright";
import { serveDist } from "./serve-dist.mjs";

const engines = (process.argv[2] ?? "chromium,firefox,webkit").split(",");
const runs = Number(process.argv[3] ?? 2);
const server = await serveDist(4173);
const all = { chromium, firefox, webkit };
for (const name of engines) {
  const browser = await all[name].launch();
  const page = await browser.newPage();
  page.on("console", (m) => m.type() === "error" && console.error(`[${name}] ${m.text()}`));
  await page.goto(`http://127.0.0.1:4173/index.html?node=ws://127.0.0.1:7450&runs=${runs}`);
  try {
    await page.waitForFunction(() => window.__bench || window.__benchError, null, { timeout: 600_000 });
    const err = await page.evaluate(() => window.__benchError);
    if (err) console.log(JSON.stringify({ engine: name, error: err }));
    else for (const r of await page.evaluate(() => window.__bench)) console.log(JSON.stringify({ engine: name, ...r }));
  } catch (e) {
    console.log(JSON.stringify({ engine: name, error: String(e) }));
  }
  await browser.close();
}
server.close();
