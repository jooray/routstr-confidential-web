// Protocol-v3 live check in headless browsers: harness/live.html (the library
// from dist/, the wasm in its Web Worker) against a local node on a real
// provider. Cases as scripts/live-v3.mjs: chat-2 (five requests on one
// framing-"2" connection, CONF_PAUSE_MS apart, the proof channel topped up in
// between), error-head (a provider 400 disclosed from its record's byte 0), chat-1.1 (HTTP/2 off), image (one, the cheapest
// variant; real money), refused (402, top-up, the same request again on the
// same connection).
//
//   npm run build && npm run harness:build
//   CONF_NODE=http://127.0.0.1:8451 CONF_KEY=sk-… [CONF_LOW_KEY=sk-… CONF_TOPUP_CMD="…"] \
//     CONF_MODEL=… CONF_IMAGE_MODEL=… ENGINE=chromium node scripts/browser-live-v3.mjs chat-2 chat-1.1 image refused
//
// Keys come from the environment, go to the page in an evaluate() argument
// (never a URL) and are never printed.
import { execSync } from "node:child_process";
import { chromium, firefox, webkit } from "playwright";
import { serveDist } from "./serve-dist.mjs";

const node = process.env.CONF_NODE ?? "http://127.0.0.1:8451";
const key = process.env.CONF_KEY;
if (!key) throw new Error("CONF_KEY is not set");
const model = process.env.CONF_MODEL ?? "mistral-small-3-2-24b-instruct";
const imageModel = process.env.CONF_IMAGE_MODEL ?? "venice-sd35";
const engine = process.env.ENGINE ?? "chromium";
const cases = process.argv.slice(2).length ? process.argv.slice(2) : ["chat-2", "chat-1.1"];
const port = Number(process.env.HARNESS_PORT ?? 4174);

const pubkey = (await (await fetch(`${node}/v1/confidential/offer?v=3`)).json()).notary_pubkey;
const server = await serveDist(port);
const browser = await { chromium, firefox, webkit }[engine].launch();
const page = await browser.newPage();
page.on("console", (m) => m.type() === "error" && console.error(`[${engine}] ${m.text().slice(0, 300)}`));
await page.goto(`http://127.0.0.1:${port}/live.html`);
await page.waitForFunction(() => window.live !== undefined, null, { timeout: 30_000 });

const rows = [];
const mb = (n) => (typeof n === "number" ? `${(n / 1e6).toFixed(2)}MB` : "");
const push = (name, r) =>
  rows.push({
    case: name,
    framing: r.framing,
    n: r.n,
    sid: r.sid,
    found: r.found,
    status: r.status,
    ttft_ms: r.ttftMs,
    total_ms: r.totalMs,
    up: mb(r.sent),
    down: mb(r.recv),
    zk_down: r.zkRecv,
    setup_up: mb(r.setupSent),
    setup_down: mb(r.setupRecv),
    cost_msat: r.costMsats,
    deposit_released: r.depositReleased ?? "",
    alpn: r.alpn,
    proofs: Object.entries(r.proofs).map(([k, v]) => `${k}${v.runs > 1 ? `×${v.runs}` : ""}:${v.via}`).join(" "),
    note: r.note,
  });
const cfg = (http, k = key) => ({ node, pubkey, key: k, model, http });

for (const name of cases) {
  try {
    if (name === "chat-2") {
      const pause = Number(process.env.CONF_PAUSE_MS ?? 2000);
      for (let i = 1; i <= 5; i++) {
        if (i > 1) await new Promise((res) => setTimeout(res, pause));
        push(name, await page.evaluate(([c, i]) => window.live.chat(c, `Say the number ${i} in one word.`), [cfg("2"), i]));
      }
    } else if (name === "error-head") {
      const r = await page.evaluate((c) => window.live.chat(c, "Say no.", "err", { temperature: "hot" }), cfg("2"));
      push(name, r);
      if (!(r.status >= 400)) throw new Error(`expected a provider error, got ${r.status}`);
    } else if (name === "chat-1.1") {
      push(name, await page.evaluate((c) => window.live.chat(c, "Say hello in one word."), cfg("1.1")));
    } else if (name === "image") {
      push(name, await page.evaluate((c) => window.live.image(c), { ...cfg("auto"), imageModel }));
    } else if (name === "refused") {
      const low = process.env.CONF_LOW_KEY;
      if (!low || !process.env.CONF_TOPUP_CMD) throw new Error("CONF_LOW_KEY and CONF_TOPUP_CMD are needed");
      const r = await page.evaluate((c) => window.live.refused(c, "low"), cfg("auto", low));
      rows.push({ case: name, status: r.status, note: `refused=${r.refused} ${r.reason ?? ""}; pool ${JSON.stringify(r.pool)}` });
      if (!r.refused) throw new Error("the request was not refused");
      execSync(process.env.CONF_TOPUP_CMD, { stdio: "ignore" });
      push(name, await page.evaluate((c) => window.live.chat(c, "Say yes.", "low"), cfg("auto", low)));
    } else throw new Error(`unknown case ${name}`);
  } catch (e) {
    rows.push({ case: name, status: "FAIL", note: String(e?.message ?? e).slice(0, 300) });
  }
}
const events = await page.evaluate(() => window.live.events());
await page.evaluate(() => window.live.close());
console.log(`engine: ${engine} (${browser.version()})`);
console.table(rows);
for (const e of events) if (["deposit", "request_refused", "framing_fallback", "certificate_verified"].includes(e.ev)) console.log(JSON.stringify(e));
const tops = events.filter((e) => e.ev === "topup");
if (tops.length) console.log(`top-ups (off the request path): ${tops.length}, ${tops.reduce((a, t) => a + t.bytes, 0)} B`);
await browser.close();
server.close();
process.exit(rows.some((r) => r.status === "FAIL") ? 1 : 0);
