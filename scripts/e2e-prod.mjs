// End-to-end test of the demo PWA in a real (headless) browser against the
// production node https://routstr.cypherpunk.today.
//
//   node scripts/e2e-prod.mjs smoke            no credential: offer fetch and
//        verification, model list, PWA (service worker, version.json), and a
//        session with an invalid key, which the node must refuse at setup.
//   CONF_TEST_KEY=sk-... node scripts/e2e-prod.mjs live [messages]
//        a funded key, read from the environment only (never logged): one cold
//        request (?prewarm=0), then pre-warmed requests; prints the verified
//        results (timings, proofs, receipt, provider certificate).
//
// Build first: npm run build (wasm + library + demo).
import { chromium, firefox, webkit } from "playwright";
import { serveDist } from "./serve-dist.mjs";

const mode = process.argv[2] ?? "smoke";
const engineName = process.env.ENGINE ?? "chromium";
const engine = { chromium, firefox, webkit }[engineName];
const PORT = 4173;
const BASE = `http://127.0.0.1:${PORT}/`;
const server = await serveDist(PORT);
const browser = await engine.launch();
let failed = false;
const fail = (msg) => {
  failed = true;
  console.log(`FAIL ${msg}`);
};
const ok = (msg) => console.log(`ok   ${msg}`);

async function open(query = "") {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  page.on("pageerror", (e) => console.log(`[pageerror] ${e.message}`));
  await page.goto(BASE + query);
  await page.waitForFunction(() => /offer (verified|rejected)/.test(document.getElementById("offer-pill")?.textContent ?? ""), null, { timeout: 30_000 });
  return { ctx, page };
}

async function useKey(page, key) {
  await page.locator("summary", { hasText: "Use an existing key" }).click();
  await page.fill("#paste-key", key);
  await page.locator("button", { hasText: "Use key" }).click();
}

async function send(page, text, timeout = 300_000) {
  const before = await page.evaluate(() => (window.__rc?.results.length ?? 0) + (window.__rc?.errors.length ?? 0));
  await page.fill("#prompt", text);
  await page.click("#send");
  await page.waitForFunction((n) => (window.__rc?.results.length ?? 0) + (window.__rc?.errors.length ?? 0) > n, before, { timeout });
  return page.evaluate(() => ({ results: window.__rc.results, errors: window.__rc.errors }));
}

try {
  if (mode === "smoke") {
    const { page } = await open();
    const pill = await page.textContent("#offer-pill");
    pill === "offer verified" ? ok("offer fetched and verified (signature, pinned key, trusted host)") : fail(`offer pill: ${pill}`);
    const models = await page.$$eval("#model option", (o) => o.map((x) => x.value));
    models.length > 0 ? ok(`models from the signed offer: ${models.join(", ")}`) : fail("no models");
    const est = await page.textContent("#estimate");
    /reserves/.test(est ?? "") ? ok(`price estimate: ${est}`) : fail(`estimate: ${est}`);
    const v = await page.evaluate(async () => (await fetch("./version.json", { cache: "no-store" })).json());
    ok(`version.json ${JSON.stringify(v)}`);
    const sw = await page.evaluate(async () => {
      const r = await navigator.serviceWorker.getRegistration();
      return r ? (r.active ?? r.installing ?? r.waiting)?.scriptURL : undefined;
    });
    sw ? ok(`service worker registered: ${sw}`) : fail("no service worker");
    // A session with an invalid key: WebSocket to the node, setup refused.
    await useKey(page, "sk-" + "0".repeat(64));
    const r = await send(page, "hello", 60_000);
    const err = r.errors.at(-1) ?? "";
    /node rejected|401|invalid|api key|unauthor/i.test(err)
      ? ok(`invalid key refused at setup: ${err}`)
      : fail(`expected a setup refusal, got: ${err || JSON.stringify(r.results)}`);
    const log = await page.$$eval("#log div", (d) => d.map((x) => x.textContent));
    log.some((l) => /"in":"error"/.test(l)) ? ok("control WebSocket connected (node sent its error frame)") : console.log(log.slice(-5).join("\n"));
  } else if (mode === "live") {
    const key = process.env.CONF_TEST_KEY;
    if (!key) throw new Error("CONF_TEST_KEY is not set");
    const n = Number(process.argv[3] ?? 2);
    const prompt = process.env.PROMPT ?? "In one short sentence: what is a zero-knowledge proof?";
    // 1. cold
    {
      const { page, ctx } = await open("?prewarm=0");
      await useKey(page, key);
      const r = await send(page, prompt);
      if (r.errors.length) fail(`cold: ${r.errors.at(-1)}`);
      else console.log(JSON.stringify({ path: "cold", ...r.results.at(-1) }));
      await ctx.close();
    }
    // 2. pre-warmed
    {
      const { page, ctx } = await open();
      await useKey(page, key);
      for (let i = 0; i < n; i++) {
        const t = Date.now();
        await page.waitForFunction(() => /armed$/.test(document.getElementById("warm-pill")?.textContent ?? ""), null, { timeout: 240_000 }).catch(() => {});
        console.log(`(waited ${Date.now() - t} ms for the armed session: ${await page.textContent("#warm-pill")})`);
        const r = await send(page, prompt);
        if (r.errors.length > 0) fail(`warm ${i}: ${r.errors.at(-1)}`);
        else console.log(JSON.stringify({ path: "prewarm", ...r.results.at(-1) }));
      }
      await ctx.close();
    }
  } else throw new Error(`unknown mode ${mode}`);
} catch (e) {
  fail(String(e));
} finally {
  await browser.close();
  server.close();
}
process.exit(failed ? 1 : 0);
