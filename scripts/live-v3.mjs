// Live protocol-v3 check of the built library (dist/) in Node, against a
// local node and sidecar on a real provider. The wasm runs inline (the same
// drivers the page runs in its Worker). Cases:
//   chat-2     five chat requests on one framing-"2" connection, CONF_PAUSE_MS (2000) apart:
//              the proof channel is topped up while it idles (PROTOCOL-V3.md §9.2), so
//              requests 2..5 download about what the request itself needs (zk_down ~0)
//   big        a ~200 kB prompt on framing "2" (one π_WIN batch at the default record size)
//   batches    a 4.6 MB body (a short prompt padded with JSON whitespace, padBucket) in 4 KiB
//              DATA records (the most records the node allows for the body, via
//              ConfidentialConnection with chunk 4096): more windows than one π_WIN batch may
//              cover, so the node asks for several batches and writes none of the request's
//              records before the last one verified
//   error-head a request the provider refuses (400: temperature "hot"): the error head is
//              disclosed from its record's byte 0 and settled as such
//   pad        a request with padBucket "pow2" (the body is padded to the next power of two)
//   chat-1.1   one chat request with HTTP/2 off (framing "1.1")
//   image      one image (cheapest variant, count 1; costs real money)
//   refused    a request the node refuses (402: the balance covers the deposit,
//              not the reservation), then the same request after a top-up,
//              on the same connection
//
//   CONF_NODE=http://127.0.0.1:8451 CONF_KEY=sk-… [CONF_LOW_KEY=sk-… CONF_TOPUP_CMD="…"] \
//   CONF_MODEL=deepseek-v4-flash CONF_IMAGE_MODEL=venice-sd35 node scripts/live-v3.mjs chat-2 chat-1.1 image refused
//
// The keys come from the environment and are never printed. CONF_TOPUP_CMD is
// a shell command the refused case runs between the two requests (e.g. an
// sqlite3 update of the scratch node's database).
import { readFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { buildPinnedBody, ConfidentialConnection, createConfidentialClient, fetchConfidentialOffer, InlineWasmHost, RequestRefusedError } from "../dist/index.js";

const node = process.env.CONF_NODE ?? "http://127.0.0.1:8451";
const key = process.env.CONF_KEY;
const model = process.env.CONF_MODEL ?? "deepseek-v4-flash";
const imageModel = process.env.CONF_IMAGE_MODEL ?? "venice-sd35";
const cases = process.argv.slice(2).length ? process.argv.slice(2) : ["chat-2", "chat-1.1"];
if (!key) throw new Error("CONF_KEY is not set");

const wasm = readFileSync(fileURLToPath(new URL("../wasm/pkg/client_wasm_bg.wasm", import.meta.url)));
const host = new InlineWasmHost({ wasm });
const offerRes = await fetch(`${node}/v1/confidential/offer?v=3`);
const pubkey = (await offerRes.json()).notary_pubkey;
const rows = [];
const events = [];
const topups = [];
const pauseMs = Number(process.env.CONF_PAUSE_MS ?? 2000);

function client(http, credential = key, extra = {}) {
  return createConfidentialClient({
    node,
    nodePubkeys: [pubkey],
    trustedHosts: ["api.venice.ai"],
    credential,
    host,
    http,
    onEvent: (e) => {
      if (e.ev === "topup") topups.push(e);
      if (["pool", "framing_fallback", "deposit", "request_refused"].includes(e.ev)) events.push(e);
    },
    ...extra,
  });
}

const kb = (n) => (n === undefined ? "" : `${(n / 1e6).toFixed(2)}MB`);
function row(name, r, note = "") {
  rows.push({
    case: name,
    framing: r.framing,
    n: r.n,
    sid: r.sid.slice(0, 8),
    found: r.connection,
    status: r.http.status,
    ttft_ms: Math.round(r.ttftMs),
    total_ms: Math.round(r.totalMs),
    up: kb(r.bytes.sent),
    down: kb(r.bytes.recv),
    zk_down: r.bytes.channels ? r.bytes.channels.zkRecv : undefined,
    setup_up: kb(r.setupBytes?.sent),
    setup_down: kb(r.setupBytes?.recv),
    cost_msat: r.costMsats,
    deposit: r.deposit.releasedMsat !== undefined ? `released ${r.deposit.releasedMsat}` : "",
    proofs: Object.entries(r.timings.proofs ?? {}).map(([k, v]) => `${k}${v.runs > 1 ? `×${v.runs}` : ""}:${v.via}`).join(" "),
    note,
  });
}

async function chat(c, text, extra = {}) {
  const stream = await c.chat.completions.create({
    model,
    messages: [{ role: "user", content: text }],
    max_tokens: 24,
    stream: true,
    ...extra,
  });
  let out = "";
  for await (const ch of stream) out += ch.choices[0]?.delta?.content ?? "";
  const r = await stream.verification;
  return { r, out };
}

for (const name of cases) {
  const t0 = Date.now();
  try {
    if (name === "chat-2") {
      const c = client("2");
      for (let i = 1; i <= 5; i++) {
        if (i > 1) await new Promise((res) => setTimeout(res, pauseMs));
        const { r, out } = await chat(c, `Say the number ${i} in one word.`);
        row(name, r, JSON.stringify(out.trim().slice(0, 20)));
      }
      c.close();
    } else if (name === "big") {
      const c = client("2");
      const filler = "lorem ipsum dolor sit amet ".repeat(7600);
      const { r, out } = await chat(c, `${filler}\nIgnore the text above and say ok.`);
      row(name, r, `pi_win batches ${r.timings.proofs?.pi_win?.runs ?? 0}; ${JSON.stringify(out.trim().slice(0, 20))}`);
      c.close();
    } else if (name === "batches") {
      const offer = await fetchConfidentialOffer(node, { pinnedPubkeys: [pubkey], trustedHosts: ["api.venice.ai"] });
      const conn = new ConfidentialConnection({ baseUrl: node, offer, framing: "2", auth: key, host, chunk: 4096 });
      // JSON whitespace (padBucket) makes the body long without making the prompt long.
      const body = buildPinnedBody({ messages: [{ role: "user", content: "Say ok." }], stream: true }, model, 16, offer.chat);
      await conn.connect();
      const res = await conn.request({ model, maxTokens: 16, body, padBucket: 4_600_000 }).done;
      const wins = res.timings.proofs.filter((p) => p.proof === "pi_win" && p.purpose === "records");
      conn.close("done");
      if (wins.length < 2) throw new Error(`${body.length} B in 4 KiB records were proven in ${wins.length} pi_win batch(es)`);
      rows.push({ case: name, framing: res.http, n: res.n, status: res.status, ttft_ms: res.timings.ttftMs, total_ms: res.timings.totalMs, cost_msat: res.costMsats,
        note: `${body.length} B body padded to 4.6 MB, pi_win batches ${wins.length} (${wins.map((w) => w.windows).join("+")} windows)` });
    } else if (name === "error-head") {
      const c = client("2");
      const { r } = await chat(c, "Say no.", { temperature: "hot" });
      if (!(r.http.status >= 400)) throw new Error(`expected a provider error, got ${r.http.status}`);
      row(name, r, `provider ${r.http.status}, error head disclosed and settled`);
      c.close();
    } else if (name === "pad") {
      const c = client("2", key, { padBucket: "pow2" });
      const { r, out } = await chat(c, "Say padded in one word.");
      row(name, r, `padBucket pow2; ${JSON.stringify(out.trim().slice(0, 20))}`);
      c.close();
    } else if (name === "chat-1.1") {
      const c = client("1.1");
      const { r, out } = await chat(c, "Say hello in one word.");
      row(name, r, JSON.stringify(out.trim().slice(0, 20)));
      c.close();
    } else if (name === "image") {
      const c = client("auto");
      const offer = await c.images.offer();
      const variants = offer?.price_list?.[imageModel];
      if (!variants) throw new Error(`no image model ${imageModel}`);
      const cheapest = [...variants].sort((a, b) => a.msat_per_image - b.msat_per_image)[0];
      const res = await c.images.generate({ model: imageModel, prompt: "a small red circle on white", count: 1, variant: cheapest.id });
      row(name, res.confidential, `${res.images.length} image(s), ${res.images[0]?.size ?? 0} B ${res.images[0]?.type ?? ""}${res.warnings.length ? `; ${res.warnings.join("; ")}` : ""}`);
      c.close();
    } else if (name === "refused") {
      const low = process.env.CONF_LOW_KEY;
      if (!low || !process.env.CONF_TOPUP_CMD) throw new Error("CONF_LOW_KEY and CONF_TOPUP_CMD are needed");
      const c = client("auto", low);
      let refused;
      try {
        await chat(c, "Say yes.");
      } catch (e) {
        refused = e;
      }
      if (!(refused instanceof RequestRefusedError)) throw new Error(`expected a refused request, got ${refused}`);
      const before = c.connections();
      rows.push({ case: name, status: refused.status, note: `refused: ${refused.reason.slice(0, 60)}; pool ${JSON.stringify(before)}` });
      execSync(process.env.CONF_TOPUP_CMD, { stdio: "ignore" });
      const { r, out } = await chat(c, "Say yes.");
      row(name, r, `after top-up ${JSON.stringify(out.trim().slice(0, 20))}`);
      c.close();
    } else throw new Error(`unknown case ${name}`);
  } catch (e) {
    rows.push({ case: name, status: "FAIL", note: `${e?.name}: ${String(e?.message ?? e).slice(0, 300)} (${Date.now() - t0} ms)` });
  }
}
console.table(rows);
if (topups.length) console.log(`top-ups (off the request path): ${topups.length}, ${topups.reduce((a, t) => a + t.bytes, 0)} B, ${topups.map((t) => `${t.bytes} B/${Math.round(t.ms)} ms`).join(", ")}`);
for (const e of events.filter((x) => x.ev !== "pool")) console.log(JSON.stringify(e));
host.terminate?.();
process.exit(rows.some((r) => r.status === "FAIL") ? 1 : 0);
