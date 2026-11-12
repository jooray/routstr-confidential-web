/**
 * Protocol-v3 live check in a real browser: the library from dist/, the wasm
 * in its default Web Worker, against a local node (loopback http). The driver
 * (scripts/browser-live-v3.mjs) calls `window.live.*` and passes the key in
 * the call, never in the URL; nothing here prints it.
 */
import { createConfidentialClient, type ConfidentialClient, type ConfidentialRequestResult } from "../../dist/index.js";

interface Cfg {
  node: string;
  pubkey: string;
  key: string;
  model: string;
  http: "auto" | "2" | "1.1";
}

const out = document.getElementById("out")!;
const clients = new Map<string, ConfidentialClient>();
const events: Record<string, unknown>[] = [];

function client(cfg: Cfg, id = cfg.http): ConfidentialClient {
  let c = clients.get(id);
  if (!c) {
    c = createConfidentialClient({
      node: cfg.node,
      nodePubkeys: [cfg.pubkey],
      trustedHosts: ["api.venice.ai"],
      credential: cfg.key,
      http: cfg.http,
      onEvent: (e) => {
        if (e.ev !== "frame" && e.ev !== "pool") events.push(e);
      },
    });
    clients.set(id, c);
  }
  return c;
}

function summary(r: ConfidentialRequestResult, note = "") {
  return {
    framing: r.framing,
    n: r.n,
    sid: r.sid.slice(0, 8),
    found: r.connection,
    status: r.http.status,
    ttftMs: Math.round(r.ttftMs),
    totalMs: Math.round(r.totalMs),
    sent: r.bytes.sent,
    recv: r.bytes.recv,
    setupSent: r.setupBytes?.sent,
    setupRecv: r.setupBytes?.recv,
    costMsats: r.costMsats,
    depositReleased: r.deposit.releasedMsat,
    alpn: r.provider?.alpn,
    leaf: r.provider?.chain[0]?.subject,
    proofs: Object.fromEntries(Object.entries(r.timings.proofs ?? {}).map(([k, v]) => [k, { via: v.via, ms: Math.round(v.ms), runs: v.runs }])),
    note,
  };
}

async function chat(cfg: Cfg, text: string, id?: string) {
  const c = client(cfg, id);
  const stream = await c.chat.completions.create({ model: cfg.model, messages: [{ role: "user", content: text }], max_tokens: 24, stream: true });
  let txt = "";
  for await (const ch of stream) txt += ch.choices[0]?.delta?.content ?? "";
  const r = await stream.verification;
  out.textContent += `\n${r.framing} n=${r.n} ${JSON.stringify(txt.slice(0, 40))}`;
  return summary(r, JSON.stringify(txt.trim().slice(0, 24)));
}

const live = {
  chat,
  async image(cfg: Cfg & { imageModel: string }) {
    const c = client(cfg);
    const offer = await c.images.offer();
    const variants = offer?.price_list[cfg.imageModel];
    if (!variants) throw new Error(`no image model ${cfg.imageModel}`);
    const cheapest = [...variants].sort((a, b) => a.msat_per_image - b.msat_per_image)[0]!;
    const res = await c.images.generate({ model: cfg.imageModel, prompt: "a small red circle on white", count: 1, variant: cheapest.id });
    const img = res.images[0];
    return summary(res.confidential, `${res.images.length} image(s), ${img?.size ?? 0} B ${img?.type ?? ""}`);
  },
  async refused(cfg: Cfg, id: string) {
    try {
      await chat(cfg, "Say yes.", id);
      return { refused: false };
    } catch (e) {
      const err = e as { name?: string; status?: number; reason?: string; message?: string };
      return { refused: err.name === "RequestRefusedError", status: err.status, reason: String(err.reason ?? err.message).slice(0, 80), pool: clients.get(id)?.connections() };
    }
  },
  events: () => events.splice(0),
  close() {
    for (const c of clients.values()) c.close();
    clients.clear();
  },
};
(window as unknown as { live: typeof live }).live = live;
out.textContent = "ready";
