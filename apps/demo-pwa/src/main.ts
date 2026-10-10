import "./style.css";
import qrcode from "qrcode-generator";
import {
  createConfidentialClient,
  formatSats,
  mintInputFees,
  NodeApi,
  offerAbandonFeeMsat,
  offerSessionFeeMsat,
  SessionRejectedError,
  type MintFee,
  roughTokens,
  costMsat,
  type BalanceInfo,
  type ConfidentialClient,
  type ConfidentialSessionResult,
  type ModelPricing,
  type VerifiedOffer,
} from "@routstr/confidential-web";
import { APP_BUILD, APP_VERSION, idle, setupPwa } from "./pwa";

// ─── settings and storage ───────────────────────────────────────────────────

const DEFAULTS = {
  node: "https://routstr.cypherpunk.today",
  pubkey: "2ca46ee98f3134c4e11a638663a45983b590bfdefd31588f9c2f03455fba15e7",
  trustedHost: "api.venice.ai",
};
const K = {
  settings: "rc:settings",
  credential: "rc:credential",
  model: "rc:model",
  maxTokens: "rc:max-tokens",
  prewarm: "rc:prewarm",
};

function load<T>(k: string, d: T): T {
  try {
    const v = localStorage.getItem(k);
    return v ? (JSON.parse(v) as T) : d;
  } catch {
    return d;
  }
}
function save(k: string, v: unknown): void {
  try {
    if (v === undefined) localStorage.removeItem(k);
    else localStorage.setItem(k, JSON.stringify(v));
  } catch {
    /* storage unavailable */
  }
}

const settings = load(K.settings, { ...DEFAULTS });
let credential: string | undefined = load<string | undefined>(K.credential, undefined);
let remember = credential !== undefined;
// `?prewarm=0` (tests) or the user's choice in the Costs panel.
let prewarmOn = new URLSearchParams(location.search).get("prewarm") === "0" ? false : load(K.prewarm, true);
let mintFees: MintFee[] | undefined;

// ─── tiny DOM helper ────────────────────────────────────────────────────────

type Child = Node | string | null | undefined | false;
function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, unknown> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false || v === null) continue;
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v as EventListener);
    else if (k === "class") el.className = String(v);
    else if (k in el && k !== "list") (el as unknown as Record<string, unknown>)[k] = v;
    else el.setAttribute(k, String(v));
  }
  for (const c of children) if (c !== null && c !== undefined && c !== false) el.append(c);
  return el;
}
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

function kv(pairs: [string, Child][]): HTMLElement {
  const dl = h("dl", { class: "kv" });
  for (const [k, v] of pairs) dl.append(h("dt", {}, k), h("dd", {}, v));
  return dl;
}
function check(ok: boolean, text: string): HTMLElement {
  return h("span", { class: ok ? "check" : "cross" }, text);
}
function short(s: string, n = 10): string {
  return s.length > 2 * n + 1 ? `${s.slice(0, n)}…${s.slice(-n)}` : s;
}

let toastTimer: ReturnType<typeof setTimeout> | undefined;
function toast(msg: string, ms = 4000): void {
  let t = document.querySelector<HTMLElement>(".toast");
  if (!t) {
    t = h("div", { class: "toast", role: "status" });
    document.body.append(t);
  }
  t.textContent = msg;
  t.classList.remove("hidden");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t!.classList.add("hidden"), ms);
}

// ─── state ──────────────────────────────────────────────────────────────────

interface Turn {
  role: "user" | "assistant";
  content: string;
  el: HTMLElement;
  result?: ConfidentialSessionResult;
  error?: string;
  meta?: HTMLElement;
}

let client: ConfidentialClient | undefined;
let api = new NodeApi(settings.node);
let offer: VerifiedOffer | undefined;
let offerError: string | undefined;
let pricing: ModelPricing[] = [];
let balance: BalanceInfo | undefined;
let busy = false;
let selected: Turn | undefined;
const turns: Turn[] = [];
const events: string[] = [];
let prewarmStatus = "off";

function logEvent(e: Record<string, unknown>): void {
  const { t, ...rest } = e;
  const line = `${new Date(Number(t) || Date.now()).toLocaleTimeString()} ${JSON.stringify(rest)}`;
  events.push(line);
  if (events.length > 300) events.shift();
  if (e.ev === "prewarm" && typeof e.status === "string") {
    prewarmStatus = e.status;
    renderStatus();
  }
  const log = document.getElementById("log");
  if (log) {
    log.append(h("div", { class: "mono" }, line));
    log.scrollTop = log.scrollHeight;
  }
}

function makeClient(): void {
  client?.close();
  api = new NodeApi(settings.node);
  client = createConfidentialClient({
    node: settings.node,
    nodePubkeys: [settings.pubkey],
    trustedHosts: [settings.trustedHost],
    credential,
    prewarm: { enabled: prewarmOn },
    onEvent: logEvent,
  });
}

// ─── layout ─────────────────────────────────────────────────────────────────

function layout(): void {
  const app = $("app");
  app.replaceChildren(
    h(
      "div",
      { class: "shell" },
      h(
        "header",
        {},
        h("h1", {}, "Confidential Chat"),
        h("span", { class: "pill", id: "offer-pill" }, "offer: …"),
        h("span", { class: "pill", id: "warm-pill", title: "Pre-warmed session" }, "pre-warm: off"),
        h("span", { class: "grow" }),
        h("span", { class: "muted", title: `build ${APP_BUILD}` }, `v${APP_VERSION}`),
      ),
      h(
        "main",
        {},
        h(
          "section",
          { class: "chat" },
          h(
            "div",
            { class: "toolbar" },
            h("select", { id: "model", "aria-label": "Model", onchange: onModelChange }),
            h("label", { class: "inline" }, "max tokens", h("input", { id: "max-tokens", type: "number", min: 1, step: 1, style: "width:90px", onchange: onModelChange })),
            h("span", { class: "est", id: "estimate" }),
          ),
          h("div", { class: "messages", id: "messages" }, emptyState()),
          h(
            "form",
            { class: "composer", onsubmit: onSend },
            h("textarea", {
              id: "prompt",
              rows: 2,
              placeholder: "Ask something. The node relays it encrypted; only the provider and you can read it.",
              oninput: () => {
                client?.activity();
                renderEstimate();
              },
              onfocus: () => client?.activity(),
              onkeydown: (e: KeyboardEvent) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  $("send").click();
                }
              },
            }),
            h("button", { class: "primary", id: "send", type: "submit" }, "Send"),
          ),
        ),
        h("aside", { id: "side" }),
      ),
    ),
  );
  $<HTMLInputElement>("max-tokens").value = String(load(K.maxTokens, 1024));
}

function emptyState(): HTMLElement {
  return h(
    "div",
    { class: "empty", id: "empty" },
    h("p", {}, "Every message runs as a confidential session: your browser is the TLS client of the provider, the node only relays encrypted records and inserts its API key, and zero-knowledge proofs keep both sides honest."),
    h("p", { class: "muted" }, "Fund the wallet (Lightning or Cashu), pick a model, and ask."),
  );
}

// ─── side panel ─────────────────────────────────────────────────────────────

function renderSide(): void {
  const side = $("side");
  side.replaceChildren(
    h("h2", {}, "Costs"),
    costsCard(),
    h("h2", {}, "Wallet"),
    walletCard(),
    h("h2", {}, "Verification"),
    verificationPanel(),
    h("h2", {}, "Node"),
    nodeCard(),
    h("h2", {}, "Events"),
    h("div", { class: "card log", id: "log" }, ...events.map((l) => h("div", { class: "mono" }, l))),
  );
}

function walletCard(): HTMLElement {
  const card = h("div", { class: "card" });
  if (credential) {
    const avail = balance ? balance.balance - balance.reserved : undefined;
    card.append(
      h("div", { class: "balance", id: "bal" }, balance ? formatSats(balance.balance) : "…"),
      h("div", { class: "muted", id: "bal-sub" }, balanceSub(avail)),
      h(
        "details",
        {},
        h("summary", {}, "Your key"),
        h("div", { class: "row" }, h("code", {}, short(credential, 8)), h("button", { type: "button", onclick: () => copy(credential!, "Key copied") }, "Copy")),
        h(
          "label",
          { class: "inline" },
          h("input", {
            type: "checkbox",
            checked: remember,
            onchange: (e: Event) => {
              remember = (e.target as HTMLInputElement).checked;
              save(K.credential, remember ? credential : undefined);
            },
          }),
          "Remember on this device",
        ),
        h(
          "p",
          { class: "warnbox" },
          "The key is a bearer credential: anyone with it can spend the balance. Stored keys sit in this site's local storage, readable by any script this origin serves. Keep balances small.",
        ),
      ),
    );
  } else {
    card.append(
      h("p", { class: "muted" }, "No funds yet. Pay a Lightning invoice or paste a Cashu token; the node gives you an sk- key that holds the balance."),
    );
  }
  card.append(
    h(
      "div",
      { class: "row" },
      h("input", { id: "ln-amount", type: "number", min: 1, value: "500", "aria-label": "Amount in sats" }),
      h("button", { type: "button", onclick: onLightning }, "Lightning"),
    ),
    h("div", { id: "invoice" }),
    h("p", { class: "muted" }, "Lightning: your wallet may add a routing fee on top of the invoice amount."),
    h(
      "details",
      {},
      h("summary", {}, "Pay with Cashu"),
      mintFeeLines(),
      h("textarea", { id: "cashu", rows: 3, placeholder: "cashuB…" }),
      h("button", { type: "button", onclick: onCashu }, credential ? "Top up" : "Create key"),
    ),
    h(
      "details",
      {},
      h("summary", {}, "Use an existing key"),
      h("input", { id: "paste-key", placeholder: "sk-…", autocomplete: "off" }),
      h("button", { type: "button", onclick: onPasteKey }, "Use key"),
    ),
  );
  if (credential) {
    card.append(
      h(
        "details",
        {},
        h("summary", {}, "Withdraw (refund)"),
        h("p", { class: "muted" }, "Returns the whole balance as a Cashu token (or to a Lightning address) and empties the key. The mint's input fee or the Lightning routing fee comes out of the amount."),
        h("input", { id: "refund-ln", placeholder: "Lightning address (optional)" }),
        h("button", { type: "button", onclick: onRefund }, "Withdraw"),
        h("div", { id: "refund-out" }),
      ),
    );
  }
  return card;
}

/** Plain-language costs, all read from the signed offer and the node's model list. */
function costsCard(): HTMLElement {
  const card = h("div", { class: "card", id: "costs" });
  if (!offer) {
    card.append(h("p", { class: "muted" }, offerError ? "No verified offer: nothing can be priced." : "Loading the node's signed prices…"));
    return card;
  }
  const abandon = offerAbandonFeeMsat(offer);
  const sessionFee = offerSessionFeeMsat(offer);
  const pct = typeof offer.rate_surcharge_pct === "number" ? offer.rate_surcharge_pct : 0;
  const p = currentModelOrNull();
  card.append(
    h(
      "p",
      {},
      h("strong", {}, "Per message: "),
      p ? `${p.name ?? p.id} costs ${formatSats(p.rates.in * 1000)} per million input tokens and ${formatSats(p.rates.out * 1000)} per million output tokens. ` : "",
      "What you pay is the provider-reported usage at these signed rates",
      sessionFee ? `, plus a session fee of ${formatSats(sessionFee)}` : "",
      pct ? ` (rates include a ${pct}% confidential surcharge)` : "",
      ". Each answer shows its exact cost from the signed receipt.",
    ),
    h(
      "p",
      {},
      h("strong", {}, "Balance needed: "),
      "while a request runs, the node reserves its worst case (a prompt filling the model's whole context plus the max tokens",
      abandon || sessionFee ? `, plus the ${formatSats(Math.max(abandon, sessionFee))} fee` : "",
      ") and releases the unused part when it settles. Your key needs at least this much available:",
    ),
    h(
      "dl",
      { class: "kv" },
      ...pricing.flatMap((m) => [
        h("dt", {}, m.name ?? m.id),
        h("dd", {}, m.reservationMsat !== undefined ? formatSats(m.reservationMsat) : "unknown (no context length)"),
      ]),
    ),
    h(
      "p",
      {},
      h("strong", {}, "Pre-warming: "),
      abandon > 0
        ? `keeping a session ready makes the first answer faster. It costs nothing if you use it; a prepared session you never use costs ${formatSats(abandon)} (the node's fee for the work it already did). It is only prepared while this page is visible and you have funds.`
        : "keeping a session ready makes the first answer faster and costs nothing extra. It is only prepared while this page is visible and you have funds.",
    ),
    h(
      "label",
      { class: "inline" },
      h("input", {
        type: "checkbox",
        checked: prewarmOn,
        onchange: (e: Event) => {
          prewarmOn = (e.target as HTMLInputElement).checked;
          save(K.prewarm, prewarmOn);
          client?.setPrewarm(prewarmOn);
          if (prewarmOn) {
            const m = currentModel();
            if (m) client?.prepare(m.id, maxTokens());
          }
        },
      }),
      "Keep a session ready (pre-warm)",
    ),
  );
  if (abandon > 5000) card.append(h("p", { class: "warnbox" }, "This node's unused-session fee is above 5 sats, so the app does not pre-warm."));
  return card;
}

function mintFeeLines(): HTMLElement {
  if (!mintFees) return h("p", { class: "muted" }, "Checking the mints' fees…");
  const paid = mintFees.filter((m) => (m.inputFeePpk ?? 0) > 0);
  return h(
    "div",
    { class: "muted" },
    h(
      "p",
      {},
      "Cashu mints may charge an input fee when your token is redeemed (and again when you withdraw): ",
      paid.length
        ? `${paid.map((m) => `${new URL(m.mint).host} ${m.inputFeePpk} ppk`).join(", ")} — that is about ${Math.ceil((paid[0]!.inputFeePpk ?? 0) / 1000)} sat per proof batch of up to ${Math.floor(1000 / Math.max(1, paid[0]!.inputFeePpk ?? 1))} proofs, rounded up.`
        : "the node's mints charge none.",
      ` Mints this node accepts: ${(offer?.mints ?? []).map((m) => new URL(m).host).join(", ") || "—"}.`,
    ),
  );
}

function currentModelOrNull(): ModelPricing | undefined {
  const sel = document.getElementById("model") as HTMLSelectElement | null;
  return sel ? pricing.find((p) => p.id === sel.value) : undefined;
}

function balanceSub(avail?: number): string {
  return balance
    ? `${formatSats(avail ?? 0)} available · ${formatSats(balance.reserved)} reserved by open sessions`
    : "loading balance";
}

function nodeCard(): HTMLElement {
  return h(
    "div",
    { class: "card" },
    h("div", { class: "field" }, "Node URL", h("input", { id: "set-node", value: settings.node })),
    h("div", { class: "field" }, "Node key (hex or npub, pinned)", h("input", { id: "set-pubkey", value: settings.pubkey })),
    h("div", { class: "field" }, "Trusted provider host", h("input", { id: "set-host", value: settings.trustedHost })),
    h(
      "div",
      { class: "row" },
      h("button", { type: "button", onclick: onSaveSettings }, "Apply"),
      h("button", { type: "button", onclick: () => { Object.assign(settings, DEFAULTS); save(K.settings, settings); void restart(); } }, "Defaults"),
    ),
    offer
      ? kv([
          ["offer", check(true, "signature valid, key pinned")],
          ["node key", h("code", {}, short(offer.notary_pubkey))],
          ["provider", check(true, `${offer.upstream_host} (trusted)`)],
          ["protocol", `v${offer.v} (two-party handshake)`],
          ["session fee", offer.session_fee_msat ? formatSats(offer.session_fee_msat) : "none"],
        ])
      : h("p", { class: offerError ? "cross" : "muted" }, offerError ?? "loading offer…"),
  );
}

function verificationPanel(): HTMLElement {
  const r = selected?.result;
  if (!r) {
    return h(
      "div",
      { class: "card muted" },
      selected?.error ? h("span", { class: "cross" }, selected.error) : "Send a message to see what your browser verified: the provider's certificate, the proofs, the signed receipt and the timings.",
    );
  }
  const p = r.provider;
  const t = r.timings;
  const usage = r.ownUsage?.usage as { prompt_tokens?: number; completion_tokens?: number; prompt_tokens_details?: { cached_tokens?: number } } | undefined;
  const rates = offer?.price_list[r.model];
  const fee = offer?.session_fee_msat ?? 0;
  const proofRow = (name: string, label: string) => {
    const x = t.proofs?.[name];
    return [label, x ? check(x.ok, `ok · ${x.ms} ms (${x.via})`) : check(false, "not run")] as [string, Child];
  };
  const ms = (v?: number) => (v === undefined ? "—" : `${Math.round(v)} ms`);
  return h(
    "div",
    {},
    h(
      "div",
      { class: "card" },
      h("strong", {}, "Provider connection"),
      p
        ? kv([
            ["host", check(true, `${p.host}${p.hostnameMatched ? ` (matched ${p.hostnameMatched})` : ""}`)],
            ["TLS", `${p.tlsVersion} · ${p.cipherSuite}${p.alpn ? ` · ${p.alpn}` : ""}`],
            ["key exchange", p.keyExchange],
            ["chain", check(true, "validated to a bundled Mozilla root in this browser")],
          ])
        : h("p", { class: "cross" }, "no certificate data"),
      p
        ? h(
            "ol",
            { class: "chain" },
            ...p.chain.map((c, i) =>
              h(
                "li",
                {},
                h("div", {}, h("strong", {}, i === 0 ? "leaf " : c.trustAnchor ? "root " : "intermediate "), c.subject),
                h(
                  "details",
                  {},
                  h("summary", {}, "details"),
                  kv([
                    ["issuer", c.issuer],
                    ["valid", `${c.notBefore.slice(0, 10)} → ${c.notAfter.slice(0, 10)}`],
                    ["SAN", c.dnsNames.join(", ") || "—"],
                    ["SPKI sha256", h("code", {}, c.spkiSha256Base64)],
                    ["cert sha256", h("code", {}, c.fingerprintSha256)],
                    ["key", c.publicKeyAlgorithm],
                    ["signature", c.signatureAlgorithm],
                    ["serial", h("code", {}, c.serialNumber)],
                  ]),
                ),
              ),
            ),
          )
        : null,
    ),
    h(
      "div",
      { class: "card" },
      h("strong", {}, "Proofs"),
      kv([
        ["2PC handshake", check(true, `key schedule run jointly · A ${ms(t.twoPcPhaseAMs)} · B ${ms(t.twoPcPhaseBMs)}`)],
        proofRow("pi_nk", "π_NK (node key record)"),
        proofRow("pi_c2s", "π_C2S (pinned suffix)"),
        proofRow("pi_c3s", "π_C3S (usage disclosure)"),
        ["attestation", check(r.attestationSigOk, "signature valid")],
      ]),
    ),
    h(
      "div",
      { class: "card" },
      h("strong", {}, "Receipt"),
      kv([
        ["signature", check(r.receiptSigOk, "valid (node key)")],
        ["usage", check(r.usageMatch, usage ? `${usage.prompt_tokens} in / ${usage.completion_tokens} out (matches our plaintext)` : "error response")],
        ["cost", check(r.costWithinOffer, `${formatSats(r.costMsats ?? 0)} (≤ signed rates${fee ? " + session fee" : ""})`)],
        [
          "at the rates",
          rates && usage
            ? formatSats(
                costMsat(rates, {
                  prompt_tokens: usage.prompt_tokens ?? 0,
                  completion_tokens: usage.completion_tokens ?? 0,
                  cached_tokens: usage.prompt_tokens_details?.cached_tokens,
                }, fee),
              )
            : "—",
        ],
        ["reserved", r.receipt.reserved_msats !== undefined ? formatSats(r.receipt.reserved_msats) : "—"],
        ["balance after", typeof r.receipt.balance_msats === "number" ? formatSats(r.receipt.balance_msats) : "—"],
        ["session", h("code", {}, short(r.sid, 8))],
      ]),
      h("details", {}, h("summary", {}, "signed receipt JSON"), h("pre", {}, r.receiptJson), h("div", { class: "mono" }, `sig ${r.receiptSig ?? ""}`)),
    ),
    h(
      "div",
      { class: "card timing" },
      h("strong", {}, r.prewarmed ? "Timings (warm: pre-armed session)" : "Timings (cold)"),
      kv([
        ["first token", ms(r.ttftMs)],
        ["total", ms(r.totalMs)],
        ["arm (setup + 2PC preprocessing)", r.prewarmed ? `${ms(t.armMs)} (before the request)` : ms(t.armMs)],
        ["2PC key share", ms(t.twoPcKeyShareMs)],
        ["handshake (2PC A + B)", ms(t.handshakeMs)],
        ["π_NK", ms(t.piNkMs)],
        ["credential record", ms(t.recordMs)],
        ["provider first byte", ms(t.upstreamTtftMs)],
        ["2PC traffic", t.twoPcBytes ? `${(t.twoPcBytes.sent / 1e6).toFixed(2)} MB up · ${(t.twoPcBytes.recv / 1e6).toFixed(1)} MB down` : "—"],
      ]),
      t.twoPcSteps?.length
        ? h("details", {}, h("summary", {}, "2PC steps (wasm)"), kv(t.twoPcSteps.map((s) => [s.step, `${Math.round(s.ms)} ms`] as [string, Child])))
        : null,
    ),
  );
}

// ─── header, models, estimate ───────────────────────────────────────────────

function renderStatus(): void {
  const op = document.getElementById("offer-pill");
  if (op) {
    op.className = `pill ${offer ? "ok" : offerError ? "bad" : ""}`;
    op.textContent = offer ? "offer verified" : offerError ? "offer rejected" : "offer: …";
    op.title = offerError ?? (offer ? `signed by ${offer.notary_pubkey}` : "");
  }
  const wp = document.getElementById("warm-pill");
  if (wp) {
    wp.className = `pill ${prewarmStatus === "armed" ? "ok" : prewarmStatus === "arming" ? "warn" : ""}`;
    wp.textContent = `pre-warm: ${prewarmStatus}`;
  }
}

function renderModels(): void {
  const sel = $<HTMLSelectElement>("model");
  const want = load<string>(K.model, "");
  sel.replaceChildren(
    ...pricing.map((p) =>
      h("option", { value: p.id, selected: p.id === want }, `${p.name ?? p.id} — in ${formatSats(p.rates.in * 1000)}/M · out ${formatSats(p.rates.out * 1000)}/M`),
    ),
  );
  if (!pricing.some((p) => p.id === want) && pricing[0]) sel.value = pricing[0].id;
  renderEstimate();
}

function currentModel(): ModelPricing | undefined {
  const id = $<HTMLSelectElement>("model").value;
  return pricing.find((p) => p.id === id);
}

function maxTokens(): number {
  const v = Number($<HTMLInputElement>("max-tokens").value);
  const cap = offer?.max_tokens_cap ?? 4096;
  return Number.isFinite(v) && v > 0 ? Math.min(Math.trunc(v), cap) : Math.min(1024, cap);
}

function renderEstimate(): void {
  const p = currentModel();
  const el = document.getElementById("estimate");
  if (!el || !p) return;
  const prompt = ($<HTMLTextAreaElement>("prompt")?.value ?? "") + turns.map((t) => t.content).join("");
  const inTok = roughTokens(prompt) + 20;
  const mt = maxTokens();
  const typical = costMsat(p.rates, { prompt_tokens: inTok, completion_tokens: Math.min(mt, 300) }, p.sessionFeeMsat);
  const worst = costMsat(p.rates, { prompt_tokens: inTok, completion_tokens: mt }, p.sessionFeeMsat);
  const resv =
    p.promptLimit !== undefined
      ? Math.ceil((p.promptLimit * p.rates.in + mt * p.rates.out) / 1000) + Math.max(p.sessionFeeMsat, p.abandonFeeMsat)
      : undefined;
  el.textContent =
    `≈ ${formatSats(typical)} per message (≤ ${formatSats(worst)} at ${mt} tokens)` +
    (resv !== undefined ? ` · needs ${formatSats(resv)} available (reserved while it runs)` : "") +
    (p.abandonFeeMsat ? ` · unused prepared session ${formatSats(p.abandonFeeMsat)}` : "") +
    (p.sessionFeeMsat ? ` · incl. session fee ${formatSats(p.sessionFeeMsat)}` : "") +
    (p.rateSurchargePct ? ` · rates incl. ${p.rateSurchargePct}% surcharge` : "");
}

function onModelChange(): void {
  const p = currentModel();
  if (!p) return;
  save(K.model, p.id);
  save(K.maxTokens, maxTokens());
  client?.prepare(p.id, maxTokens());
  renderEstimate();
  void client?.pricing(maxTokens()).then((list) => {
    pricing = list;
    document.getElementById("costs")?.replaceWith(costsCard());
  });
}

// ─── wallet actions ─────────────────────────────────────────────────────────

async function refreshBalance(): Promise<void> {
  if (!credential?.startsWith("sk-")) {
    balance = undefined;
    return;
  }
  const had = balance !== undefined;
  try {
    balance = await api.balance(credential);
  } catch (e) {
    logEvent({ ev: "balance_error", msg: String(e) });
  }
  const bal = document.getElementById("bal");
  if (had && bal && balance) {
    // Update in place: do not wipe what the user is typing in the side panel.
    bal.textContent = formatSats(balance.balance);
    $("bal-sub").textContent = balanceSub(balance.balance - balance.reserved);
  } else renderSide();
}

function setCredential(key: string | undefined): void {
  credential = key;
  balance = undefined;
  save(K.credential, remember && key ? key : undefined);
  client?.setCredential(key);
  void refreshBalance().then(() => {
    const p = currentModel();
    if (p) client?.prepare(p.id, maxTokens());
  });
}

async function copy(text: string, msg: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast(msg);
  } catch {
    toast("Copy failed; select the text manually");
  }
}

let invoicePoll: ReturnType<typeof setInterval> | undefined;
async function onLightning(): Promise<void> {
  const amount = Math.trunc(Number($<HTMLInputElement>("ln-amount").value));
  if (!(amount > 0)) return toast("Enter an amount in sats");
  const box = $("invoice");
  box.replaceChildren(h("p", { class: "muted" }, "Creating invoice…"));
  try {
    const inv = await api.lightningInvoice(amount, credential?.startsWith("sk-") ? credential : undefined);
    const qr = qrcode(0, "L");
    qr.addData(inv.bolt11.toUpperCase(), "Alphanumeric");
    qr.make();
    box.replaceChildren(
      h("div", { class: "qr" }, h("img", { src: qr.createDataURL(6, 2), alt: "Lightning invoice QR code" })),
      h("div", { class: "row" }, h("a", { href: `lightning:${inv.bolt11}` }, "Open in wallet"), h("button", { type: "button", onclick: () => copy(inv.bolt11, "Invoice copied") }, "Copy invoice")),
      h("p", { class: "muted", id: "inv-status" }, `${amount} sat · waiting for payment…`),
    );
    if (invoicePoll) clearInterval(invoicePoll);
    const started = Date.now();
    invoicePoll = setInterval(async () => {
      if (Date.now() > inv.expires_at * 1000 || Date.now() - started > 3_600_000) {
        clearInterval(invoicePoll);
        $("inv-status").textContent = "Invoice expired";
        return;
      }
      try {
        const st = await api.lightningStatus(inv.invoice_id);
        if (st.status === "paid") {
          clearInterval(invoicePoll);
          box.replaceChildren(h("p", { class: "check" }, `Paid ${st.amount_sats} sat`));
          if (st.api_key && st.api_key !== credential) {
            setCredential(st.api_key);
            toast("Funded. Copy your key or tick “Remember” so the balance is not lost.", 8000);
          } else void refreshBalance();
        } else if (st.status === "expired") {
          clearInterval(invoicePoll);
          $("inv-status").textContent = "Invoice expired";
        }
      } catch {
        /* keep polling */
      }
    }, 3000);
  } catch (e) {
    box.replaceChildren(h("p", { class: "cross" }, String(e instanceof Error ? e.message : e)));
  }
}

async function onCashu(): Promise<void> {
  const token = $<HTMLTextAreaElement>("cashu").value.trim();
  if (!token.startsWith("cashu")) return toast("Paste a Cashu token (cashuA… / cashuB…)");
  try {
    if (credential?.startsWith("sk-")) {
      await api.topupCashu(credential, token);
      toast("Topped up");
      void refreshBalance();
    } else {
      const r = await api.createKeyFromCashu(token);
      setCredential(r.api_key);
      toast("Key created. Copy it or tick “Remember” so the balance is not lost.", 8000);
    }
    $<HTMLTextAreaElement>("cashu").value = "";
  } catch (e) {
    toast(`Cashu failed: ${e instanceof Error ? e.message : e}`, 8000);
  }
}

function onPasteKey(): void {
  const k = $<HTMLInputElement>("paste-key").value.trim();
  if (!k.startsWith("sk-")) return toast("Expected an sk- key");
  setCredential(k);
}

async function onRefund(): Promise<void> {
  if (!credential) return;
  if (!confirm("Withdraw the whole balance and empty this key?")) return;
  const ln = $<HTMLInputElement>("refund-ln").value.trim() || undefined;
  client?.prewarmer?.teardown("refund");
  try {
    const r = await api.refund(credential, ln);
    const out = $("refund-out");
    if (typeof r.token === "string") {
      out.replaceChildren(
        h("p", { class: "check" }, "Withdrawn as a Cashu token. Redeem it in any Cashu wallet:"),
        h("textarea", { rows: 4, readOnly: true, value: r.token }),
        h("button", { type: "button", onclick: () => copy(r.token as string, "Token copied") }, "Copy token"),
      );
    } else out.replaceChildren(h("p", { class: "check" }, "Withdrawal sent."), h("pre", {}, JSON.stringify(r, null, 2)));
    void refreshBalance();
  } catch (e) {
    toast(`Refund failed: ${e instanceof Error ? e.message : e}`, 8000);
  }
}

// ─── chat ───────────────────────────────────────────────────────────────────

function addTurn(role: Turn["role"], content: string): Turn {
  document.getElementById("empty")?.remove();
  const el = h("div", { class: `msg ${role}` }, content);
  const t: Turn = { role, content, el };
  $("messages").append(el);
  turns.push(t);
  el.scrollIntoView({ block: "end" });
  return t;
}

function selectTurn(t: Turn): void {
  selected = t;
  renderSide();
}

async function onSend(e: Event): Promise<void> {
  e.preventDefault();
  if (busy || !client) return;
  const ta = $<HTMLTextAreaElement>("prompt");
  const text = ta.value.trim();
  if (!text) return;
  const p = currentModel();
  if (!p) return toast("No confidential model available");
  if (!credential) return toast("Fund the wallet first (Lightning or Cashu)");
  ta.value = "";
  addTurn("user", text);
  const history = turns.filter((t) => !t.error).map((t) => ({ role: t.role, content: t.content }));
  const answer = addTurn("assistant", "");
  const body = h("span", {}, "");
  const meta = h("div", { class: "meta" }, "starting confidential session…");
  answer.el.replaceChildren(body, meta);
  answer.meta = meta;
  busy = true;
  $<HTMLButtonElement>("send").disabled = true;
  const t0 = performance.now();
  try {
    const stream = await client.chat.completions.create({
      model: p.id,
      messages: history,
      max_tokens: maxTokens(),
      stream: true,
    });
    meta.textContent = "streaming (records verified as they decrypt)…";
    for await (const chunk of stream) {
      const d = chunk.choices?.[0]?.delta?.content;
      if (d) {
        answer.content += d;
        body.textContent = answer.content;
        answer.el.scrollIntoView({ block: "end" });
      }
    }
    meta.textContent = "settling: proofs and receipt…";
    const r = await stream.verification;
    answer.result = r;
    testHook().results.push({
      prewarmed: r.prewarmed,
      ttftMs: r.ttftMs,
      totalMs: r.totalMs,
      wallMs: Math.round(performance.now() - t0),
      costMsats: r.costMsats,
      usage: r.ownUsage?.usage,
      receiptSigOk: r.receiptSigOk,
      usageMatch: r.usageMatch,
      costWithinOffer: r.costWithinOffer,
      provider: r.provider && { host: r.provider.host, matched: r.provider.hostnameMatched, leaf: r.provider.chain[0]?.subject, chain: r.provider.chain.length, cipher: r.provider.cipherSuite },
      timings: r.timings,
      textLength: answer.content.length,
    });
    const usage = r.ownUsage?.usage as { prompt_tokens?: number; completion_tokens?: number } | undefined;
    meta.replaceChildren(
      h("span", { class: "check" }, "verified"),
      h("span", {}, r.prewarmed ? "warm" : "cold"),
      h("span", {}, `first token ${(r.ttftMs / 1000).toFixed(1)} s`),
      h("span", {}, `total ${((performance.now() - t0) / 1000).toFixed(1)} s`),
      h("span", {}, usage ? `${usage.prompt_tokens}/${usage.completion_tokens} tok` : ""),
      h("span", {}, formatSats(r.costMsats ?? 0)),
      h("button", { type: "button", onclick: () => selectTurn(answer) }, "details"),
    );
    selectTurn(answer);
  } catch (err) {
    const msg = friendlyError(err);
    answer.error = msg;
    testHook().errors.push(msg);
    answer.el.classList.add("error");
    if (!answer.content) body.textContent = "";
    meta.replaceChildren(h("span", { class: "cross" }, msg), h("button", { type: "button", onclick: () => selectTurn(answer) }, "details"));
    selectTurn(answer);
  } finally {
    busy = false;
    $<HTMLButtonElement>("send").disabled = false;
    void refreshBalance();
    idle();
  }
}

function friendlyError(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  if (err instanceof SessionRejectedError) {
    if (err.status === 402) return `Not enough balance for this request's reservation (${raw}). Top up, or lower max tokens.`;
    if (err.status === 429) return "The node already holds 3 unused sessions for your address (other tabs or devices behind the same IP). Close them or wait a few minutes.";
    if (err.status === 409) return `The node's signed offer changed (prices or fees); reload to accept the new one. (${raw})`;
    if (err.status === 401) return `The node does not know this key (${raw}).`;
  }
  return raw;
}

/** Non-secret outcomes for the browser tests (no credential, no prompt). */
function testHook(): { results: unknown[]; errors: string[] } {
  const w = window as unknown as { __rc?: { results: unknown[]; errors: string[] } };
  w.__rc ??= { results: [], errors: [] };
  return w.__rc;
}

// ─── settings / boot ────────────────────────────────────────────────────────

function onSaveSettings(): void {
  settings.node = $<HTMLInputElement>("set-node").value.trim().replace(/\/$/, "");
  settings.pubkey = $<HTMLInputElement>("set-pubkey").value.trim();
  settings.trustedHost = $<HTMLInputElement>("set-host").value.trim();
  save(K.settings, settings);
  void restart();
}

async function restart(): Promise<void> {
  offer = undefined;
  offerError = undefined;
  pricing = [];
  makeClient();
  renderStatus();
  renderSide();
  try {
    offer = await client!.offer();
    pricing = await client!.pricing(maxTokens());
    renderModels();
    void mintInputFees(offer.mints ?? []).then((f) => {
      mintFees = f;
      renderSide();
    });
  } catch (e) {
    offerError = e instanceof Error ? e.message : String(e);
  }
  renderStatus();
  renderSide();
  await refreshBalance();
  const p = currentModel();
  if (p) client?.prepare(p.id, maxTokens());
}

window.addEventListener("beforeunload", (e) => {
  if (credential && !remember && balance && balance.balance > 0) {
    e.preventDefault();
  }
});

layout();
renderSide();
setupPwa({ isBusy: () => busy, toast });
void restart();
setInterval(() => void refreshBalance(), 60_000);
