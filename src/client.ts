/**
 * `createConfidentialClient`: an OpenAI-like client whose every request runs
 * on a confidential connection (protocol v3) from the browser.
 *
 * ```ts
 * const client = createConfidentialClient({
 *   node: "https://routstr.cypherpunk.today",
 *   nodePubkeys: ["2ca46ee9…"],
 *   trustedHosts: ["api.venice.ai"],
 *   credential: "sk-…",
 * });
 * const stream = await client.chat.completions.create({ model, messages, stream: true });
 * for await (const chunk of stream) console.log(chunk.choices[0]?.delta?.content);
 * const proof = await stream.verification; // receipt, proofs, provider certificate, framing, deposit, timings
 * ```
 *
 * A request runs on a connection from the client's pool (`pool.ts`): framing
 * `"2"` (HTTP/2 to the provider) keeps the connection and serves later
 * requests on it, one two-party handshake for many requests; framing `"1.1"`
 * opens a connection per request. The framing comes from the node's signed
 * offer (`http: "auto"`, the default) or the caller (`"2"`, `"1.1"`), and a
 * framing-`"2"` connection that fails to open falls back to `"1.1"` on the
 * same node for 10 minutes (PROTOCOL-V3.md §2.3).
 *
 * A stream ends cleanly only after settlement verified (π_WIN, π_C3S, the
 * signed attestation and receipt, its usage, its cost and the deposit); any
 * failed check makes the iterator throw. Body bytes are handed out as TLS
 * records decrypt: each one is authenticated by AES-GCM under keys only this
 * page holds.
 */

import {
  ConfidentialError,
  ConnectionDepositError,
  NodeProtocolOutdatedError,
  RequestRefusedError,
  SessionRejectedError,
  TwoPcVersionMismatchError,
  UpgradeRequiredError,
  UpstreamImageError,
} from "./errors.js";
import { encryptedNodeTransport } from "./hosts.js";
import {
  fetchConfidentialOffer,
  imageCountKey,
  offerConnectionDepositMsat,
  offerFramingsFor,
  offerImages,
  offerSessionFeeMsat,
  verifyConfidentialOffer,
  type ConfidentialFraming,
  type ConfidentialImagesOffer,
  type ConfidentialImageVariant,
  type VerifiedOffer,
} from "./offer.js";
import { base64ToBytes, buildImageBody, imageMimeType, imageSuffix, pinnedImageKeys, planImageRequest } from "./images.js";
import { NodeApi, type NodeModel } from "./node-api.js";
import { modelPricing, type ModelPricing } from "./pricing.js";
import { aggregateChatCompletion, buildPinnedBody, requestedMaxTokens, SseParser } from "./request.js";
import {
  ConfidentialConnection,
  connectionTerms,
  DEFAULT_MAX_CONNECTION_DEPOSIT_MSAT,
  type ConnectionRequestHandle,
  type ConnectionRequestResult,
} from "./connection.js";
import { ConnectionPool, poolKey, type Http2Options, type PoolLease } from "./pool.js";
import { requestResult, type ConfidentialRequestResult } from "./result.js";
import { checkImageResponse } from "./wire.js";
import type { PadBucket } from "./suffix.js";
import { getDefaultWasmHost, type WasmHost } from "./wasm/host.js";

export interface PrewarmOptions {
  /** Default true when an options object is given. */
  enabled?: boolean;
  /** Retire an armed connection this long after its setup (the node ends armed connections at 600 s; at least 60 s). */
  maxAgeMs?: number;
  /** No activity (request, typing, focus) for this long: armed connections are closed and none is armed. */
  idleMs?: number;
  /**
   * Arm only while `document.visibilityState === "visible"` (default true).
   * Hiding the page closes the armed connection; showing it again arms
   * nothing until the next `activity()` or request.
   */
  onlyWhenVisible?: boolean;
  /**
   * Pre-warm on a metered connection too: when the browser reports
   * `navigator.connection.saveData` or a cellular connection (default false).
   * Each arm costs about 16 MB.
   */
  allowMetered?: boolean;
  /** Retry delay after a failed arm (doubles up to 10 min). */
  backoffMs?: number;
  /**
   * Do not pre-warm when an armed connection that is never used costs more
   * than this (msat): the offer's connection deposit. Default 5000 (5 sats).
   */
  maxDepositMsat?: number;
  /**
   * Framing "2": keep one armed connection while the key has no open one
   * (default true), so the next message after a pause skips the 2PC
   * preprocessing. Off: only while every open connection is busy (§9.2).
   */
  armWithoutOpen?: boolean;
}

export interface ConfidentialClientOptions {
  /** Node base URL (https; plain http only for loopback or an onion service). */
  node: string;
  /**
   * Development only: allow a plain-http node that is neither loopback nor an
   * onion service. The credential then travels unencrypted.
   */
  allowInsecureTransport?: boolean;
  /** Node signing keys (hex or npub) whose offers are accepted. */
  nodePubkeys: readonly string[];
  /** Provider hostnames the client accepts (exact or wildcard), e.g. ["api.venice.ai"]. */
  trustedHosts: readonly string[];
  /** `sk-` key (or a Cashu token, used for one request) — see `setCredential`. */
  credential?: string;
  /** Where the wasm runs (default: a dedicated Worker). */
  host?: WasmHost;
  /**
   * The framing towards the provider (§2.3): `auto` (default) takes the first
   * the node's signed offer lists and falls back from `"2"` to `"1.1"` when a
   * framing-`"2"` connection fails to open; `"2"` or `"1.1"` uses only that
   * framing (a node that does not offer it is not used). `"1.1"` turns
   * HTTP/2 off: one connection, and one two-party handshake, per request.
   */
  http?: "auto" | ConfidentialFraming;
  /**
   * The largest connection deposit (msat) accepted from the node's offer
   * (default 100 000). The node reserves it at a connection's setup and
   * releases it with the connection's first settled request.
   */
  maxConnectionDepositMsat?: number;
  /** Connection reuse and limits (framing "2"): `reuse: "none"` opens a connection per request. */
  http2?: Pick<
    Http2Options,
    "reuse" | "maxConnectionsPerKey" | "maxConnections" | "idleMarginMs" | "maxIdleMs" | "maxRequestsPerConnection" | "acquireTimeoutMs"
  >;
  /**
   * Requests with different scopes never share a connection, so the provider
   * cannot link them by it (§9.1). Default: one scope for the credential.
   */
  reuseScope?: string;
  /**
   * Optional body-size bucket (off by default): pad each request body with
   * JSON whitespace before the pinned suffix to the next multiple of this many
   * bytes, or to the next power of two (`"pow2"`), so observers of the
   * client–node and node–provider connections (and the provider) see the
   * bucket, not the exact size. Costs upload bytes; the node still learns the
   * prompt's token count at settlement (PROTOCOL-V3.md §9.3).
   */
  padBucket?: PadBucket;
  /** Keep one connection armed while the page is visible and the key is funded. */
  prewarm?: boolean | PrewarmOptions;
  /** Called once per client when the node's offer names an older protocol (`node_protocol_outdated`). */
  onNodeProtocolOutdated?: (node: string, nodeVersion: number) => void;
  /** Structured progress events (never secrets). */
  onEvent?: (event: Record<string, unknown>) => void;
  webSocketImpl?: typeof WebSocket;
  fetchImpl?: typeof fetch;
}

export interface ChatCompletionCreateParams {
  model: string;
  messages: { role: string; content: unknown; [k: string]: unknown }[];
  max_tokens?: number;
  stream?: boolean;
  [k: string]: unknown;
}

export interface ChatCompletionChunk {
  id?: string;
  object?: string;
  created?: number;
  model?: string;
  choices: { index: number; delta: { role?: string; content?: string; reasoning_content?: string }; finish_reason?: string | null }[];
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens?: number };
  [k: string]: unknown;
}

export interface ConfidentialStream extends AsyncIterable<ChatCompletionChunk> {
  /** Settles with the verified request (receipt, proofs, certificate, framing, deposit, timings); rejects on any failed check. */
  verification: Promise<ConfidentialRequestResult>;
  /** The upstream HTTP status and headers. */
  head: Promise<{ status: number; statusText: string; headers: Record<string, string> }>;
  /**
   * Stop the answer. Before the body is released this closes the connection;
   * after it, only this stream ends (with an AbortError) and the request
   * settles in the background, `verification` resolving with its receipt.
   */
  abort(): void;
}

export type ChatCompletion = Record<string, unknown> & { confidential: ConfidentialRequestResult };

/**
 * A confidential image request. `model`, `count`, `variant` / `resolution` /
 * `quality` / `format` choose the priced variant (pinned, visible to the
 * node); `prompt`, `aspectRatio` and any other field are private options the
 * node never sees (e.g. `seed`, `negative_prompt`, `safe_mode`).
 */
export interface ImageGenerateParams {
  model: string;
  prompt: string;
  /** Images in one request, 1..`offer.images.max_count` (default 1). */
  count?: number;
  /** An offered variant id; else chosen from `resolution`/`quality`/`format`. */
  variant?: string;
  resolution?: string;
  quality?: string;
  format?: string;
  /** Private: e.g. "16:9" (sent as `aspect_ratio`). */
  aspectRatio?: string;
  [k: string]: unknown;
}

export interface ImageGenerateResult {
  /** The images, as received (the pinned format, e.g. image/webp). */
  images: Blob[];
  model: string;
  variant: string;
  count: number;
  /** The signed per-image price and what the receipt charged (msats). */
  msatPerImage: number;
  costMsats: number;
  /**
   * What is wrong with the answer, if anything: fewer images than asked for,
   * an incomplete body, or a provider echo naming another model or count. The
   * request was charged at the signed price regardless.
   */
  warnings: string[];
  /** The verified request: receipt, proofs, provider certificate, framing, timings. */
  confidential: ConfidentialRequestResult;
}

/**
 * What one image request costs at the signed offer (msats), before it runs:
 * the price per image × count, plus the session fee when the request is the
 * first settlement of its connection (the most it can be).
 */
export function imageRequestCostMsat(offer: VerifiedOffer, variant: ConfidentialImageVariant, count: number): number {
  return Math.ceil(variant.msat_per_image * count + offerSessionFeeMsat(offer));
}

type Head = { status: number; statusText: string; headers: Record<string, string> };

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

const aborted = () => new DOMException("aborted", "AbortError");

/** The node no longer holds the offer the setup or the request named, or its connection-level terms or fees changed. */
export function isOfferExpired(e: unknown): boolean {
  if (!(e instanceof SessionRejectedError)) return false;
  const d = e.nodeDetail as { error?: { type?: string } } | undefined;
  const reason = e instanceof RequestRefusedError ? e.reason : "";
  const named = (t: string | undefined) => t === "offer_expired" || t === "offer_changed" || t === "session_fee_not_accepted";
  return e.status === 409 && (named(d?.error?.type) || named(reason));
}

/** A request the node refused because the connection's terms are no longer served (`offer_changed`). */
function offerChangedRefusal(e: RequestRefusedError): boolean {
  const d = e.nodeDetail as { error?: { type?: string } } | undefined;
  return e.reason === "offer_changed" || d?.error?.type === "offer_changed";
}

/**
 * The framing a request of `kind` uses with `offer` (§2.3): the configured
 * one, else the first the offer lists that serves the kind and is not marked
 * bad for the node. A one-off Cashu bearer prefers `"1.1"` (a connection per
 * token, §9.1). Throws when the node serves the request with no framing the
 * caller allows.
 */
export function chooseFraming(
  offer: VerifiedOffer,
  kind: "chat" | "images",
  choice: { http?: "auto" | ConfidentialFraming; oneOff?: boolean; bad?: boolean; node?: string } = {},
): ConfidentialFraming {
  const served = offerFramingsFor(offer, kind);
  const node = choice.node ?? "the node";
  if (served.length === 0) {
    throw new ConfidentialError(kind === "images" ? "offer_no_images" : "offer_malformed", `${node} serves no confidential ${kind} requests`);
  }
  const want = choice.http ?? "auto";
  if (want !== "auto") {
    if (want !== "2" && want !== "1.1") throw new ConfidentialError("not_configured", `http is not "auto", "2" or "1.1"`);
    if (!served.includes(want)) {
      throw new ConfidentialError(
        "not_configured",
        `${node} does not serve ${kind} requests with framing "${want}" (it offers ${JSON.stringify(served)}); the HTTP setting allows nothing else`,
      );
    }
    return want;
  }
  if (choice.oneOff && served.includes("1.1")) return "1.1";
  return served.find((f) => !(f === "2" && choice.bad)) ?? served[0]!;
}

/**
 * Whether a failure of a framing-`"2"` connection, before the body of its
 * first request was released, is one the fallback of §2.3 covers (the
 * handshake, ALPN, the connection head, the provider closing): not a refusal
 * the node gave with a status (the credential, the balance, an expired
 * offer), which another framing would not change, and not a local fault.
 */
export function http2OpenFailure(error: unknown): boolean {
  if (error instanceof RequestRefusedError || error instanceof ConnectionDepositError) return false;
  if (error instanceof UpgradeRequiredError || error instanceof TwoPcVersionMismatchError) return false;
  if (error instanceof SessionRejectedError) {
    if (error.nodeCode?.startsWith("h2_") || error.nodeCode === "upstream_unreachable" || error.fault === "upstream") return true;
    return error.status === undefined || error.status >= 500 || error.status === 408;
  }
  if (error instanceof ConfidentialError) return error.code !== "not_configured" && error.code !== "pinned_parameter";
  return !(error instanceof DOMException);
}

/** A request that failed on a pooled connection before release may run again on a fresh one, unless the node refused it with a status. */
function retryOnFreshConnection(error: unknown): boolean {
  if (error instanceof RequestRefusedError) return false;
  return !(error instanceof SessionRejectedError && error.status !== undefined && error.status !== 408);
}

export const PREWARM_DEFAULTS = {
  enabled: true,
  maxAgeMs: 480_000,
  idleMs: 10 * 60_000,
  onlyWhenVisible: true,
  backoffMs: 30_000,
  maxDepositMsat: 5000,
  allowMetered: false,
  armWithoutOpen: true,
};

/**
 * The browser says the connection is metered: Save-Data is on, or the link is
 * cellular (Network Information API; false where the browser has none).
 */
export function meteredConnection(nav: unknown = typeof navigator !== "undefined" ? navigator : undefined): boolean {
  try {
    const c = (nav as { connection?: { saveData?: unknown; type?: unknown } } | undefined)?.connection;
    return !!c && (c.saveData === true || c.type === "cellular");
  } catch {
    return false;
  }
}

/**
 * When the pool may keep an armed connection: pre-warming on, the page
 * visible (and, after being hidden, only after real activity), not on a
 * metered link, the user active, an `sk-` key that already made a request,
 * and the key's available balance at least the deposit plus one reservation
 * of the current model. The pool itself arms only after a settled request of
 * the key, and only for a deposit of at most `maxDepositMsat`.
 */
export class Prewarmer {
  cfg: typeof PREWARM_DEFAULTS;
  private lastActivity = 0;
  private hiddenSinceActivity = false;
  private requestedWith?: string;
  private target?: { model: string; maxTokens: number };
  private funded = false;
  private fundsCheckedAt = 0;
  private applied?: boolean;
  private timer?: ReturnType<typeof setInterval>;
  private stopped = false;
  status: "off" | "idle" | "armed" | "waiting-funds" | "metered" | "hidden" = "off";

  constructor(
    private readonly client: ConfidentialClient,
    opts: PrewarmOptions,
  ) {
    this.cfg = { ...PREWARM_DEFAULTS, ...opts };
    if (!(this.cfg.maxAgeMs >= 60_000)) this.cfg.maxAgeMs = 60_000;
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState !== "visible" && this.cfg.onlyWhenVisible) {
          this.hiddenSinceActivity = true;
          this.apply("page hidden");
        }
      });
    }
    this.timer = setInterval(() => void this.tick(), 15_000);
  }

  private log(msg: string, extra: Record<string, unknown> = {}): void {
    this.client.emit({ ev: "prewarm", msg, status: this.status, ...extra });
  }

  private visible(): boolean {
    return !this.cfg.onlyWhenVisible || typeof document === "undefined" || document.visibilityState === "visible";
  }

  setTarget(model: string, maxTokens: number): void {
    const t = this.target;
    this.target = { model, maxTokens };
    if (t?.model !== model || t.maxTokens !== maxTokens) this.fundsCheckedAt = 0;
    void this.tick();
  }

  activity(): void {
    this.lastActivity = Date.now();
    if (this.visible()) this.hiddenSinceActivity = false;
    void this.tick();
  }

  /** A request was sent with the current credential: from now on the pool may arm for it. */
  noteRequest(): void {
    this.requestedWith = this.client.credential;
    this.lastActivity = Date.now();
    this.fundsCheckedAt = 0;
  }

  /** A request settled (or failed): the balance moved. */
  noteSettled(): void {
    this.fundsCheckedAt = 0;
    void this.tick();
  }

  /** Whether the pool may arm now, and why not. */
  private allowed(): { ok: boolean; why: Prewarmer["status"]; reason: string } {
    if (this.stopped || !this.cfg.enabled) return { ok: false, why: "off", reason: "pre-warming is off" };
    if (!this.visible() || this.hiddenSinceActivity) return { ok: false, why: "hidden", reason: "the page is hidden" };
    if (Date.now() - this.lastActivity > this.cfg.idleMs) return { ok: false, why: "idle", reason: "no recent activity" };
    if (!this.cfg.allowMetered && meteredConnection()) {
      return { ok: false, why: "metered", reason: "the connection is metered (Save-Data or cellular)" };
    }
    const cred = this.client.credential;
    if (!cred || !cred.startsWith("sk-") || this.requestedWith !== cred) return { ok: false, why: "idle", reason: "no request with this key yet" };
    if (!this.funded) return { ok: false, why: "waiting-funds", reason: "available balance below the deposit plus one reservation" };
    return { ok: true, why: "idle", reason: "" };
  }

  private async tick(): Promise<void> {
    if (this.stopped) return;
    const cred = this.client.credential;
    if (cred && cred.startsWith("sk-") && this.target && this.requestedWith === cred && Date.now() - this.fundsCheckedAt > 30_000) {
      this.fundsCheckedAt = Date.now();
      try {
        const target = this.target;
        const [bal, pricing] = await Promise.all([this.client.api.balance(cred), this.client.pricing(target.maxTokens)]);
        // Unknown pricing means an unknown reservation: do not arm blind.
        const need = pricing.find((x) => x.id === target.model)?.requiredMsat;
        const available = bal.balance - bal.reserved;
        const was = this.funded;
        this.funded = need !== undefined && available >= need;
        if (!this.funded && was) this.log("not arming: available balance below the deposit plus one reservation", { available, need });
      } catch (e) {
        this.funded = false;
        this.log(`cannot check the balance: ${errorText(e)}`);
      }
    }
    this.apply();
  }

  /** Tell the pool whether it may keep armed connections. */
  apply(reason?: string): void {
    const a = this.allowed();
    if (a.ok !== this.applied) {
      this.applied = a.ok;
      this.client.configurePrewarm(a.ok ? this.cfg : undefined);
      this.log(a.ok ? "pre-warming allowed" : `pre-warming paused: ${reason ?? a.reason}`);
    }
    this.status = a.ok ? (this.client.armedCount() > 0 ? "armed" : "idle") : a.why;
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.apply("stopped");
  }
}

// ─── client ─────────────────────────────────────────────────────────────────

/** A request the client is running: for its abort handling and its retries. */
interface RunState {
  handle?: ConnectionRequestHandle;
  conn?: ConfidentialConnection;
  warm?: PoolLease<ConfidentialConnection>["warm"];
  framing?: ConfidentialFraming;
  fellBack?: boolean;
  /** The response head reached the caller: never run the request again. */
  headSeen: boolean;
}

interface RequestSpec {
  kind: "chat" | "images";
  model: string;
  maxTokens: number;
  image?: { variant: string; count: number };
  body: Uint8Array;
  onResponseHead?: (h: Head) => void;
  onResponseBody?: (chunk: Uint8Array) => void;
}

export class ConfidentialClient {
  readonly node: string;
  readonly api: NodeApi;
  credential?: string;
  private readonly opts: ConfidentialClientOptions;
  private offerCache?: { offer: VerifiedOffer; at: number };
  private modelsCache?: { models: NodeModel[]; at: number };
  private outdatedReported = false;
  readonly pool: ConnectionPool<ConfidentialConnection>;
  readonly prewarmer?: Prewarmer;
  /** The framing setting (`setHttp`). */
  http: "auto" | ConfidentialFraming;

  /**
   * Where the wasm runs: the configured host, else the page-wide default,
   * looked up per connection so a crashed default worker is replaced.
   */
  get host(): WasmHost {
    return this.opts.host ?? getDefaultWasmHost();
  }

  constructor(opts: ConfidentialClientOptions) {
    if (!opts.trustedHosts?.length) throw new ConfidentialError("not_configured", "trustedHosts is required");
    if (!opts.nodePubkeys?.length) throw new ConfidentialError("not_configured", "nodePubkeys is required");
    // Pinned keys authenticate the offer, not the connection: the setup
    // carries the credential, which plain http would expose on the wire.
    if (!opts.allowInsecureTransport && !encryptedNodeTransport(opts.node)) {
      throw new ConfidentialError(
        "not_configured",
        `refusing plain http to ${opts.node}: the credential would travel unencrypted (use https)`,
      );
    }
    if (opts.http !== undefined && opts.http !== "auto" && opts.http !== "2" && opts.http !== "1.1") {
      throw new ConfidentialError("not_configured", `http is not "auto", "2" or "1.1"`);
    }
    this.opts = opts;
    this.http = opts.http ?? "auto";
    this.node = opts.node.replace(/\/$/, "");
    this.api = new NodeApi(this.node, opts.fetchImpl);
    this.credential = opts.credential;
    this.pool = new ConnectionPool<ConfidentialConnection>(this.poolOptions(), undefined);
    if (opts.prewarm) this.prewarmer = new Prewarmer(this, opts.prewarm === true ? {} : opts.prewarm);
  }

  private poolOptions(): Http2Options {
    return { ...(this.opts.http2 ?? {}), log: (message) => this.emit({ ev: "pool", msg: message }) };
  }

  /** @internal The pre-warmer's switch: armed connections allowed with these terms, or none. */
  configurePrewarm(cfg: typeof PREWARM_DEFAULTS | undefined): void {
    this.pool.configure(
      this.poolOptions(),
      cfg
        ? {
            enabled: true,
            maxAgeMs: cfg.maxAgeMs,
            activityWindowMs: cfg.idleMs,
            maxTotal: 1,
            backoffBaseMs: cfg.backoffMs,
            maxDepositMsat: cfg.maxDepositMsat,
            armWithoutOpen: cfg.armWithoutOpen,
            log: (message) => this.emit({ ev: "pool", msg: message }),
          }
        : undefined,
    );
  }

  /** Armed connections in the pool (pre-warmed, unused). */
  armedCount(): number {
    return this.pool.snapshot().filter((e) => e.state === "armed").length;
  }

  /** The pool's connections (no credentials), for a status display. */
  connections(): ReturnType<ConnectionPool["snapshot"]> {
    return this.pool.snapshot();
  }

  emit(ev: Record<string, unknown>): void {
    this.opts.onEvent?.({ t: Date.now(), ...ev });
  }

  setCredential(credential: string | undefined): void {
    // Connections hold the old credential's deposit: another key opens its own.
    if (credential !== this.credential) this.pool.close();
    this.credential = credential;
    this.prewarmer?.activity();
  }

  /**
   * The framing setting: `"auto"` (the offer's choice, with fallback), `"2"`,
   * or `"1.1"` (HTTP/2 off). Open and armed connections are closed.
   */
  setHttp(http: "auto" | ConfidentialFraming): void {
    if (http !== "auto" && http !== "2" && http !== "1.1") throw new ConfidentialError("not_configured", `http is not "auto", "2" or "1.1"`);
    if (http === this.http) return;
    this.http = http;
    this.pool.close();
    this.prewarmer?.activity();
  }

  /** The node's signed offer, verified under this client's pins (cached 30 s). */
  async offer(fresh = false): Promise<VerifiedOffer> {
    const policy = { pinnedPubkeys: this.opts.nodePubkeys, trustedHosts: this.opts.trustedHosts };
    const hit = this.offerCache;
    if (!fresh && hit && Date.now() - hit.at < 30_000) return verifyConfidentialOffer(hit.offer, policy);
    try {
      const offer = await fetchConfidentialOffer(this.node, { ...policy, fetchImpl: this.opts.fetchImpl });
      this.offerCache = { offer, at: Date.now() };
      return offer;
    } catch (e) {
      if (e instanceof NodeProtocolOutdatedError && !this.outdatedReported) {
        this.outdatedReported = true;
        this.emit({ ev: "node_protocol_outdated", node: this.node, node_version: e.nodeVersion });
        try {
          this.opts.onNodeProtocolOutdated?.(this.node, e.nodeVersion);
        } catch {
          /* the caller's */
        }
      }
      throw e;
    }
  }

  async models(): Promise<NodeModel[]> {
    if (this.modelsCache && Date.now() - this.modelsCache.at < 300_000) return this.modelsCache.models;
    const models = await this.api.models().catch(() => [] as NodeModel[]);
    this.modelsCache = { models, at: Date.now() };
    return models;
  }

  /** Confidential models with their signed rates, the reservation for `maxTokens` and the connection deposit. */
  async pricing(maxTokens?: number): Promise<ModelPricing[]> {
    const [offer, models] = await Promise.all([this.offer(), this.models()]);
    return modelPricing(offer, models, maxTokens ?? offer.max_tokens_cap);
  }

  /** The framing the next request of `kind` would use (the setting, the offer, a fallback in force). */
  async framing(kind: "chat" | "images" = "chat"): Promise<ConfidentialFraming> {
    const offer = await this.offer();
    return chooseFraming(offer, kind, { http: this.http, bad: this.pool.isBad(this.node), node: this.node });
  }

  /** Arm for the model the user is about to use (pre-warm). */
  prepare(model: string, maxTokens?: number): void {
    this.prewarmer?.setTarget(model, maxTokens ?? this.offerCache?.offer.max_tokens_cap ?? 4096);
  }

  /** Turn pre-warming on or off at runtime (off closes the armed connection). */
  setPrewarm(enabled: boolean): void {
    if (!this.prewarmer) return;
    this.prewarmer.cfg.enabled = enabled;
    if (enabled) this.prewarmer.activity();
    else this.prewarmer.apply("pre-warming turned off");
  }

  /** Signal user activity (typing, focus) to the pre-warmer. */
  activity(): void {
    this.prewarmer?.activity();
  }

  private maxDepositMsat(): number {
    const v = this.opts.maxConnectionDepositMsat;
    return typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : DEFAULT_MAX_CONNECTION_DEPOSIT_MSAT;
  }

  private checkDeposit(offer: VerifiedOffer): void {
    const deposit = offerConnectionDepositMsat(offer);
    const max = this.maxDepositMsat();
    if (deposit > max) {
      throw new ConnectionDepositError(
        `${this.node} asks for a connection deposit of ${deposit} msat, above the maximum of ${max} msat (maxConnectionDepositMsat)`,
        deposit,
      );
    }
  }

  /**
   * One request on a pooled connection: an idle open one, else an armed one,
   * else a new one. A pooled connection may have died since its last request;
   * while nothing of this request was released towards the provider it runs
   * again on a fresh connection, and never after. A framing-"2" connection that
   * fails to open is marked bad and the request is served on "1.1" (§2.3).
   */
  private async runOnPool(
    offer: VerifiedOffer,
    auth: string,
    spec: RequestSpec,
    state: RunState,
    signal: AbortSignal | undefined,
  ): Promise<ConnectionRequestResult> {
    const pool = this.pool;
    const oneOff = auth.startsWith("cashu");
    this.checkDeposit(offer);
    // Connections of other connection-level terms (an offer that changed) are never taken.
    const key = poolKey({
      baseUrl: this.node,
      bearer: auth,
      scope: `${this.opts.reuseScope ?? ""}\0${connectionTerms(offer)}${oneOff ? `\0${crypto.randomUUID()}` : ""}`,
    });
    const open = (framing: ConfidentialFraming) =>
      new ConfidentialConnection({
        baseUrl: this.node,
        offer,
        framing,
        auth,
        host: this.host,
        webSocketImpl: this.opts.webSocketImpl,
        allowInsecureTransport: this.opts.allowInsecureTransport,
        maxDepositMsat: this.maxDepositMsat(),
        onEvent: (e) => this.emit({ ...e, kind: spec.kind }),
      });
    let forced: ConfidentialFraming | undefined;
    for (let attempt = 0; ; attempt++) {
      if (signal?.aborted) throw aborted();
      const framing = forced ?? chooseFraming(offer, spec.kind, { http: this.http, oneOff, bad: pool.isBad(this.node), node: this.node });
      const fallbackTo11 = (error: unknown): boolean =>
        framing === "2" && this.http === "auto" && offerFramingsFor(offer, spec.kind).includes("1.1") && http2OpenFailure(error);
      const traffic = pool.noteRequest(
        key,
        // Image requests never start an arm: the pool arms for chat traffic.
        { baseUrl: this.node, framing, depositMsat: offerConnectionDepositMsat(offer), prewarmable: !oneOff && spec.kind === "chat" },
        open,
      );
      let lease: PoolLease<ConfidentialConnection>;
      try {
        lease = await pool.acquire(key, framing, open, signal);
      } catch (error) {
        traffic.done();
        if (signal?.aborted) throw error;
        if (fallbackTo11(error) && attempt < 3) {
          // §2.3: the connection failed before any request: "1.1" on the same node.
          pool.markBad(this.node, errorText(error));
          this.emit({ ev: "framing_fallback", from: "2", to: "1.1", reason: errorText(error) });
          forced = "1.1";
          state.fellBack = true;
          continue;
        }
        throw error;
      }
      const conn = lease.conn;
      if (signal?.aborted) {
        lease.release();
        traffic.done();
        throw aborted();
      }
      let handle: ConnectionRequestHandle;
      try {
        handle = conn.request({
          // Priced by the offer verified for this call (the node may have re-signed it since the connection opened).
          offer,
          auth,
          model: spec.model,
          maxTokens: spec.maxTokens,
          image: spec.image,
          body: spec.body,
          padBucket: this.opts.padBucket,
          onResponseHead: (h) => {
            state.headSeen = true;
            spec.onResponseHead?.(h);
          },
          onResponseBody: spec.onResponseBody,
        });
      } catch (error) {
        // The connection ended between the pool's check and now: nothing was sent.
        lease.release();
        traffic.done();
        if (attempt < 2 && !(error instanceof ConfidentialError && error.code === "session_protocol")) continue;
        throw error;
      }
      state.handle = handle;
      state.conn = conn;
      state.framing = framing;
      state.warm = lease.warm;
      this.emit({ ev: "request", kind: spec.kind, model: spec.model, http: framing, n: handle.n, path: lease.warm === "open" ? "reused" : lease.warm });
      try {
        const r = await handle.done;
        // A one-off bearer's connection is never kept (§9.1).
        if (oneOff) conn.close("one-off bearer");
        lease.release(true);
        traffic.done();
        return r;
      } catch (error) {
        const refused = error instanceof RequestRefusedError;
        // A refused request leaves its connection usable: it goes back to the
        // pool. Except `offer_changed`: the node takes no further request on a
        // connection whose terms it no longer serves (§3.3), so the retry with
        // the refetched offer opens a new one.
        if (oneOff) conn.close("one-off bearer");
        else if (refused && offerChangedRefusal(error)) conn.close("offer_changed");
        lease.release();
        traffic.done();
        if (refused || handle.bodyReleased || state.headSeen || signal?.aborted || attempt >= 3) throw error;
        const first = handle.n === 1 && lease.warm !== "open";
        if (first && fallbackTo11(error)) {
          // §2.3: the connection failed before the body of its first request was released.
          pool.markBad(this.node, errorText(error));
          this.emit({ ev: "framing_fallback", from: "2", to: "1.1", reason: errorText(error) });
          forced = "1.1";
          state.fellBack = true;
          state.handle = undefined;
          continue;
        }
        // A connection that was open or armed before the request may have died meanwhile: once more on a fresh one.
        if (lease.warm === "cold" || !retryOnFreshConnection(error)) throw error;
        this.emit({ ev: "request_retry", reason: `failed before release on a kept connection: ${errorText(error)}` });
        state.handle = undefined;
      }
    }
  }

  /**
   * Confidential image generation, flat-priced at the signed offer's
   * per-image price: on a framing-"2" connection when the offer's `h2.kinds`
   * lists images, else on a connection of its own. Never armed in advance.
   */
  readonly images = {
    generate: (params: ImageGenerateParams, options?: { signal?: AbortSignal }) => this.generateImages(params, options?.signal, false),
    /** The signed offer's image block (models, variants, prices), or undefined. */
    offer: async (): Promise<ConfidentialImagesOffer | undefined> => offerImages(await this.offer()),
  };

  private async generateImages(params: ImageGenerateParams, signal: AbortSignal | undefined, freshOffer: boolean): Promise<ImageGenerateResult> {
    const auth = this.credential;
    if (!auth) throw new ConfidentialError("not_configured", "no credential: fund the wallet or paste an sk- key");
    if (signal?.aborted) throw aborted();
    const offer = await this.offer(freshOffer);
    const images = offerImages(offer);
    if (!images) throw new ConfidentialError("offer_no_images", "the node offers no confidential image generation");
    const { variant: variantId, aspectRatio, ...request } = params;
    if (!images.price_list[params.model]) {
      throw new ConfidentialError("offer_no_images", `the node does not serve ${params.model} for confidential images`);
    }
    if (aspectRatio !== undefined) request.aspect_ratio = aspectRatio;
    const { model, variant, count, privateOptions } = planImageRequest(images, request, variantId);
    const suffix = imageSuffix(images, model, variant, count);
    const body = buildImageBody(privateOptions, suffix, pinnedImageKeys(images, variant));
    if (signal?.aborted) throw aborted();
    const state: RunState = { headSeen: false };
    const tRequest = Date.now();
    let rejectAborted!: (e: unknown) => void;
    const abortedP = new Promise<never>((_, rej) => (rejectAborted = rej));
    abortedP.catch(() => {});
    let detached = false;
    // Before release, an abort closes the connection. After it the provider
    // has the request: the caller gets an AbortError at once and the request
    // settles in the background (accept, or the error head).
    const abort = () => {
      rejectAborted(aborted());
      if (state.handle?.bodyReleased) {
        detached = true;
        this.emit({ ev: "request_aborted", kind: "images", released: true, msg: "settling in the background" });
      } else {
        state.handle?.close();
        this.emit({ ev: "request_aborted", kind: "images", released: false });
      }
    };
    signal?.addEventListener("abort", abort, { once: true });
    const runP = this.runOnPool(offer, auth, { kind: "images", model, maxTokens: 0, image: { variant: variant.id, count }, body }, state, signal).finally(
      () => {
        signal?.removeEventListener("abort", abort);
        this.prewarmer?.noteSettled();
      },
    );
    runP.catch(() => {});
    let r: ConnectionRequestResult;
    try {
      r = await Promise.race([runP, abortedP]);
    } catch (e) {
      if (!detached && !(e instanceof RequestRefusedError)) state.handle?.close();
      // Retried only while nothing could have reached the provider.
      if (isOfferExpired(e) && !freshOffer && !state.handle?.bodyReleased && !signal?.aborted) {
        return this.generateImages(params, signal, true);
      }
      throw e;
    }
    let warnings: string[] = r.warnings ?? [];
    let blobs: Blob[] = [];
    if (r.status >= 200 && r.status < 300) {
      // The body is held once at each step: the pieces become the text, the text the images.
      const dec = new TextDecoder();
      const chunks = r.bodyChunks ?? [r.body];
      let text = "";
      while (chunks.length) text += dec.decode(chunks.shift()!, { stream: true });
      text += dec.decode();
      const checked = checkImageResponse(
        {
          status: r.status,
          statusText: "",
          headers: r.headers,
          raw: new Uint8Array(0),
          body: new Uint8Array(0),
          bodyText: text,
          contentType: r.headers["content-type"] ?? "",
          // The response ended (END_STREAM, or the end of the chunked body) before it was accepted.
          complete: true,
        },
        images.response_shape,
        { model, count, countKey: imageCountKey(images) },
      );
      warnings = [...warnings, ...checked.warnings];
      const mime = imageMimeType(variant.pins);
      blobs = checked.image.data.map((d) => new Blob([base64ToBytes(d.b64_json) as BlobPart], { type: mime }));
    }
    const result = requestResult(r, state.conn!, state.warm ?? "cold", tRequest, { responseText: "", fellBack: state.fellBack });
    result.images = blobs;
    result.imageVariant = variant.id;
    result.imageCount = count;
    result.warnings = warnings;
    if (r.status >= 400) throw new UpstreamImageError(r.status, `the provider refused the image request: HTTP ${r.status}`, result);
    return {
      images: blobs,
      model,
      variant: variant.id,
      count,
      msatPerImage: variant.msat_per_image,
      costMsats: Number(r.receipt.cost_msats ?? 0),
      warnings,
      confidential: result,
    };
  }

  readonly chat = {
    completions: {
      create: ((params: ChatCompletionCreateParams, options?: { signal?: AbortSignal }) => this.create(params, options)) as {
        (params: ChatCompletionCreateParams & { stream: true }, options?: { signal?: AbortSignal }): Promise<ConfidentialStream>;
        (params: ChatCompletionCreateParams & { stream?: false }, options?: { signal?: AbortSignal }): Promise<ChatCompletion>;
        (params: ChatCompletionCreateParams, options?: { signal?: AbortSignal }): Promise<ConfidentialStream | ChatCompletion>;
      },
    },
  };

  private async create(params: ChatCompletionCreateParams, options: { signal?: AbortSignal } = {}): Promise<ConfidentialStream | ChatCompletion> {
    const stream = await this.runStream(params, options.signal, false);
    if (params.stream) return stream;
    const events: ChatCompletionChunk[] = [];
    for await (const c of stream) events.push(c);
    const result = await stream.verification;
    return { ...aggregateChatCompletion(events as never[]), confidential: result };
  }

  private async runStream(params: ChatCompletionCreateParams, signal: AbortSignal | undefined, freshOffer: boolean): Promise<ConfidentialStream> {
    const auth = this.credential;
    if (!auth) throw new ConfidentialError("not_configured", "no credential: fund the wallet or paste an sk- key");
    const offer = await this.offer(freshOffer);
    const model = params.model;
    if (!Object.hasOwn(offer.price_list, model)) {
      throw new ConfidentialError("offer_malformed", `the node does not serve ${model} confidentially`);
    }
    const maxTokens = requestedMaxTokens(params, Number(offer.max_tokens_cap ?? 4096));
    const body = buildPinnedBody(params, model, maxTokens, offer.chat);
    const pw = this.prewarmer;
    // The request's start: it may first wait for a connection, and that wait belongs in its timings.
    const tRequest = Date.now();
    pw?.noteRequest();
    pw?.setTarget(model, maxTokens);

    const queue: ChatCompletionChunk[] = [];
    let wake: (() => void) | undefined;
    let ended = false;
    let failure: unknown;
    const notify = () => {
      wake?.();
      wake = undefined;
    };
    const sse = new SseParser();
    const textParts: Uint8Array[] = [];
    let resolveHead!: (h: Head) => void;
    const head = new Promise<Head>((r) => (resolveHead = r));
    const state: RunState = { headSeen: false };
    let callerAborted = false;
    let detached = false;
    const isAborted = () => callerAborted || !!signal?.aborted;
    let rejectAborted!: (e: unknown) => void;
    const abortedP = new Promise<never>((_, rej) => (rejectAborted = rej));
    abortedP.catch(() => {});
    // Before release nothing reached the provider: close at once (the
    // connection ends; §12.10 says what the node keeps). After it the provider
    // has the request: closing would leave the node to charge the whole
    // reservation, so only the caller's stream ends and the request drains
    // (capped by the pinned max_tokens) and settles on the reported usage.
    const abort = () => {
      if (callerAborted) return;
      callerAborted = true;
      failure ??= aborted();
      rejectAborted(aborted());
      if (state.handle?.bodyReleased) {
        detached = true;
        queue.length = 0;
        this.emit({ ev: "request_aborted", released: true, msg: "settling in the background" });
      } else {
        state.handle?.close();
        this.emit({ ev: "request_aborted", released: false });
      }
      ended = true;
      notify();
    };
    if (signal?.aborted) abort();
    signal?.addEventListener("abort", abort, { once: true });

    const runP = this.runOnPool(
      offer,
      auth,
      {
        kind: "chat",
        model,
        maxTokens,
        body,
        onResponseHead: (h) => resolveHead(h),
        onResponseBody: (chunk) => {
          if (!chunk.length) return;
          textParts.push(chunk);
          if (detached) return;
          for (const ev of sse.push(chunk)) queue.push(ev as ChatCompletionChunk);
          notify();
        },
      },
      state,
      signal,
    );
    const verification = runP
      .then((r) => {
        const text = new TextDecoder().decode(concatParts(textParts));
        return requestResult(r, state.conn!, state.warm ?? "cold", tRequest, { responseText: text, fellBack: state.fellBack });
      })
      .finally(() => {
        signal?.removeEventListener("abort", abort);
        pw?.noteSettled();
      });
    verification.then(
      () => {
        ended = true;
        notify();
      },
      (e) => {
        failure ??= e;
        ended = true;
        notify();
      },
    );
    verification.catch(() => {});

    // Fail fast on a refusal before any response (402 balance, 409 offer changed, a deposit too large).
    const first = await Promise.race([head.then(() => "head" as const), verification.then(() => "done" as const), abortedP]).catch(
      async (e: unknown) => {
        // Retried only while nothing could have reached the provider.
        if (isOfferExpired(e) && !freshOffer && !state.handle?.bodyReleased && !isAborted()) return "retry" as const;
        throw e;
      },
    );
    if (first === "retry") return this.runStream(params, signal, true);

    const iterator = async function* (): AsyncGenerator<ChatCompletionChunk> {
      for (;;) {
        while (queue.length) yield queue.shift()!;
        if (ended) break;
        await new Promise<void>((r) => (wake = r));
      }
      while (queue.length) yield queue.shift()!;
      if (failure) throw failure;
    };
    return { [Symbol.asyncIterator]: iterator, verification, head, abort };
  }

  /** Close every connection and stop pre-warming (an unused armed connection loses its deposit). */
  close(): void {
    this.prewarmer?.stop();
    this.pool.close();
  }
}

function concatParts(parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function createConfidentialClient(opts: ConfidentialClientOptions): ConfidentialClient {
  return new ConfidentialClient(opts);
}

export type { ConfidentialRequestResult };
