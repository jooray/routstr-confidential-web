/**
 * `createConfidentialClient`: an OpenAI-like client whose every request runs
 * as a confidential session (protocol v2) from the browser.
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
 * const proof = await stream.verification; // receipt, proofs, provider certificate, timings
 * ```
 *
 * A stream ends cleanly only after settlement verified (π_C2S, π_C3S, the
 * signed receipt, its usage and its cost); any failed check makes the
 * iterator throw. Body bytes are handed out as TLS records decrypt: each one
 * is authenticated by AES-GCM under keys only this page holds.
 */

import { ConfidentialError, SessionRejectedError, UpstreamImageError } from "./errors.js";
import { encryptedNodeTransport } from "./hosts.js";
import {
  fetchConfidentialOffer,
  offerAbandonFeeMsat,
  offerImages,
  offerSessionFeeMsat,
  verifyConfidentialOffer,
  type ConfidentialImagesOffer,
  type ConfidentialImageVariant,
  type VerifiedOffer,
} from "./offer.js";
import { buildImageBody, imageSuffix, pinnedImageKeys, planImageRequest } from "./images.js";
import { NodeApi, type NodeModel } from "./node-api.js";
import { modelPricing, type ModelPricing } from "./pricing.js";
import { aggregateChatCompletion, buildPinnedBody, chooseBucket, padPinnedBody, requestedMaxTokens, SseParser } from "./request.js";
import { ConfidentialSession, type ConfidentialSessionResult } from "./session.js";
import { canonicalSuffix } from "./suffix.js";
import { getDefaultWasmHost, type WasmHost } from "./wasm/host.js";

export interface PrewarmOptions {
  /** Default true when an options object is given. */
  enabled?: boolean;
  /** Close an armed session this long after setup (the node ends sessions at 600 s; at least 60 s). */
  maxAgeMs?: number;
  /** No activity (request, typing, focus) for this long: tear down, stop arming. */
  idleMs?: number;
  /**
   * Arm only while `document.visibilityState === "visible"` (default true).
   * Hiding the page closes the armed session; showing it again arms nothing
   * until the next `activity()` or request.
   */
  onlyWhenVisible?: boolean;
  /**
   * Pre-warm on a metered connection too: when the browser reports
   * `navigator.connection.saveData` or a cellular connection (default false).
   * Each arm costs about 22 MB.
   */
  allowMetered?: boolean;
  /** Smallest armed body length (bytes). */
  minBucket?: number;
  /** Retry delay after a failed arm (doubles up to 10 min). */
  backoffMs?: number;
  /**
   * Do not pre-warm when the node keeps more than this (msat) for a session
   * that is armed but never used (the offer's abandon fee). Default 5000
   * (5 sats, the SDK's default): symbolic fees are fine, anything larger is not.
   */
  maxAbandonFeeMsat?: number;
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
  /** Keep one session armed while the page is visible and the key is funded. */
  prewarm?: boolean | PrewarmOptions;
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
  /** Settles with the verified session (receipt, proofs, certificate, timings); rejects on any failed check. */
  verification: Promise<ConfidentialSessionResult>;
  /** The upstream HTTP status and headers. */
  head: Promise<{ status: number; statusText: string; headers: Record<string, string> }>;
  /**
   * Stop the answer. Before the body is released this closes the session;
   * after it, only this stream ends (with an AbortError) and the session
   * settles in the background, `verification` resolving with its receipt.
   */
  abort(): void;
}

export type ChatCompletion = Record<string, unknown> & { confidential: ConfidentialSessionResult };

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
  /** The verified session: receipt, proofs, provider certificate, timings. */
  confidential: ConfidentialSessionResult;
}

/** What one image request costs at the signed offer (msats), before it runs. */
export function imageRequestCostMsat(offer: VerifiedOffer, variant: ConfidentialImageVariant, count: number): number {
  return Math.ceil(variant.msat_per_image * count + offerSessionFeeMsat(offer));
}


type Head = { status: number; statusText: string; headers: Record<string, string> };

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function isOfferExpired(e: unknown): boolean {
  if (!(e instanceof SessionRejectedError)) return false;
  const d = e.nodeDetail as { error?: { type?: string } } | undefined;
  return e.status === 409 && (d?.error?.type === "offer_expired" || d?.error?.type === "session_fee_not_accepted");
}

// ─── pre-warm ───────────────────────────────────────────────────────────────

interface Armed {
  key: string;
  session: ConfidentialSession;
  ready: Promise<ConfidentialSession>;
  model: string;
  maxTokens: number;
}

/** The shortest `maxAgeMs` the pre-warmer accepts. */
const PREWARM_MIN_MAX_AGE_MS = 60_000;

const PREWARM_DEFAULTS = {
  enabled: true,
  maxAgeMs: 480_000,
  idleMs: 10 * 60_000,
  onlyWhenVisible: true,
  minBucket: 4096,
  backoffMs: 30_000,
  maxAbandonFeeMsat: 5000,
  allowMetered: false,
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
 * One armed session for the current (model, max_tokens), kept while the page
 * is visible, the user is active and the key is funded. A simplified version
 * of routstr-sdk's traffic-driven pool: nothing is armed before there is a
 * funded `sk-` key, a target model, a first chat request with that key (so
 * the first one is cold) and recent user activity (`activity()`, or a
 * request); an armed session is closed (the node
 * releases its reservation) when the page is hidden, after `idleMs` without
 * activity, or `maxAgeMs` after setup.
 */
export class Prewarmer {
  cfg: typeof PREWARM_DEFAULTS;
  private armed?: Armed;
  private target?: { model: string; maxTokens: number };
  /** No activity yet: choosing a model or opening the page arms nothing. */
  private lastActivity = 0;
  /**
   * The page was hidden since the last activity: showing it again (or the
   * periodic tick) must not arm; the next real activity or request does.
   */
  private hiddenSinceActivity = false;
  /** The credential of the last chat request: no arm before a first request with the current one. */
  private requestedWith?: string;
  /**
   * The body length of the latest request. The next arm is sized for it (a
   * conversation's body only grows, and chooseBucket adds headroom), not for
   * the largest body ever seen: one message with an image would otherwise pad
   * every later prepared session, in a new chat too, to that image's size.
   */
  private lastBody = 0;
  /** Requests still waiting for a 2PC preparation (cold, or a claimed arm in progress). */
  private preparing = 0;
  /** Set while ensure() is between its first check and registering the armed session. */
  private armWait?: Promise<Armed | undefined>;
  private arming = false;
  private backoffUntil = 0;
  private backoff = 0;
  /**
   * Armed sessions that died before use since a warm request last succeeded.
   * Each one doubles the wait before the next arm: a node that keeps ending
   * armed sessions would otherwise cost an arm (and its abandon fee) per tick.
   */
  private deaths = 0;
  private timer?: ReturnType<typeof setInterval>;
  private stopped = false;
  status: "off" | "idle" | "arming" | "armed" | "waiting-funds" | "backoff" | "metered" = "off";

  constructor(
    private readonly client: ConfidentialClient,
    opts: PrewarmOptions,
  ) {
    this.cfg = { ...PREWARM_DEFAULTS, ...opts };
    // Each retired, unused session costs its 2PC traffic and possibly an
    // abandon fee: a near-zero age would arm and retire one on every tick.
    if (this.cfg.maxAgeMs === undefined) this.cfg.maxAgeMs = PREWARM_DEFAULTS.maxAgeMs;
    if (!(this.cfg.maxAgeMs >= PREWARM_MIN_MAX_AGE_MS)) this.cfg.maxAgeMs = PREWARM_MIN_MAX_AGE_MS;
    if (typeof document !== "undefined") {
      // Each hide closes the armed session (its abandon fee) and each re-arm
      // costs ~22 MB: switching apps on a phone must not repeat that, so a
      // page shown again waits for real activity before it arms.
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState !== "visible" && this.cfg.onlyWhenVisible) {
          this.hiddenSinceActivity = true;
          this.teardown("page hidden");
        }
      });
    }
    this.timer = setInterval(() => this.tick(), 15_000);
  }

  private log(msg: string, extra: Record<string, unknown> = {}): void {
    this.client.emit({ ev: "prewarm", msg, status: this.status, ...extra });
  }

  setTarget(model: string, maxTokens: number): void {
    const t = this.target;
    this.target = { model, maxTokens };
    if (this.armed && (t?.model !== model || t.maxTokens !== maxTokens)) this.teardown("target changed");
    void this.ensure();
  }

  noteBody(len: number): void {
    this.lastBody = len;
  }

  activity(): void {
    this.lastActivity = Date.now();
    if (this.visible()) this.hiddenSinceActivity = false;
    void this.ensure();
  }

  /** A chat request was sent with the current credential: from now on activity may arm. */
  noteRequest(): void {
    this.requestedWith = this.client.credential;
  }

  /**
   * A request is waiting for a 2PC preparation. No new session is armed
   * meanwhile: two ~22 MB preparations at once would slow the one the user is
   * waiting for.
   */
  beginPreparing(): void {
    this.preparing++;
  }

  /**
   * That preparation is done (or failed): arm the next session right away.
   * An image request passes `activity: false`: it held the pool back while it
   * ran, but it is not chat activity and must not start a chat arm itself.
   */
  endPreparing(activity = true): void {
    this.preparing = Math.max(0, this.preparing - 1);
    if (activity) this.activity();
    else void this.ensure();
  }

  private visible(): boolean {
    return !this.cfg.onlyWhenVisible || typeof document === "undefined" || document.visibilityState === "visible";
  }

  /** A healthy armed session for this request, or undefined. */
  take(model: string, maxTokens: number, bodyLen: number): Promise<ConfidentialSession> | undefined {
    const a = this.armed;
    if (!a && this.armWait) {
      // An arm is starting (checking funds and the offer): wait for it rather
      // than starting a second, cold preparation.
      return this.armWait.then((armed) => {
        const lease = armed && this.armed === armed ? this.take(model, maxTokens, bodyLen) : undefined;
        if (!lease) throw new Error("no armed session after all");
        return lease;
      });
    }
    if (!a || a.model !== model || a.maxTokens !== maxTokens) return undefined;
    if (a.session.bodyLength < bodyLen) {
      this.teardown("armed body length too small");
      return undefined;
    }
    if (!a.session.healthy && a.session.isArmed) {
      this.teardown("armed session unhealthy");
      this.armedFailed("armed session died before use");
      return undefined;
    }
    this.armed = undefined;
    this.status = "idle";
    this.log("claimed armed session");
    return a.ready;
  }

  teardown(reason: string): void {
    if (this.armed) {
      this.armed.session.close();
      this.armed = undefined;
      this.log(`closed armed session (${reason})`);
    }
    this.status = this.stopped || !this.cfg.enabled ? "off" : "idle";
  }

  /** An armed session ended (or failed when claimed) before it was used: back off. */
  armedFailed(reason: string): void {
    this.deaths++;
    const ms = Math.min(this.cfg.backoffMs * 2 ** (this.deaths - 1), 600_000);
    this.backoffUntil = Math.max(this.backoffUntil, Date.now() + ms);
    this.status = "backoff";
    this.log(`${reason}; backing off`, { backoff_ms: ms });
  }

  /** A request served from an armed session succeeded: earlier deaths stop counting. */
  servedWarm(): void {
    if (this.deaths === 0) return;
    this.deaths = 0;
    this.backoffUntil = 0;
  }

  private tick(): void {
    const a = this.armed;
    if (a && a.session.isArmed && !a.session.healthy) {
      this.teardown("unhealthy");
      this.armedFailed("armed session died before use");
    } else if (a && Date.now() - a.session.startedAt > this.cfg.maxAgeMs) {
      this.teardown("expired");
    }
    if (Date.now() - this.lastActivity > this.cfg.idleMs) this.teardown("idle");
    void this.ensure();
  }

  async ensure(): Promise<void> {
    if (this.stopped || !this.cfg.enabled || this.arming || this.armed || this.preparing > 0) return;
    if (!this.visible() || this.hiddenSinceActivity || Date.now() - this.lastActivity > this.cfg.idleMs) return;
    if (Date.now() < this.backoffUntil) return;
    if (!this.cfg.allowMetered && meteredConnection()) {
      if (this.status !== "metered") {
        this.status = "metered";
        this.log("not arming: the connection is metered (Save-Data or cellular)");
      }
      return;
    }
    if (this.status === "metered") this.status = "idle";
    const cred = this.client.credential;
    const target = this.target;
    if (!cred || !cred.startsWith("sk-") || !target || this.requestedWith !== cred) return;
    this.arming = true;
    let registered: (a: Armed | undefined) => void = () => {};
    this.armWait = new Promise<Armed | undefined>((r) => (registered = r));
    try {
      // No sats, no session: arming reserves funds on the key.
      const [offer, bal] = await Promise.all([this.client.offer(), this.client.api.balance(cred)]);
      const pricing = (await this.client.pricing(target.maxTokens)).find((p) => p.id === target.model);
      const available = bal.balance - bal.reserved;
      // Unknown pricing means an unknown reservation: do not arm blind.
      const need = pricing?.reservationMsat;
      if (need === undefined) return;
      if (available < need) {
        this.status = "waiting-funds";
        this.log("not arming: available balance below one reservation", { available, need });
        return;
      }
      if (!Object.hasOwn(offer.price_list, target.model)) return;
      const abandonFee = offerAbandonFeeMsat(offer);
      if (abandonFee > this.cfg.maxAbandonFeeMsat) {
        this.status = "off";
        this.log("not arming: the node's abandon fee exceeds maxAbandonFeeMsat", { abandonFee });
        return;
      }
      const len = chooseBucket(this.lastBody, { minBucket: this.cfg.minBucket });
      const session = this.client.newSession(offer, cred, target.model, target.maxTokens, len);
      this.status = "arming";
      this.log("arming", { model: target.model, body_len: len });
      const ready = session.arm().then(() => session);
      const armed: Armed = { key: `${target.model}|${target.maxTokens}`, session, ready, model: target.model, maxTokens: target.maxTokens };
      this.armed = armed;
      registered(armed);
      ready.then(
        () => {
          if (this.armed === armed) {
            this.status = "armed";
            this.backoff = 0;
            this.log("armed", { arm_ms: session.armedAt - session.startedAt });
          }
        },
        (e) => {
          if (this.armed === armed) {
            this.armed = undefined;
            this.backoff = Math.min(this.backoff ? this.backoff * 2 : this.cfg.backoffMs, 600_000);
            this.backoffUntil = Date.now() + this.backoff;
            this.status = "backoff";
            this.log(`arm failed: ${errorText(e)}`);
          }
          session.close();
        },
      );
      ready.catch(() => {});
    } catch (e) {
      this.backoff = Math.min(this.backoff ? this.backoff * 2 : this.cfg.backoffMs, 600_000);
      this.backoffUntil = Date.now() + this.backoff;
      this.status = "backoff";
      this.log(`cannot arm: ${errorText(e)}`);
    } finally {
      this.arming = false;
      this.armWait = undefined;
      registered(undefined);
    }
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.teardown("stopped");
  }
}

// ─── client ─────────────────────────────────────────────────────────────────

export class ConfidentialClient {
  readonly node: string;
  readonly api: NodeApi;
  credential?: string;
  private readonly opts: ConfidentialClientOptions;
  private offerCache?: { offer: VerifiedOffer; at: number };
  private modelsCache?: { models: NodeModel[]; at: number };
  readonly prewarmer?: Prewarmer;

  /**
   * Where the wasm runs: the configured host, else the page-wide default,
   * looked up per session so a crashed default worker is replaced.
   */
  get host(): WasmHost {
    return this.opts.host ?? getDefaultWasmHost();
  }

  constructor(opts: ConfidentialClientOptions) {
    if (!opts.trustedHosts?.length) throw new ConfidentialError("not_configured", "trustedHosts is required");
    if (!opts.nodePubkeys?.length) throw new ConfidentialError("not_configured", "nodePubkeys is required");
    // Pinned keys authenticate the offer, not the connection: the session
    // carries the credential, which plain http would expose on the wire.
    if (!opts.allowInsecureTransport && !encryptedNodeTransport(opts.node)) {
      throw new ConfidentialError(
        "not_configured",
        `refusing plain http to ${opts.node}: the credential would travel unencrypted (use https)`,
      );
    }
    this.opts = opts;
    this.node = opts.node.replace(/\/$/, "");
    this.api = new NodeApi(this.node, opts.fetchImpl);
    this.credential = opts.credential;
    if (opts.prewarm) this.prewarmer = new Prewarmer(this, opts.prewarm === true ? {} : opts.prewarm);
  }

  emit(ev: Record<string, unknown>): void {
    this.opts.onEvent?.({ t: Date.now(), ...ev });
  }

  setCredential(credential: string | undefined): void {
    if (credential !== this.credential) this.prewarmer?.teardown("credential changed");
    this.credential = credential;
    this.prewarmer?.activity();
  }

  /** The node's signed offer, verified under this client's pins (cached 30 s). */
  async offer(fresh = false): Promise<VerifiedOffer> {
    const policy = { pinnedPubkeys: this.opts.nodePubkeys, trustedHosts: this.opts.trustedHosts };
    const hit = this.offerCache;
    if (!fresh && hit && Date.now() - hit.at < 30_000) return verifyConfidentialOffer(hit.offer, policy);
    const offer = await fetchConfidentialOffer(this.node, { ...policy, fetchImpl: this.opts.fetchImpl });
    this.offerCache = { offer, at: Date.now() };
    return offer;
  }

  async models(): Promise<NodeModel[]> {
    if (this.modelsCache && Date.now() - this.modelsCache.at < 300_000) return this.modelsCache.models;
    const models = await this.api.models().catch(() => [] as NodeModel[]);
    this.modelsCache = { models, at: Date.now() };
    return models;
  }

  /** Confidential models with their signed rates and the reservation for `maxTokens`. */
  async pricing(maxTokens?: number): Promise<ModelPricing[]> {
    const [offer, models] = await Promise.all([this.offer(), this.models()]);
    return modelPricing(offer, models, maxTokens ?? offer.max_tokens_cap);
  }

  newSession(offer: VerifiedOffer, auth: string, model: string, maxTokens: number, bodyLength: number): ConfidentialSession {
    return new ConfidentialSession({
      baseUrl: this.node,
      offer,
      auth,
      model,
      maxTokens,
      bodyLength,
      host: this.host,
      webSocketImpl: this.opts.webSocketImpl,
      allowInsecureTransport: this.opts.allowInsecureTransport,
      onEvent: (e) => this.emit({ ...e, session: undefined }),
    });
  }

  /** Arm for the model the user is about to use (pre-warm). */
  prepare(model: string, maxTokens?: number): void {
    this.prewarmer?.setTarget(model, maxTokens ?? this.offerCache?.offer.max_tokens_cap ?? 4096);
  }

  /** Turn pre-warming on or off at runtime (off closes the armed session). */
  setPrewarm(enabled: boolean): void {
    if (!this.prewarmer) return;
    this.prewarmer.cfg.enabled = enabled;
    if (enabled) this.prewarmer.activity();
    else this.prewarmer.teardown("pre-warming turned off");
  }

  /** Signal user activity (typing, focus) to the pre-warmer. */
  activity(): void {
    this.prewarmer?.activity();
  }

  /**
   * Confidential image generation: one cold session per request (never
   * pre-armed), flat-priced at the signed offer's per-image price.
   */
  readonly images = {
    generate: (params: ImageGenerateParams, options?: { signal?: AbortSignal }) => this.generateImages(params, options?.signal, false),
    /** The signed offer's image block (models, variants, prices), or undefined. */
    offer: async (): Promise<ConfidentialImagesOffer | undefined> => offerImages(await this.offer()),
  };

  private async generateImages(
    params: ImageGenerateParams,
    signal: AbortSignal | undefined,
    freshOffer: boolean,
  ): Promise<ImageGenerateResult> {
    const auth = this.credential;
    if (!auth) throw new ConfidentialError("not_configured", "no credential: fund the wallet or paste an sk- key");
    if (signal?.aborted) throw new DOMException("aborted", "AbortError");
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
    // No pre-warm: an image session is set up for this request only, and it
    // must not arm (or claim) the chat pool.
    const session = new ConfidentialSession({
      baseUrl: this.node,
      offer,
      auth,
      model,
      maxTokens: 0,
      kind: "images",
      image: { variant, count },
      bodyLength: body.length,
      host: this.host,
      webSocketImpl: this.opts.webSocketImpl,
      allowInsecureTransport: this.opts.allowInsecureTransport,
      onEvent: (e) => this.emit({ ...e, kind: "images", session: undefined }),
    });
    // Aborted while the offer was fetched: never open the session.
    if (signal?.aborted) throw new DOMException("aborted", "AbortError");
    // Before release, an abort closes the session (the node releases the
    // reservation, less any abandon fee). After it the provider has the
    // request: the caller gets an AbortError at once and the session settles
    // in the background (accept, or the error head), which never costs more
    // than closing it would.
    let rejectAborted!: (e: unknown) => void;
    const abortedP = new Promise<never>((_, rej) => (rejectAborted = rej));
    abortedP.catch(() => {});
    let detached = false;
    const abort = () => {
      // First, so the caller sees an AbortError rather than the closed session's error.
      rejectAborted(new DOMException("aborted", "AbortError"));
      if (session.bodyReleased) {
        detached = true;
        this.emit({ ev: "request_aborted", kind: "images", released: true, msg: "settling in the background" });
      } else {
        session.close();
        this.emit({ ev: "request_aborted", kind: "images", released: false });
      }
    };
    signal?.addEventListener("abort", abort, { once: true });
    // Hold the chat pre-warmer back while the image's own 2PC runs: two
    // ~22 MB preparations at once would slow this one and cost the data twice.
    const pw = this.prewarmer;
    pw?.beginPreparing();
    let result: ConfidentialSessionResult;
    this.emit({ ev: "request", path: "cold", kind: "images", model, variant: variant.id, count });
    const runP = session.run(body);
    // Whoever ends first, the session is closed once it has settled.
    const settled = runP.finally(() => {
      session.close();
      signal?.removeEventListener("abort", abort);
      pw?.endPreparing(false);
    });
    settled.catch(() => {});
    try {
      result = await Promise.race([runP, abortedP]);
    } catch (e) {
      if (!detached) session.close();
      // Retry only while nothing could have reached the provider.
      if (isOfferExpired(e) && !freshOffer && !session.bodyReleased && !signal?.aborted) {
        await settled.catch(() => {});
        return this.generateImages(params, signal, true);
      }
      throw e;
    }
    if (result.http.status >= 400) {
      throw new UpstreamImageError(
        result.http.status,
        `the provider refused the image request: HTTP ${result.http.status} ${result.http.statusText}`.trim(),
        result,
      );
    }
    return {
      images: result.images ?? [],
      model,
      variant: variant.id,
      count,
      msatPerImage: variant.msat_per_image,
      costMsats: Number(result.receipt.cost_msats ?? 0),
      warnings: result.warnings ?? [],
      confidential: result,
    };
  }

  readonly chat = {
    completions: {
      create: ((params: ChatCompletionCreateParams, options?: { signal?: AbortSignal }) =>
        this.create(params, options)) as {
        (params: ChatCompletionCreateParams & { stream: true }, options?: { signal?: AbortSignal }): Promise<ConfidentialStream>;
        (params: ChatCompletionCreateParams & { stream?: false }, options?: { signal?: AbortSignal }): Promise<ChatCompletion>;
        (params: ChatCompletionCreateParams, options?: { signal?: AbortSignal }): Promise<ConfidentialStream | ChatCompletion>;
      },
    },
  };

  private async create(
    params: ChatCompletionCreateParams,
    options: { signal?: AbortSignal } = {},
  ): Promise<ConfidentialStream | ChatCompletion> {
    const stream = await this.runStream(params, options.signal, false);
    if (params.stream) return stream;
    const events: ChatCompletionChunk[] = [];
    for await (const c of stream) events.push(c);
    const result = await stream.verification;
    return { ...aggregateChatCompletion(events as never[]), confidential: result };
  }

  private async runStream(
    params: ChatCompletionCreateParams,
    signal: AbortSignal | undefined,
    freshOffer: boolean,
  ): Promise<ConfidentialStream> {
    const auth = this.credential;
    if (!auth) throw new ConfidentialError("not_configured", "no credential: fund the wallet or paste an sk- key");
    const offer = await this.offer(freshOffer);
    const model = params.model;
    if (!Object.hasOwn(offer.price_list, model)) {
      throw new ConfidentialError("offer_malformed", `the node does not serve ${model} confidentially`);
    }
    const maxTokens = requestedMaxTokens(params, Number(offer.max_tokens_cap ?? 4096));
    const body = buildPinnedBody(params, model, maxTokens, offer.chat);
    const suffix = canonicalSuffix(offer.chat, model, maxTokens);
    const pw = this.prewarmer;
    // The request's start: a warm request may first wait for an arm still in
    // progress, and that wait belongs in its timings.
    const tRequest = Date.now();
    pw?.noteBody(body.length);
    pw?.setTarget(model, maxTokens);
    pw?.activity();
    const lease = pw?.take(model, maxTokens, body.length);
    pw?.noteRequest();
    // Hold off arming the next session only until this request's own 2PC
    // preparation is done: for a claimed arm, when it is ready (the next one
    // then starts while this answer streams); for a cold request, at its end.
    let stillPreparing = !!pw;
    if (pw) {
      pw.beginPreparing();
      // A failed arm falls back to a cold preparation: keep counting until the end.
      if (lease) lease.then(() => { stillPreparing = false; pw.endPreparing(); }, () => {});
    }

    // Async iterator plumbing.
    const queue: ChatCompletionChunk[] = [];
    let wake: (() => void) | undefined;
    let ended = false;
    let failure: unknown;
    const notify = () => {
      wake?.();
      wake = undefined;
    };
    const sse = new SseParser();
    let resolveHead!: (h: Head) => void;
    const head = new Promise<Head>((r) => (resolveHead = r));
    let session: ConfidentialSession | undefined;
    /** The caller aborted (signal or `stream.abort()`): sticky. */
    let callerAborted = false;
    /** Aborted after release: the caller's stream is cut off, the session settles on its own. */
    let detached = false;
    const isAborted = () => callerAborted || !!signal?.aborted;
    let rejectAborted!: (e: unknown) => void;
    const abortedP = new Promise<never>((_, rej) => (rejectAborted = rej));
    abortedP.catch(() => {});
    const attach = (s: ConfidentialSession) =>
      s.setResponseHandlers(
        (h) => resolveHead(h),
        (chunk) => {
          if (!chunk.length || detached) return;
          for (const ev of sse.push(chunk)) queue.push(ev as ChatCompletionChunk);
          notify();
        },
      );
    const aborted = () => new DOMException("aborted", "AbortError");
    const cold = () => {
      if (isAborted()) return Promise.reject(aborted());
      const s = this.newSession(offer, auth, model, maxTokens, body.length);
      session = s;
      attach(s);
      this.emit({ ev: "request", path: "cold", model });
      return s.run(body);
    };
    const warm = async (): Promise<ConfidentialSessionResult> => {
      let s: ConfidentialSession;
      try {
        s = await lease!;
      } catch (e) {
        if (isAborted()) throw aborted();
        this.emit({ ev: "request", path: "cold", reason: `armed session failed: ${errorText(e)}` });
        return cold();
      }
      // Aborted while the arm was pending: abort() had no session to close.
      if (isAborted()) {
        s.close();
        throw aborted();
      }
      session = s;
      attach(s);
      this.emit({ ev: "request", path: "warm", model });
      try {
        const result = await s.claim(padPinnedBody(body, s.bodyLength, suffix), tRequest);
        pw?.servedWarm();
        return result;
      } catch (e) {
        // Before the credential record is released nothing reached the
        // provider: retry once on a cold session. Never after.
        if (s.bodyReleased || isAborted()) throw e;
        s.close();
        pw?.armedFailed(`armed session failed before release: ${errorText(e)}`);
        this.emit({ ev: "request", path: "cold", reason: `warm session failed before release: ${errorText(e)}` });
        return cold();
      }
    };
    // Before release nothing reached the provider: close at once (the node
    // releases the reservation, less any abandon fee). After it the provider
    // has the request: closing would leave the node to charge the whole
    // reservation, so only the caller's stream ends and the session drains
    // (its answer is capped by the pinned max_tokens) and settles on the
    // usage actually reported. `verification` still settles with its result.
    const abort = () => {
      if (callerAborted) return;
      callerAborted = true;
      failure ??= aborted();
      rejectAborted(aborted());
      if (session?.bodyReleased) {
        detached = true;
        queue.length = 0;
        this.emit({ ev: "request_aborted", released: true, msg: "settling in the background" });
      } else {
        session?.close();
        this.emit({ ev: "request_aborted", released: false });
      }
      ended = true;
      notify();
    };
    if (signal?.aborted) abort();
    signal?.addEventListener("abort", abort, { once: true });

    const verification = (lease ? warm() : cold()).finally(() => {
      session?.close();
      signal?.removeEventListener("abort", abort);
      if (pw && stillPreparing) {
        stillPreparing = false;
        pw.endPreparing();
      } else pw?.activity();
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

    // Fail fast on a refusal before any response (e.g. 402 insufficient balance, 409 offer expired).
    const first = await Promise.race([
      head.then(() => "head" as const),
      verification.then(() => "done" as const),
      abortedP,
    ]).catch(
      async (e: unknown) => {
        // Retry only while nothing could have reached the provider.
        if (isOfferExpired(e) && !freshOffer && !session?.bodyReleased && !isAborted()) return "retry" as const;
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
    return {
      [Symbol.asyncIterator]: iterator,
      verification,
      head,
      abort,
    };
  }

  /** Close armed sessions and stop pre-warming. */
  close(): void {
    this.prewarmer?.stop();
  }
}

export function createConfidentialClient(opts: ConfidentialClientOptions): ConfidentialClient {
  return new ConfidentialClient(opts);
}
