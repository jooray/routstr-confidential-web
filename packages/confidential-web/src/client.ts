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

import { ConfidentialError, SessionRejectedError } from "./errors";
import { fetchConfidentialOffer, offerAbandonFeeMsat, verifyConfidentialOffer, type VerifiedOffer } from "./offer";
import { NodeApi, type NodeModel } from "./node-api";
import { modelPricing, type ModelPricing } from "./pricing";
import { aggregateChatCompletion, buildPinnedBody, chooseBucket, padPinnedBody, requestedMaxTokens, SseParser } from "./request";
import { ConfidentialSession, type ConfidentialSessionResult } from "./session";
import { canonicalSuffix } from "./suffix";
import { getDefaultWasmHost, type WasmHost } from "./wasm/host";

export interface PrewarmOptions {
  /** Default true when an options object is given. */
  enabled?: boolean;
  /** Close an armed session this long after setup (the node ends sessions at 600 s). */
  maxAgeMs?: number;
  /** No activity (request, typing, focus) for this long: tear down, stop arming. */
  idleMs?: number;
  /** Arm only while `document.visibilityState === "visible"` (default true). */
  onlyWhenVisible?: boolean;
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
  /** Node base URL (https). */
  node: string;
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
  /** Abort the session. */
  abort(): void;
}

export type ChatCompletion = Record<string, unknown> & { confidential: ConfidentialSessionResult };

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

const PREWARM_DEFAULTS = {
  enabled: true,
  maxAgeMs: 480_000,
  idleMs: 10 * 60_000,
  onlyWhenVisible: true,
  minBucket: 4096,
  backoffMs: 30_000,
  maxAbandonFeeMsat: 5000,
};

/**
 * One armed session for the current (model, max_tokens), kept while the page
 * is visible, the user is active and the key is funded. A simplified version
 * of routstr-sdk's traffic-driven pool: nothing is armed before there is a
 * funded `sk-` key and a target model; an armed session is closed (the node
 * releases its reservation) when the page is hidden, after `idleMs` without
 * activity, or `maxAgeMs` after setup.
 */
class Prewarmer {
  cfg: typeof PREWARM_DEFAULTS;
  private armed?: Armed;
  private target?: { model: string; maxTokens: number };
  private lastActivity = Date.now();
  private maxBody = 0;
  private busy = 0;
  private arming = false;
  private backoffUntil = 0;
  private backoff = 0;
  private timer?: ReturnType<typeof setInterval>;
  private stopped = false;
  status: "off" | "idle" | "arming" | "armed" | "waiting-funds" | "backoff" = "off";

  constructor(
    private readonly client: ConfidentialClient,
    opts: PrewarmOptions,
  ) {
    this.cfg = { ...PREWARM_DEFAULTS, ...opts };
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") this.activity();
        else if (this.cfg.onlyWhenVisible) this.teardown("page hidden");
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
    this.activity();
  }

  noteBody(len: number): void {
    this.maxBody = Math.max(this.maxBody, len);
  }

  activity(): void {
    this.lastActivity = Date.now();
    void this.ensure();
  }

  begin(): void {
    this.busy++;
  }

  end(): void {
    this.busy = Math.max(0, this.busy - 1);
    this.activity();
  }

  private visible(): boolean {
    return !this.cfg.onlyWhenVisible || typeof document === "undefined" || document.visibilityState === "visible";
  }

  /** A healthy armed session for this request, or undefined. */
  take(model: string, maxTokens: number, bodyLen: number): Promise<ConfidentialSession> | undefined {
    const a = this.armed;
    if (!a || a.model !== model || a.maxTokens !== maxTokens) return undefined;
    if (a.session.bodyLength < bodyLen) {
      this.teardown("armed body length too small");
      return undefined;
    }
    if (!a.session.healthy && a.session.isArmed) {
      this.teardown("armed session unhealthy");
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

  private tick(): void {
    const a = this.armed;
    if (a && (Date.now() - a.session.startedAt > this.cfg.maxAgeMs || (a.session.isArmed && !a.session.healthy))) {
      this.teardown("expired or unhealthy");
    }
    if (Date.now() - this.lastActivity > this.cfg.idleMs) this.teardown("idle");
    void this.ensure();
  }

  async ensure(): Promise<void> {
    if (this.stopped || !this.cfg.enabled || this.arming || this.armed || this.busy > 0) return;
    if (!this.visible() || Date.now() - this.lastActivity > this.cfg.idleMs) return;
    if (Date.now() < this.backoffUntil) return;
    const cred = this.client.credential;
    const target = this.target;
    if (!cred || !cred.startsWith("sk-") || !target) return;
    this.arming = true;
    try {
      // No sats, no session: arming reserves funds on the key.
      const [offer, bal] = await Promise.all([this.client.offer(), this.client.api.balance(cred)]);
      const pricing = (await this.client.pricing(target.maxTokens)).find((p) => p.id === target.model);
      const available = bal.balance - bal.reserved;
      const need = pricing?.reservationMsat ?? 1;
      if (available < need) {
        this.status = "waiting-funds";
        this.log("not arming: available balance below one reservation", { available, need });
        return;
      }
      if (!(target.model in offer.price_list)) return;
      const abandonFee = offerAbandonFeeMsat(offer);
      if (abandonFee > this.cfg.maxAbandonFeeMsat) {
        this.status = "off";
        this.log("not arming: the node's abandon fee exceeds maxAbandonFeeMsat", { abandonFee });
        return;
      }
      const len = chooseBucket(this.maxBody, { minBucket: this.cfg.minBucket });
      const session = this.client.newSession(offer, cred, target.model, target.maxTokens, len);
      this.status = "arming";
      this.log("arming", { model: target.model, body_len: len });
      const ready = session.arm().then(() => session);
      const armed: Armed = { key: `${target.model}|${target.maxTokens}`, session, ready, model: target.model, maxTokens: target.maxTokens };
      this.armed = armed;
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
  readonly host: WasmHost;
  credential?: string;
  private readonly opts: ConfidentialClientOptions;
  private offerCache?: { offer: VerifiedOffer; at: number };
  private modelsCache?: { models: NodeModel[]; at: number };
  readonly prewarmer?: Prewarmer;

  constructor(opts: ConfidentialClientOptions) {
    if (!opts.trustedHosts?.length) throw new ConfidentialError("not_configured", "trustedHosts is required");
    if (!opts.nodePubkeys?.length) throw new ConfidentialError("not_configured", "nodePubkeys is required");
    this.opts = opts;
    this.node = opts.node.replace(/\/$/, "");
    this.api = new NodeApi(this.node, opts.fetchImpl);
    this.host = opts.host ?? getDefaultWasmHost();
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
    if (!(model in offer.price_list)) {
      throw new ConfidentialError("offer_malformed", `the node does not serve ${model} confidentially`);
    }
    const maxTokens = requestedMaxTokens(params, Number(offer.max_tokens_cap ?? 4096));
    const body = buildPinnedBody(params, model, maxTokens);
    const suffix = canonicalSuffix(model, maxTokens);
    const pw = this.prewarmer;
    pw?.noteBody(body.length);
    pw?.setTarget(model, maxTokens);
    const lease = pw?.take(model, maxTokens, body.length);
    pw?.begin();

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
    const attach = (s: ConfidentialSession) =>
      s.setResponseHandlers(
        (h) => resolveHead(h),
        (chunk) => {
          if (!chunk.length) return;
          for (const ev of sse.push(chunk)) queue.push(ev as ChatCompletionChunk);
          notify();
        },
      );
    const cold = () => {
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
        this.emit({ ev: "request", path: "cold", reason: `armed session failed: ${errorText(e)}` });
        return cold();
      }
      session = s;
      attach(s);
      this.emit({ ev: "request", path: "warm", model });
      try {
        return await s.claim(padPinnedBody(body, s.bodyLength, suffix));
      } catch (e) {
        // Before the credential record is released nothing reached the
        // provider: retry once on a cold session. Never after.
        if (s.bodyReleased || signal?.aborted) throw e;
        s.close();
        this.emit({ ev: "request", path: "cold", reason: `warm session failed before release: ${errorText(e)}` });
        return cold();
      }
    };
    const abort = () => {
      session?.close();
      failure ??= new DOMException("aborted", "AbortError");
      ended = true;
      notify();
    };
    if (signal?.aborted) abort();
    signal?.addEventListener("abort", abort, { once: true });

    const verification = (lease ? warm() : cold()).finally(() => {
      session?.close();
      signal?.removeEventListener("abort", abort);
      pw?.end();
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
    const first = await Promise.race([head.then(() => "head" as const), verification.then(() => "done" as const)]).catch(
      async (e: unknown) => {
        if (isOfferExpired(e) && !freshOffer) return "retry" as const;
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
