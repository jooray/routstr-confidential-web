/**
 * The confidential session driver (C side, protocol v2), for the browser.
 *
 * C is the TLS 1.3 client of the provider through the node's WebSocket relay.
 * The handshake key schedule runs jointly with the node (2PC, wasm), so the
 * node never learns the response or body secrets (s_ap_0, c_ap_1) and C never
 * learns the key of the credential record (K_0):
 *
 *   setup → ready(v=2) → 2PC key share P = P_C + P_N → TLS handshake with the
 *   external key schedule (P-256; c_hs/s_hs, then s_ap_0/c_ap_1 from the 2PC)
 *   → hs_verified → c_commit → π_NK (we verify) → release_head (the node
 *   writes the credential record and a KeyUpdate under K_0) → head_written
 *   → body in epoch 1 → body_suffix → π_C2S → attestation → disclose → π_C3S
 *   → receipt
 *
 * Ported from routstr-sdk `client/confidential/session.ts` (v2 path), with
 * the child processes replaced by the wasm drivers and node:fs/node:crypto
 * removed. Every check of the SDK client is kept: provider certificate and
 * hostname (in the TLS fork), the π_NK statement rebuilt from the signed
 * offer, π_C2S/π_C3S parameters against our own records, attestation and
 * receipt signatures, the receipt's binding to this session, its usage and
 * its cost against our own plaintext and the signed rates. Fail-closed.
 */

import { verifySchnorrSignature } from "./canonical.js";
import { concat, hex, randomHex, sha256 } from "./bytes.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2";
import {
  ConfidentialTimeoutError,
  ReceiptVerificationError,
  ResponseVerificationError,
  SessionProtocolError,
  SessionRejectedError,
} from "./errors.js";
import { encryptedNodeTransport, matchHostname } from "./hosts.js";
import { checkPiC2SParams, checkPiC3SParams, checkPiNKParams, serverTailEpoch, type ServerPostRecord } from "./params.js";
import { WasmProverBackend } from "./prover.js";
import {
  checkAttestationBinding,
  checkUpstreamErrorReceipt,
  parseSignedReceipt,
  verifyFlatReceipt,
  verifyReceipt,
} from "./receipt.js";
import { base64ToBytes, imageMimeType, imageSuffix, responseImages } from "./images.js";
import {
  canonicalSuffix,
  disclosureTailLens,
  effectiveModelFromText,
  extractUsageDisclosure,
  IncrementalHttpResponse,
  parseHttpResponse,
  usageEventFromDisclosure,
  type ParsedHttpResponse,
  type UpstreamUsageEvent,
} from "./suffix.js";
import { TwoPcSession, type TwoPcApplicationSecrets, type TwoPcTiming } from "./twopc.js";
import { ProofChannel } from "./zkchan.js";
import {
  offerAbandonFeeMsat,
  offerImages,
  offerSessionFeeMsat,
  type ConfidentialImagesOffer,
  type ConfidentialImageVariant,
  type ImagePin,
  type VerifiedOffer,
} from "./offer.js";
import type { WasmHost } from "./wasm/host.js";
import { makeTLSClient } from "./tls-fork/lib/index.js";
import { setCryptoImplementation } from "./tls-fork/lib/crypto/index.js";
import { webcryptoCrypto } from "./tls-fork/lib/crypto/webcrypto.js";

setCryptoImplementation(webcryptoCrypto);

/** The fork-patched TLS client surface we use. */
interface TlsHandle {
  getMetadata(): { cipherSuite?: string; keyType?: string; version?: string; selectedAlpn?: string };
  startHandshake(): Promise<void>;
  handleReceivedBytes(data: Uint8Array): Promise<void>;
  write(data: Uint8Array): Promise<void>;
}

export interface ConfidentialReceipt {
  v?: number;
  sid: string;
  model: string;
  usage: UpstreamUsageEvent;
  cost_msats?: number;
  reserved_msats?: number;
  balance_msats?: number | null;
  session_fee_msat?: number;
  abandon_fee_msat?: number;
  rate_surcharge_pct?: number;
  notary_pubkey?: string;
  attestation_hash?: string;
  time?: number;
  [k: string]: unknown;
}

/** One certificate of the provider's chain, as the client verified it. */
export interface CertificateInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  dnsNames: string[];
  /** SHA-256 of the SubjectPublicKeyInfo (hex and base64, the HPKP pin format). */
  spkiSha256: string;
  spkiSha256Base64: string;
  /** SHA-256 of the whole certificate (DER). */
  fingerprintSha256: string;
  publicKeyAlgorithm: string;
  signatureAlgorithm: string;
  /** In the validated path: the trust anchor (from the bundled Mozilla roots). */
  trustAnchor: boolean;
}

/** What the client itself verified about the provider connection. */
export interface ProviderVerification {
  host: string;
  /** The SAN (or CN) entry the hostname matched. */
  hostnameMatched?: string;
  /** Leaf first, trust anchor last (the validated path). */
  chain: CertificateInfo[];
  tlsVersion: string;
  cipherSuite: string;
  /** "P-256 joint key share (2PC: P = P_C + P_N; neither party knows the ECDHE secret)" */
  keyExchange: string;
  alpn?: string;
}

export interface ProofOutcome {
  ok: boolean;
  via: string;
  ms: number;
  innerMs?: number;
  bytesSent?: number;
  bytesRecv?: number;
}

const PROOF_LABEL: Record<"pi_nk" | "pi_c2s" | "pi_c3s", string> = {
  pi_nk: "π_NK (node's record is the template)",
  pi_c2s: "π_C2S (pinned suffix)",
  pi_c3s: "π_C3S (usage disclosure)",
};

export interface ConfidentialSessionTimings {
  readyMs?: number;
  handshakeMs?: number;
  piNkMs?: number;
  recordMs?: number;
  claimToBodyMs?: number;
  upstreamTtftMs?: number;
  armMs?: number;
  twoPcKeyShareMs?: number;
  twoPcPhaseAMs?: number;
  twoPcPhaseBMs?: number;
  twoPcSteps?: TwoPcTiming[];
  twoPcBytes?: { sent: number; recv: number };
  proofs?: Record<string, ProofOutcome>;
  proofChannelReadyMs?: number;
  proofChannelSteps?: TwoPcTiming[];
  totalMs: number;
  /**
   * Every step as a span, in ms relative to the request (claim): negative
   * values happened before it (a pre-armed session's setup and 2PC
   * preprocessing). For waterfall charts.
   */
  spans?: TimingSpan[];
}

export interface TimingSpan {
  name: string;
  /** "node" (setup, record, settlement), "2pc", "proofs", "tls", "provider". */
  lane: "node" | "2pc" | "proofs" | "tls" | "provider";
  startMs: number;
  endMs: number;
}

export interface ConfidentialSessionResult {
  sid: string;
  uuid: string;
  model: string;
  effectiveModel?: string;
  http: ParsedHttpResponse;
  responseText: string;
  receipt: ConfidentialReceipt;
  receiptJson: string;
  receiptSig?: string;
  attestation: unknown;
  receiptSigOk: boolean;
  attestationSigOk: boolean;
  usageMatch: boolean;
  costWithinOffer: boolean;
  costMsats?: number;
  /** Our own usage, parsed from the disclosed usage event. */
  ownUsage?: UpstreamUsageEvent;
  provider?: ProviderVerification;
  ttftMs: number;
  totalMs: number;
  timings: ConfidentialSessionTimings;
  proofs: string[];
  /** True when the session was armed before the request (pre-warmed). */
  prewarmed: boolean;
  /**
   * The request arrived while its session was still arming and waited this
   * long for the arm to finish (counted in `ttftMs` and `totalMs`).
   */
  waitedForArmMs?: number;
  protocol: number;
  nodePubkey: string;
  /** Image sessions: the generated images (empty for an upstream error). */
  images?: Blob[];
  /** Image sessions: the variant and count that were pinned and charged. */
  imageVariant?: string;
  imageCount?: number;
  /**
   * Image sessions: what is wrong with an accepted answer (short count, an
   * incomplete body, an echo naming another model or count). Already paid.
   */
  warnings?: string[];
}

/** What an image session asks for: a variant of the signed offer and a count. */
export interface ImageSessionRequest {
  variant: ConfidentialImageVariant;
  count: number;
}

export interface ConfidentialSessionOptions {
  /** Node HTTP(S) base, e.g. `https://routstr.cypherpunk.today`. */
  baseUrl: string;
  offer: VerifiedOffer;
  /** The node credential (`sk-` key or Cashu token); sent only in-band in `setup.auth`. */
  auth: string;
  model: string;
  /** Chat: the pinned max_tokens. Ignored for images. */
  maxTokens: number;
  /** `chat` (default) or `images` (flat-priced, never armed ahead). */
  kind?: "chat" | "images";
  /** Required for `kind: "images"`. */
  image?: ImageSessionRequest;
  /** Body length declared at setup (must equal the body passed to claim()). */
  bodyLength: number;
  suffix?: string;
  host: WasmHost;
  /** Use the pre-warmed proof channel (default true). */
  proofChannel?: boolean;
  webSocketImpl?: typeof WebSocket;
  /**
   * Development only: allow a plain-http node that is neither loopback nor an
   * onion service. The credential then travels unencrypted.
   */
  allowInsecureTransport?: boolean;
  timeouts?: Partial<typeof DEFAULT_TIMEOUTS>;
  /** Structured events (never secrets). */
  onEvent?: (event: Record<string, unknown>) => void;
  onResponseHead?: (head: { status: number; statusText: string; headers: Record<string, string> }) => void;
  onResponseBody?: (chunk: Uint8Array) => void;
}

export const DEFAULT_TIMEOUTS = {
  ready: 30_000,
  hsVerified: 30_000,
  cCommit: 60_000,
  headWritten: 30_000,
  zkParams: 30_000,
  attestation: 120_000,
  receipt: 60_000,
  /** Preprocessing (OT, 22 MB of garbled tables) precedes the key share. */
  twoPcKeyShare: 175_000,
  /** The handshake includes both garbled-circuit phases (slower in wasm). */
  handshakeV2: 60_000,
  proofChannelReady: 120_000,
  proof: 90_000,
};

/**
 * Server records kept for an image session: the most a π_C3S covers
 * (MAX_C3S_RECORDS) plus the trailing records allowed after them.
 */
const RETAINED_SERVER_RECORDS = 64 + 17;

class Bus {
  private pending = new Map<string, unknown[]>();
  private waiters = new Map<string, ((m: unknown) => void)[]>();

  emit(msg: { type: string }): void {
    const w = this.waiters.get(msg.type);
    if (w && w.length) w.shift()!(msg);
    else {
      const p = this.pending.get(msg.type) ?? [];
      p.push(msg);
      this.pending.set(msg.type, p);
    }
  }

  wait(type: string): Promise<unknown> {
    const p = this.pending.get(type);
    if (p && p.length) return Promise.resolve(p.shift());
    return new Promise((res) => {
      const w = this.waiters.get(type) ?? [];
      w.push(res);
      this.waiters.set(type, w);
    });
  }
}

function timeout(ms: number, what: string): Promise<never> {
  return new Promise((_, rej) => setTimeout(() => rej(new ConfidentialTimeoutError(`timeout waiting for ${what}`)), ms));
}

/**
 * Rejects after `ms` without activity: `last()` returns the time of the last
 * progress (e.g. response data). For waits whose length depends on how long
 * the provider streams, so a long answer is not mistaken for a stall.
 */
function idleTimeout(ms: number, what: string, last: () => number, stop: Promise<unknown>): Promise<never> {
  return new Promise((_, rej) => {
    const timer = setInterval(() => {
      if (Date.now() - last() > ms) {
        clearInterval(timer);
        rej(new ConfidentialTimeoutError(`timeout waiting for ${what} (no response data for ${Math.round(ms / 1000)} s)`));
      }
    }, 1000);
    stop.finally(() => clearInterval(timer)).catch(() => {});
  });
}

function b64(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

/** Read what we show from a verified certificate (@peculiar/x509 object). */
function certInfo(cert: { internal: any; getAlternativeDNSNames(): string[] }, anchor: boolean): CertificateInfo {
  const c = cert.internal;
  const spki = new Uint8Array(c.publicKey.rawData as ArrayBuffer);
  const spkiHash = sha256(spki);
  const alg = (a: any) => (a ? [a.name, a.namedCurve, a.hash?.name].filter(Boolean).join(" ") : "");
  return {
    subject: String(c.subject),
    issuer: String(c.issuer),
    serialNumber: String(c.serialNumber),
    notBefore: new Date(c.notBefore).toISOString(),
    notAfter: new Date(c.notAfter).toISOString(),
    dnsNames: cert.getAlternativeDNSNames(),
    spkiSha256: hex(spkiHash),
    spkiSha256Base64: b64(spkiHash),
    fingerprintSha256: hex(sha256(new Uint8Array(c.rawData as ArrayBuffer))),
    publicKeyAlgorithm: alg(c.publicKey?.algorithm),
    signatureAlgorithm: alg(c.signatureAlgorithm),
    trustAnchor: anchor,
  };
}

function indexOfCrlfCrlf(b: Uint8Array): number {
  for (let i = 0; i + 3 < b.length; i++) {
    if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i;
  }
  return -1;
}

/**
 * How a claimed session relates to its request: pre-warmed only if the arm had
 * finished when the request was made (`tClaim`); a request that arrived while
 * the arm was running waited `waitedForArmMs` for it.
 */
export function claimTiming(
  tClaim: number,
  tArmed: number,
  armingBefore: boolean,
): { prewarmed: boolean; waitedForArmMs?: number } {
  const prewarmed = tArmed > 0 && tArmed <= tClaim;
  return { prewarmed, waitedForArmMs: armingBefore && tArmed > tClaim ? tArmed - tClaim : undefined };
}

export class ConfidentialSession {
  readonly uuid = globalThis.crypto.randomUUID();
  readonly baseUrl: string;
  readonly offer: VerifiedOffer;
  readonly model: string;
  readonly maxTokens: number;
  readonly bodyLength: number;
  readonly suffix: string;
  readonly protocol = 2;
  readonly kind: "chat" | "images";
  private readonly image?: ImageSessionRequest;
  private readonly imagesOffer?: ConfidentialImagesOffer;
  /** Set by run(): an image session only ever runs cold, start to end. */
  private coldRun = false;
  private readonly host: WasmHost;
  private readonly prover: WasmProverBackend;
  private twoPc?: TwoPcSession;
  private readonly useProofChannel: boolean;
  private zkChan?: ProofChannel;
  private proofTimes: Record<string, ProofOutcome> = {};
  private ap?: TwoPcApplicationSecrets;
  /** Handshake transcript hashes (ClientHello..ServerHello, ..server Finished). */
  private thSH?: Uint8Array;
  private thSF?: Uint8Array;
  private tKeyShare = 0;
  private tPhaseA = 0;
  private tPhaseB = 0;
  private readonly auth: string;
  private readonly timeouts: typeof DEFAULT_TIMEOUTS;
  private readonly onEvent?: (event: Record<string, unknown>) => void;
  private readonly WS: typeof WebSocket;
  private onResponseHead?: ConfidentialSessionOptions["onResponseHead"];
  private onResponseBody?: ConfidentialSessionOptions["onResponseBody"];
  private incremental = new IncrementalHttpResponse();
  private headEmitted = false;
  private completeSignaled = false;

  private ws?: WebSocket;
  private wsOpen = false;
  private wsReady: Promise<void>;
  private wsResolve!: () => void;
  private outbox: Uint8Array[] = [];
  private bus = new Bus();
  private errRej!: (e: Error) => void;
  private errP!: Promise<never>;
  private tls!: TlsHandle;
  private handshakeP!: Promise<void>;
  private handshakeDone!: () => void;
  private flushChain: Promise<void> = Promise.resolve();
  private provider?: ProviderVerification;

  private responseChunks: Uint8Array[] = [];
  /** The length of each response record, in order (the disclosure's tail). */
  private responseRecordLens: number[] = [];
  private serverRecords: Uint8Array[] = [];
  /** Encrypted server records seen after the handshake (π_C3S key epoch). */
  private postHandshake = false;
  private serverPost: ServerPostRecord[] = [];
  private serverPending: Uint8Array = new Uint8Array(0);
  /** Every upstream byte and complete record received (checked against the attestation). */
  private readonly recvHash = nobleSha256.create();
  private recvRecords = 0;
  /** The node's head-record commitment, from its c_commit frame. */
  private cCommitHex?: string;
  /** SHA-256 of the provider's certificate DERs as sent, concatenated. */
  private certChainHash?: Uint8Array;
  private epochBody = false;
  private bodyRecords: Uint8Array[] = [];
  /** Response plaintext bytes received (the records are in responseChunks). */
  private responseLength = 0;
  private responseJoined?: Uint8Array;
  private progressAt = 0;
  /** Server records dropped from the front of serverRecords (bounded retention). */
  private serverRecordsDropped = 0;
  private tlsEnded = false;
  sid = "";
  ready: any = null;

  private tStart = 0;
  private tReady = 0;
  private tHs = 0;
  private tNkStart = 0;
  private tProofsReady = 0;
  private tRecordStart = 0;
  private tHeadWritten = 0;
  private tBodyWrite = 0;
  private ttft = 0;
  private prepared = false;
  private keyShareReady = false;
  private armStarted = false;
  private handshaken = false;
  private released = false;
  private failure?: Error;
  private tArmed = 0;
  private tHsStart = 0;
  private tLastData = 0;
  /** Absolute-time spans (Date.now()), converted to claim-relative in finish(). */
  private absSpans: { name: string; lane: TimingSpan["lane"]; start: number; end: number }[] = [];
  private finished = false;
  private c2Failed = false;

  constructor(options: ConfidentialSessionOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.offer = options.offer;
    this.model = options.model;
    this.maxTokens = options.maxTokens;
    this.bodyLength = options.bodyLength;
    this.kind = options.kind ?? "chat";
    if (this.kind === "images") {
      const images = offerImages(options.offer);
      if (!images) throw new SessionProtocolError("the node's signed offer serves no confidential images");
      if (!options.image) throw new SessionProtocolError("an image session needs a variant and a count");
      const signed = images.price_list[options.model]?.find((v) => v.id === options.image!.variant.id);
      if (!signed) {
        throw new SessionProtocolError(`the signed offer has no variant ${options.image.variant.id} for ${options.model}`);
      }
      const maxCount = Math.min(images.max_count, signed.max_count ?? images.max_count);
      if (!(Number.isSafeInteger(options.image.count) && options.image.count >= 1 && options.image.count <= maxCount)) {
        throw new SessionProtocolError(`image count ${options.image.count} is outside 1..${maxCount}`);
      }
      this.imagesOffer = images;
      this.image = options.image;
      this.suffix = imageSuffix(images, options.model, options.image.variant, options.image.count);
    } else {
      this.suffix = options.suffix ?? canonicalSuffix(options.model, options.maxTokens);
    }
    if (options.offer.v !== 2) {
      throw new SessionProtocolError(`the browser client speaks protocol v2 only (offer v=${options.offer.v})`);
    }
    if (!options.allowInsecureTransport && !encryptedNodeTransport(this.baseUrl)) {
      throw new SessionProtocolError(
        `refusing plain http to ${this.baseUrl}: the node credential would travel unencrypted`,
      );
    }
    this.host = options.host;
    this.WS = options.webSocketImpl ?? WebSocket;
    this.prover = new WasmProverBackend(this.host, 60_000, options.webSocketImpl);
    this.useProofChannel = options.proofChannel !== false;
    this.auth = options.auth;
    this.timeouts = { ...DEFAULT_TIMEOUTS, ...(options.timeouts ?? {}) };
    this.onEvent = options.onEvent;
    this.onResponseHead = options.onResponseHead;
    this.onResponseBody = options.onResponseBody;
    this.tStart = Date.now();
    this.wsReady = new Promise<void>((r) => (this.wsResolve = r));
    this.errP = new Promise<never>((_, rej) => (this.errRej = rej));
    this.errP.catch((e: Error) => {
      this.failure ??= e;
    });
  }

  /** The response plaintext so far, joined once (not per record). */
  private get responseBytes(): Uint8Array {
    if (!this.responseJoined) {
      this.responseJoined = concat(...this.responseChunks);
      // Keep one copy: the records are only needed as lengths from here on.
      this.responseChunks = [this.responseJoined];
    }
    return this.responseJoined;
  }

  get healthy(): boolean {
    return !this.failure && !this.finished && !(this.twoPc?.failed ?? false);
  }

  get failureReason(): Error | undefined {
    return this.failure ?? this.twoPc?.failure;
  }

  /** True once the node was asked to write the credential record: never retry after this. */
  get bodyReleased(): boolean {
    return this.released;
  }

  get isArmed(): boolean {
    return this.keyShareReady && !this.handshaken;
  }

  get armedAt(): number {
    return this.tArmed;
  }

  /** What the node keeps if this session ends unused (the offer's abandon fee). */
  get abandonFeeMsat(): number {
    return offerAbandonFeeMsat(this.offer);
  }

  get startedAt(): number {
    return this.tStart;
  }

  private event(ev: Record<string, unknown>): void {
    this.onEvent?.({ t: Date.now(), ...ev });
  }

  private wsBase(): string {
    return this.baseUrl.replace(/^http/, "ws");
  }

  private controlUrl(): string {
    return `${this.wsBase()}/v1/confidential/ws?session_id=${this.uuid}&v=2`;
  }

  private zkUrl(proof: string): string {
    return `${this.wsBase()}/v1/confidential/zk?proof=${proof}&session_id=${this.sid}`;
  }

  setResponseHandlers(
    onHead?: ConfidentialSessionOptions["onResponseHead"],
    onBody?: ConfidentialSessionOptions["onResponseBody"],
  ): void {
    this.onResponseHead = onHead;
    this.onResponseBody = onBody;
  }

  /** Open the control/relay socket. */
  async open(): Promise<void> {
    if (this.ws) return this.wsReady;
    const ws = new this.WS(this.controlUrl());
    this.ws = ws;
    ws.binaryType = "arraybuffer";
    ws.onopen = () => {
      this.wsOpen = true;
      for (const b of this.outbox) ws.send(b);
      this.outbox.length = 0;
      this.wsResolve();
    };
    ws.onerror = () => this.errRej(new SessionRejectedError("control websocket error"));
    ws.onclose = (ev: CloseEvent) => {
      const reason = ev?.reason;
      this.errRej(new SessionRejectedError(reason ? `connection closed: ${reason}` : "connection closed"));
    };
    ws.onmessage = (ev: MessageEvent) => {
      const d = ev.data as ArrayBuffer | string;
      if (typeof d === "string") {
        let m: { type?: string; reason?: string };
        try {
          m = JSON.parse(d);
        } catch {
          this.errRej(new SessionProtocolError("non-JSON control frame"));
          return;
        }
        this.event({ ev: "frame", in: m.type });
        if (m.type === "error") {
          const e = m as { reason?: string; status?: number; detail?: unknown };
          this.errRej(new SessionRejectedError(`node rejected: ${e.reason ?? "unknown"}`, undefined, e.status, e.detail));
        }
        this.bus.emit(m as { type: string });
        return;
      }
      const bytes = new Uint8Array(d);
      this.trackServerRecords(bytes);
      this.flushChain = this.flushChain
        .then(() => this.tls.handleReceivedBytes(bytes))
        .catch((e) => {
          this.errRej(
            e instanceof Error
              ? new ResponseVerificationError(`TLS record failed: ${e.message}`)
              : new ResponseVerificationError(String(e)),
          );
        });
    };
    return Promise.race([this.wsReady, this.errP]);
  }

  private makeTls(external: {
    keyShare: Uint8Array;
    onServerHello(serverShare: Uint8Array, thSH: Uint8Array): Promise<{ clientHs: Uint8Array; serverHs: Uint8Array }>;
    onServerFinished(thSF: Uint8Array): Promise<{ serverAp0: Uint8Array; clientAp1: Uint8Array }>;
  }): void {
    const host = this.offer.upstream_host;
    this.tls = makeTLSClient({
      external,
      host,
      verifyServerCertificate: true,
      cipherSuites: ["TLS_AES_128_GCM_SHA256"],
      supportedProtocolVersions: ["TLS1_3"],
      namedCurves: ["SECP256R1"],
      applicationLayerProtocols: ["http/1.1"],
      write: (packet: { header: Uint8Array; content: Uint8Array }) => {
        const record = concat(packet.header, packet.content);
        if (this.epochBody) this.bodyRecords.push(record);
        this.sendBytes(record);
      },
      // Server KeyUpdates (encrypted, so only we see them) move the response
      // to the next key epoch; π_C3S must derive that epoch's key and count
      // sequence numbers from its first record.
      onRead: (rec: { content: Uint8Array }, ctx?: { type?: string; contentType?: string }) => {
        if (!this.postHandshake || ctx?.type !== "ciphertext") return;
        this.serverPost.push({
          data: ctx.contentType === "APPLICATION_DATA",
          keyUpdates: ctx.contentType === "HANDSHAKE" ? countKeyUpdates(rec.content) : 0,
        });
      },
      onRecvCertificates: ({ certificates, verifiedPath }: { certificates: any[]; verifiedPath?: any[] }) => {
        // Called only after the fork validated the chain to a bundled Mozilla
        // root and matched the hostname (it throws otherwise).
        this.certChainHash = sha256(...certificates.map((c: any) => new Uint8Array(c.internal.rawData as ArrayBuffer)));
        const path = verifiedPath ?? certificates;
        const leaf = path[0];
        const names: string[] = leaf?.getAlternativeDNSNames?.() ?? [];
        this.provider = {
          host,
          hostnameMatched: names.find((n) => matchHostname(host, n)) ?? leaf?.getSubjectField?.("CN")?.[0],
          chain: path.map((c: any, i: number) => certInfo(c, verifiedPath !== undefined && i === path.length - 1)),
          tlsVersion: "TLS 1.3",
          cipherSuite: "TLS_AES_128_GCM_SHA256",
          keyExchange: "ECDHE secp256r1 (P-256), joint key share P = P_C + P_N from the 2PC",
        };
        this.event({ ev: "certificate_verified", host, subject: this.provider.chain[0]?.subject });
      },
      onApplicationData: (rec: Uint8Array) => {
        if (!this.ttft) this.ttft = Date.now();
        this.tLastData = Date.now();
        this.responseChunks.push(rec);
        this.responseRecordLens.push(rec.length);
        this.responseLength += rec.length;
        this.responseJoined = undefined;
        if (this.responseLength - this.progressAt >= 256 * 1024) {
          this.progressAt = this.responseLength;
          this.event({ ev: "response_progress", bytes: this.responseLength });
        }
        if (this.onResponseHead || this.onResponseBody) {
          try {
            const parts = this.incremental.push(rec);
            if (!this.headEmitted && this.incremental.head) {
              this.headEmitted = true;
              this.onResponseHead?.(this.incremental.head);
            }
            for (const p of parts) this.onResponseBody?.(p);
            if (parts.length === 0 && this.incremental.complete && !this.completeSignaled) {
              this.completeSignaled = true;
              this.onResponseBody?.(new Uint8Array(0));
            }
          } catch (e) {
            this.errRej(new ResponseVerificationError(`malformed upstream HTTP: ${e instanceof Error ? e.message : e}`));
          }
        }
      },
      onTlsEnd: () => {
        this.tlsEnded = true;
      },
      onHandshake: () => {
        this.postHandshake = true;
        this.handshakeDone?.();
      },
      logger: { trace: () => {}, debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
    }) as TlsHandle;
  }

  private trackServerRecords(bytes: Uint8Array): void {
    this.recvHash.update(bytes);
    let buf = concat(this.serverPending, bytes);
    while (buf.length >= 5) {
      const len = (buf[3]! << 8) | buf[4]!;
      if (buf.length < 5 + len) break;
      this.recvRecords += 1;
      if (buf[0] === 0x17) {
        this.serverRecords.push(buf.slice(5, 5 + len));
        // An image response is megabytes of records, but a proof only ever
        // covers the tail (the error head of a short error body): keep the
        // last ones and count the rest.
        if (this.kind === "images" && this.serverRecords.length > RETAINED_SERVER_RECORDS) {
          this.serverRecords.shift();
          this.serverRecordsDropped += 1;
        }
      }
      buf = buf.subarray(5 + len);
    }
    this.serverPending = buf.slice();
  }

  private sendText(obj: unknown): void {
    this.ws?.send(JSON.stringify(obj));
  }

  private sendBytes(b: Uint8Array): void {
    if (this.wsOpen && this.ws) this.ws.send(b);
    else this.outbox.push(b);
  }

  private waitT(type: string, ms: number): Promise<any> {
    return Promise.race([this.bus.wait(type), this.errP, timeout(ms, type)]);
  }

  /**
   * setup → ready → 2PC preprocessing + joint key share, then stop: the
   * ClientHello goes out only at claim() (the sidecar dials the provider
   * when it arrives), so an armed session can wait for a request.
   */
  async arm(): Promise<void> {
    if (this.armStarted) throw new SessionProtocolError("arm() called twice");
    if (this.kind === "images" && !this.coldRun) {
      throw new SessionProtocolError("image sessions are never armed ahead; use run()");
    }
    this.armStarted = true;
    await this.host.ready();
    await this.open();
    const setup: Record<string, unknown> =
      this.kind === "images"
        ? {
            type: "setup",
            kind: "images",
            nonce_c: randomHex(32),
            model: this.model,
            variant: this.image!.variant.id,
            count: this.image!.count,
            len: this.bodyLength,
          }
        : {
            type: "setup",
            nonce_c: randomHex(32),
            model: this.model,
            max_tokens: this.maxTokens,
            len: this.bodyLength,
            armed: true,
          };
    if (this.offer.sig) setup.offer_sig = this.offer.sig;
    // Accept that offer's fees explicitly (the node refuses a setup that does
    // not, so a client unaware of fees is never charged one).
    const fee = offerSessionFeeMsat(this.offer);
    const abandonFee = offerAbandonFeeMsat(this.offer);
    if (fee > 0) setup.session_fee_msat = fee;
    if (abandonFee > 0) setup.abandon_fee_msat = abandonFee;
    setup.auth = this.auth;
    this.sendText(setup);

    this.ready = await this.waitT("ready", this.timeouts.ready);
    this.sid = this.ready.sid;
    this.tReady = Date.now();
    this.event({ ev: "ready", sid: this.sid, v: this.ready.v ?? 1 });
    if (this.ready.v !== 2) {
      throw new SessionProtocolError(`node started a v${this.ready.v ?? 1} session for a v2 offer`);
    }
    if (this.ready.pubkey !== undefined && this.ready.pubkey !== this.offer.notary_pubkey) {
      throw new SessionProtocolError("the session key differs from the signed offer's key");
    }

    const twoPc = new TwoPcSession(this.host, this.WS);
    this.twoPc = twoPc;
    twoPc.start(this.zkUrl("twopc"));
    if (this.useProofChannel) {
      this.zkChan = new ProofChannel(this.host, { webSocketImpl: this.WS });
      this.zkChan.start(this.zkUrl("zkchan"));
    }
    const t0 = Date.now();
    const keyShare = await Promise.race([twoPc.keyShare(this.timeouts.twoPcKeyShare), this.errP]);
    this.tKeyShare = Date.now();
    this.event({ ev: "twopc_key_share", ms: this.tKeyShare - t0 });
    this.makeTls({
      keyShare,
      onServerHello: async (serverShare, thSH) => {
        this.thSH = thSH;
        const t = Date.now();
        const out = await twoPc.handshake(serverShare, thSH, this.timeouts.handshakeV2);
        this.tPhaseA = Date.now() - t;
        this.absSpans.push({ name: "2PC phase A (handshake keys)", lane: "2pc", start: t, end: Date.now() });
        this.event({ ev: "twopc_phase_a", ms: this.tPhaseA });
        return out;
      },
      onServerFinished: async (thSF) => {
        this.thSF = thSF;
        const t = Date.now();
        this.ap = await twoPc.application(thSF, this.timeouts.handshakeV2);
        this.tPhaseB = Date.now() - t;
        this.absSpans.push({ name: "2PC phase B (application keys)", lane: "2pc", start: t, end: Date.now() });
        this.event({ ev: "twopc_phase_b", ms: this.tPhaseB });
        return { serverAp0: this.ap.serverAp0, clientAp1: this.ap.clientAp1 };
      },
    });
    this.keyShareReady = true;
    this.tArmed = Date.now();
    this.event({ ev: "armed", ms: this.tArmed - this.tStart });
  }

  private async handshakeV2(): Promise<void> {
    if (!this.keyShareReady) throw new SessionProtocolError("handshake before arm");
    if (this.failure) throw this.failure;
    const twoPcFailure = this.twoPc?.failure;
    if (twoPcFailure) throw twoPcFailure;
    this.handshaken = true;
    this.handshakeP = new Promise<void>((res) => (this.handshakeDone = res));
    this.tHsStart = Date.now();
    await this.tls.startHandshake();
    await Promise.race([this.handshakeP, this.errP, timeout(this.timeouts.handshakeV2, "handshake")]);
    if (!this.ap) throw new SessionProtocolError("handshake finished without 2PC application secrets");
    if (!this.provider) throw new SessionProtocolError("handshake finished without a verified certificate");
    const meta = this.tls.getMetadata?.();
    if (meta?.cipherSuite) this.provider.cipherSuite = meta.cipherSuite;
    if (meta?.selectedAlpn) this.provider.alpn = meta.selectedAlpn;
    await this.waitT("hs_verified", this.timeouts.hsVerified);
    this.tHs = Date.now();
    this.event({ ev: "hs_verified", twopc_phase_a_ms: this.tPhaseA, twopc_phase_b_ms: this.tPhaseB });
  }

  /** π_NK: the node's head record under K_0 is the published template. */
  private async prepareProofs(): Promise<void> {
    if (this.prepared) return;
    if (!this.handshaken) await this.handshakeV2();
    if (!this.ap) throw new SessionProtocolError("prepareProofs before arm");
    this.tNkStart = Date.now();
    const commit = await this.waitT("c_commit", this.timeouts.cCommit);
    for (const k of ["h1", "h2", "hk"] as const) {
      if (commit[k] !== undefined && commit[k] !== hex(this.ap[k])) {
        throw new SessionProtocolError(`c_commit: ${k} differs from our 2PC output`);
      }
    }
    // An image session's credential record is the image route's head.
    const nkOffer = this.imagesOffer ? { ...this.offer, head_template: this.imagesOffer.head_template } : this.offer;
    checkPiNKParams(commit.params, { offer: nkOffer, hk: this.ap.hk, bodyLen: this.bodyLength, kind: this.kind });
    // The head-record commitment the attestation must name is the one π_NK
    // proves; the frame has to carry exactly it.
    const pinkCommit = hex(Uint8Array.from((commit.params as { PiNK: { c_commit: number[] } }).PiNK.c_commit));
    if (commit.c_commit !== pinkCommit) {
      throw new SessionProtocolError("c_commit: the frame's commitment is not the one π_NK proves");
    }
    this.cCommitHex = pinkCommit;
    await this.proofV2("pi_nk", "verify", commit.params);
    this.event({ ev: "pi_nk_ok" });
    this.tProofsReady = Date.now();
    this.prepared = true;
  }

  private async proofV2(
    proof: "pi_nk" | "pi_c2s" | "pi_c3s",
    cmd: "prove" | "verify",
    params: unknown,
    witness?: unknown,
  ): Promise<void> {
    const t = Date.now();
    const ch = this.zkChan;
    if (ch && (ch.used || (await ch.ready(this.timeouts.proofChannelReady)))) {
      const m = await ch.run(cmd, proof, params, witness, this.timeouts.proof);
      this.proofTimes[proof] = {
        ok: true,
        via: "zkchan",
        ms: Date.now() - t,
        innerMs: m.ms,
        bytesSent: m.bytes_sent,
        bytesRecv: m.bytes_recv,
      };
      this.absSpans.push({ name: PROOF_LABEL[proof], lane: "proofs", start: t, end: Date.now() });
      return;
    }
    if (ch) this.event({ ev: "proof_channel_fallback", proof, err: String(ch.failure?.message ?? "") });
    await this.prover.run(
      this.zkUrl(proof),
      { proof, role: cmd === "prove" ? "prover" : "verifier", params, witness },
      this.timeouts.proof,
    );
    this.proofTimes[proof] = { ok: true, via: "per-proof", ms: Date.now() - t };
    this.absSpans.push({ name: PROOF_LABEL[proof], lane: "proofs", start: t, end: Date.now() });
  }

  /**
   * Serve one request on this session (arming it first if needed). `tClaim` is
   * when the request was made: a caller that first waited for this session's
   * arm passes the time before that wait, so the wait counts in the timings.
   */
  async claim(body: Uint8Array, tClaim = Date.now()): Promise<ConfidentialSessionResult> {
    if (this.kind === "images") throw new SessionProtocolError("image sessions are never claimed; use run()");
    const armingBefore = this.armStarted;
    if (!this.armStarted) await this.arm();
    await this.prepareProofs();
    const { prewarmed, waitedForArmMs } = claimTiming(tClaim, this.tArmed, armingBefore);
    return this.finish(body, tClaim, prewarmed, waitedForArmMs);
  }

  private async finish(
    body: Uint8Array,
    tClaim: number,
    prewarmed: boolean,
    waitedForArmMs?: number,
  ): Promise<ConfidentialSessionResult> {
    if (!this.prepared) throw new SessionProtocolError("finish before prepareProofs");
    if (body.length !== this.bodyLength) {
      throw new SessionProtocolError(`body length ${body.length} != declared setup len ${this.bodyLength}`);
    }
    if ((this.kind === "images" || this.ready.suffix !== undefined) && this.ready.suffix !== this.suffix) {
      throw new SessionProtocolError("node expects a different pinned suffix than ours");
    }
    const suffixBytes = new TextEncoder().encode(this.suffix);
    const tail = body.subarray(body.length - suffixBytes.length);
    if (!tail.every((b, i) => b === suffixBytes[i])) {
      throw new SessionProtocolError("request body does not end with the pinned suffix");
    }

    this.released = true;
    this.tRecordStart = Date.now();
    this.sendText({ type: "release_head" });
    await this.waitT("head_written", this.timeouts.headWritten);
    this.tHeadWritten = Date.now();
    this.event({ ev: "head_written" });

    this.tBodyWrite = Date.now();
    this.epochBody = true;
    // The pinned suffix is its own final record: the node holds it until π_C2S.
    await this.tls.write(body.subarray(0, body.length - suffixBytes.length));
    await this.tls.write(suffixBytes);
    this.event({ ev: "body_sent", len: body.length });

    this.sendText({ type: "body_suffix", suffix: hex(suffixBytes) });
    const c2params = await this.waitT("zk_params", this.timeouts.zkParams);
    const lastBody = this.bodyRecords[this.bodyRecords.length - 1] ?? new Uint8Array(0);
    checkPiC2SParams(c2params.params, {
      h1: this.ap!.h1,
      seq: this.bodyRecords.length - 1,
      record: lastBody,
      suffix: suffixBytes,
    });
    const c2Promise = this.proofV2("pi_c2s", "prove", c2params.params, { Secret: Array.from(this.ap!.clientAp1) }).then(
      () => this.event({ ev: "pi_c2s_ok" }),
      (e: unknown) => {
        this.c2Failed = true;
        this.event({ ev: "pi_c2s_fail", err: String(e) });
      },
    );

    // The node attests after the provider closes the response, so the wait
    // lasts as long as the answer streams: time out only on silence.
    const attP = this.bus.wait("attestation");
    // An image response sends nothing until the image is done.
    const idleMs = this.imagesOffer
      ? Math.max(this.timeouts.attestation, (this.imagesOffer.response_idle_s ?? 300) * 1000)
      : this.timeouts.attestation;
    const att = (await Promise.race([
      attP,
      this.errP,
      idleTimeout(idleMs, "attestation", () => Math.max(this.tLastData, this.tBodyWrite), attP),
    ])) as { a?: unknown; a_json?: string; sig?: string };
    if (this.ready.pubkey !== this.offer.notary_pubkey) {
      throw new ReceiptVerificationError(
        `session pubkey ${this.ready.pubkey} differs from the signed offer key ${this.offer.notary_pubkey}`,
      );
    }
    const attJson: string = att.a_json ?? JSON.stringify(att.a);
    const attOk = verifySchnorrSignature(attJson, att.sig, this.ready.pubkey);
    this.event({ ev: "attestation", sig_ok: attOk });
    if (!attOk) throw new ReceiptVerificationError("attestation signature invalid");
    checkAttestationBinding(attJson, {
      sid: this.sid,
      thSH: this.thSH,
      thSF: this.thSF,
      cCommit: this.cCommitHex,
      certChainHash: this.certChainHash,
      serverRecords: this.recvRecords,
      recvSha256: this.recvHash.clone().digest(),
    });

    await this.settleFlush();
    await c2Promise;
    if (this.c2Failed) throw new SessionProtocolError("π_C2S failed; the node will not settle without it");

    // An upstream HTTP error discloses only the response head.
    const httpEarly = parseHttpResponse(this.responseBytes);
    const upstreamError = httpEarly.status >= 400;
    // A flat-priced (image) success needs no disclosure: the charge is fixed
    // by the pinned request, so we accept and the node charges exactly it.
    // Only a 2xx is a success: anything else below 400 (a redirect) has no
    // image, so it is neither accepted nor disclosed.
    const outcome = imageOutcome(httpEarly.status);
    if (this.kind === "images" && outcome === "invalid") {
      throw new ResponseVerificationError(`image response HTTP ${httpEarly.status} is neither a success nor an error`);
    }
    const flatAccept = this.kind === "images" && outcome === "accept";
    let receipt: ConfidentialReceipt;
    let receiptJson: string;
    let sigHex: string | undefined;
    let usageMatch: boolean;
    let costWithinOffer = true;
    let ownUsage: UpstreamUsageEvent | undefined;
    const fee = offerSessionFeeMsat(this.offer);
    if (flatAccept) {
      this.sendText({ type: "accept" });
      ({ receipt, receiptJson, sigHex } = await this.waitReceipt(attJson));
      verifyFlatReceipt(receipt, {
        model: this.model,
        variant: this.image!.variant.id,
        count: this.image!.count,
        msatPerImage: this.image!.variant.msat_per_image,
        sessionFeeMsat: fee,
        abandonFeeMsat: offerAbandonFeeMsat(this.offer),
      });
      usageMatch = true;
      this.twoPc?.close();
      this.zkChan?.close();
    } else {
      let r: Uint8Array | undefined;
      let skip = 0;
      if (upstreamError) {
        const headEnd = indexOfCrlfCrlf(this.responseBytes);
        if (headEnd < 0) throw new ResponseVerificationError("upstream error response has no head");
        r = this.responseBytes.slice(0, headEnd + 4);
        skip = this.responseBytes.length - r.length;
      } else {
        r = extractUsageDisclosure(this.responseBytes) ?? undefined;
      }
      if (!r) throw new ResponseVerificationError("could not extract a valid usage disclosure R");
      const tailLens = disclosureTailLens(
        this.responseRecordLens,
        r.length + skip,
      );
      const epoch = serverTailEpoch(this.serverPost, tailLens.length);
      const disclose: Record<string, unknown> = {
        type: "disclose",
        r: hex(r),
        tail_lens: tailLens,
        skip,
        trailing: epoch.trailing,
      };
      if (epoch.keyUpdates > 0) {
        disclose.key_updates = epoch.keyUpdates;
        disclose.epoch_start = epoch.epochStart;
      }
      this.sendText(disclose);

      const c3 = await this.waitT("zk_params", this.timeouts.zkParams);
      // Wire index of sequence 0 of the covered records' epoch: the records
      // before the post-handshake ones are the encrypted server flight. (Indices
      // into the retained records: an image session drops the oldest ones.)
      const handshakeRecords = this.serverRecords.length + this.serverRecordsDropped - this.serverPost.length;
      checkPiC3SParams(c3.params, {
        h2: this.ap!.h2,
        serverRecords: this.serverRecords,
        r,
        skip,
        keyUpdates: epoch.keyUpdates,
        epochBase:
          handshakeRecords >= 0 ? handshakeRecords + epoch.epochStart - this.serverRecordsDropped : undefined,
        trailing: epoch.trailing,
        tailLens,
      });
      await this.proofV2("pi_c3s", "prove", c3.params, { Secret: Array.from(this.ap!.serverAp0) });
      this.twoPc?.close();
      this.zkChan?.close();
      this.event({ ev: "pi_c3s_ok" });

      ({ receipt, receiptJson, sigHex } = await this.waitReceipt(attJson));

      if (upstreamError) {
        // A rejected request (4xx but 429) costs the abandon fee, a 429/503 the
        // session fee, any other error at most the session's reservation.
        usageMatch = checkUpstreamErrorReceipt(
          receipt,
          httpEarly.status,
          fee,
          offerAbandonFeeMsat(this.offer),
          this.image
            ? { model: this.model, variant: this.image.variant.id, count: this.image.count, msatPerImage: this.image.variant.msat_per_image }
            : undefined,
        );
      } else {
        ownUsage = usageEventFromDisclosure(r) ?? undefined;
        if (!ownUsage) throw new ResponseVerificationError("could not parse our own usage event");
        const checked = verifyReceipt({
          receipt,
          receiptJson,
          sig: sigHex,
          pubkey: this.ready.pubkey,
          ownUsage,
          priceEntry: this.offer.price_list[this.model],
          sessionFeeMsat: fee,
          abandonFeeMsat: offerAbandonFeeMsat(this.offer),
        });
        usageMatch = checked.usageMatch;
        costWithinOffer = checked.costWithinOffer;
        if (!costWithinOffer) {
          throw new ReceiptVerificationError(
            `receipt cost ${receipt.cost_msats} msats exceeds the usage priced at the signed offer's rates`,
          );
        }
      }
    }
    if (!usageMatch) throw new ReceiptVerificationError("receipt usage does not match our own plaintext");
    const receiptSigOk = verifySchnorrSignature(receiptJson, sigHex, this.ready.pubkey);

    const http = httpEarly;
    let effectiveModel: string | undefined;
    let images: Blob[] | undefined;
    let warnings: string[] | undefined;
    if (this.kind === "images") {
      // Accepted already (the charge was fixed; refusing would cost the
      // reservation): a short or broken answer is reported, not thrown.
      ({ images, warnings } = flatAccept ? this.decodeImages(http) : { images: [], warnings: undefined });
      if (flatAccept) {
        // The images are Blobs now; the plaintext copies can go.
        this.responseChunks = [];
        this.responseJoined = undefined;
      }
    } else {
      effectiveModel = effectiveModelFromText(http.bodyText);
      if (effectiveModel !== undefined && effectiveModel !== this.model) {
        throw new ResponseVerificationError(`effective model ${effectiveModel} != ${this.model}`);
      }
    }

    this.finished = true;
    const tEnd = Date.now();
    const ttftAbs = this.ttft || tEnd;
    const lastData = this.tLastData || ttftAbs;
    const isImage = this.kind === "images";
    const abs = [
      ...(this.tReady ? [{ name: "setup (node checks credential, reserves)", lane: "node" as const, start: this.tStart, end: this.tReady }] : []),
      ...(this.tKeyShare ? [{ name: "2PC preprocessing + key share", lane: "2pc" as const, start: this.tReady, end: this.tKeyShare }] : []),
      ...(this.zkChan?.tReady ? [{ name: "proof channel setup", lane: "proofs" as const, start: this.zkChan.tStart, end: this.zkChan.tReady }] : []),
      ...(this.tHs ? [{ name: "TLS handshake with provider", lane: "tls" as const, start: this.tHsStart, end: this.tHs }] : []),
      ...this.absSpans,
      ...(this.tRecordStart ? [{ name: "credential record (node)", lane: "node" as const, start: this.tRecordStart, end: this.tHeadWritten }] : []),
      ...(this.tBodyWrite
        ? [{ name: isImage ? "provider: generating the image" : "provider: time to first byte", lane: "provider" as const, start: this.tBodyWrite, end: ttftAbs }]
        : []),
      { name: isImage ? "image download" : "response streaming", lane: "provider" as const, start: ttftAbs, end: lastData },
      { name: isImage ? "settlement (accept, receipt)" : "settlement (usage proof, receipt)", lane: "node" as const, start: lastData, end: tEnd },
    ];
    const spans: TimingSpan[] = abs
      .filter((x) => x.start > 0 && x.end >= x.start)
      .map((x) => ({ name: x.name, lane: x.lane, startMs: x.start - tClaim, endMs: x.end - tClaim }))
      .sort((a, b) => a.startMs - b.startMs);
    const timings: ConfidentialSessionTimings = {
      readyMs: this.tReady && this.tReady >= tClaim ? this.tReady - tClaim : undefined,
      handshakeMs: this.tHs ? this.tHs - Math.max(tClaim, this.tArmed) : undefined,
      piNkMs: this.tNkStart ? this.tProofsReady - this.tNkStart : undefined,
      recordMs: this.tRecordStart ? this.tHeadWritten - this.tRecordStart : undefined,
      claimToBodyMs: this.tBodyWrite ? this.tBodyWrite - tClaim : undefined,
      upstreamTtftMs: this.tBodyWrite ? ttftAbs - this.tBodyWrite : undefined,
      armMs: this.tArmed ? this.tArmed - this.tStart : undefined,
      twoPcKeyShareMs: this.tKeyShare ? this.tKeyShare - this.tReady : undefined,
      twoPcPhaseAMs: this.tPhaseA || undefined,
      twoPcPhaseBMs: this.tPhaseB || undefined,
      twoPcSteps: this.twoPc?.timings.slice(),
      twoPcBytes: this.twoPc?.bytes,
      proofs: { ...this.proofTimes },
      proofChannelReadyMs: this.zkChan?.tReady ? this.zkChan.tReady - this.zkChan.tStart : undefined,
      proofChannelSteps: this.zkChan?.timings.slice(),
      totalMs: tEnd - tClaim,
      spans,
    };
    return {
      sid: this.sid,
      uuid: this.uuid,
      model: this.model,
      effectiveModel,
      http: flatAccept ? imageHead(http) : http,
      responseText: this.kind === "images" ? "" : http.bodyText,
      receipt,
      receiptJson,
      receiptSig: sigHex,
      attestation: att.a,
      receiptSigOk,
      attestationSigOk: attOk,
      usageMatch,
      costWithinOffer,
      costMsats: receipt.cost_msats,
      ownUsage,
      provider: this.provider,
      ttftMs: ttftAbs - tClaim,
      totalMs: tEnd - tClaim,
      timings,
      proofs: flatAccept ? ["twopc", "pi_nk", "pi_c2s"] : ["twopc", "pi_nk", "pi_c2s", "pi_c3s"],
      prewarmed,
      waitedForArmMs,
      protocol: 2,
      nodePubkey: this.ready.pubkey,
      images,
      imageVariant: this.image?.variant.id,
      imageCount: this.image?.count,
      warnings,
    };
  }

  /** The signed receipt, bound to this session and its attestation. */
  private async waitReceipt(attJson: string): Promise<{ receipt: ConfidentialReceipt; receiptJson: string; sigHex?: string }> {
    const m = (await Promise.race([
      this.bus.wait("receipt"),
      this.errP,
      timeout(this.timeouts.receipt, "receipt"),
    ])) as { receipt: ConfidentialReceipt; receipt_json?: string; sig?: string };
    const receiptJson = m.receipt_json ?? JSON.stringify(m.receipt);
    const receipt = parseSignedReceipt({
      receiptJson,
      sig: m.sig,
      pubkey: this.ready.pubkey,
      sid: this.sid,
      // The bytes whose signature and session binding were checked above.
      attestationJson: attJson,
    });
    return { receipt, receiptJson, sigHex: m.sig };
  }

  /** The images of a 2xx image response and what is wrong with it. */
  private decodeImages(http: ParsedHttpResponse): { images: Blob[]; warnings: string[] } {
    return decodeImageResponse(http, {
      model: this.model,
      count: this.image!.count,
      countKey: this.imagesOffer!.count_key,
      shape: this.imagesOffer!.response_shape,
      pins: this.image!.variant.pins,
    });
  }

  /** Cold path: arm, then claim. */
  async run(body: Uint8Array): Promise<ConfidentialSessionResult> {
    this.coldRun = true;
    const tClaim = Date.now();
    await this.arm();
    await this.prepareProofs();
    // Armed inside this request, so it is a cold request even though the key
    // share is ready by now.
    return this.finish(body, tClaim, false);
  }

  /** Abort an unclaimed session; the node releases its reservation (minus any session fee). */
  close(): void {
    this.twoPc?.close();
    this.zkChan?.close();
    try {
      this.ws?.close();
    } catch {
      /* ignore */
    }
  }

  private async settleFlush(): Promise<void> {
    for (let i = 0; i < 200; i++) {
      const c = this.flushChain;
      await c;
      if (c === this.flushChain && this.tlsEnded) break;
      await new Promise((r2) => setTimeout(r2, 5));
    }
  }
}

/** KeyUpdate messages (type 24) in a decrypted handshake record. */
function countKeyUpdates(content: Uint8Array): number {
  let n = 0;
  let i = 0;
  while (i + 4 <= content.length) {
    if (content[i] === 24) n++;
    i += 4 + ((content[i + 1]! << 16) | (content[i + 2]! << 8) | content[i + 3]!);
  }
  return n;
}

/** A successful image response without its body: the images are returned as Blobs. */
function imageHead(http: ParsedHttpResponse): ParsedHttpResponse {
  const empty = new Uint8Array(0);
  return {
    status: http.status,
    statusText: http.statusText,
    headers: http.headers,
    raw: empty,
    body: empty,
    bodyText: "",
    contentType: http.contentType,
    complete: http.complete,
  };
}

/**
 * The images of an accepted (2xx) image response, as Blobs of the pinned
 * format, and what is wrong with the answer: an incomplete body, fewer images
 * than the pinned count, or a provider echo (`request`) naming another model
 * or count. The request is paid either way, so this reports and never throws.
 */
export function decodeImageResponse(
  http: ParsedHttpResponse,
  terms: { model: string; count: number; countKey: string; shape: "venice" | "openai"; pins: readonly ImagePin[] },
): { images: Blob[]; warnings: string[] } {
  const warnings: string[] = [];
  if (!http.complete) warnings.push("the image response ended before its declared length");
  let body: unknown;
  try {
    // Parsed from the bytes directly: the text exists only for this parse.
    body = JSON.parse(new TextDecoder().decode(http.body));
  } catch {
    warnings.push("the image response body is not JSON");
    return { images: [], warnings };
  }
  const type = imageMimeType(terms.pins);
  let images: Blob[] = [];
  try {
    images = responseImages(body, terms.shape).map((b64) => new Blob([base64ToBytes(b64) as BlobPart], { type }));
  } catch (e) {
    warnings.push(`the image response has no readable images (${(e as Error).message})`);
  }
  if (images.length !== terms.count) warnings.push(`the provider returned ${images.length} of ${terms.count} images`);
  const echo = (body as { request?: unknown } | null)?.request;
  if (echo && typeof echo === "object") {
    const e = echo as Record<string, unknown>;
    const echoed = (e.data && typeof e.data === "object" ? e.data : e) as Record<string, unknown>;
    if (echoed.model !== undefined && echoed.model !== terms.model) {
      warnings.push(`the provider echoes model ${JSON.stringify(echoed.model)}, not ${terms.model}`);
    }
    const n = echoed[terms.countKey];
    if (n !== undefined && n !== terms.count) warnings.push(`the provider echoes count ${JSON.stringify(n)}, not ${terms.count}`);
  }
  return { images, warnings };
}

/**
 * What an image session does with the provider's status: accept only a 2xx
 * (the flat charge), disclose the head of an error (>= 400) for a release,
 * and neither for anything else (a redirect carries no image).
 */
export function imageOutcome(status: number): "accept" | "error" | "invalid" {
  if (status >= 200 && status < 300) return "accept";
  if (status >= 400) return "error";
  return "invalid";
}
