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
import {
  ConfidentialTimeoutError,
  ReceiptVerificationError,
  ResponseVerificationError,
  SessionProtocolError,
  SessionRejectedError,
} from "./errors.js";
import { matchHostname } from "./hosts.js";
import { checkPiC2SParams, checkPiC3SParams, checkPiNKParams } from "./params.js";
import { WasmProverBackend } from "./prover.js";
import { checkAttestationBinding, feeOnlyChargeOk, parseSignedReceipt, verifyReceipt } from "./receipt.js";
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
import { offerAbandonFeeMsat, offerSessionFeeMsat, type VerifiedOffer } from "./offer.js";
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
  protocol: number;
  nodePubkey: string;
}

export interface ConfidentialSessionOptions {
  /** Node HTTP(S) base, e.g. `https://routstr.cypherpunk.today`. */
  baseUrl: string;
  offer: VerifiedOffer;
  /** The node credential (`sk-` key or Cashu token); sent only in-band in `setup.auth`. */
  auth: string;
  model: string;
  maxTokens: number;
  /** Body length declared at setup (must equal the body passed to claim()). */
  bodyLength: number;
  suffix?: string;
  host: WasmHost;
  /** Use the pre-warmed proof channel (default true). */
  proofChannel?: boolean;
  webSocketImpl?: typeof WebSocket;
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

export class ConfidentialSession {
  readonly uuid = globalThis.crypto.randomUUID();
  readonly baseUrl: string;
  readonly offer: VerifiedOffer;
  readonly model: string;
  readonly maxTokens: number;
  readonly bodyLength: number;
  readonly suffix: string;
  readonly protocol = 2;
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
  private serverRecords: Uint8Array[] = [];
  private serverPending: Uint8Array = new Uint8Array(0);
  private epochBody = false;
  private bodyRecords: Uint8Array[] = [];
  private responseBytes: Uint8Array = new Uint8Array(0);
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
    this.suffix = options.suffix ?? canonicalSuffix(options.model, options.maxTokens);
    if (options.offer.v !== 2) {
      throw new SessionProtocolError(`the browser client speaks protocol v2 only (offer v=${options.offer.v})`);
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
      onRead: () => {},
      onRecvCertificates: ({ certificates, verifiedPath }: { certificates: any[]; verifiedPath?: any[] }) => {
        // Called only after the fork validated the chain to a bundled Mozilla
        // root and matched the hostname (it throws otherwise).
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
        this.responseBytes = concat(this.responseBytes, rec);
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
      onHandshake: () => this.handshakeDone?.(),
      logger: { trace: () => {}, debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
    }) as TlsHandle;
  }

  private trackServerRecords(bytes: Uint8Array): void {
    let buf = concat(this.serverPending, bytes);
    while (buf.length >= 5) {
      const len = (buf[3]! << 8) | buf[4]!;
      if (buf.length < 5 + len) break;
      if (buf[0] === 0x17) this.serverRecords.push(buf.slice(5, 5 + len));
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
    this.armStarted = true;
    await this.host.ready();
    await this.open();
    const setup: Record<string, unknown> = {
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
    checkPiNKParams(commit.params, { offer: this.offer, hk: this.ap.hk, bodyLen: this.bodyLength });
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
    await this.prover.run(this.zkUrl(proof), { proof, role: cmd === "prove" ? "prover" : "verifier", params, witness });
    this.proofTimes[proof] = { ok: true, via: "per-proof", ms: Date.now() - t };
    this.absSpans.push({ name: PROOF_LABEL[proof], lane: "proofs", start: t, end: Date.now() });
  }

  /** Serve one request on this session (arming it first if needed). */
  async claim(body: Uint8Array, tClaim = Date.now()): Promise<ConfidentialSessionResult> {
    const prewarmed = this.keyShareReady;
    if (!this.armStarted) await this.arm();
    await this.prepareProofs();
    return this.finish(body, tClaim, prewarmed);
  }

  private async finish(body: Uint8Array, tClaim: number, prewarmed: boolean): Promise<ConfidentialSessionResult> {
    if (!this.prepared) throw new SessionProtocolError("finish before prepareProofs");
    if (body.length !== this.bodyLength) {
      throw new SessionProtocolError(`body length ${body.length} != declared setup len ${this.bodyLength}`);
    }
    if (this.ready.suffix !== undefined && this.ready.suffix !== this.suffix) {
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
    const att = (await Promise.race([
      attP,
      this.errP,
      idleTimeout(this.timeouts.attestation, "attestation", () => Math.max(this.tLastData, this.tBodyWrite), attP),
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
    checkAttestationBinding(attJson, { sid: this.sid, thSH: this.thSH, thSF: this.thSF });

    await this.settleFlush();
    await c2Promise;
    if (this.c2Failed) throw new SessionProtocolError("π_C2S failed; the node will not settle without it");

    // An upstream HTTP error discloses only the response head.
    const httpEarly = parseHttpResponse(this.responseBytes);
    const upstreamError = httpEarly.status >= 400;
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
      this.responseChunks.map((c) => c.length),
      r.length + skip,
    );
    this.sendText({ type: "disclose", r: hex(r), tail_lens: tailLens, skip });

    const c3 = await this.waitT("zk_params", this.timeouts.zkParams);
    checkPiC3SParams(c3.params, { h2: this.ap!.h2, serverRecords: this.serverRecords, r, skip });
    await this.proofV2("pi_c3s", "prove", c3.params, { Secret: Array.from(this.ap!.serverAp0) });
    this.twoPc?.close();
    this.zkChan?.close();
    this.event({ ev: "pi_c3s_ok" });

    const m = (await Promise.race([
      this.bus.wait("receipt"),
      this.errP,
      timeout(this.timeouts.receipt, "receipt"),
    ])) as { receipt: ConfidentialReceipt; receipt_json?: string; sig?: string };
    const receiptJson = m.receipt_json ?? JSON.stringify(m.receipt);
    const sigHex = m.sig;
    const receipt = parseSignedReceipt({
      receiptJson,
      sig: sigHex,
      pubkey: this.ready.pubkey,
      sid: this.sid,
      attestationJson: att.a_json,
    });
    const receiptSigOk = verifySchnorrSignature(receiptJson, sigHex, this.ready.pubkey);
    const fee = offerSessionFeeMsat(this.offer);

    let usageMatch: boolean;
    let costWithinOffer = true;
    let ownUsage: UpstreamUsageEvent | undefined;
    if (upstreamError) {
      const ru = receipt.usage as unknown as { error_status?: number };
      usageMatch = ru?.error_status === httpEarly.status;
      // Errors the provider answers before doing any work cost at most the session fee.
      const unbilled = httpEarly.status === 503 || (httpEarly.status >= 400 && httpEarly.status < 500);
      if (unbilled && !feeOnlyChargeOk(receipt.cost_msats, fee)) {
        throw new ReceiptVerificationError(
          `node charged ${receipt.cost_msats} msats for an unbilled upstream error (session fee ${fee} msats)`,
        );
      }
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
    if (!usageMatch) throw new ReceiptVerificationError("receipt usage does not match our own plaintext");

    const http = parseHttpResponse(this.responseBytes);
    const effectiveModel = effectiveModelFromText(http.bodyText);
    if (effectiveModel !== undefined && effectiveModel !== this.model) {
      throw new ResponseVerificationError(`effective model ${effectiveModel} != ${this.model}`);
    }

    this.finished = true;
    const tEnd = Date.now();
    const ttftAbs = this.ttft || tEnd;
    const lastData = this.tLastData || ttftAbs;
    const abs = [
      ...(this.tReady ? [{ name: "setup (node checks credential, reserves)", lane: "node" as const, start: this.tStart, end: this.tReady }] : []),
      ...(this.tKeyShare ? [{ name: "2PC preprocessing + key share", lane: "2pc" as const, start: this.tReady, end: this.tKeyShare }] : []),
      ...(this.zkChan?.tReady ? [{ name: "proof channel setup", lane: "proofs" as const, start: this.zkChan.tStart, end: this.zkChan.tReady }] : []),
      ...(this.tHs ? [{ name: "TLS handshake with provider", lane: "tls" as const, start: this.tHsStart, end: this.tHs }] : []),
      ...this.absSpans,
      ...(this.tRecordStart ? [{ name: "credential record (node)", lane: "node" as const, start: this.tRecordStart, end: this.tHeadWritten }] : []),
      ...(this.tBodyWrite ? [{ name: "provider: time to first byte", lane: "provider" as const, start: this.tBodyWrite, end: ttftAbs }] : []),
      { name: "response streaming", lane: "provider" as const, start: ttftAbs, end: lastData },
      { name: "settlement (usage proof, receipt)", lane: "node" as const, start: lastData, end: tEnd },
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
      http,
      responseText: http.bodyText,
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
      proofs: ["twopc", "pi_nk", "pi_c2s", "pi_c3s"],
      prewarmed,
      protocol: 2,
      nodePubkey: this.ready.pubkey,
    };
  }

  /** Cold path: arm, then claim. */
  async run(body: Uint8Array): Promise<ConfidentialSessionResult> {
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
