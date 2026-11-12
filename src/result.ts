/**
 * What a verified confidential request returns to the page: the provider's
 * answer, the signed receipt, what the browser itself verified, and the
 * timings and bytes of the request on its connection (PROTOCOL-V3.md).
 */

import type { ProviderVerification } from "./certinfo.js";
import type {
  ConfidentialConnection,
  ConnectionBytes,
  ConnectionRequestResult,
  DepositOutcome,
  ProofTiming,
} from "./connection.js";
import type { ConfidentialFraming } from "./offer.js";
import type { UpstreamUsageEvent } from "./suffix.js";
import type { TwoPcTiming } from "./twopc.js";
import type { ConfidentialReceipt } from "./wire.js";

export type { CertificateInfo, ProviderVerification } from "./certinfo.js";
export type { ConfidentialReceipt } from "./wire.js";

export interface ProofOutcome {
  ok: boolean;
  /** `channel` (the connection's pre-warmed proof channel) or `socket` (a /zk socket of its own). */
  via: string;
  ms: number;
  innerMs?: number;
  bytesSent?: number;
  bytesRecv?: number;
  /** π_WIN: how many windows and ciphertext bytes the proof covered. */
  windows?: number;
  ctBytes?: number;
  /** How many runs of this proof the request needed (π_WIN: per record batch, control records included). */
  runs?: number;
}

export interface TimingSpan {
  name: string;
  /** "node" (setup, records, settlement), "2pc", "proofs", "tls", "provider". */
  lane: "node" | "2pc" | "proofs" | "tls" | "provider";
  /** Milliseconds relative to the request (negative: before it, e.g. an armed connection's setup). */
  startMs: number;
  endMs: number;
}

export interface ConfidentialTimings {
  /** The connection's setup (only when this request opened or claimed the connection). */
  readyMs?: number;
  armMs?: number;
  twoPcKeyShareMs?: number;
  handshakeMs?: number;
  twoPcPhaseAMs?: number;
  twoPcPhaseBMs?: number;
  piNkMs?: number;
  /** The node writing the connection head (credential record) and, framing "2", the provider's SETTINGS. */
  recordMs?: number;
  /** From the request to its last record written to the provider. */
  releasedMs?: number;
  /** From the request to the first response byte the provider sent. */
  upstreamTtftMs?: number;
  twoPcSteps?: TwoPcTiming[];
  twoPcBytes?: { sent: number; recv: number };
  proofs?: Record<string, ProofOutcome>;
  proofChannelSteps?: TwoPcTiming[];
  totalMs: number;
  spans?: TimingSpan[];
}

/** What the connection's deposit did, as far as this request saw it. */
export interface ConfidentialDepositInfo {
  /** The signed offer's deposit for the connection (0: none). */
  msat: number;
  /** This request's receipt released it (the connection's first settlement). */
  releasedMsat?: number;
  /** The outcome the node reported (receipt or the connection's last frame), if any yet. */
  outcome?: DepositOutcome;
}

export interface ConfidentialRequestResult {
  /** The connection (`sid`), its framing towards the provider, and the request's number on it. */
  sid: string;
  framing: ConfidentialFraming;
  n: number;
  /** Framing "2": the HTTP/2 stream of the request. */
  stream?: number;
  /** What the request found: a connection kept open from an earlier request, an armed one, or none. */
  connection: "reused" | "armed" | "new";
  /** The framing was "2" and failed to open, so the request ran on "1.1" (§2.3). */
  fellBack?: boolean;
  model: string;
  effectiveModel?: string;
  /** The provider's response head (the body stays private). */
  http: { status: number; statusText: string; headers: Record<string, string> };
  responseText: string;
  receipt: ConfidentialReceipt;
  receiptJson: string;
  receiptSig?: string;
  attestation: unknown;
  /** Every check below passed, or the request would have thrown. */
  receiptSigOk: boolean;
  attestationSigOk: boolean;
  usageMatch: boolean;
  costWithinOffer: boolean;
  costMsats?: number;
  ownUsage?: UpstreamUsageEvent;
  provider?: ProviderVerification;
  deposit: ConfidentialDepositInfo;
  /** From the request (the caller's call) to the first response byte, and to settlement (ms). */
  ttftMs: number;
  totalMs: number;
  timings: ConfidentialTimings;
  /** Bytes between this page and the node for the request (setup excluded), and for setting the connection up when this request did. */
  bytes: { sent: number; recv: number; channels: ConnectionBytes };
  setupBytes?: { sent: number; recv: number };
  proofs: string[];
  /** True when the connection was armed or open before the request (no 2PC preprocessing on its path). */
  prewarmed: boolean;
  /** The request arrived while its armed connection was still arming and waited this long. */
  waitedForArmMs?: number;
  protocol: number;
  nodePubkey: string;
  /** Image requests: the generated images (empty for an upstream error). */
  images?: Blob[];
  imageVariant?: string;
  imageCount?: number;
  warnings?: string[];
}

/** The v2 name of the result, kept for callers. */
export type ConfidentialSessionResult = ConfidentialRequestResult;

const sumSent = (b: ConnectionBytes) => b.relaySent + b.controlSent + b.twoPcSent + b.zkSent;
const sumRecv = (b: ConnectionBytes) => b.relayRecv + b.controlRecv + b.twoPcRecv + b.zkRecv;

export const bytesSent = sumSent;
export const bytesRecv = sumRecv;

function proofOutcomes(proofs: ProofTiming[], head?: ProofTiming): Record<string, ProofOutcome> {
  const out: Record<string, ProofOutcome> = {};
  const all = head ? [head, ...proofs] : proofs;
  for (const p of all) {
    const key = p.purpose === "error_head" ? `${p.proof}_error_head` : p.proof;
    const prev = out[key];
    if (!prev) {
      out[key] = {
        ok: true,
        via: p.via ?? "channel",
        ms: p.ms,
        innerMs: p.innerMs,
        bytesSent: p.bytesSent,
        bytesRecv: p.bytesRecv,
        windows: p.windows,
        ctBytes: p.ctBytes,
        runs: 1,
      };
    } else {
      prev.ms += p.ms;
      prev.runs = (prev.runs ?? 1) + 1;
      if (p.innerMs !== undefined) prev.innerMs = (prev.innerMs ?? 0) + p.innerMs;
      if (p.windows !== undefined) prev.windows = (prev.windows ?? 0) + p.windows;
      if (p.ctBytes !== undefined) prev.ctBytes = (prev.ctBytes ?? 0) + p.ctBytes;
      if (p.bytesSent !== undefined) prev.bytesSent = (prev.bytesSent ?? 0) + p.bytesSent;
      if (p.bytesRecv !== undefined) prev.bytesRecv = (prev.bytesRecv ?? 0) + p.bytesRecv;
    }
  }
  return out;
}

/**
 * The page's result for one settled request on `conn`. `tRequest` is when the
 * caller asked (the request may have waited for a connection); `warm` what it
 * found in the pool.
 */
export function requestResult(
  r: ConnectionRequestResult,
  conn: ConfidentialConnection,
  warm: "open" | "armed" | "cold",
  tRequest: number,
  extra: { responseText: string; fellBack?: boolean; waitedForArmMs?: number } = { responseText: "" },
): ConfidentialRequestResult {
  const t0 = tRequest;
  const rel = (t: number | undefined) => (t === undefined || !t ? undefined : t - t0);
  const start = r.timings.startedAt;
  const ttftAbs = r.timings.ttftMs !== undefined ? start + r.timings.ttftMs : undefined;
  const endAbs = start + r.timings.totalMs;
  const releasedAbs = r.timings.releasedMs !== undefined ? start + r.timings.releasedMs : undefined;
  // The connection's own setup is part of this request when the request opened it (or claimed an armed one).
  const ownSetup = warm !== "open";
  const st = conn.setupTimings;
  const m = conn.marks;
  const spans: TimingSpan[] = [];
  const span = (name: string, lane: TimingSpan["lane"], a?: number, b?: number) => {
    if (a === undefined || b === undefined || !(b >= a)) return;
    spans.push({ name, lane, startMs: a - t0, endMs: b - t0 });
  };
  if (ownSetup) {
    const tc = conn.tCreated;
    const readyAt = st.readyMs !== undefined ? tc + st.readyMs : undefined;
    span("setup (deposit)", "node", tc, readyAt);
    span("2PC preprocessing + key share", "2pc", readyAt, readyAt !== undefined && st.twoPcKeyShareMs !== undefined ? readyAt + st.twoPcKeyShareMs : undefined);
    if (st.armMs !== undefined && conn.tArmed) span("proof channel", "proofs", readyAt, conn.tArmed);
    span("TLS handshake", "tls", m.handshake, m.phaseB);
    span("2PC phase A", "2pc", m.serverHello, m.phaseA);
    span("2PC phase B", "2pc", m.serverFinished, m.phaseB);
    span("π_NK", "proofs", m.phaseB, m.piNk);
    if (r.http === "2") span("connection head + SETTINGS", "node", m.piNk, conn.tOpen || undefined);
    else span("request head", "node", m.piNk, m.piNk !== undefined && st.headMs !== undefined ? m.piNk + st.headMs : undefined);
  }
  span("request + π_WIN", "node", start, releasedAbs);
  span("provider", "provider", releasedAbs, ttftAbs ?? endAbs);
  span("response", "provider", ttftAbs, endAbs);
  const settleProofs = r.timings.proofs.filter((p) => p.proof === "pi_c3s" || p.purpose === "error_head");
  const proofMs = settleProofs.reduce((a, p) => a + p.ms, 0);
  if (proofMs > 0) span(settleProofs[0]!.proof === "pi_c3s" ? "π_C3S + receipt" : "π_WIN (error head) + receipt", "proofs", endAbs - proofMs, endAbs);

  const twoPcSteps = ownSetup ? conn.twoPcSteps : [];
  const phase = (name: string) => twoPcSteps.filter((s) => s.step.startsWith(name)).reduce((a, s) => a + s.ms, 0) || undefined;
  // Framing "2": the request's bytes start after the connection opened (setupBytes: arming, handshake, π_NK).
  // Framing "1.1": they start after arming and include the handshake (armBytes: setup, 2PC preprocessing).
  const setup = ownSetup ? (r.http === "2" ? conn.setupBytes : conn.armBytes) : undefined;
  const setupSent = setup ? sumSent(setup) : undefined;
  const setupRecv = setup ? sumRecv(setup) : undefined;
  const status = r.status;
  const proofs = proofOutcomes(r.timings.proofs, ownSetup ? conn.headProof : undefined);
  const backMsat = typeof r.receipt.deposit_released_msat === "number" ? r.receipt.deposit_released_msat : undefined;
  return {
    sid: r.sid,
    framing: r.http,
    n: r.n,
    stream: r.stream,
    connection: warm === "open" ? "reused" : warm === "armed" ? "armed" : "new",
    fellBack: extra.fellBack,
    model: r.model,
    effectiveModel: r.effectiveModel,
    http: { status, statusText: "", headers: r.headers },
    responseText: extra.responseText,
    receipt: r.receipt,
    receiptJson: r.receiptJson,
    receiptSig: r.receiptSig,
    attestation: r.attestation,
    receiptSigOk: true,
    attestationSigOk: true,
    usageMatch: true,
    costWithinOffer: true,
    costMsats: r.costMsats,
    ownUsage: r.ownUsage ?? (status < 300 ? (r.receipt.usage as UpstreamUsageEvent | undefined) : undefined),
    provider: conn.provider,
    deposit: { msat: conn.depositMsat, releasedMsat: backMsat, outcome: conn.deposit },
    ttftMs: ttftAbs !== undefined ? ttftAbs - t0 : endAbs - t0,
    totalMs: endAbs - t0,
    timings: {
      readyMs: ownSetup ? st.readyMs : undefined,
      armMs: ownSetup ? st.armMs : undefined,
      twoPcKeyShareMs: ownSetup ? st.twoPcKeyShareMs : undefined,
      handshakeMs: ownSetup ? st.handshakeMs : undefined,
      twoPcPhaseAMs: ownSetup ? (m.phaseA && m.serverHello ? m.phaseA - m.serverHello : phase("phase_a")) : undefined,
      twoPcPhaseBMs: ownSetup ? (m.phaseB && m.serverFinished ? m.phaseB - m.serverFinished : phase("phase_b")) : undefined,
      piNkMs: ownSetup ? st.piNkMs : undefined,
      recordMs: ownSetup ? (st.headMs ?? 0) + (st.settingsMs ?? 0) || undefined : undefined,
      releasedMs: rel(releasedAbs),
      upstreamTtftMs: rel(ttftAbs),
      twoPcSteps,
      twoPcBytes: ownSetup ? { sent: r.bytes.twoPcSent + (setup?.twoPcSent ?? 0), recv: r.bytes.twoPcRecv + (setup?.twoPcRecv ?? 0) } : undefined,
      proofs,
      proofChannelSteps: ownSetup ? conn.proofChannelSteps : undefined,
      totalMs: endAbs - t0,
      spans,
    },
    bytes: { sent: sumSent(r.bytes), recv: sumRecv(r.bytes), channels: r.bytes },
    setupBytes: setupSent !== undefined && setupRecv !== undefined ? { sent: setupSent, recv: setupRecv } : undefined,
    proofs: Object.keys(proofs),
    prewarmed: warm !== "cold",
    waitedForArmMs: extra.waitedForArmMs,
    protocol: 3,
    nodePubkey: conn.offer.notary_pubkey,
  };
}
