/**
 * @routstr/confidential-web — routstr confidential mode (protocol v2) in the
 * browser. See README.md for the security model.
 */

export { createConfidentialClient, ConfidentialClient } from "./client.js";
export type {
  ChatCompletion,
  ChatCompletionChunk,
  ChatCompletionCreateParams,
  ConfidentialClientOptions,
  ConfidentialStream,
  PrewarmOptions,
} from "./client.js";
export { ConfidentialSession, DEFAULT_TIMEOUTS } from "./session.js";
export type {
  CertificateInfo,
  ConfidentialReceipt,
  ConfidentialSessionResult,
  ConfidentialSessionTimings,
  ProofOutcome,
  ProviderVerification,
  TimingSpan,
} from "./session.js";
export * from "./errors.js";
export {
  fetchConfidentialOffer,
  offerAbandonFeeMsat,
  offerSessionFeeMsat,
  verifyConfidentialOffer,
  verifyOfferSignature,
  CONFIDENTIAL_VERSION_MAX,
  CONFIDENTIAL_VERSION_MIN,
} from "./offer.js";
export type { ConfidentialOffer, ConfidentialPriceEntry, VerifiedOffer } from "./offer.js";
export { parseSignedReceipt, verifyReceipt } from "./receipt.js";
export { canonicalJson, npubToHex, verifySchnorrSignature } from "./canonical.js";
export { canonicalSuffix } from "./suffix.js";
export { buildPinnedBody, padPinnedBody, chooseBucket, requestedMaxTokens, SseParser, aggregateChatCompletion } from "./request.js";
export { mintInputFees, NodeApi, NodeApiError } from "./node-api.js";
export type { BalanceInfo, LightningInvoice, LightningInvoiceStatus, MintFee, NodeModel } from "./node-api.js";
export { costMsat, formatSats, modelPricing, promptLimit, roughTokens, sessionFeeMsat } from "./pricing.js";
export type { ModelPricing } from "./pricing.js";
export { InlineWasmHost, WorkerWasmHost, getDefaultWasmHost, setDefaultWasmHost } from "./wasm/host.js";
export type { WasmHost } from "./wasm/host.js";
export { TwoPcSession } from "./twopc.js";
export { ProofChannel } from "./zkchan.js";
export { probeProviderTls } from "./diagnostics.js";
export type { TlsProbeResult } from "./diagnostics.js";
