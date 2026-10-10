/**
 * @routstr/confidential-web — routstr confidential mode (protocol v2) in the
 * browser. See README.md for the security model.
 */

export { createConfidentialClient, ConfidentialClient } from "./client";
export type {
  ChatCompletion,
  ChatCompletionChunk,
  ChatCompletionCreateParams,
  ConfidentialClientOptions,
  ConfidentialStream,
  PrewarmOptions,
} from "./client";
export { ConfidentialSession, DEFAULT_TIMEOUTS } from "./session";
export type {
  CertificateInfo,
  ConfidentialReceipt,
  ConfidentialSessionResult,
  ConfidentialSessionTimings,
  ProofOutcome,
  ProviderVerification,
} from "./session";
export * from "./errors";
export {
  fetchConfidentialOffer,
  offerAbandonFeeMsat,
  offerSessionFeeMsat,
  verifyConfidentialOffer,
  verifyOfferSignature,
  CONFIDENTIAL_VERSION_MAX,
  CONFIDENTIAL_VERSION_MIN,
} from "./offer";
export type { ConfidentialOffer, ConfidentialPriceEntry, VerifiedOffer } from "./offer";
export { parseSignedReceipt, verifyReceipt } from "./receipt";
export { canonicalJson, npubToHex, verifySchnorrSignature } from "./canonical";
export { canonicalSuffix } from "./suffix";
export { buildPinnedBody, padPinnedBody, chooseBucket, requestedMaxTokens, SseParser, aggregateChatCompletion } from "./request";
export { mintInputFees, NodeApi, NodeApiError } from "./node-api";
export type { BalanceInfo, LightningInvoice, LightningInvoiceStatus, MintFee, NodeModel } from "./node-api";
export { costMsat, formatSats, modelPricing, promptLimit, roughTokens, sessionFeeMsat } from "./pricing";
export type { ModelPricing } from "./pricing";
export { InlineWasmHost, WorkerWasmHost, getDefaultWasmHost, setDefaultWasmHost } from "./wasm/host";
export type { WasmHost } from "./wasm/host";
export { TwoPcSession } from "./twopc";
export { ProofChannel } from "./zkchan";
export { probeProviderTls } from "./diagnostics";
export type { TlsProbeResult } from "./diagnostics";
