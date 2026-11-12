/**
 * @routstr/confidential-web — routstr confidential mode (protocol v3) in the
 * browser. See README.md for the security model.
 */

export {
  createConfidentialClient,
  ConfidentialClient,
  chooseFraming,
  http2OpenFailure,
  imageRequestCostMsat,
  isOfferExpired,
  meteredConnection,
  Prewarmer,
  PREWARM_DEFAULTS as CLIENT_PREWARM_DEFAULTS,
} from "./client.js";
export type {
  ChatCompletion,
  ChatCompletionChunk,
  ChatCompletionCreateParams,
  ConfidentialClientOptions,
  ConfidentialStream,
  ImageGenerateParams,
  ImageGenerateResult,
  PrewarmOptions,
} from "./client.js";
export {
  base64ToBytes,
  buildImageBody,
  chooseImageVariant,
  IMAGE_SELECTOR_KEYS,
  ImageRequestError,
  planImageRequest,
  resolutionFromSize,
  imageMimeType,
  imageSuffix,
  pinnedImageKeys,
  renderImageSuffix,
  responseImages,
  toOpenAiImages,
} from "./images.js";
export type { PlannedImageRequest } from "./images.js";
export { ConfidentialConnection, connectionTerms, DEFAULT_MAX_CONNECTION_DEPOSIT_MSAT } from "./connection.js";
export type {
  ConfidentialConnectionOptions,
  ConnectionBytes,
  ConnectionPhase,
  ConnectionRequestHandle,
  ConnectionRequestOptions,
  ConnectionRequestResult,
  DepositOutcome,
  ProofTiming,
} from "./connection.js";
export { ConnectionPool, FRAMING_BAD_MS, HTTP2_DEFAULTS, PREWARM_DEFAULTS, poolIdleMs, poolKey } from "./pool.js";
export type { Http2Options, PoolLease } from "./pool.js";
export { requestResult } from "./result.js";
export type {
  CertificateInfo,
  ConfidentialDepositInfo,
  ConfidentialReceipt,
  ConfidentialRequestResult,
  ConfidentialSessionResult,
  ConfidentialTimings,
  ProofOutcome,
  ProviderVerification,
  TimingSpan,
} from "./result.js";
export * from "./errors.js";
export {
  CONFIDENTIAL_FRAMINGS,
  CONFIDENTIAL_TWOPC,
  CONFIDENTIAL_VERSION,
  CONFIDENTIAL_VERSION_MAX,
  CONFIDENTIAL_VERSION_MIN,
  fetchConfidentialOffer,
  imageCountKey,
  imageCountKeyForRoute,
  imagesOfferProblem,
  offerAbandonFeeMsat,
  offerConnectionDepositMsat,
  offerFramings,
  offerFramingsFor,
  offerIdleTimeoutS,
  offerImages,
  offerReserveMarginTokens,
  offerSessionFeeMsat,
  offerSupportsHttp2,
  offerSupportsHttp2Images,
  offerSupportsImages,
  validateImagesOffer,
  verifyConfidentialOffer,
  verifyOfferSignature,
} from "./offer.js";
export type {
  ConfidentialFraming,
  ConfidentialH2Offer,
  ConfidentialImagesOffer,
  ConfidentialImageVariant,
  ConfidentialOffer,
  ConfidentialPriceEntry,
  ImagePin,
  VerifiedOffer,
} from "./offer.js";
export { checkH2Offer, checkPiNKParamsH2, checkPiWinFinalRecord, checkPiWinParams, errorHeadPrefixProblem, FrameReader, requestBlock, splitBody } from "./h2.js";
export { checkPiC3SParams, checkPiNKParams, headRouteProblem, headTemplateProblem } from "./params.js";
export { checkUpstreamErrorReceipt, maxChargeMsats, parseSignedReceipt, verifyFlatReceipt, verifyReceipt } from "./receipt.js";
export { canonicalJson, npubToHex, verifySchnorrSignature } from "./canonical.js";
export { canonicalSuffix, MAX_BODY_LEN, padBody, paddedBodyLength, type PadBucket } from "./suffix.js";
export { buildPinnedBody, requestedMaxTokens, SseParser, aggregateChatCompletion } from "./request.js";
export { mintInputFees, NodeApi, NodeApiError } from "./node-api.js";
export type { BalanceInfo, LightningInvoice, LightningInvoiceStatus, MintFee, NodeModel } from "./node-api.js";
export { costMsat, formatSats, modelPricing, promptLimit, reservationMsat, roughTokens, sessionFeeMsat } from "./pricing.js";
export type { ModelPricing } from "./pricing.js";
export { InlineWasmHost, WorkerWasmHost, getDefaultWasmHost, setDefaultWasmHost } from "./wasm/host.js";
export type { WasmHost } from "./wasm/host.js";
export { TwoPcSession } from "./twopc.js";
export { ProofChannel, type ProofChannelTopup } from "./zkchan.js";
export { probeProviderTls } from "./diagnostics.js";
export type { TlsProbeResult } from "./diagnostics.js";
