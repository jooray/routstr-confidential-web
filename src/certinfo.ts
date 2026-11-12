/** What the page shows of the provider's certificate path, as the TLS client verified it. */

import { hex, sha256 } from "./bytes.js";

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
  /** The ALPN protocol the connection offered and the node required: `h2` (framing "2") or `http/1.1`. */
  alpn?: string;
}

function b64(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

/** Read what we show from a verified certificate (@peculiar/x509 object). */
export function certInfo(cert: { internal: any; getAlternativeDNSNames(): string[] }, anchor: boolean): CertificateInfo {
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
