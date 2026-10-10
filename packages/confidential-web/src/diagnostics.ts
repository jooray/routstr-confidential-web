/**
 * Diagnostics: run the vendored TLS client in this browser against a provider
 * through a plain WebSocket→TCP relay (test setups only; the confidential
 * session never uses one: the node relays and the key schedule is joint).
 * Exercises what the confidential session relies on in the browser:
 * WebCrypto, the bundled Mozilla roots, RFC 5280 path validation, the
 * hostname check and TLS 1.3 records.
 */

import { concat, sha256, hex } from "./bytes";
import { matchHostname } from "./hosts";
import { makeTLSClient } from "./tls-fork/lib/index.js";
import { setCryptoImplementation } from "./tls-fork/lib/crypto/index.js";
import { webcryptoCrypto } from "./tls-fork/lib/crypto/webcrypto.js";

setCryptoImplementation(webcryptoCrypto);

export interface TlsProbeResult {
  ok: boolean;
  host: string;
  chain: { subject: string; issuer: string; notAfter: string; spkiSha256: string }[];
  hostnameMatched?: string;
  cipherSuite?: string;
  httpStatusLine?: string;
  ms: number;
  error?: string;
}

/** `relayUrl` must forward the WebSocket's binary messages to host:443 and back. */
export function probeProviderTls(relayUrl: string, host: string, path = "/", timeoutMs = 20_000): Promise<TlsProbeResult> {
  const t0 = performance.now();
  return new Promise((resolve) => {
    const ws = new WebSocket(relayUrl);
    ws.binaryType = "arraybuffer";
    const result: TlsProbeResult = { ok: false, host, chain: [], ms: 0 };
    let response: Uint8Array = new Uint8Array(0);
    const done = (error?: string) => {
      result.ms = Math.round(performance.now() - t0);
      if (error) result.error = error;
      try {
        ws.close();
      } catch {
        /* ignore */
      }
      resolve(result);
    };
    const timer = setTimeout(() => done("timeout"), timeoutMs);
    const tls = makeTLSClient({
      host,
      verifyServerCertificate: true,
      cipherSuites: ["TLS_AES_128_GCM_SHA256"],
      supportedProtocolVersions: ["TLS1_3"],
      namedCurves: ["SECP256R1"],
      applicationLayerProtocols: ["http/1.1"],
      write: (p: { header: Uint8Array; content: Uint8Array }) => ws.send(concat(p.header, p.content)),
      onRead: () => {},
      onRecvCertificates: ({ certificates, verifiedPath }: { certificates: any[]; verifiedPath?: any[] }) => {
        const path = verifiedPath ?? certificates;
        result.hostnameMatched = path[0]?.getAlternativeDNSNames().find((n: string) => matchHostname(host, n));
        result.chain = path.map((c: any) => ({
          subject: String(c.internal.subject),
          issuer: String(c.internal.issuer),
          notAfter: new Date(c.internal.notAfter).toISOString(),
          spkiSha256: hex(sha256(new Uint8Array(c.internal.publicKey.rawData))),
        }));
      },
      onHandshake: () => {
        result.cipherSuite = tls.getMetadata?.().cipherSuite;
        void tls.write(new TextEncoder().encode(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`));
      },
      onApplicationData: (d: Uint8Array) => {
        response = concat(response, d);
        const s = new TextDecoder().decode(response.subarray(0, 200));
        const nl = s.indexOf("\r\n");
        if (nl > 0 && !result.httpStatusLine) {
          result.httpStatusLine = s.slice(0, nl);
          result.ok = true;
          clearTimeout(timer);
          done();
        }
      },
      onTlsEnd: (e?: Error) => {
        if (!result.ok) {
          clearTimeout(timer);
          done(e?.message ?? "TLS ended");
        }
      },
      logger: { trace: () => {}, debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
    });
    ws.onopen = () => {
      tls.startHandshake().catch((e: Error) => {
        clearTimeout(timer);
        done(e.message);
      });
    };
    ws.onmessage = (ev) => {
      tls.handleReceivedBytes(new Uint8Array(ev.data as ArrayBuffer)).catch((e: Error) => {
        clearTimeout(timer);
        done(e.message);
      });
    };
    ws.onerror = () => {
      clearTimeout(timer);
      done("relay websocket error");
    };
  });
}
