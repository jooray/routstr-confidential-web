/**
 * Per-proof fallback: one proof over its own `/v1/confidential/zk?proof=…`
 * connection (the wasm build of `cu-prover --job-stdin`). Used only when the
 * session's proof channel failed before any proof started on it.
 */

import { ProverError } from "./errors.js";
import { DriverRelay } from "./relay.js";
import type { WasmHost } from "./wasm/host.js";

export interface ZkJob {
  proof: string;
  role: "prover" | "verifier";
  params: unknown;
  witness?: unknown;
}

export class WasmProverBackend {
  constructor(
    private readonly host: WasmHost,
    private readonly timeoutMs = 60_000,
    private readonly webSocketImpl?: typeof WebSocket,
  ) {}

  async run(zkUrl: string, job: ZkJob, timeoutMs = this.timeoutMs): Promise<void> {
    const jobBytes = new TextEncoder().encode(
      JSON.stringify({ proof: job.proof, role: job.role, params: job.params, witness: job.witness ?? null }),
    );
    let relay: DriverRelay | undefined;
    let done = false;
    try {
      await new Promise<void>((resolve, reject) => {
        const t = setTimeout(() => reject(new ProverError(`zk timeout (${timeoutMs}ms) for ${job.proof}`)), timeoutMs);
        relay = new DriverRelay({
          host: this.host,
          kind: "job",
          driverOptions: { job: jobBytes },
          url: zkUrl,
          webSocketImpl: this.webSocketImpl,
          label: `zk ${job.proof}`,
          closeIsNormal: () => done,
          onFailure: (e) => {
            clearTimeout(t);
            reject(e);
          },
          onEvent: (m) => {
            if (m.ev !== "done") return;
            done = true;
            clearTimeout(t);
            const checks = (m.checks as { ok: boolean }[] | undefined) ?? [];
            // The verifier must report checks: none at all verified nothing.
            const checked = job.role !== "verifier" || checks.length > 0;
            if (m.ok === true && checked && checks.every((c) => c.ok)) resolve();
            else reject(new ProverError(`${job.proof} failed: ${String(m.err ?? "checks failed")}`));
          },
        });
        relay.start().catch(reject);
      });
    } finally {
      jobBytes.fill(0);
      relay?.close(500);
    }
  }
}
