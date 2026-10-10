/**
 * Browser benchmark of the wasm client against `bench-node serve` (no node,
 * no credential, no provider): 2PC preprocessing + key share, phase A, phase
 * B, proof channel preprocessing and the three proofs, all in the Worker the
 * library uses. Results go to `window.__bench` (read by scripts/browser-bench.mjs).
 */
import { probeProviderTls, ProofChannel, TwoPcSession, WorkerWasmHost } from "../../dist/index.js";

const q = new URLSearchParams(location.search);
const node = q.get("node") ?? "ws://127.0.0.1:7450";
const runs = Number(q.get("runs") ?? 2);
const out = document.getElementById("out")!;
const w = window as unknown as { __bench?: unknown; __benchError?: string };

async function main(): Promise<void> {
  const host = new WorkerWasmHost();
  const tLoad = performance.now();
  await host.ready();
  const loadMs = performance.now() - tLoad;
  const fixtures = JSON.parse(await host.fixtures()) as { proof: string; params: unknown; witness: unknown }[];
  const params = await new Promise<{ s: string; th_sh: string; th_sf: string }>((res, rej) => {
    const ws = new WebSocket(`${node}/params`);
    ws.onmessage = (ev) => res(JSON.parse(String(ev.data)));
    ws.onerror = () => rej(new Error(`cannot reach ${node}`));
  });
  const fromHex = (s: string) => new Uint8Array(s.match(/../g)!.map((x) => parseInt(x, 16)));
  const results: unknown[] = [];
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    const tp = new TwoPcSession(host);
    tp.start(`${node}/twopc`);
    const zk = new ProofChannel(host);
    zk.start(`${node}/zkchan`);
    await tp.keyShare(180_000);
    const keyShare = performance.now() - t0;
    let t = performance.now();
    await tp.handshake(fromHex(params.s), fromHex(params.th_sh), 60_000);
    const phaseA = performance.now() - t;
    t = performance.now();
    await tp.application(fromHex(params.th_sf), 60_000);
    const phaseB = performance.now() - t;
    if (!(await zk.ready(180_000))) throw new Error(`proof channel: ${zk.failure?.message}`);
    const zkReady = performance.now() - t0;
    const proofs: Record<string, number> = {};
    for (const f of fixtures) {
      t = performance.now();
      const verify = f.proof === "pi_nk";
      await zk.run(verify ? "verify" : "prove", f.proof, f.params, verify ? undefined : f.witness);
      proofs[f.proof] = Math.round(performance.now() - t);
    }
    zk.close();
    tp.close();
    const r = {
      run: i,
      runtime: `wasm/${navigator.userAgent.match(/(Firefox|Chrome|Version)\/[\d.]+/)?.[0] ?? "browser"}`,
      wasm_load_ms: i === 0 ? Math.round(loadMs) : undefined,
      key_share_ms: Math.round(keyShare),
      phase_a_ms: Math.round(phaseA),
      phase_b_ms: Math.round(phaseB),
      zkchan_ready_ms: Math.round(zkReady),
      zkchan_steps: zk.timings.map((s) => [s.step, Math.round(s.ms)]),
      proofs,
      steps: tp.timings.map((s) => [s.step, Math.round(s.ms)]),
      bytes: tp.bytes,
    };
    results.push(r);
    out.textContent = results.map((x) => JSON.stringify(x)).join("\n");
  }
  w.__bench = results;
}

const tlsRelay = q.get("tls");
if (tlsRelay) {
  // TLS diagnostic: the vendored TLS client against the real provider via a
  // local WS→TCP relay (scripts/ws-tcp-relay.mjs).
  probeProviderTls(tlsRelay, q.get("host") ?? "api.venice.ai", "/api/v1/models").then((r) => {
    (window as unknown as { __tls?: unknown }).__tls = r;
    out.textContent = JSON.stringify(r, null, 2);
  });
} else main().catch((e: unknown) => {
  w.__benchError = e instanceof Error ? e.message : String(e);
  out.textContent = `error: ${w.__benchError}`;
});
