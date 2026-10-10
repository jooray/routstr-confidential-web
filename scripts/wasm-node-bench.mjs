// Runs the wasm client drivers (crates/client-wasm) in Node's V8 against a
// local `bench-node serve` (no credential, no provider): 2PC preprocessing,
// key share, phase A, phase B, then the proof channel and the three proofs.
//   cargo run --release -p bench-node -- serve &   (or target/release/bench-node serve)
//   node scripts/wasm-node-bench.mjs [ws://127.0.0.1:7450] [runs]
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const base = process.argv[2] ?? "ws://127.0.0.1:7450";
const runs = Number(process.argv[3] ?? 2);
const pkg = new URL("../wasm/pkg/", import.meta.url);
const wasm = await import(new URL("client_wasm.js", pkg));
await wasm.default({ module_or_path: await readFile(fileURLToPath(new URL("client_wasm_bg.wasm", pkg))) });

function connect(path, make) {
  const ws = new WebSocket(base + path);
  ws.binaryType = "arraybuffer";
  const events = [];
  let waiter;
  const outbox = [];
  let open = false;
  const drv = make((ch, data) => {
    if (ch === 0) open ? ws.send(data) : outbox.push(data.slice());
    else {
      const m = JSON.parse(new TextDecoder().decode(data));
      events.push(m);
      waiter?.();
    }
  });
  ws.onopen = () => { open = true; for (const b of outbox) ws.send(b); };
  ws.onmessage = (ev) => drv.push(0, new Uint8Array(ev.data));
  const cmd = (o) => drv.push(1, new TextEncoder().encode(JSON.stringify(o)));
  const wait = async (ev, steps) => {
    for (;;) {
      while (events.length) {
        const m = events.shift();
        if (m.ev === ev) return m;
        if (m.ev === "error") throw new Error(m.msg);
        if (m.ev === "timing" && steps) steps.push([m.step, Math.round(m.ms)]);
      }
      await new Promise((r) => (waiter = r));
    }
  };
  return { ws, drv, cmd, wait };
}

const params = await new Promise((res) => {
  const ws = new WebSocket(base + "/params");
  ws.onmessage = (ev) => { res(JSON.parse(ev.data)); ws.close(); };
});
const fixtures = JSON.parse(wasm.fixturesV2());

for (let i = 0; i < runs; i++) {
  const t0 = performance.now();
  const steps = [];
  const tp = connect("/twopc", (cb) => new wasm.TwoPcClient(cb));
  const zk = connect("/zkchan", (cb) => new wasm.ProofChannelClient(cb, 0, 0));
  await tp.wait("key_share", steps);
  const tKs = performance.now() - t0;
  let t = performance.now();
  tp.cmd({ cmd: "handshake", s: params.s, th_sh: params.th_sh });
  await tp.wait("hs", steps);
  const tA = performance.now() - t;
  t = performance.now();
  tp.cmd({ cmd: "app", th_sf: params.th_sf });
  await tp.wait("ap", steps);
  const tB = performance.now() - t;
  const ready = await zk.wait("ready");
  const tZ = performance.now() - t0;
  const proofs = {};
  let id = 0;
  for (const f of fixtures) {
    t = performance.now();
    const verify = f.proof === "pi_nk";
    zk.cmd({ cmd: verify ? "verify" : "prove", id: ++id, proof: f.proof, params: f.params, witness: verify ? null : f.witness });
    const d = await zk.wait("done");
    if (!d.ok) throw new Error(`${f.proof}: ${d.err}`);
    proofs[f.proof] = Math.round(performance.now() - t);
  }
  zk.cmd({ cmd: "close" });
  setTimeout(() => { tp.ws.close(); zk.ws.close(); }, 300);
  console.log(JSON.stringify({ run: i, runtime: "wasm/node-v8", key_share_ms: Math.round(tKs), phase_a_ms: Math.round(tA), phase_b_ms: Math.round(tB), zkchan_ready_ms: Math.round(tZ), zkchan_steps: ready.timings.map((s) => [s.step, Math.round(s.ms)]), proofs, steps }));
}
process.exit(0);
