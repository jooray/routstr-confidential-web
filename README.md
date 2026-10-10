# routstr-confidential-web

Routstr **confidential mode in the browser**: chat with an LLM through a
routstr node that never sees your prompt or the answer, and never gives you its
provider API key, with every check done by the page itself.

- The TypeScript library at the repository root (`@routstr/confidential-web`, ESM),
  `createConfidentialClient(...)` → `client.chat.completions.create({...,
  stream: true})`, OpenAI-style. It is "routstrd as a library" for confidential
  inference.
- `crates/client-wasm`: the client side of protocol v2 compiled to
  `wasm32-unknown-unknown`. It runs the 2PC handshake (`cu-2pc`) and the
  proof channel (`cu-prover --channel`: verify π_NK, prove π_C2S/π_C3S), plus
  the per-proof fallback.
- The demo app is a separate repository,
  [routstr-confidential-pwa](https://github.com/jooray/routstr-confidential-pwa)
  ([live](https://jooray.github.io/routstr-confidential-pwa/)): a streaming
  chat, a wallet (Lightning, Cashu, refund), signed prices, pre-warming, and a
  panel that shows what your browser verified.

It speaks protocol v2 of
[routstr-confidential](https://github.com/jooray/routstr-confidential), the
two-party handshake with node-only authenticated garbling. It needs no change
on the node. It is tested against the production node
`https://routstr.cypherpunk.today` (provider `api.venice.ai`).

## How it works (one request)

1. **Offer.** The page fetches `GET /v1/confidential/offer`. It verifies the
   BIP-340 signature over the signed payload, checks it against the **pinned
   node key**, and accepts only a **trusted provider host**
   (`api.venice.ai`). Prices, fees and the HTTP head template come from the
   signed bytes only.
2. **Setup.** The page opens a WebSocket to `/v1/confidential/ws` and sends its
   `sk-` key in-band (`setup.auth`, never in a URL or header). It also sends
   the offer signature and any signed fees it accepts. The node reserves the
   worst-case cost.
3. **2PC.** A Web Worker runs the wasm 2PC with the node over
   `/v1/confidential/zk?proof=twopc`. The work is OT preprocessing (about
   1.2 MB up and 22 MB of garbled tables down) followed by a joint P-256 key
   share. Neither side ever knows the ECDHE secret. The proof channel's
   OT/VOLE setup runs alongside over `?proof=zkchan`. A session that is ready
   up to here is **armed** (pre-warmed).
4. **TLS 1.3 to the provider**, from the page, through the node's relay. The
   vendored TLS client (WebCrypto) validates the provider's certificate chain
   to the bundled Mozilla roots and checks the hostname, CertificateVerify and
   Finished. The key schedule comes from the 2PC (phase A, then phase B): the
   page gets `s_ap_0` and `c_ap_1`, and the node gets only `K_0`, the key of
   the record that carries its API key.
5. **π_NK.** The page verifies that the node's credential record is the
   published head template, using a statement it rebuilds from the signed
   offer. Then the node writes that record.
6. **Body.** The page sends the body under `c_ap_1`. The final record is the
   pinned suffix (model, `max_tokens`, `stream`). The node holds that record
   until **π_C2S** proves it is the canonical suffix.
7. **Response.** The answer streams. Every record is AES-GCM-authenticated under
   `s_ap_0`, which only the page holds, and the chunks are handed out as they
   decrypt.
8. **Settlement.** **π_C3S** discloses only the usage event. The page then
   verifies the node-signed attestation and the **signed receipt**: the
   signature, the binding to this session, usage equal to its own plaintext,
   and cost ≤ usage × signed rates + signed fee. A stream ends cleanly only
   after all of these pass. Any failure throws.

The protocol and its security argument are in routstr-confidential:
`docs/TWOPC-DESIGN.md` and `paper/`.

## Security model, and the catch: you trust the code you are served

The protocol protects you from the **node**. The node relays ciphertext and
learns the usage you disclose, not your prompt or the answer. It cannot charge
more than the signed rates without the receipt check failing.

A web page adds a new party: **whoever serves the JavaScript and wasm**. The
page holds your prompt, the session secrets and your key. A malicious or
compromised deploy can ship code that sends them anywhere, and neither the node
nor you would notice. This is the browser version of "verify what you run". The
cryptography is sound only if the code is the audited code.

Recommendations, from weakest to strongest:

- **Separate origin.** Serve the app from a dedicated origin that serves
  nothing else. The demo ships a strict CSP: `script-src 'self'
  'wasm-unsafe-eval'`, no inline scripts, and no third-party code at runtime.
- **SRI / hashes.** These only protect against a compromised CDN, because the
  HTML that carries the hashes comes from the same host.
- **Content-addressed delivery.** Publish each release as an IPFS CID, or as a
  zip of `dist/` with its SHA-256, built reproducibly from a tagged commit, and
  let users open that exact content (an IPFS gateway/companion, or a local
  copy). `version.json` carries an `assets_sha256` over every built file for
  comparison.
- **Signed version manifest.** For the installed PWA, the next step is to sign
  `version.json` with the maintainers' Nostr key. The service worker would
  accept an update only if the signature verifies against the key bundled in
  the previous release (trust on first use). This is not implemented yet: today
  the update check trusts HTTPS to the serving origin.
- **Browser extension.** Store review, signed and pinned code. TLSNotary went
  this way.

Other caveats:

- **The key is a bearer credential.** Your `sk-` key is held in memory, and in
  `localStorage` only if you tick "Remember". Any script running in this origin
  can read it: XSS, a compromised dependency, a malicious update, or a browser
  extension with host access. Keep balances small and withdraw (refund) what
  you do not use.
- **Trust configuration is page configuration.** The node URL, the pinned node
  key and the trusted provider host are shown in the "Node" panel. The
  provider certificate the page validated is shown for every answer.
- **Pre-warming.** An armed session holds a reservation, and the node may keep
  an abandon fee (2 sats on `routstr.cypherpunk.today`) when an armed session
  is never used. The library arms only while the page is visible, the key has
  enough available balance and the user is active, at most one session at a
  time. It does not arm if the abandon fee is above `maxAbandonFeeMsat`
  (default 5 sats). It can be turned off.
- The 2PC has **no external review** yet (see routstr-confidential). The
  client's selective-failure leakage bound is ≤ log2 5 bits per session, about
  fresh single-use values.

## Costs (all read from the signed offer, never hard-coded)

- **Per message**: the provider-reported usage at the offer's signed rates (msat
  per 1k tokens), plus `session_fee_msat` if the node sets one. A typical
  short chat on `deepseek-v4-flash` costs well under 1 sat. Each answer shows
  its exact cost from the signed receipt.
- **Balance needed**: while a request runs, the node reserves its worst case: a
  prompt filling the model's whole context, plus `max_tokens`, plus the fee. It
  releases the unused part at settlement. The app shows this per model; for a
  1M-context model it is about 160 sats.
- **Unused prepared session**: `abandon_fee_msat` (2 sats on the production node).
- **Funding**: Lightning invoices from the node (`/lightning/invoice`; your
  wallet may add routing fees). Cashu tokens can create a key
  (`/v1/balance/create`) or top one up (`/v1/balance/topup`); the mint's
  `input_fee_ppk` applies when the node swaps them, and again on refund. The
  app reads each accepted mint's `/v1/keysets`. **Refund**
  (`/v1/balance/refund`) returns the whole balance as a Cashu token or to a
  Lightning address.
- Node refusals the client maps to messages: **402** (insufficient balance for
  the reservation), **409** (the offer or its fees changed: the library
  refetches and retries once), **429** (3 unused sessions per address), **401**
  (unknown key).

## Library usage

```ts
import { createConfidentialClient } from "@routstr/confidential-web";

const client = createConfidentialClient({
  node: "https://routstr.cypherpunk.today",
  nodePubkeys: ["2ca46ee98f3134c4e11a638663a45983b590bfdefd31588f9c2f03455fba15e7"],
  trustedHosts: ["api.venice.ai"],
  credential: "sk-…",            // or client.setCredential(...) later
  prewarm: true,                 // one armed session while visible + funded
  onEvent: (e) => console.debug(e), // progress events, never secrets
});

const stream = await client.chat.completions.create({
  model: "deepseek-v4-flash",
  messages: [{ role: "user", content: "Hello" }],
  max_tokens: 512,
  stream: true,
});
for await (const chunk of stream) out.textContent += chunk.choices[0]?.delta?.content ?? "";
const v = await stream.verification; // throws if any proof or receipt check failed
console.log(v.provider?.chain[0]?.subject, v.receipt.cost_msats, v.timings);
```

Other entry points: `client.offer()`, `client.pricing(maxTokens)`,
`client.prepare(model, maxTokens)` (pre-warm for the model the user picked),
`client.activity()`, `client.setPrewarm(on)`, `client.api` (balance, Lightning,
Cashu, refund), and `probeProviderTls` (diagnostics). The wasm runs in a module
Worker (`WorkerWasmHost`) by default; pass `host: new InlineWasmHost()` to run
it on the calling thread. The package is consumed as TypeScript source by a
bundler (Vite, esbuild). It needs `new URL(..., import.meta.url)` worker and
wasm asset support, and `optimizeDeps.exclude` for the package in Vite.

## Build

The library is consumed as built ESM (`dist/`: JS + `.d.ts`) plus the wasm in
`wasm/pkg/`. **`wasm/pkg/` is committed**, so a git dependency
(`"@routstr/confidential-web": "github:jooray/routstr-confidential-web#<commit>"`)
works without a Rust toolchain. npm runs `prepare` (`tsc` → `dist/`) on install.

```bash
npm install            # also builds dist/ (prepare)
npm run build          # dist/ again (tsc + the vendored TLS client)
npm run build:wasm     # rebuild wasm/pkg from crates/client-wasm (needs Rust, see below)
```

Rebuilding the wasm needs rustup (the toolchain is pinned in
`rust-toolchain.toml`, 1.97.1 with `wasm32-unknown-unknown`; mpz2 needs rustc
≥ 1.95) and `wasm-bindgen-cli` matching `Cargo.lock`
(`cargo install wasm-bindgen-cli --version 0.2.129 --locked`). `wasm-opt`
comes from the `binaryen` devDependency. `.cargo/config.toml` selects the
getrandom `wasm_js` backend and enables `simd128`, which every evergreen
browser supports (Safari ≥ 16.4). The wasm is 5.98 MB, 1.81 MB gzipped. Commit
`wasm/pkg/` after rebuilding.

**Using it from a bundler.** The worker (`new URL("./worker.js",
import.meta.url)`) and the `.wasm` (`new URL("client_wasm_bg.wasm",
import.meta.url)` in the wasm-bindgen glue) are resolved by the bundler. In
Vite, set `worker: { format: "es" }` and
`optimizeDeps: { exclude: ["@routstr/confidential-web"] }` (see the demo
app's `vite.config.ts`). The page's CSP needs `script-src 'wasm-unsafe-eval'`,
`worker-src 'self'`, and `connect-src` for the node (`https:` and `wss:`).

## Dependencies on routstr-confidential

`crates/vendor/{cu-crypto,twopc,zkbench}` are copies of
`jooray/routstr-confidential@0903e77` (branch `twopc-v2`). The first commit
here is the pristine copy. The second applies the wasm32 patch, which is also
exported as `patches/routstr-confidential-wasm32.patch` with an explanation in
`patches/README.md`, for upstreaming. Once it is upstream, the vendored copies
can become a git dependency on that repository. Later upstream changes are
applied to the vendored copies as they land; `zkbench` currently matches
`twopc-v2@dda9e5c` (plus the wasm32 patch). mpz2 is pinned at the same rev
(`8f89783`) and needed no change. The TS sources `offer.ts`, `receipt.ts`,
`params.ts`, `suffix.ts`, `hosts.ts`, `canonical.ts`, `errors.ts` and the TLS
fork come from routstr-sdk (`confidential-2pc`, commit `2f4aacf`) with
node-only imports replaced. The browser changes to the TLS fork are listed in
`src/tls-fork/FORK-NOTES.md`.

## Tests

```bash
npm test                                             # vitest: offer/receipt/fees/suffix/padding/params/SSE/pricing (33 tests)
cargo test --release -p client-wasm                  # the wasm drivers' logic natively, against the real node side (2PC + proof channel)
cargo test --release -p twopc -p zkbench             # the vendored crates with the patch, natively (unchanged results)
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test --target wasm32-unknown-unknown -p client-wasm --test web   # in Node; add WASM_BINDGEN_USE_BROWSER=1 CHROMEDRIVER=… for headless Chrome

# Local benchmark peer: the node side of the 2PC and proof channel, no credential:
cargo build --release -p bench-node && target/release/bench-node serve --port 7450 &
target/release/bench-node client --runs 3            # native client
node scripts/wasm-node-bench.mjs                     # wasm in Node (V8)
npm run harness:build && node scripts/browser-bench.mjs chromium,firefox,webkit 2   # wasm in headless browsers (Worker)

# Browser TLS stack against the real provider via a test-only WS→TCP relay:
node scripts/ws-tcp-relay.mjs 7451 & node scripts/tls-check.mjs

```

`node scripts/browser-bench.mjs` and `scripts/tls-check.mjs` serve the test
harness (`harness/`, `npm run harness:build`, built from `dist/`). End-to-end
tests against the production node, including the live test with a funded key,
live in the demo app's repository (`scripts/e2e-prod.mjs`).

## Measured timings (M2 Max laptop, loopback, against `bench-node`)

Same driver code, native vs wasm (simd128, wasm-opt -O3, single-threaded, in a
Web Worker). Network time is excluded (loopback): these are compute-bound
numbers. On a real link, preprocessing is dominated by downloading 22 MB of
tables.

| step | native driver | Chrome 153 | Firefox 155 | WebKit 26.6 | Node 26 (V8) |
|---|---|---|---|---|---|
| 2PC preprocessing + key share (cold only) | 0.46 s | 3.0 s | 3.2 s | 3.0 s | 3.2 s |
| phase A (ECtF + GC evaluation + check) | 21 ms | 630 ms | 650 ms | 620 ms | 630 ms |
| phase B (GC evaluation + check) | 25 ms | 750 ms | 780 ms | 740 ms | 756 ms |
| proof channel preprocessing (in parallel with the 2PC) | 0.19 s | 2.9 s | 2.8 s | 2.6–2.9 s | 1.9 s |
| π_NK verify (on the channel) | 64 ms | 82 ms | 95 ms | 85 ms | 85 ms |
| π_C2S prove | 29 ms | 44 ms | 56 ms | 47 ms | 46 ms |
| π_C3S prove | 60 ms | 93 ms | 113 ms | 92 ms | 93 ms |
| wasm instantiate (5.98 MB, cached) | — | 26 ms | 120 ms | 29 ms | — |

Traffic per 2PC session: 1.21 MB up, 22.1 MB down. simd128 gave about −20 %
preprocessing and −30 % proof time; phases A/B are bound by software AES
(no AES instructions in wasm) and did not change. Without simd128
(Node): preprocessing 3.8 s, proofs 80–160 ms.

What this means for a request: in a pre-warmed session, the browser adds about
1.4 s to the request path (phases A + B) compared with native's ~50 ms, plus
about 0.2 s for the three proofs. A cold request also pays the preprocessing
(about 3 s of wasm CPU here, overlapped with the 22 MB download).

## Layout

```
src/                    the TypeScript library (client, session, offer/receipt/params, wasm hosts, TLS fork)
test/                   vitest unit tests
wasm/pkg/               wasm-bindgen output (committed)
dist/                   built library (npm prepare; not committed)
crates/client-wasm      wasm-bindgen crate: TwoPcClient, ProofChannelClient, ProverJob (+ native and wasm tests)
crates/bench-node       local node-side peer for benchmarks/tests (native)
crates/vendor/*         routstr-confidential crates (pristine + wasm32 patch)
harness/                browser benchmark + TLS diagnostic page (tests only)
scripts/                build-wasm.sh, build-lib.mjs, benches, test relay
patches/                the wasm32 patch for upstream
```

## License

MIT (see `LICENSE`). The vendored TLS client is MIT (CreatorOS Inc.,
`src/tls-fork/LICENSE`).
