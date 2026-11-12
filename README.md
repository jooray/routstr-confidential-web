# routstr-confidential-web

Routstr **confidential mode in the browser**: chat with an LLM through a
routstr node that never sees your prompt or the answer, and never gives you its
provider API key, with every check done by the page itself.

Introduction: [Confidential inference on Routstr without trusted hardware](https://juraj.bednar.io/en/blog-en/2026/10/10/confidential-inference-on-routstr-without-trusted-hardware/)
(blog post).

For more depth, there is a programmer's guide, [How routstr confidential mode works](https://juraj.bednar.io/wp-content/uploads/2026/10/routstr-confidential-for-programmers.pdf) (PDF, 72 pages; in Slovak: [Ako funguje dôverný režim routstr](https://juraj.bednar.io/wp-content/uploads/2026/10/routstr-confidential-pre-programatorov.pdf)), and a gentler explanation of the protocol as a magic show, [Seven magic tricks inside one AI request](https://juraj.bednar.io/en/blog-en/2026/10/12/seven-magic-tricks-inside-one-ai-request/), with an illustrated video (in Slovak: [Sedem kúzelníckych trikov v jednej AI požiadavke](https://juraj.bednar.io/blog/2026/10/12/sedem-kuzelnickych-trikov-v-jednej-ai-poziadavke/)).

- The TypeScript library at the repository root (`@routstr/confidential-web`, ESM),
  `createConfidentialClient(...)` → `client.chat.completions.create({...,
  stream: true})`, OpenAI-style. It is "routstrd as a library" for confidential
  inference.
- `crates/client-wasm`: the client side of protocol v3 compiled to
  `wasm32-unknown-unknown`. It runs the two-party key schedule
  (`cu-2pc`, `split-public-1`) and the proof channel (`cu-prover --channel`:
  verify π_NK, prove π_WIN and π_C3S), plus the per-proof fallback.
- The demo app is a separate repository,
  [routstr-confidential-pwa](https://github.com/jooray/routstr-confidential-pwa)
  ([live](https://jooray.github.io/routstr-confidential-pwa/)): a streaming
  chat, a wallet (Lightning, Cashu, refund), signed prices, pre-warming, and a
  panel that shows what your browser verified.

It speaks protocol v3 of
[routstr-confidential](https://github.com/jooray/routstr-confidential)
(`PROTOCOL-V3.md` there): a **connection** that carries **requests**, the
two-party key schedule `split-public-1` (node-only authenticated garbling,
16.4 MB of tables down instead of v2's 22.1 MB), and two framings towards the
provider: `"2"` (HTTP/2, many requests on one connection and one 2PC) and
`"1.1"` (one request per connection). It needs a v3 node: a v2 node's offer
is refused as `node_protocol_outdated`, and a v3 node answers a v2 client with
426 `upgrade_required` (routstr.cypherpunk.today runs v3). Tested against a local
v3 node and sidecar on the real provider (`api.venice.ai`; `scripts/live-v3.mjs`, `scripts/browser-live-v3.mjs`).

## How it works (one connection, its requests)

1. **Offer.** The page fetches `GET /v1/confidential/offer?v=3`. It verifies the
   BIP-340 signature over the signed payload, checks it against the **pinned
   node key**, and accepts only a **trusted provider host**
   (`api.venice.ai`), `v = 3`, the key schedule `split-public-1`, the framings
   it knows (`http`, the operator's order) and an `h2` block in range. Prices,
   fees, the connection deposit and the head templates come from the signed
   bytes only.
2. **Framing.** `http: "auto"` (default) takes the offer's first framing; a
   framing-`"2"` connection that fails to open falls back to `"1.1"` on the
   same node for 10 minutes. `http: "1.1"` turns HTTP/2 off.
3. **Setup.** The page opens a WebSocket to `/v1/confidential/ws?…&v=3` and
   sends its `sk-` key in-band (`setup.auth`, never in a URL or header) and the
   offer signature. The node reserves the **connection deposit** (nothing about
   a request yet). A deposit above `maxConnectionDepositMsat` (default
   100 sats) is refused before anything is sent.
4. **2PC.** A Web Worker runs the wasm 2PC with the node over
   `/v1/confidential/zk?proof=twopc` (version tag `routstr-2pc/split-public-1`
   first; another tag is `twopc_version_mismatch`): OT preprocessing (about
   1.1 MB up, 16.4 MB down) and the joint P-256 key share. The proof channel's
   OT/VOLE setup runs alongside (`?proof=zkchan`). A connection ready up to
   here is **armed**: it holds the deposit and no provider connection.
5. **TLS 1.3 to the provider**, from the page, through the node's relay: the
   canonical ClientHello with the joint share and ALPN `h2` or `http/1.1`. The
   vendored TLS client (WebCrypto) validates the provider's certificate chain
   to the bundled Mozilla roots and checks the hostname, CertificateVerify and
   Finished; it accepts application data only after the handshake and no
   plaintext record once TLS 1.3 keys are installed. The key schedule runs in
   five stages; the page gets `s_ap_0` and `c_ap_1`, the node only `K_0`.
6. **π_NK.** The page verifies that the node's epoch-0 record is the head it
   rebuilt from the signed offer: framing `"2"` the HTTP/2 connection head
   (preface, SETTINGS, the probe request that puts the credential into the
   provider's HPACK table), framing `"1.1"` the request head of request 1.
7. **Requests.** `request` n (model, `max_tokens` or the image variant and
   count, the body length, the credential, the offer signature): the node
   reserves the request's worst case and answers `request_ok`, or
   `request_refused` (402, 409 …), which leaves the connection as it was. The
   page sends the body (framing `"2"`: one HTTP/2 frame per TLS record, DATA
   frames under the provider's flow control; `"1.1"`: the suffix alone in the
   final record) and proves with **π_WIN** that every record is what it must
   be: the node checks each window against its own relay buffer, the page
   checks every window against its own plaintext before proving.
8. **Response and settlement.** The answer streams, authenticated under
   `s_ap_0`. **π_C3S** discloses only the usage event (an image is settled by
   `accept` at the flat price; an error head by π_WIN or π_C3S). The page
   verifies the node-signed attestation (connection, request, stream, the
   server records of the request's interval and our own records) and the
   **signed receipt**: its binding (`sid`, `http`, `n`), usage equal to our
   plaintext, cost ≤ usage × signed rates + the session fee still due on the
   connection, and the deposit released with the connection's first
   settlement. A stream ends cleanly only after all of these pass.
9. **Next request.** Framing `"2"`: the connection goes back to the pool and
   the next request runs on it (no 2PC, no π_NK) until the node's idle limit,
   `h2.max_requests` or `h2.max_lifetime_s`. While it idles (after the head and
   after each settled request) the page asks the node to **top up the proof
   channel** (one Ferret step, about 0.6 MB from the node, granted only while
   the chain holds less than one request's worth), so the next request's proofs
   use preprocessed correlations and its download is about what the request
   needs (PROTOCOL-V3.md §9.2). A request that starts during a top-up waits for
   it (about 0.9 s in wasm). Framing `"1.1"`: the connection ends after its
   request.

An error head is disclosed from byte 0 of the record that holds the response
HEADERS frame; the frames before it in that record may only be ones that carry
nothing of the page's (stream-0 SETTINGS, PING, GOAWAY, WINDOW_UPDATE on stream
0 or the request's stream, the node's probe stream). A long body is proven in
as many π_WIN batches as the node asks for, and the page never sends an HTTP/2
WINDOW_UPDATE of its own. A request refused with `offer_expired` is sent again
with the same number after the offer is refetched; `offer_changed` closes the
connection and the request opens a new one. A connection the node closes
(`closed`, any reason, `evicted` included) leaves the pool.

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
- **Trust configuration is page configuration.** The node URL (https; plain
  http only for loopback or an onion service), the pinned node
  key and the trusted provider host are shown in the "Node" panel. The
  provider certificate the page validated is shown for every answer.
- **Linkability.** Requests on one framing-`"2"` connection share a TLS
  connection to the provider, which can tell they come from one client (as
  requests under one API key already are). `reuseScope` separates what must
  not be linked; `http2.reuse: "none"` opens a connection per request (and a
  connection kept before reuse was turned off is never handed out again).
- **Body size.** The body length is exact unless `padBucket` is set (a
  multiple of N bytes, or `"pow2"`): the body is then padded with JSON
  whitespace before the pinned suffix. Off by default; it hides the size from
  observers of the connections and the provider, not from the node (which
  learns the token count at settlement), and costs upload.
- **Pre-warming.** An armed connection holds the connection deposit and is
  bound to the credential only; the node keeps the deposit when an armed
  connection is never used. The library arms only after a first settled chat
  request with the current key, and then only while the page is visible, the
  user is active and the key's available balance covers the deposit plus one
  reservation, at most one armed connection at a time. Framing `"2"`: one is
  armed when the key has no open connection (its last one was closed idle)
  or every open one is busy. It does not arm if the deposit is above
  `maxDepositMsat` (default 5 sats). A failed arm backs off (30 s, doubling to
  10 min). Hiding the page closes the armed connection, and showing it again
  arms nothing until the next activity or request. It does not arm on a
  metered connection (`navigator.connection.saveData`, or a cellular link
  where the browser reports one) unless `allowMetered` is set. It can be
  turned off.
- **Stopping an answer.** An abort before the request body is released closes
  the connection (the node keeps the deposit if the connection settled nothing
  yet, else at most the abandon fee). After release the provider already has
  the request, so an abort only ends the caller's stream: the request drains
  in the background (capped by the pinned `max_tokens`) and settles on the
  usage the provider reported, and `verification` still resolves with its
  receipt. Closing it would cost the whole reservation.
- The 2PC and π_WIN have **no external review** yet (see routstr-confidential).
  A cheating node learns at most log2 8 = 3 bits per connection about fresh,
  single-use values.

## Costs (all read from the signed offer, never hard-coded)

- **Per message**: the provider-reported usage at the offer's signed rates (msat
  per 1k tokens), plus `session_fee_msat` **once per connection** (at its
  first settlement). Each answer shows its exact cost from the signed receipt.
- **Connection deposit** (`connection_deposit_msat`): reserved at a
  connection's setup, released by its first settled request (the receipt says
  `deposit_released_msat`), kept when the connection ends without one (an
  unused armed connection, a request abandoned before release). A failure of
  the node, its sidecar or the provider releases it; the node signs the
  outcome in the connection's last frame.
- **Balance needed**: while a request runs, the node reserves its worst case: a
  prompt filling the model's whole context (the larger context length, at the
  dearer of the input and cache-write rates), plus `max_tokens`, plus the fee.
  A new connection needs that plus the deposit (`ModelPricing.requiredMsat`).
- **Funding**: Lightning invoices from the node (`/lightning/invoice`; your
  wallet may add routing fees). Cashu tokens can create a key
  (`/v1/balance/create`) or top one up (`/v1/balance/topup`); the mint's
  `input_fee_ppk` applies when the node swaps them, and again on refund. The
  app reads each accepted mint's `/v1/keysets`. **Refund**
  (`/v1/balance/refund`) returns the whole balance as a Cashu token or to a
  Lightning address.
- Node refusals the client maps to typed errors: `RequestRefusedError` (402
  insufficient balance for a request's reservation, 409 `offer_expired` /
  `offer_changed`: the library refetches the offer and retries once),
  `ConnectionDepositError` (the deposit is not funded, or above the maximum),
  `NodeProtocolOutdatedError` (a v2 node), `UpgradeRequiredError` (426),
  `TwoPcVersionMismatchError`.

## Library usage

```ts
import { createConfidentialClient } from "@routstr/confidential-web";

const client = createConfidentialClient({
  node: "https://routstr.cypherpunk.today",
  nodePubkeys: ["2ca46ee98f3134c4e11a638663a45983b590bfdefd31588f9c2f03455fba15e7"],
  trustedHosts: ["api.venice.ai"],
  credential: "sk-…",            // or client.setCredential(...) later
  http: "auto",                  // or "2", or "1.1" (HTTP/2 off); client.setHttp(...) later
  prewarm: true,                 // after a first request: one armed connection while visible + funded
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
console.log(v.framing, v.n, v.connection, v.deposit, v.bytes, v.ttftMs, v.receipt.cost_msats, v.provider?.alpn);
```

### Images

When the node's signed offer lists `capabilities: ["chat", "images"]`, the same
client generates images confidentially: the node sees the model, the priced
variant (resolution tier, format) and the count, but not the prompt, the
private options or the image.

```ts
const offer = await client.images.offer();         // undefined: the node offers no images
const r = await client.images.generate({
  model: "qwen-image-2-1-turbo",
  prompt: "A lighthouse at dusk, oil painting",
  count: 1,                  // 1..offer.max_count (4)
  resolution: "1K",          // or variant: "1K-webp"; chooses a signed variant
  aspectRatio: "16:9",       // private, like seed, negative_prompt, safe_mode
});
img.src = URL.createObjectURL(r.images[0]);        // image/webp
console.log(r.msatPerImage, r.costMsats, r.confidential.receipt);
```

- **Price**: flat, `msat_per_image × count` (+ the session fee) from the signed
  offer's `images.price_list` (`imageRequestCostMsat(offer, variant, count)`
  computes it up front). No usage proof runs on success: after the attestation
  the client sends `accept`, and the receipt must charge exactly that amount
  (`kind: "images"`, `variant`, `count`, `msat_per_image`).
- **Short answers**: the request is paid once accepted, so a problem with the
  answer is reported, not thrown: `r.warnings` lists fewer images than asked
  for, an incomplete body, or a provider echo naming another model or count.
- **Errors**: a node without images throws `offer_no_images`, and a malformed
  image block in its offer `offer_malformed` (chat keeps working). A provider
  HTTP error throws `UpstreamImageError` (`.status`, `.result` with the
  verified receipt); a rejected request (4xx but 429) costs the abandon fee, a
  429 or 503 the session fee, as for chat.
- **What the node may pin**: the client takes only fixed pins that switch a
  provider extra off (`false`, `[]`) and variant pins on the price tiers
  (`resolution`, `quality`, `format`, values from the offer's `param_space`),
  and a head template on the image route with exactly the expected headers;
  anything else refuses the image block.
- **Framing**: on a framing-`"2"` connection when the offer's `h2.kinds` lists
  images (it then reuses a connection a chat request left), else on a
  connection of its own. Image requests never arm a connection in advance.

Other entry points: `client.offer()`, `client.pricing(maxTokens)` (rates,
reservation, deposit, `requiredMsat`), `client.framing()`, `client.setHttp()`,
`client.connections()` (the pool, no credentials), `client.prepare(model,
maxTokens)`, `client.activity()`, `client.setPrewarm(on)`, `client.api`
(balance, Lightning, Cashu, refund), `ConfidentialConnection` and
`ConnectionPool` for callers that manage connections themselves, and
`probeProviderTls` (diagnostics). The wasm runs in a module
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
browser supports (Safari ≥ 16.4). The wasm is 5.97 MB, 1.83 MB gzipped. Commit
`wasm/pkg/` after rebuilding.

**Checking the committed wasm.** The build is meant to be byte-reproducible:
`build-wasm.sh` remaps host paths (the checkout and `CARGO_HOME`) out of the
binary, enforces `Cargo.lock` and uses the pinned `wasm-opt`. Rebuilding the
same tree from another checkout path and an empty target directory on the
same host platform gives the same bytes. The reference platform is
x86_64-linux (CI's `ubuntu-24.04`): the committed `wasm/pkg` is that build.
rustc's crate hashes and some codegen depend on the host, so a macOS build of
the same tree is functionally the same but not byte-identical; to check the
committed files, rebuild on x86_64 Linux (or in a container). `buildInfo()` (exposed by the wasm and shown by the demo app)
names the upstream commit, the mpz2 rev and `src:<digest>`, a SHA-256 over
every source file that goes into the wasm; `node scripts/source-digest.mjs`
recomputes it from a checkout and `--check` fails if `wasm/pkg` was not built
from that tree. CI (`.github/workflows/wasm.yml`) runs the digest check and the
tests, and rebuilds `wasm/pkg` on Linux and compares it byte for byte with the
committed files.

**Using it from a bundler.** The worker (`new URL("./worker.js",
import.meta.url)`) and the `.wasm` (`new URL("client_wasm_bg.wasm",
import.meta.url)` in the wasm-bindgen glue) are resolved by the bundler. In
Vite, set `worker: { format: "es" }` and
`optimizeDeps: { exclude: ["@routstr/confidential-web"] }` (see the demo
app's `vite.config.ts`). The page's CSP needs `script-src 'wasm-unsafe-eval'`,
`worker-src 'self'`, and `connect-src` for the node (`https:` and `wss:`).

## Dependencies on routstr-confidential

`crates/vendor/{cu-crypto,twopc,zkbench}` are copies of
`jooray/routstr-confidential` (branch `main`, protocol v3) at the commit named in
`crates/vendor/UPSTREAM`, with the wasm32 patch applied. The patch is
`patches/routstr-confidential-wasm32.patch`, explained in
`patches/README.md`; applying it to that commit reproduces `crates/vendor/`
exactly. Once it is upstream, the vendored copies can become a git dependency
on that repository. mpz2 is pinned at the same rev (`8f89783`) and needed no
change. The TS sources `offer.ts`, `receipt.ts`, `params.ts`, `h2.ts`,
`hpack-tables.ts`, `pool.ts`, `wire.ts`, `suffix.ts`, `hosts.ts`,
`canonical.ts`, `errors.ts` and the TLS fork come from routstr-sdk
(branch `confidential-2pc` of jooray/routstr-sdk) with node-only imports replaced (`hash.ts` stands in for
`node:crypto`); `connection.ts` is a port of the SDK's with the 2PC and the
proofs on the wasm host and the provider's certificate path kept for display. The browser changes to the TLS fork are listed in
`src/tls-fork/FORK-NOTES.md`.

## Tests

```bash
npm test                                             # vitest: offer/receipt/fees/suffix/padding/params/SSE/pricing/worker host, and the wasm source digest
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

# Protocol v3 live, against a local node + sidecar on the real provider (keys from the environment, never printed):
npm run build && CONF_NODE=http://127.0.0.1:8451 CONF_KEY=sk-… node scripts/live-v3.mjs chat-2 big batches error-head pad chat-1.1 image refused   # in Node
npm run harness:build && CONF_KEY=sk-… node scripts/browser-live-v3.mjs chat-2 error-head chat-1.1 image refused                                  # headless Chromium (ENGINE=firefox|webkit)

```

`node scripts/browser-bench.mjs` and `scripts/tls-check.mjs` serve the test
harness (`harness/`, `npm run harness:build`, built from `dist/`). End-to-end
tests against the production node, including the live test with a funded key,
live in the demo app's repository (`scripts/e2e-prod.mjs`).

## Protocol v3, live (M2 Max laptop, headless Chromium 153, local node and sidecar, provider api.venice.ai)

`scripts/browser-live-v3.mjs`, 2026-11-12, `mistral-small-3-2-24b-instruct` with
`max_tokens` 24, the image `venice-sd35` (count 1). Time to first token from
the call; bytes between page and node for the request, and for the
connection's setup (2PC preprocessing, key share, proof channel, handshake,
π_NK) when the request opened it.

| case | framing | n | connection | first token | total | request up / down | setup up / down |
|---|---|---|---|---|---|---|---|
| chat | 2 | 1 | new | 4.81 s | 5.16 s | 0.08 / 0.02 MB | 2.55 / 17.96 MB |
| chat | 2 | 2 | reused | 0.49 s | 0.84 s | 0.08 / 0.02 MB | — |
| chat | 2 | 3 | reused | 0.61 s | 1.36 s | 0.08 / 0.02 MB | — |
| chat | 2 | 4 | reused | 0.65 s | 0.96 s | 0.08 / 0.02 MB | — |
| chat | 2 | 5 | reused | 0.61 s | 1.39 s | 0.08 / 0.02 MB | — |
| error head (provider 400) | 2 | 1 | new | 4.25 s | 4.52 s | 0.13 / 0.02 MB | 2.55 / 17.96 MB |
| chat, HTTP/2 off | 1.1 | 1 | new | 4.09 s | 4.29 s | 0.08 / 0.09 MB | 2.55 / 17.88 MB |
| refused (402), top-up, again | 2 | 1 | the same | 0.83 s | 2.08 s | 0.08 / 0.02 MB | — |
| image (earlier run) | 2 | 1 | new | 10.76 s | 10.84 s | 0.04 / 0.05 MB | 2.55 / 17.96 MB |

The five chat requests ran 2 s apart. Between them the proof channel was topped
up three times (0.61 MB each, off the request path); before the top-up, the
third request of a connection downloaded 1.46 MB on its path while the channel
extended its correlations online. In Node (`scripts/live-v3.mjs batches`) a
4.6 MB body (padded) in 4 KiB records was proven in two π_WIN batches (2200 +
49 windows).

The v2 numbers below are kept for comparison (they name v2's π_C2S and the
22.1 MB of v2 garbled tables).

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
