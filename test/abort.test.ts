import { describe, expect, it, vi } from "vitest";

// Sessions the client creates are fakes the test drives: release, response, end.
const fakes = vi.hoisted(() => {
  class FakeSession {
    static all: FakeSession[] = [];
    released = false;
    closed = false;
    bodyLength: number;
    opts: Record<string, unknown>;
    onHead?: (h: { status: number; statusText: string; headers: Record<string, string> }) => void;
    onBody?: (b: Uint8Array) => void;
    resolve!: (r: unknown) => void;
    reject!: (e: unknown) => void;
    done: Promise<unknown>;
    constructor(opts: Record<string, unknown>) {
      this.opts = opts;
      this.bodyLength = opts.bodyLength as number;
      this.done = new Promise((res, rej) => {
        this.resolve = res;
        this.reject = rej;
      });
      this.done.catch(() => {});
      FakeSession.all.push(this);
    }
    get bodyReleased() {
      return this.released;
    }
    setResponseHandlers(h: FakeSession["onHead"], b: FakeSession["onBody"]) {
      this.onHead = h;
      this.onBody = b;
    }
    run() {
      if (this.closed) return Promise.reject(new Error("session closed by the client"));
      return this.done;
    }
    close() {
      if (this.closed) return;
      this.closed = true;
      this.reject(new Error("session closed by the client"));
    }
  }
  return { FakeSession };
});

vi.mock("../src/session.js", () => ({ ConfidentialSession: fakes.FakeSession }));

import { ConfidentialClient } from "../src/client.js";
import { SessionRejectedError } from "../src/errors.js";
import type { VerifiedOffer } from "../src/offer.js";
import prod from "./fixtures/cypherpunk-offer.json";

const MODEL = Object.keys(prod.price_list)[0]!;
const tick = () => new Promise((r) => setTimeout(r, 0));
const enc = (s: string) => new TextEncoder().encode(s);

function client(offer: VerifiedOffer = prod as never as VerifiedOffer) {
  const c = new ConfidentialClient({
    node: "https://node.example",
    nodePubkeys: [prod.notary_pubkey],
    trustedHosts: ["api.venice.ai"],
    credential: "sk-test",
    host: {} as never,
  });
  (c as unknown as { offer: () => Promise<VerifiedOffer> }).offer = async () => offer;
  return c;
}

function latest() {
  return fakes.FakeSession.all[fakes.FakeSession.all.length - 1]!;
}

const params = { model: MODEL, messages: [{ role: "user", content: "hi" }], max_tokens: 50, stream: true as const };

describe("caller abort", () => {
  it("after release: ends the caller's stream, the session drains and settles", async () => {
    const ac = new AbortController();
    const c = client();
    const p = c.chat.completions.create(params, { signal: ac.signal });
    await tick();
    const s = latest();
    s.released = true;
    s.onHead!({ status: 200, statusText: "OK", headers: {} });
    s.onBody!(enc('data: {"choices":[{"index":0,"delta":{"content":"a"}}]}\n\n'));
    const stream = await p;
    const it = stream[Symbol.asyncIterator]();
    expect((await it.next()).value.choices[0].delta.content).toBe("a");
    ac.abort();
    await expect(it.next()).rejects.toMatchObject({ name: "AbortError" });
    expect(s.closed).toBe(false); // not closed: the node would charge the whole reservation
    s.onBody!(enc('data: {"choices":[{"index":0,"delta":{"content":"b"}}]}\n\n')); // dropped
    const result = { receipt: { cost_msats: 7 } };
    s.resolve(result);
    await expect(stream.verification).resolves.toBe(result);
    expect(s.closed).toBe(true); // closed only once settled
  });

  it("after release, before the response head: the caller gets AbortError at once", async () => {
    const ac = new AbortController();
    const p = client().chat.completions.create(params, { signal: ac.signal });
    await tick();
    const s = latest();
    s.released = true;
    ac.abort();
    await expect(p).rejects.toMatchObject({ name: "AbortError" });
    expect(s.closed).toBe(false);
    s.resolve({});
    await tick();
    expect(s.closed).toBe(true);
  });

  it("before release: closes the session at once", async () => {
    const ac = new AbortController();
    const p = client().chat.completions.create(params, { signal: ac.signal });
    await tick();
    const s = latest();
    ac.abort();
    await expect(p).rejects.toMatchObject({ name: "AbortError" });
    expect(s.closed).toBe(true);
  });

  it("an already aborted signal opens no session", async () => {
    const ac = new AbortController();
    ac.abort();
    const n = fakes.FakeSession.all.length;
    await expect(client().chat.completions.create(params, { signal: ac.signal })).rejects.toMatchObject({ name: "AbortError" });
    expect(fakes.FakeSession.all.length).toBe(n);
  });

  it("a node error after release is not retried", async () => {
    const p = client().chat.completions.create(params);
    await tick();
    const s = latest();
    const n = fakes.FakeSession.all.length;
    s.released = true;
    s.reject(new SessionRejectedError("node rejected: offer expired", undefined, 409, { error: { type: "offer_expired" } }));
    await expect(p).rejects.toBeInstanceOf(SessionRejectedError);
    await tick();
    expect(fakes.FakeSession.all.length).toBe(n); // no second session: the provider already ran it
  });

  it("an offer refusal before release is retried once on a fresh offer", async () => {
    const p = client().chat.completions.create(params);
    await tick();
    const n = fakes.FakeSession.all.length;
    latest().reject(new SessionRejectedError("node rejected: offer expired", undefined, 409, { error: { type: "offer_expired" } }));
    await tick();
    await tick();
    expect(fakes.FakeSession.all.length).toBe(n + 1);
    const s = latest();
    s.released = true;
    s.onHead!({ status: 200, statusText: "OK", headers: {} });
    s.resolve({});
    await expect(p).resolves.toBeDefined();
  });
});

const IMAGES = {
  head_template:
    "POST /api/v1/image/generate HTTP/1.1\r\nHost: api.venice.ai\r\nAuthorization: Bearer {KEY:42}\r\nContent-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {LEN}\r\n\r\n",
  response_shape: "venice",
  response_idle_s: 300,
  max_count: 4,
  count_key: "variants",
  fixed_pins: [["return_binary", false]],
  param_space: { format: ["webp"] },
  price_list: { "z-image-turbo": [{ id: "webp", pins: [["format", "webp"]], msat_per_image: 12164 }] },
};
const imageOffer = { ...(prod as never as VerifiedOffer), capabilities: ["chat", "images"], images: IMAGES, signedPayload: "" } as never as VerifiedOffer;

describe("caller abort of an image request", () => {
  it("after release: AbortError at once, the session settles in the background", async () => {
    const ac = new AbortController();
    const p = client(imageOffer).images.generate({ model: "z-image-turbo", prompt: "a cat" }, { signal: ac.signal });
    await tick();
    const s = latest();
    expect(s.opts.kind).toBe("images");
    s.released = true;
    ac.abort();
    await expect(p).rejects.toMatchObject({ name: "AbortError" });
    expect(s.closed).toBe(false);
    s.resolve({ http: { status: 200 }, receipt: {} });
    await tick();
    expect(s.closed).toBe(true);
  });

  it("before release: closes the session", async () => {
    const ac = new AbortController();
    const p = client(imageOffer).images.generate({ model: "z-image-turbo", prompt: "a cat" }, { signal: ac.signal });
    await tick();
    const s = latest();
    ac.abort();
    await expect(p).rejects.toMatchObject({ name: "AbortError" });
    expect(s.closed).toBe(true);
  });
});
