/**
 * The request body as the provider sees it: the private part (messages,
 * temperature, …) followed by the pinned suffix that fixes every
 * cost-relevant parameter (model, max_tokens, n, stream). Ported from
 * routstr-sdk `transport.ts` / `prewarm.ts`.
 */

import { endsWith } from "./bytes.js";
import { SessionProtocolError } from "./errors.js";
import { canonicalSuffix } from "./suffix.js";

/** Request keys the pinned suffix sets; they never come from the caller. */
export const PINNED_KEYS = new Set([
  "model",
  "max_tokens",
  "max_completion_tokens",
  "max_output_tokens",
  "n",
  "stream",
  "stream_options",
  "venice_parameters",
]);

export function buildPinnedBody(request: Record<string, unknown>, model: string, maxTokens: number): Uint8Array {
  const priv: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(request)) {
    if (!PINNED_KEYS.has(k)) priv[k] = v;
  }
  // The body must end with the exact suffix π_C2S proves, leading comma
  // included, so it needs at least one private field before it.
  if (Object.keys(priv).length === 0) throw new SessionProtocolError("a confidential request needs its messages");
  const json = JSON.stringify(priv);
  // Drop the closing brace: the suffix closes the object and wins last.
  return new TextEncoder().encode(json.slice(0, -1) + canonicalSuffix(model, maxTokens));
}

export function requestedMaxTokens(request: Record<string, unknown>, cap: number): number {
  // The provider honours the tightest of the caps it is sent, so pin that one.
  let asked: number | undefined;
  for (const k of ["max_tokens", "max_completion_tokens", "max_output_tokens"]) {
    const v = request[k];
    if (typeof v === "number" && Number.isFinite(v) && v > 0) {
      asked = Math.min(asked ?? Infinity, Math.trunc(v));
    }
  }
  return asked === undefined ? cap : Math.max(1, Math.min(asked, cap));
}

/**
 * Pad a pinned body to exactly `length` bytes with spaces between the private
 * part and the suffix (JSON allows whitespace before the suffix's comma), so a
 * session armed for length L serves any body ≤ L.
 */
export function padPinnedBody(body: Uint8Array, length: number, suffix: string): Uint8Array {
  const s = new TextEncoder().encode(suffix);
  if (!endsWith(body, s)) throw new RangeError("body does not end with the pinned suffix");
  if (body.length > length) throw new RangeError(`body ${body.length} exceeds armed length ${length}`);
  if (body.length === length) return body;
  const out = new Uint8Array(length);
  const cut = body.length - s.length;
  out.set(body.subarray(0, cut), 0);
  out.fill(0x20, cut, length - s.length);
  out.set(s, length - s.length);
  return out;
}

/** Power-of-two body-length bucket for the largest recent body, with headroom. */
export function chooseBucket(
  maxLen: number,
  opts: { minBucket?: number; maxBucket?: number; headroom?: number } = {},
): number {
  const min = opts.minBucket ?? 4096;
  const max = opts.maxBucket ?? 8 << 20;
  const want = Math.ceil(Math.max(0, maxLen) * (opts.headroom ?? 1.25));
  let b = min;
  while (b < want && b < max) b *= 2;
  return Math.min(b, max);
}

/** Incremental SSE `data:` line parser (OpenAI chat-completions stream). */
export class SseParser {
  private buf = "";
  private dec = new TextDecoder();
  done = false;

  /** Feed decrypted body bytes; returns the parsed JSON events completed so far. */
  push(chunk: Uint8Array): Record<string, unknown>[] {
    this.buf += this.dec.decode(chunk, { stream: true });
    const out: Record<string, unknown>[] = [];
    let i: number;
    while ((i = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, i).replace(/\r$/, "");
      this.buf = this.buf.slice(i + 1);
      if (!line.startsWith("data:")) continue;
      const payload = line.slice(5).trim();
      if (!payload) continue;
      if (payload === "[DONE]") {
        this.done = true;
        continue;
      }
      try {
        out.push(JSON.parse(payload));
      } catch {
        /* not JSON: ignore (keep-alive comments etc.) */
      }
    }
    return out;
  }
}

/** Fold a streamed chat completion into one `chat.completion` object. */
export function aggregateChatCompletion(events: Record<string, any>[]): Record<string, unknown> {
  let id: unknown, created: unknown, model: unknown, usage: unknown;
  const choices = new Map<
    number,
    {
      role: string;
      content: string;
      reasoning: string;
      finish_reason: unknown;
      tool_calls: Map<number, { id?: unknown; type?: unknown; function: { name: string; arguments: string } }>;
    }
  >();
  for (const ev of events) {
    id ??= ev.id;
    created ??= ev.created;
    model ??= ev.model;
    if (ev.usage) usage = ev.usage;
    for (const c of Array.isArray(ev.choices) ? ev.choices : []) {
      const idx = typeof c.index === "number" ? c.index : 0;
      let acc = choices.get(idx);
      if (!acc) {
        acc = { role: "assistant", content: "", reasoning: "", finish_reason: null, tool_calls: new Map() };
        choices.set(idx, acc);
      }
      const d = c.delta ?? {};
      if (typeof d.role === "string") acc.role = d.role;
      if (typeof d.content === "string") acc.content += d.content;
      const r = d.reasoning_content ?? d.reasoning;
      if (typeof r === "string") acc.reasoning += r;
      for (const tc of Array.isArray(d.tool_calls) ? d.tool_calls : []) {
        const ti = typeof tc.index === "number" ? tc.index : 0;
        let t = acc.tool_calls.get(ti);
        if (!t) {
          t = { function: { name: "", arguments: "" } };
          acc.tool_calls.set(ti, t);
        }
        if (tc.id !== undefined) t.id = tc.id;
        if (tc.type !== undefined) t.type = tc.type;
        if (typeof tc.function?.name === "string") t.function.name += tc.function.name;
        if (typeof tc.function?.arguments === "string") t.function.arguments += tc.function.arguments;
      }
      if (c.finish_reason != null) acc.finish_reason = c.finish_reason;
    }
  }
  const out: Record<string, unknown> = {
    id,
    object: "chat.completion",
    created,
    model,
    choices: [...choices.entries()]
      .sort(([a], [b]) => a - b)
      .map(([index, acc]) => {
        const message: Record<string, unknown> = { role: acc.role, content: acc.content };
        if (acc.reasoning) message.reasoning_content = acc.reasoning;
        if (acc.tool_calls.size > 0) {
          message.tool_calls = [...acc.tool_calls.entries()]
            .sort(([a], [b]) => a - b)
            .map(([, t]) => ({ id: t.id, type: t.type ?? "function", function: t.function }));
        }
        return { index, message, finish_reason: acc.finish_reason };
      }),
  };
  if (usage !== undefined) out.usage = usage;
  return out;
}
