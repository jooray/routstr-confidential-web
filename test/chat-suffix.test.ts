import { describe, expect, it } from "vitest";
import { ConfidentialError, OfferMalformedError } from "../src/errors.js";
import { buildPinnedBody } from "../src/request.js";
import { canonicalSuffix, chatSuffixKeys, validateChatSuffix, type ChatSuffixSpec } from "../src/suffix.js";
import { VENICE_CHAT } from "./fixtures/chat.js";
import vectors from "./fixtures/chat-suffix-vectors.json";

/**
 * The shared chat-suffix vectors (routstr-sdk runs its copy of this file, and
 * the sidecar's tests pin the Venice rendering), so every party renders the
 * same bytes from the same offer.
 */
describe("chat suffix vectors", () => {
  for (const v of vectors.accepted) {
    it(`renders ${v.model}/${v.max_tokens} with ${v.suffix_keys.join(",")}`, () => {
      const chat = v.chat as ChatSuffixSpec;
      validateChatSuffix(chat, v.suffix_keys);
      expect(chatSuffixKeys(chat)).toEqual(v.suffix_keys);
      expect(canonicalSuffix(chat, v.model, v.max_tokens)).toBe(v.suffix);
    });
  }
  for (const v of vectors.refused) {
    it(`refuses a chat block: ${v.why}`, () => {
      const c = v.chat as ChatSuffixSpec;
      const keys = Array.isArray(c.cap_keys) && Array.isArray(c.fixed_pins) ? chatSuffixKeys(c) : [];
      expect(() => validateChatSuffix(v.chat, keys)).toThrow(OfferMalformedError);
    });
  }
});

describe("pinned keys in the caller's request", () => {
  const messages = [{ role: "user", content: "hi" }];
  const vp = { enable_web_search: "off", include_venice_system_prompt: false };

  it("drops a pinned key set to the pinned value", () => {
    const body = new TextDecoder().decode(buildPinnedBody({ messages, venice_parameters: vp }, "m", 3, VENICE_CHAT));
    expect(body.startsWith('{"messages":[{"role":"user","content":"hi"}],"model"')).toBe(true);
  });

  it("refuses a pinned key set to another value", () => {
    let err: unknown;
    try {
      buildPinnedBody({ messages, venice_parameters: { ...vp, enable_web_search: "on" } }, "m", 3, VENICE_CHAT);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConfidentialError);
    expect((err as ConfidentialError).code).toBe("pinned_parameter");
  });
});
