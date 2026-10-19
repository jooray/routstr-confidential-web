import type { ChatSuffixSpec } from "../../src/suffix.js";
import vectors from "./chat-suffix-vectors.json";

/** The Venice chat block from the shared vectors (the shipped sidecar offer's). */
export const VENICE_CHAT = vectors.venice as ChatSuffixSpec;
