// key-guard.ts — Auto-redact API keys from chat, store temporarily for agent use

import { definePlugin } from "@opencode-ai/plugin";

// Session-scoped key store
const keyStore = new Map<string, string>();
let keyCounter = 0;

// All patterns to detect
const PATTERNS = [
  { pattern: /\b(sk-[a-zA-Z0-9]{20,})\b/g, name: "OpenAI Key" },
  { pattern: /\b(dop_v1_[a-zA-Z0-9]+)\b/g, name: "DigitalOcean Token" },
  { pattern: /\b(AKIA[A-Z0-9]{16})\b/g, name: "AWS Access Key" },
  { pattern: /\b(gh[pousr]_[a-zA-Z0-9]{36})\b/g, name: "GitHub Token" },
  { pattern: /\b(xox[baprs]-[a-zA-Z0-9-]{10,})\b/g, name: "Slack Token" },
  { pattern: /(-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----[\s\S]*?-----END (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----)/g, name: "SSH Private Key" },
  { pattern: /\b(Bearer\s+[a-zA-Z0-9._-]{20,})\b/g, name: "Bearer Token" },
  { pattern: /\b(Basic\s+[a-zA-Z0-9=+/]{20,})\b/g, name: "Basic Auth" },
  { pattern: /\b((?:api[_-]?key|apikey|secret|token|password)\s*[=:]\s*['"]?[a-zA-Z0-9_!@#$%^&*()=+-]{16,})/gi, name: "API Key/Secret" },
];

function redactKeys(text: string): string {
  let result = text;
  for (const { pattern } of PATTERNS) {
    pattern.lastIndex = 0;
    result = result.replace(pattern, (match, captured) => {
      const key = captured || match;
      keyCounter++;
      const placeholder = `[KEY_${keyCounter}]`;
      keyStore.set(placeholder, key);
      return placeholder;
    });
  }
  return result;
}

export default definePlugin({
  name: "key-guard",
  description: "Auto-redacts API keys from chat, stores temporarily for agent use",

  tools: [
    {
      name: "resolve_key",
      description: "Resolve a redacted key placeholder to its actual value. Only call this when you actually need to use the key.",
      parameters: {
        type: "object",
        properties: {
          placeholder: {
            type: "string",
            description: "The placeholder like [KEY_1], [KEY_2], etc."
          }
        },
        required: ["placeholder"]
      },
      handler: async ({ placeholder }: { placeholder: string }) => {
        const value = keyStore.get(placeholder);
        if (!value) {
          return `No key found for ${placeholder}. It may have expired or was not stored.`;
        }
        return value;
      }
    },
    {
      name: "list_keys",
      description: "List all redacted key placeholders stored in the current session (shows names only, not values).",
      parameters: {
        type: "object",
        properties: {},
        required: []
      },
      handler: async () => {
        if (keyStore.size === 0) return "No keys stored in this session.";
        const entries = Array.from(keyStore.entries()).map(([k, v]) => {
          const preview = v.length > 8 ? v.substring(0, 4) + "..." + v.substring(v.length - 4) : v;
          return `${k}: ${preview}`;
        });
        return `Stored keys:\n${entries.join("\n")}`;
      }
    },
    {
      name: "clear_keys",
      description: "Clear all stored keys from the current session. Call this when you're done using the keys.",
      parameters: {
        type: "object",
        properties: {},
        required: []
      },
      handler: async () => {
        const count = keyStore.size;
        keyStore.clear();
        keyCounter = 0;
        return `Cleared ${count} keys from session memory.`;
      }
    }
  ],

  hooks: {
    "message.updated": async ({ message }: { message: { role: string; content: string } }) => {
      if (message.role === "user" && typeof message.content === "string") {
        const redacted = redactKeys(message.content);
        if (redacted !== message.content) {
          message.content = redacted;
        }
      }
    }
  }
});
