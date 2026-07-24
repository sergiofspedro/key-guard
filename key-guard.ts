// key-guard.ts — Auto-redact API keys from chat, store temporarily for agent use
// v2.0.0 — Improved with configurable patterns, expiry, encryption, audit, session isolation

import { definePlugin } from "@opencode-ai/plugin";

// ─── Types ───────────────────────────────────────────────────────────

interface KeyEntry {
  value: string;
  createdAt: number;
  resolvedCount: number;
  lastResolvedAt: number | null;
}

interface PatternConfig {
  pattern: RegExp;
  name: string;
  enabled: boolean;
}

interface KeyGuardConfig {
  expiryMs: number;
  maxKeysPerSession: number;
  maxResolvesPerKey: number;
  debug: boolean;
  patterns: PatternConfig[];
}

// ─── Default Configuration ───────────────────────────────────────────

const DEFAULT_CONFIG: KeyGuardConfig = {
  expiryMs: 30 * 60 * 1000, // 30 minutes
  maxKeysPerSession: 50,
  maxResolvesPerKey: 20,
  debug: false,
  patterns: [
    // OpenAI
    { pattern: /\b(sk-[a-zA-Z0-9]{20,})\b/g, name: "OpenAI Key", enabled: true },
    { pattern: /\b(sk-proj-[a-zA-Z0-9]{20,})\b/g, name: "OpenAI Project Key", enabled: true },
    // Anthropic
    { pattern: /\b(sk-ant-[a-zA-Z0-9]{20,})\b/g, name: "Anthropic Key", enabled: true },
    // DigitalOcean
    { pattern: /\b(dop_v1_[a-zA-Z0-9]+)\b/g, name: "DigitalOcean Token", enabled: true },
    // AWS
    { pattern: /\b((?:AKIA|ASIA)[A-Z0-9]{16})\b/g, name: "AWS Access Key", enabled: true },
    // GitHub
    { pattern: /\b(gh[pousr]_[a-zA-Z0-9]{36})\b/g, name: "GitHub Token", enabled: true },
    // GitLab
    { pattern: /\b(glpat-[a-zA-Z0-9\-_]{20,})\b/g, name: "GitLab Token", enabled: true },
    // Slack
    { pattern: /\b(xox[baprs]-[a-zA-Z0-9-]{10,})\b/g, name: "Slack Token", enabled: true },
    // Discord
    { pattern: /\b([MN][A-Za-z\d]{23,25}\.[A-Za-z\d]{6,7}\.[A-Za-z\d_-]{27,})\b/g, name: "Discord Token", enabled: true },
    // SSH private keys
    { pattern: /(-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP|ED25519) PRIVATE KEY-----[\s\S]*?-----END (?:RSA|OPENSSH|DSA|EC|PGP|ED25519) PRIVATE KEY-----)/g, name: "SSH Private Key", enabled: true },
    // Bearer tokens
    { pattern: /\b(Bearer\s+[a-zA-Z0-9._\-]{20,})\b/g, name: "Bearer Token", enabled: true },
    // Basic auth
    { pattern: /\b(Basic\s+[a-zA-Z0-9=+/]{20,})\b/g, name: "Basic Auth", enabled: true },
    // JWT
    { pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g, name: "JWT Token", enabled: true },
    // Google API keys
    { pattern: /\b(AIza[A-Za-z0-9_-]{35})\b/g, name: "Google API Key", enabled: true },
    // Heroku
    { pattern: /\b(heroku[a-zA-Z0-9_-]{20,})\b/g, name: "Heroku API Key", enabled: true },
    // Stripe
    { pattern: /\b((?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{20,})\b/g, name: "Stripe Key", enabled: true },
    // Twilio
    { pattern: /\b(SK[a-zA-Z0-9]{32})\b/g, name: "Twilio Key", enabled: true },
    // Generic API keys (key=value or key:value patterns)
    { pattern: /\b((?:api[_-]?key|apikey|secret|token|password)\s*[=:]\s*['\u201C\u201D]?[a-zA-Z0-9_!@#$%^&*()=+\-]{16,})/gi, name: "API Key/Secret", enabled: true },
  ],
};

// ─── Session-scoped state ───────────────────────────────────────────

const keyStore = new Map<string, KeyEntry>();
let keyCounter = 0;
let auditLog: string[] = [];
let currentSessionID: string | null = null;

// ─── Encryption helpers (simple XOR + base64 for at-rest obfuscation) ─

function obfuscate(text: string): string {
  const key = "key-guard-session-v1";
  let result = "";
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return Buffer.from(result, "utf-8").toString("base64");
}

function deobfuscate(obfuscated: string): string {
  const key = "key-guard-session-v1";
  const decoded = Buffer.from(obfuscated, "base64").toString("utf-8");
  let result = "";
  for (let i = 0; i < decoded.length; i++) {
    result += String.fromCharCode(decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return result;
}

// ─── Core functions ──────────────────────────────────────────────────

function getActivePatterns(): PatternConfig[] {
  return DEFAULT_CONFIG.patterns.filter((p) => p.enabled);
}

function redactKeys(text: string): { text: string; redacted: number } {
  let result = text;
  let redacted = 0;
  const now = Date.now();

  // Clean expired keys
  for (const [k, entry] of keyStore) {
    if (now - entry.createdAt > DEFAULT_CONFIG.expiryMs) {
      keyStore.delete(k);
      auditLog.push(`[${new Date().toISOString()}] Key ${k} expired (${DEFAULT_CONFIG.expiryMs}ms)`);
    }
  }

  for (const { pattern, name } of getActivePatterns()) {
    pattern.lastIndex = 0;
    result = result.replace(pattern, (match, captured) => {
      const key = captured || match;

      // Validate: skip if too short or looks like a placeholder
      if (key.length < 8 || key.includes("[KEY_")) return match;

      // Check session limit
      if (keyStore.size >= DEFAULT_CONFIG.maxKeysPerSession) {
        auditLog.push(`[${new Date().toISOString()}] Session key limit reached (${DEFAULT_CONFIG.maxKeysPerSession})`);
        return match;
      }

      keyCounter++;
      const placeholder = `[KEY_${keyCounter}]`;
      keyStore.set(placeholder, {
        value: obfuscate(key),
        createdAt: now,
        resolvedCount: 0,
        lastResolvedAt: null,
      });
      redacted++;
      auditLog.push(`[${new Date().toISOString()}] Redacted ${name} → ${placeholder}`);
      return placeholder;
    });
  }

  return { text: result, redacted };
}

// ─── Plugin definition ───────────────────────────────────────────────

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
            description: "The placeholder like [KEY_1], [KEY_2], etc.",
          },
        },
        required: ["placeholder"],
      },
      handler: async ({ placeholder }: { placeholder: string }) => {
        const entry = keyStore.get(placeholder);
        if (!entry) {
          return `No key found for ${placeholder}. It may have expired or was not stored.`;
        }

        // Check resolve limit
        if (entry.resolvedCount >= DEFAULT_CONFIG.maxResolvesPerKey) {
          return `Key ${placeholder} has reached the maximum number of resolves (${DEFAULT_CONFIG.maxResolvesPerKey}). Call clear_keys() to reset.`;
        }

        // Check expiry
        if (Date.now() - entry.createdAt > DEFAULT_CONFIG.expiryMs) {
          keyStore.delete(placeholder);
          return `Key ${placeholder} has expired. Please paste it again.`;
        }

        entry.resolvedCount++;
        entry.lastResolvedAt = Date.now();
        auditLog.push(`[${new Date().toISOString()}] Resolved ${placeholder} (resolve #${entry.resolvedCount})`);

        return deobfuscate(entry.value);
      },
    },
    {
      name: "list_keys",
      description: "List all redacted key placeholders stored in the current session (shows preview only, never full values).",
      parameters: {
        type: "object",
        properties: {},
        required: [],
      },
      handler: async () => {
        if (keyStore.size === 0) return "No keys stored in this session.";

        const now = Date.now();
        const entries = Array.from(keyStore.entries()).map(([k, entry]) => {
          const value = deobfuscate(entry.value);
          const preview = value.length > 12 ? value.substring(0, 4) + "..." + value.substring(value.length - 4) : value;
          const age = Math.round((now - entry.createdAt) / 1000);
          const expiresIn = Math.max(0, Math.round((DEFAULT_CONFIG.expiryMs - (now - entry.createdAt)) / 1000));
          return `${k}: ${preview} (age: ${age}s, expires: ${expiresIn}s, resolves: ${entry.resolvedCount})`;
        });

        return `Stored keys (${keyStore.size} total):\n${entries.join("\n")}\n\nUse resolve_key("<placeholder>") to get the actual value.`;
      },
    },
    {
      name: "clear_keys",
      description: "Clear all stored keys from the current session. Call this when you are done using the keys.",
      parameters: {
        type: "object",
        properties: {},
        required: [],
      },
      handler: async () => {
        const count = keyStore.size;
        keyStore.clear();
        keyCounter = 0;
        auditLog.push(`[${new Date().toISOString()}] Cleared ${count} keys from session`);
        return `Cleared ${count} keys from session memory.`;
      },
    },
    {
      name: "key_guard_status",
      description: "Show key-guard plugin status: active keys, config, and recent audit log.",
      parameters: {
        type: "object",
        properties: {},
        required: [],
      },
      handler: async () => {
        const activePatterns = getActivePatterns().map((p) => p.name);
        const recentLog = auditLog.slice(-10).join("\n") || "No events yet.";
        return [
          `key-guard v2.0.0`,
          `Active patterns (${activePatterns.length}): ${activePatterns.join(", ")}`,
          `Keys stored: ${keyStore.size}/${DEFAULT_CONFIG.maxKeysPerSession}`,
          `Key expiry: ${DEFAULT_CONFIG.expiryMs / 1000}s`,
          `Max resolves per key: ${DEFAULT_CONFIG.maxResolvesPerKey}`,
          `Session ID: ${currentSessionID || "not set"}`,
          ``,
          `Recent audit log (last 10):`,
          recentLog,
        ].join("\n");
      },
    },
    {
      name: "batch_resolve_keys",
      description: "Resolve multiple redacted key placeholders at once. Returns a JSON object mapping placeholders to values.",
      parameters: {
        type: "object",
        properties: {
          placeholders: {
            type: "array",
            items: { type: "string" },
            description: "Array of placeholders like [\"KEY_1\", \"KEY_2\"]",
          },
        },
        required: ["placeholders"],
      },
      handler: async ({ placeholders }: { placeholders: string[] }) => {
        const results: Record<string, string> = {};
        const errors: string[] = [];

        for (const ph of placeholders) {
          const entry = keyStore.get(ph);
          if (!entry) {
            errors.push(`${ph}: not found`);
            continue;
          }
          if (entry.resolvedCount >= DEFAULT_CONFIG.maxResolvesPerKey) {
            errors.push(`${ph}: max resolves reached`);
            continue;
          }
          if (Date.now() - entry.createdAt > DEFAULT_CONFIG.expiryMs) {
            keyStore.delete(ph);
            errors.push(`${ph}: expired`);
            continue;
          }
          entry.resolvedCount++;
          entry.lastResolvedAt = Date.now();
          results[ph] = deobfuscate(entry.value);
        }

        let response = `Resolved ${Object.keys(results).length} keys.`;
        if (errors.length > 0) response += `\nErrors: ${errors.join("; ")}`;
        response += `\n\nValues:\n${JSON.stringify(results, null, 2)}`;
        return response;
      },
    },
  ],

  hooks: {
    "session.created": async ({ sessionID }: { sessionID: string }) => {
      currentSessionID = sessionID;
      auditLog.push(`[${new Date().toISOString()}] Session started: ${sessionID}`);
    },
    "session.deleted": async ({ sessionID }: { sessionID: string }) => {
      if (sessionID === currentSessionID) {
        const count = keyStore.size;
        keyStore.clear();
        keyCounter = 0;
        auditLog.push(`[${new Date().toISOString()}] Session ended: ${sessionID}, cleared ${count} keys`);
        currentSessionID = null;
      }
    },
    "message.updated": async ({ message }: { message: { role: string; content: string } }) => {
      if (message.role === "user" && typeof message.content === "string") {
        const { text: redacted, redacted: count } = redactKeys(message.content);
        if (redacted !== message.content) {
          message.content = redacted;
          if (DEFAULT_CONFIG.debug) {
            auditLog.push(`[${new Date().toISOString()}] Redacted ${count} key(s) from user message`);
          }
        }
      }
    },
  },
});
