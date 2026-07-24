# 🔑 key-guard — OpenCode Key Redaction Plugin

Auto-redacts API keys pasted into chat, stores them temporarily in session memory, and provides tools for the agent to resolve them when needed.

## Why?

Accidentally pasting API keys into chat is one of the easiest ways to leak secrets into:
- Chat transcripts (sent to the model provider)
- Logs and tool output
- Database storage (`opencode.db`)
- Commits and shared sessions

**key-guard** intercepts keys before they reach the provider, redacts them, and stores them temporarily in memory for the agent to use.

## How it works

```
You paste: "my API key is sk-proj-abc123..."
                │
                ▼
    ┌─────────────────────────────┐
    │  key-guard intercepts        │
    │  BEFORE sending to provider   │
    │                              │
    │  "sk-proj-abc123..."          │
    │       ↓                      │
    │  "[KEY_1]"  ← redacted       │
    │                              │
    │  Stores real key in RAM Map  │
    └─────────────────────────────┘
                │
     ┌──────────┴──────────┐
     ▼                     ▼
  Provider              DB/Logs
  sees "[KEY_1]"       store "[KEY_1]"
  NEVER the real key   NEVER the real key
```

## Installation

### Option A: Add to `opencode.jsonc`
```json
{
  "plugin": ["opencode-key-guard"]
}
```

### Option B: Local plugin file
Copy `key-guard.ts` to `~/.config/opencode/plugins/` — OpenCode auto-discovers `.ts` files.

## Usage

Paste your API key as usual:

```
You: "my DigitalOcean token is dop_v1_abc123xyz789"
```

The plugin automatically:
1. Detects the key pattern
2. Replaces it with `[KEY_1]` in the message
3. Stores the real key in session memory

The agent can then:
- `resolve_key("[KEY_1]")` — get the actual key value
- `list_keys()` — see stored keys (preview only)
- `clear_keys()` — wipe all keys from session

## Detected patterns

| Pattern | Example |
|---------|---------|
| OpenAI keys | `sk-...` |
| DigitalOcean tokens | `dop_v1_...` |
| AWS access keys | `AKIA...` |
| GitHub tokens | `ghp_...`, `gho_...`, `ghu_...`, `ghs_...`, `ghr_...` |
| Slack tokens | `xox[baprs]-...` |
| SSH private keys | `-----BEGIN PRIVATE KEY-----` |
| Bearer tokens | `Bearer ...` |
| Basic auth | `Basic ...` |
| Generic API keys | `api_key=...`, `secret=...`, `token=...`, `password=...` |

## Security

- Keys are stored in a **RAM-only Map** — never written to disk
- Keys are **never sent to the model provider**
- Keys are **never logged** to `opencode.db` or prompt-tracker
- Call `clear_keys()` to wipe all keys mid-session
- Keys are automatically cleared when OpenCode closes

## License

MIT
