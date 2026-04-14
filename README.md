# n8n-readonly-mcp

Hardened read-only MCP (Model Context Protocol) proxy for n8n. Exposes only read-only tools (`list_workflows`, `get_workflow`, `list_executions`, `get_execution`) to Claude Code / other MCP clients, with secret scrubbing, rate limiting, input validation, and sanitized error handling.

## Why this exists

The n8n public API has no read-only key scope — any valid API key can create, update, delete, and execute workflows. This proxy enforces read-only at the tool layer so an LLM session cannot mutate workflows even if prompt-injected.

## Security hardening

| Fix | Description |
|---|---|
| **Allowlist tools** | Only `list_workflows`, `get_workflow`, `list_executions`, and `get_execution` are registered — no write surface |
| **ID validation** | Workflow ID must match `^[A-Za-z0-9]+$` (max 64 chars) — blocks path traversal and injection |
| **Secret scrubbing** | Deep-scrubs response JSON: redacts keys matching `authorization`/`api-key`/`secret`/`token`/`password`/`credential`/`bearer`, strips embedded credentials, and regex-matches known secret formats (OpenAI, Slack, GitHub PAT, JWT, Google API key, AWS, Stripe, PEM private keys, Basic/Bearer auth) |
| **Rate limiting** | 30 calls / 60 seconds per process — prevents bulk exfiltration in a single session |
| **Cursor bounds** | Pagination cursor must be URL-safe, max 512 chars |
| **Error sanitization** | Upstream error bodies are never forwarded — only the status code |
| **Keychain credentials** | Launch wrapper reads the API key from macOS Keychain instead of a config file |

## Setup

### 1. Install

```bash
git clone https://github.com/Brendan4am/n8n-readonly-mcp.git
cd n8n-readonly-mcp
npm install
chmod +x run.sh
```

### 2. Store API key in macOS Keychain

```bash
security add-generic-password -a n8n -s n8n-api-key -w "<your-n8n-api-key>"
```

### 3. Set your n8n instance URL

Edit `run.sh` and replace `https://your-instance.app.n8n.cloud` with your instance URL, or set it via env:

```bash
export N8N_BASE_URL="https://your-instance.app.n8n.cloud"
```

### 4. Smoke test

```bash
./run.sh
```

The process should start and wait on stdin (MCP stdio transport). Ctrl+C to exit.

## Register with Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "n8n-readonly": {
      "command": "/absolute/path/to/n8n-readonly-mcp/run.sh"
    }
  }
}
```

No secrets in the config — the wrapper pulls them from Keychain at launch.

## Tools

### `list_workflows`

List n8n workflows.

| Param | Type | Description |
|---|---|---|
| `cursor` | string (optional) | Pagination cursor from a previous response |
| `limit` | integer 1–250 (optional) | Page size (default 100) |
| `active` | boolean (optional) | Filter by active status |

Returns: `{ workflows: [...], nextCursor: string \| null }`

### `get_workflow`

Get full details of a workflow by ID. Secrets are redacted before return.

| Param | Type | Description |
|---|---|---|
| `id` | string (required, `^[A-Za-z0-9]+$`, max 64) | Workflow ID |

Returns: full workflow JSON with credentials, API keys, JWTs, and known secret patterns replaced with `[REDACTED]`.

### `list_executions`

List n8n executions with optional filters.

| Param | Type | Description |
|---|---|---|
| `cursor` | string (optional) | Pagination cursor from a previous response |
| `limit` | integer 1–250 (optional) | Page size (default 100) |
| `workflowId` | string (optional) | Filter by workflow ID |
| `status` | enum (optional) | Filter by status: `error`, `new`, `running`, `success`, `waiting` |

Returns: `{ executions: [...], nextCursor: string | null }`

### `get_execution`

Get full details of an execution by ID. Secrets are redacted before return.

| Param | Type | Description |
|---|---|---|
| `id` | string (required, `^[A-Za-z0-9]+$`, max 64) | Execution ID |

Returns: full execution JSON with secrets replaced with `[REDACTED]`.

## Development

```bash
npm install
N8N_API_KEY="..." N8N_BASE_URL="https://..." node index.js
```

## License

MIT
