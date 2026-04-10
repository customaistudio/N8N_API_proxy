import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// ---------- Config ----------
const API_KEY = process.env.N8N_API_KEY;
const BASE_URL = process.env.N8N_BASE_URL?.replace(/\/+$/, "");

if (!API_KEY || !BASE_URL) {
  console.error("Missing required env vars: N8N_API_KEY, N8N_BASE_URL");
  process.exit(1);
}

// ---------- Rate limit (per process) ----------
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_CALLS = 30;
const callTimestamps = [];

function checkRateLimit() {
  const now = Date.now();
  while (
    callTimestamps.length &&
    now - callTimestamps[0] > RATE_LIMIT_WINDOW_MS
  ) {
    callTimestamps.shift();
  }
  if (callTimestamps.length >= RATE_LIMIT_MAX_CALLS) {
    throw new Error(
      `Rate limit exceeded: ${RATE_LIMIT_MAX_CALLS} calls per ${
        RATE_LIMIT_WINDOW_MS / 1000
      }s`
    );
  }
  callTimestamps.push(now);
}

// ---------- HTTP ----------
async function n8nGet(path) {
  checkRateLimit();

  const res = await fetch(`${BASE_URL}/api/v1${path}`, {
    method: "GET",
    headers: {
      "X-N8N-API-KEY": API_KEY,
      Accept: "application/json",
    },
  });

  if (!res.ok) {
    // Sanitized error — do not leak raw upstream body
    throw new Error(`n8n API request failed with status ${res.status}`);
  }

  return res.json();
}

// ---------- Secret scrubbing ----------
const SECRET_KEY_PATTERNS = [
  /authorization/i,
  /api[-_]?key/i,
  /secret/i,
  /token/i,
  /password/i,
  /credential/i,
  /bearer/i,
  /x-[a-z0-9-]*-key/i,
];

const SECRET_VALUE_PATTERNS = [
  /sk-[a-zA-Z0-9_-]{20,}/g, // OpenAI / OpenRouter
  /xox[baprs]-[a-zA-Z0-9-]+/g, // Slack
  /ghp_[a-zA-Z0-9]{36}/g, // GitHub PAT
  /github_pat_[a-zA-Z0-9_]{50,}/g, // GitHub fine-grained PAT
  /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, // JWT
  /AIza[0-9A-Za-z_-]{35}/g, // Google API key
];

function scrubString(str) {
  if (typeof str !== "string") return str;
  let out = str;
  for (const re of SECRET_VALUE_PATTERNS) {
    out = out.replace(re, "[REDACTED]");
  }
  return out;
}

function scrubDeep(value, keyName = "") {
  if (value === null || value === undefined) return value;

  if (keyName && SECRET_KEY_PATTERNS.some((re) => re.test(keyName))) {
    return "[REDACTED]";
  }

  if (typeof value === "string") return scrubString(value);
  if (typeof value !== "object") return value;

  if (Array.isArray(value)) {
    return value.map((v) => scrubDeep(v, keyName));
  }

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (k === "credentials" && v && typeof v === "object") {
      out[k] = Object.fromEntries(
        Object.entries(v).map(([credType, credRef]) => [
          credType,
          { name: credRef?.name ?? "[REDACTED]", id: "[REDACTED]" },
        ])
      );
      continue;
    }
    out[k] = scrubDeep(v, k);
  }
  return out;
}

// ---------- Server ----------
const server = new McpServer({
  name: "n8n-readonly",
  version: "1.1.0",
});

server.tool(
  "list_workflows",
  "List all n8n workflows with their IDs, names, active status, and tags",
  {
    cursor: z
      .string()
      .max(512)
      .regex(/^[A-Za-z0-9+/=_-]+$/, "cursor must be a URL-safe token")
      .optional()
      .describe("Pagination cursor from a previous response"),
    limit: z
      .number()
      .int()
      .min(1)
      .max(250)
      .optional()
      .describe("Number of workflows to return (default 100, max 250)"),
    active: z.boolean().optional().describe("Filter by active status"),
  },
  async ({ cursor, limit, active }) => {
    const params = new URLSearchParams();
    if (cursor) params.set("cursor", cursor);
    if (limit) params.set("limit", String(limit));
    if (active !== undefined) params.set("active", String(active));

    const query = params.toString();
    const data = await n8nGet(`/workflows${query ? `?${query}` : ""}`);

    const workflows = data.data.map((wf) => ({
      id: wf.id,
      name: wf.name,
      active: wf.active,
      tags: wf.tags?.map((t) => t.name) ?? [],
      createdAt: wf.createdAt,
      updatedAt: wf.updatedAt,
    }));

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { workflows, nextCursor: data.nextCursor ?? null },
            null,
            2
          ),
        },
      ],
    };
  }
);

// n8n workflow IDs are short alphanumeric strings.
// Strict format blocks path traversal and injection.
const WORKFLOW_ID_SCHEMA = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9]+$/, "Workflow ID must be alphanumeric");

server.tool(
  "get_workflow",
  "Get the full details of a specific n8n workflow by ID, including all nodes, connections, and settings (secrets are redacted)",
  {
    id: WORKFLOW_ID_SCHEMA.describe("The workflow ID"),
  },
  async ({ id }) => {
    const data = await n8nGet(`/workflows/${encodeURIComponent(id)}`);
    const scrubbed = scrubDeep(data);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(scrubbed, null, 2),
        },
      ],
    };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
