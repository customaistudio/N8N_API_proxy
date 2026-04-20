import { createServer } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { n8nGet, scrubDeep } from "./common.js";

process.on("unhandledRejection", (reason) => {
  console.error("[FATAL] Unhandled rejection:", reason);
  process.exit(1);
});

// ---------- Config ----------
const PORT = parseInt(process.env.PORT || "3000", 10);
if (PORT < 1 || PORT > 65535 || isNaN(PORT)) {
  console.error("Invalid PORT: must be 1-65535");
  process.exit(1);
}
const HOST = process.env.HOST || "127.0.0.1";
const PROXY_API_KEY = process.env.PROXY_API_KEY || randomBytes(32).toString("hex");
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || null;
const TRUST_PROXY = process.env.TRUST_PROXY === "true";
const MAX_URL_LENGTH = 8192;

if (ALLOWED_ORIGIN === "*") {
  console.error('ALLOWED_ORIGIN must not be "*" — set a specific origin (e.g. https://example.com)');
  process.exit(1);
}
if (ALLOWED_ORIGIN && !ALLOWED_ORIGIN.startsWith("http")) {
  console.error("ALLOWED_ORIGIN must be a full origin (e.g. https://example.com)");
  process.exit(1);
}

// ---------- Auth brute-force protection ----------
const AUTH_WINDOW_MS = 60_000;
const AUTH_MAX_FAILURES = 10;
const AUTH_MAP_MAX_SIZE = 10_000;
const authFailures = new Map(); // ip -> [timestamps]

// Evict stale IPs every 5 minutes to prevent unbounded memory growth
setInterval(() => {
  const now = Date.now();
  for (const [ip, timestamps] of authFailures) {
    const recent = timestamps.filter((t) => now - t < AUTH_WINDOW_MS);
    if (recent.length === 0) {
      authFailures.delete(ip);
    } else {
      authFailures.set(ip, recent);
    }
  }
}, 5 * 60_000).unref();

function checkAuthRateLimit(ip) {
  const now = Date.now();
  const timestamps = authFailures.get(ip) || [];
  const recent = timestamps.filter((t) => now - t < AUTH_WINDOW_MS);
  if (recent.length >= AUTH_MAX_FAILURES) {
    return false;
  }
  return true;
}

function recordAuthFailure(ip) {
  // Prevent memory exhaustion from distributed attacks
  if (!authFailures.has(ip) && authFailures.size >= AUTH_MAP_MAX_SIZE) {
    return;
  }
  const now = Date.now();
  const timestamps = authFailures.get(ip) || [];
  timestamps.push(now);
  const recent = timestamps.filter((t) => now - t < AUTH_WINDOW_MS);
  authFailures.set(ip, recent);
}

// ---------- Helpers ----------
function getClientIP(req) {
  if (TRUST_PROXY) {
    const forwarded = req.headers["x-forwarded-for"];
    if (forwarded) return forwarded.split(",")[0].trim();
  }
  return req.socket.remoteAddress || "unknown";
}

function json(res, status, body, req) {
  const payload = JSON.stringify(body);
  const headers = {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  };
  if (ALLOWED_ORIGIN && req?.headers?.origin === ALLOWED_ORIGIN) {
    headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN;
    headers["Vary"] = "Origin";
  }
  res.writeHead(status, headers);
  res.end(payload);
}

function authenticate(req) {
  const supplied = req.headers["x-n8n-api-key"] || "";
  if (supplied.length !== PROXY_API_KEY.length) return false;
  return timingSafeEqual(
    Buffer.from(supplied, "utf8"),
    Buffer.from(PROXY_API_KEY, "utf8")
  );
}

// ---------- Homepage ----------
function serveHomepage(res) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>n8n Read-Only API Proxy</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f1117; color: #e1e4e8; line-height: 1.6; padding: 2rem 1rem; }
  .container { max-width: 780px; margin: 0 auto; }
  h1 { font-size: 1.8rem; margin-bottom: 0.25rem; color: #fff; }
  .subtitle { color: #8b949e; margin-bottom: 2rem; font-size: 1.05rem; }
  h2 { font-size: 1.2rem; color: #fff; margin: 2rem 0 0.75rem; padding-bottom: 0.4rem; border-bottom: 1px solid #21262d; }
  h3 { font-size: 1rem; color: #c9d1d9; margin: 1.25rem 0 0.5rem; }
  p, li { color: #c9d1d9; }
  ul, ol { padding-left: 1.5rem; margin-bottom: 0.75rem; }
  li { margin-bottom: 0.35rem; }
  code { background: #161b22; padding: 0.15em 0.4em; border-radius: 4px; font-size: 0.9em; color: #f0883e; font-family: "SF Mono", "Fira Code", monospace; }
  pre { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 1rem; overflow-x: auto; margin: 0.75rem 0 1rem; }
  pre code { background: none; padding: 0; color: #e1e4e8; }
  .badge { display: inline-block; background: #1f6feb33; color: #58a6ff; padding: 0.15em 0.6em; border-radius: 12px; font-size: 0.8rem; font-weight: 500; margin-left: 0.5rem; }
  .endpoint { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 0.75rem 1rem; margin: 0.5rem 0; display: flex; align-items: center; gap: 0.75rem; }
  .method { background: #238636; color: #fff; padding: 0.15em 0.5em; border-radius: 4px; font-size: 0.8rem; font-weight: 600; font-family: monospace; }
  .path { color: #58a6ff; font-family: monospace; font-size: 0.95rem; }
  .desc { color: #8b949e; font-size: 0.85rem; margin-left: auto; }
  .card { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 1.25rem; margin: 1rem 0; }
  .warn { border-color: #d29922; }
  .warn-title { color: #d29922; font-weight: 600; margin-bottom: 0.5rem; }
  .section-label { display: inline-block; background: #23862033; color: #3fb950; padding: 0.1em 0.5em; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .footer { margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid #21262d; color: #484f58; font-size: 0.85rem; text-align: center; }
</style>
</head>
<body>
<div class="container">

<h1>n8n Read-Only API Proxy</h1>
<p class="subtitle">A secure, read-only HTTP proxy for your n8n instance. Query workflows and executions without exposing your n8n API key or allowing write operations.</p>

<h2>Environment Variables</h2>
<p>Set these on your Railway service (or wherever you deploy):</p>
<div class="card">
<table style="width:100%; border-collapse:collapse;">
  <tr><td style="padding:0.3rem 0;"><code>N8N_BASE_URL</code></td><td style="padding:0.3rem 0; color:#8b949e;">Your n8n instance URL, e.g. <code>https://your-instance.app.n8n.cloud</code></td></tr>
  <tr><td style="padding:0.3rem 0;"><code>N8N_API_KEY</code></td><td style="padding:0.3rem 0; color:#8b949e;">Your n8n API key (kept secret, never exposed to clients)</td></tr>
  <tr><td style="padding:0.3rem 0;"><code>PROXY_API_KEY</code></td><td style="padding:0.3rem 0; color:#8b949e;">The key clients use to authenticate with this proxy</td></tr>
  <tr><td style="padding:0.3rem 0;"><code>HOST</code></td><td style="padding:0.3rem 0; color:#8b949e;">Bind address (default <code>127.0.0.1</code>, use <code>0.0.0.0</code> for Railway)</td></tr>
  <tr><td style="padding:0.3rem 0;"><code>TRUST_PROXY</code></td><td style="padding:0.3rem 0; color:#8b949e;">Set to <code>true</code> if behind a reverse proxy (Railway, etc.)</td></tr>
  <tr><td style="padding:0.3rem 0;"><code>ALLOWED_ORIGIN</code></td><td style="padding:0.3rem 0; color:#8b949e;">CORS origin, e.g. <code>https://yourdomain.com</code> (optional)</td></tr>
</table>
</div>

<h2>API Endpoints</h2>
<p>All endpoints (except <code>/health</code> and this page) require the <code>X-N8N-API-KEY</code> header set to your <code>PROXY_API_KEY</code>.</p>

<div class="endpoint"><span class="method">GET</span> <span class="path">/health</span> <span class="desc">Health check (no auth)</span></div>
<div class="endpoint"><span class="method">GET</span> <span class="path">/api/v1/workflows</span> <span class="desc">List all workflows</span></div>
<div class="endpoint"><span class="method">GET</span> <span class="path">/api/v1/workflows/:id</span> <span class="desc">Get workflow details</span></div>
<div class="endpoint"><span class="method">GET</span> <span class="path">/api/v1/executions</span> <span class="desc">List executions</span></div>
<div class="endpoint"><span class="method">GET</span> <span class="path">/api/v1/executions/:id</span> <span class="desc">Get execution details</span></div>

<h3>Query Parameters</h3>
<ul>
  <li><code>/api/v1/workflows</code> &mdash; <code>cursor</code>, <code>limit</code> (1-250), <code>active</code> (true/false)</li>
  <li><code>/api/v1/executions</code> &mdash; <code>cursor</code>, <code>limit</code> (1-250), <code>workflowId</code>, <code>status</code> (error/new/running/success/waiting)</li>
</ul>

<h2>Quick Start</h2>

<div class="section-label">Using curl</div>
<pre><code># List workflows
curl -H "X-N8N-API-KEY: YOUR_PROXY_API_KEY" \\
  https://your-railway-app.up.railway.app/api/v1/workflows

# Get a specific workflow
curl -H "X-N8N-API-KEY: YOUR_PROXY_API_KEY" \\
  https://your-railway-app.up.railway.app/api/v1/workflows/abc123

# List failed executions
curl -H "X-N8N-API-KEY: YOUR_PROXY_API_KEY" \\
  "https://your-railway-app.up.railway.app/api/v1/executions?status=error"</code></pre>

<h2>MCP Server (for Claude Desktop / AI Assistants)</h2>
<p>This project also includes an MCP (Model Context Protocol) server that lets AI assistants like Claude read your n8n workflows directly. The MCP server runs locally via stdio &mdash; it is <strong>not</strong> what's deployed on Railway.</p>

<h3>Setup</h3>
<ol>
  <li>Clone the repo locally:
    <pre><code>git clone https://github.com/customaistudio/N8N_API_proxy.git
cd N8N_API_proxy
npm install</code></pre>
  </li>
  <li>Create a <code>.env</code> file:
    <pre><code>N8N_API_KEY=your-n8n-api-key
N8N_BASE_URL=https://your-instance.app.n8n.cloud</code></pre>
  </li>
  <li>Add to your Claude Desktop config (<code>claude_desktop_config.json</code>):
    <pre><code>{
  "mcpServers": {
    "n8n-readonly": {
      "command": "node",
      "args": ["--env-file=.env", "index.js"],
      "cwd": "/path/to/N8N_API_proxy"
    }
  }
}</code></pre>
  </li>
  <li>Restart Claude Desktop. You'll see 4 new tools available:
    <ul>
      <li><code>list_workflows</code> &mdash; List all workflows with IDs, names, active status, and tags</li>
      <li><code>get_workflow</code> &mdash; Get full workflow details (nodes, connections, settings)</li>
      <li><code>list_executions</code> &mdash; List executions with optional filters</li>
      <li><code>get_execution</code> &mdash; Get full execution details including node results</li>
    </ul>
  </li>
</ol>

<div class="card warn">
  <div class="warn-title">Security Notes</div>
  <ul>
    <li>All responses have secrets automatically redacted (API keys, tokens, passwords, credentials)</li>
    <li>Only GET requests are allowed &mdash; no one can modify your workflows through this proxy</li>
    <li>Your real n8n API key is never exposed to clients</li>
    <li>Auth brute-force protection: 10 failures per IP per minute</li>
  </ul>
</div>

<div class="footer">
  <a href="https://github.com/customaistudio/N8N_API_proxy">GitHub</a> &middot; n8n Read-Only API Proxy v1.1.0
</div>

</div>
</body>
</html>`;

  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": Buffer.byteLength(html),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  });
  res.end(html);
}

// ---------- Route handlers ----------
async function listWorkflows(url) {
  const params = url.searchParams;
  const query = new URLSearchParams();

  const cursor = params.get("cursor");
  const limit = params.get("limit");
  const active = params.get("active");

  if (cursor) {
    if (!/^[A-Za-z0-9+/=_-]+$/.test(cursor) || cursor.length > 512) {
      return { status: 400, body: { error: "Invalid cursor" } };
    }
    query.set("cursor", cursor);
  }

  if (limit) {
    const n = parseInt(limit, 10);
    if (isNaN(n) || n < 1 || n > 250) {
      return { status: 400, body: { error: "limit must be 1-250" } };
    }
    query.set("limit", String(n));
  }

  if (active !== null) {
    if (active !== "true" && active !== "false") {
      return { status: 400, body: { error: "active must be true or false" } };
    }
    query.set("active", active);
  }

  const qs = query.toString();
  const data = await n8nGet(`/workflows${qs ? `?${qs}` : ""}`);

  if (!Array.isArray(data.data)) {
    throw new Error("Unexpected response format from n8n API");
  }

  return {
    status: 200,
    body: {
      data: data.data.map((wf) => ({
        id: wf.id,
        name: wf.name,
        active: wf.active,
        tags: wf.tags?.map((t) => t.name) ?? [],
        createdAt: wf.createdAt,
        updatedAt: wf.updatedAt,
      })),
      nextCursor: data.nextCursor ?? null,
    },
  };
}

async function getWorkflow(id) {
  if (!/^[A-Za-z0-9]+$/.test(id) || id.length > 64) {
    return { status: 400, body: { error: "Invalid workflow ID" } };
  }

  const data = await n8nGet(`/workflows/${encodeURIComponent(id)}`);
  return { status: 200, body: scrubDeep(data) };
}

// ---------- Execution handlers ----------
const VALID_EXEC_STATUSES = new Set(["error", "new", "running", "success", "waiting"]);

async function listExecutions(url) {
  const params = url.searchParams;
  const query = new URLSearchParams();

  const cursor = params.get("cursor");
  const limit = params.get("limit");
  const workflowId = params.get("workflowId");
  const status = params.get("status");

  if (cursor) {
    if (!/^[A-Za-z0-9+/=_-]+$/.test(cursor) || cursor.length > 512) {
      return { status: 400, body: { error: "Invalid cursor" } };
    }
    query.set("cursor", cursor);
  }

  if (limit) {
    const n = parseInt(limit, 10);
    if (isNaN(n) || n < 1 || n > 250) {
      return { status: 400, body: { error: "limit must be 1-250" } };
    }
    query.set("limit", String(n));
  }

  if (workflowId) {
    if (!/^[A-Za-z0-9]+$/.test(workflowId) || workflowId.length > 64) {
      return { status: 400, body: { error: "Invalid workflowId" } };
    }
    query.set("workflowId", workflowId);
  }

  if (status) {
    if (!VALID_EXEC_STATUSES.has(status)) {
      return { status: 400, body: { error: "status must be one of: error, new, running, success, waiting" } };
    }
    query.set("status", status);
  }

  const qs = query.toString();
  const data = await n8nGet(`/executions${qs ? `?${qs}` : ""}`);

  if (!Array.isArray(data.data)) {
    throw new Error("Unexpected response format from n8n API");
  }

  return {
    status: 200,
    body: {
      data: data.data.map((ex) => ({
        id: ex.id,
        workflowId: ex.workflowId,
        status: ex.status,
        startedAt: ex.startedAt,
        stoppedAt: ex.stoppedAt,
        finished: ex.finished,
      })),
      nextCursor: data.nextCursor ?? null,
    },
  };
}

async function getExecution(id) {
  if (!/^[A-Za-z0-9]+$/.test(id) || id.length > 64) {
    return { status: 400, body: { error: "Invalid execution ID" } };
  }

  const data = await n8nGet(`/executions/${encodeURIComponent(id)}`);
  return { status: 200, body: scrubDeep(data) };
}

// ---------- Router ----------
async function handleRequest(req, res) {
  // URL length guard
  if (req.url.length > MAX_URL_LENGTH) {
    return json(res, 414, { error: "Request URL too large" }, req);
  }

  // Health check (no auth required)
  if (req.method === "GET" && req.url === "/health") {
    return json(res, 200, { status: "ok" }, req);
  }

  // Homepage (no auth required)
  if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
    return serveHomepage(res);
  }

  // CORS preflight
  if (req.method === "OPTIONS") {
    const origin = req.headers.origin || "";
    if (ALLOWED_ORIGIN && origin === ALLOWED_ORIGIN) {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "X-N8N-API-KEY, Content-Type",
        "Vary": "Origin",
        "X-Content-Type-Options": "nosniff",
      });
      return res.end();
    }
    res.writeHead(403, { "X-Content-Type-Options": "nosniff" });
    return res.end();
  }

  // Auth
  const ip = getClientIP(req);
  if (!checkAuthRateLimit(ip)) {
    return json(res, 429, { error: "Too many failed auth attempts — try again later" }, req);
  }
  if (!authenticate(req)) {
    recordAuthFailure(ip);
    return json(res, 401, { error: "Unauthorized — invalid API key" }, req);
  }

  // Only GET allowed
  if (req.method !== "GET") {
    return json(res, 405, { error: "Method not allowed — read-only proxy" }, req);
  }

  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;

  try {
    let result;

    if (path === "/api/v1/workflows") {
      result = await listWorkflows(url);
    } else if (path === "/api/v1/executions") {
      result = await listExecutions(url);
    } else {
      const wfMatch = path.match(/^\/api\/v1\/workflows\/([A-Za-z0-9]+)$/);
      const exMatch = path.match(/^\/api\/v1\/executions\/([A-Za-z0-9]+)$/);
      if (wfMatch) {
        result = await getWorkflow(wfMatch[1]);
      } else if (exMatch) {
        result = await getExecution(exMatch[1]);
      } else {
        return json(res, 404, { error: "Not found — available: /api/v1/workflows, /api/v1/executions" }, req);
      }
    }

    return json(res, result.status, result.body, req);
  } catch (err) {
    const isRateLimit = err.message.includes("Rate limit");
    const status = isRateLimit ? 429 : 502;
    const safeMessage = isRateLimit
      ? "Rate limit exceeded — try again later"
      : "Upstream request failed";
    console.error(`[${new Date().toISOString()}] ${req.method} ${path} -> ${status}: ${err.message}`);
    return json(res, status, { error: safeMessage }, req);
  }
}

// ---------- Start ----------
const server = createServer(handleRequest);

server.listen(PORT, HOST, () => {
  const isProduction = process.env.NODE_ENV === "production" || process.env.RAILWAY_ENVIRONMENT;

  console.log(`\n  n8n read-only proxy running on http://${HOST}:${PORT}`);
  if (!process.env.PROXY_API_KEY && !isProduction) {
    console.log(`\n  Your read-only API key:\n`);
    console.log(`    ${PROXY_API_KEY}\n`);
  } else if (!process.env.PROXY_API_KEY && isProduction) {
    console.log(`\n  WARNING: No PROXY_API_KEY set — using auto-generated key.`);
    console.log(`  Set PROXY_API_KEY in your environment variables.\n`);
  } else {
    console.log(`\n  Using API key from PROXY_API_KEY env var.\n`);
  }
  console.log(`  Trust proxy: ${TRUST_PROXY ? "yes" : "no"}`);
  console.log(`  CORS origin: ${ALLOWED_ORIGIN || "disabled (no ALLOWED_ORIGIN set)"}`);
  console.log(`  Endpoints:`);
  console.log(`    GET /health`);
  console.log(`    GET /api/v1/workflows`);
  console.log(`    GET /api/v1/workflows/:id`);
  console.log(`    GET /api/v1/executions`);
  console.log(`    GET /api/v1/executions/:id\n`);
});

// ---------- Graceful shutdown ----------
function shutdown(signal) {
  console.log(`\n  ${signal} received — shutting down...`);
  server.close(() => {
    console.log("  Server closed.");
    process.exit(0);
  });
  // Force exit after 10s if connections don't drain
  setTimeout(() => {
    console.error("  Forced exit — connections did not drain in time.");
    process.exit(1);
  }, 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
