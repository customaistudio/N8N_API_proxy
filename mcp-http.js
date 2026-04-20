import { createServer } from "node:http";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { n8nGet, scrubDeep } from "./common.js";

process.on("unhandledRejection", (reason) => {
  console.error("[FATAL] Unhandled rejection:", reason);
  process.exit(1);
});

// ---------- Config ----------
const PORT = parseInt(process.env.PORT || "3000", 10);
const HOST = process.env.HOST || "0.0.0.0";
const PROXY_API_KEY = process.env.PROXY_API_KEY;

if (!PROXY_API_KEY) {
  console.error("PROXY_API_KEY is required for MCP HTTP server");
  process.exit(1);
}

// ---------- Shared schemas ----------
const WORKFLOW_ID_SCHEMA = z
  .string().min(1).max(64)
  .regex(/^[A-Za-z0-9]+$/, "Workflow ID must be alphanumeric");

const EXECUTION_ID_SCHEMA = z
  .string().min(1).max(64)
  .regex(/^[A-Za-z0-9]+$/, "Execution ID must be alphanumeric");

const PROJECT_ID_SCHEMA = z
  .string().min(1).max(64)
  .regex(/^[A-Za-z0-9_-]+$/, "Project ID must be alphanumeric (hyphens/underscores allowed)");

// ---------- Register tools on an McpServer instance ----------
function registerTools(server) {
  server.tool(
    "list_projects",
    "List all n8n projects (workspaces) with their IDs and names. Use project IDs to filter workflows and executions by project.",
    {
      cursor: z.string().max(512).regex(/^[A-Za-z0-9+/=_-]+$/).optional()
        .describe("Pagination cursor from a previous response"),
      limit: z.number().int().min(1).max(250).optional()
        .describe("Number of projects to return (default 100, max 250)"),
    },
    async ({ cursor, limit }) => {
      const params = new URLSearchParams();
      if (cursor) params.set("cursor", cursor);
      if (limit) params.set("limit", String(limit));
      const query = params.toString();
      const data = await n8nGet(`/projects${query ? `?${query}` : ""}`);
      if (!Array.isArray(data.data)) throw new Error("Unexpected response format");
      const projects = data.data.map((p) => ({
        id: p.id, name: p.name, type: p.type,
        createdAt: p.createdAt, updatedAt: p.updatedAt,
      }));
      return { content: [{ type: "text", text: JSON.stringify({ projects, nextCursor: data.nextCursor ?? null }, null, 2) }] };
    }
  );

  server.tool(
    "list_workflows",
    "List all n8n workflows with their IDs, names, active status, and tags. Optionally filter by project ID to see workflows across different projects.",
    {
      cursor: z.string().max(512).regex(/^[A-Za-z0-9+/=_-]+$/).optional()
        .describe("Pagination cursor from a previous response"),
      limit: z.number().int().min(1).max(250).optional()
        .describe("Number of workflows to return (default 100, max 250)"),
      active: z.boolean().optional().describe("Filter by active status"),
      projectId: PROJECT_ID_SCHEMA.optional()
        .describe("Filter workflows by project ID (use list_projects to get project IDs)"),
    },
    async ({ cursor, limit, active, projectId }) => {
      const params = new URLSearchParams();
      if (cursor) params.set("cursor", cursor);
      if (limit) params.set("limit", String(limit));
      if (active !== undefined) params.set("active", String(active));
      if (projectId) params.set("projectId", projectId);
      const query = params.toString();
      const data = await n8nGet(`/workflows${query ? `?${query}` : ""}`);
      if (!Array.isArray(data.data)) throw new Error("Unexpected response format");
      const workflows = data.data.map((wf) => ({
        id: wf.id, name: wf.name, active: wf.active,
        tags: wf.tags?.map((t) => t.name) ?? [],
        createdAt: wf.createdAt, updatedAt: wf.updatedAt,
      }));
      return { content: [{ type: "text", text: JSON.stringify({ workflows, nextCursor: data.nextCursor ?? null }, null, 2) }] };
    }
  );

  server.tool(
    "get_workflow",
    "Get the full details of a specific n8n workflow by ID, including all nodes, connections, and settings (secrets are redacted)",
    { id: WORKFLOW_ID_SCHEMA.describe("The workflow ID") },
    async ({ id }) => {
      const data = await n8nGet(`/workflows/${encodeURIComponent(id)}`);
      return { content: [{ type: "text", text: JSON.stringify(scrubDeep(data), null, 2) }] };
    }
  );

  server.tool(
    "list_executions",
    "List n8n executions with optional filters by workflow ID, status, and project ID",
    {
      cursor: z.string().max(512).regex(/^[A-Za-z0-9+/=_-]+$/).optional()
        .describe("Pagination cursor from a previous response"),
      limit: z.number().int().min(1).max(250).optional()
        .describe("Number of executions to return (default 100, max 250)"),
      workflowId: WORKFLOW_ID_SCHEMA.optional().describe("Filter executions by workflow ID"),
      status: z.enum(["error", "new", "running", "success", "waiting"]).optional()
        .describe("Filter by execution status"),
      projectId: PROJECT_ID_SCHEMA.optional()
        .describe("Filter executions by project ID (use list_projects to get project IDs)"),
    },
    async ({ cursor, limit, workflowId, status, projectId }) => {
      const params = new URLSearchParams();
      if (cursor) params.set("cursor", cursor);
      if (limit) params.set("limit", String(limit));
      if (workflowId) params.set("workflowId", workflowId);
      if (status) params.set("status", status);
      if (projectId) params.set("projectId", projectId);
      const query = params.toString();
      const data = await n8nGet(`/executions${query ? `?${query}` : ""}`);
      if (!Array.isArray(data.data)) throw new Error("Unexpected response format");
      const executions = data.data.map((ex) => ({
        id: ex.id, workflowId: ex.workflowId, status: ex.status,
        startedAt: ex.startedAt, stoppedAt: ex.stoppedAt, finished: ex.finished,
      }));
      return { content: [{ type: "text", text: JSON.stringify({ executions, nextCursor: data.nextCursor ?? null }, null, 2) }] };
    }
  );

  server.tool(
    "get_execution",
    "Get full details of a specific n8n execution by ID, including node results and timing (secrets are redacted)",
    { id: EXECUTION_ID_SCHEMA.describe("The execution ID") },
    async ({ id }) => {
      const data = await n8nGet(`/executions/${encodeURIComponent(id)}`);
      return { content: [{ type: "text", text: JSON.stringify(scrubDeep(data), null, 2) }] };
    }
  );
}

// ---------- REST helpers ----------
function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    "X-Content-Type-Options": "nosniff",
  });
  res.end(payload);
}

function authenticateApiKey(req) {
  const supplied = req.headers["x-n8n-api-key"] || "";
  if (supplied.length !== PROXY_API_KEY.length) return false;
  return timingSafeEqual(Buffer.from(supplied, "utf8"), Buffer.from(PROXY_API_KEY, "utf8"));
}

// ---------- REST route handlers ----------
const VALID_EXEC_STATUSES = new Set(["error", "new", "running", "success", "waiting"]);

async function restListProjects(url) {
  const params = url.searchParams;
  const query = new URLSearchParams();
  const cursor = params.get("cursor");
  const limit = params.get("limit");
  if (cursor) {
    if (!/^[A-Za-z0-9+/=_-]+$/.test(cursor) || cursor.length > 512) return { status: 400, body: { error: "Invalid cursor" } };
    query.set("cursor", cursor);
  }
  if (limit) {
    const n = parseInt(limit, 10);
    if (isNaN(n) || n < 1 || n > 250) return { status: 400, body: { error: "limit must be 1-250" } };
    query.set("limit", String(n));
  }
  const qs = query.toString();
  const data = await n8nGet(`/projects${qs ? `?${qs}` : ""}`);
  if (!Array.isArray(data.data)) throw new Error("Unexpected response format");
  return {
    status: 200,
    body: {
      data: data.data.map((p) => ({ id: p.id, name: p.name, type: p.type, createdAt: p.createdAt, updatedAt: p.updatedAt })),
      nextCursor: data.nextCursor ?? null,
    },
  };
}

async function restListWorkflows(url) {
  const params = url.searchParams;
  const query = new URLSearchParams();
  const cursor = params.get("cursor");
  const limit = params.get("limit");
  const active = params.get("active");
  const projectId = params.get("projectId");
  if (cursor) {
    if (!/^[A-Za-z0-9+/=_-]+$/.test(cursor) || cursor.length > 512) return { status: 400, body: { error: "Invalid cursor" } };
    query.set("cursor", cursor);
  }
  if (limit) {
    const n = parseInt(limit, 10);
    if (isNaN(n) || n < 1 || n > 250) return { status: 400, body: { error: "limit must be 1-250" } };
    query.set("limit", String(n));
  }
  if (active !== null) {
    if (active !== "true" && active !== "false") return { status: 400, body: { error: "active must be true or false" } };
    query.set("active", active);
  }
  if (projectId) {
    if (!/^[A-Za-z0-9_-]+$/.test(projectId) || projectId.length > 64) return { status: 400, body: { error: "Invalid projectId" } };
    query.set("projectId", projectId);
  }
  const qs = query.toString();
  const data = await n8nGet(`/workflows${qs ? `?${qs}` : ""}`);
  if (!Array.isArray(data.data)) throw new Error("Unexpected response format");
  return {
    status: 200,
    body: {
      data: data.data.map((wf) => ({ id: wf.id, name: wf.name, active: wf.active, tags: wf.tags?.map((t) => t.name) ?? [], createdAt: wf.createdAt, updatedAt: wf.updatedAt })),
      nextCursor: data.nextCursor ?? null,
    },
  };
}

async function restGetWorkflow(id) {
  if (!/^[A-Za-z0-9]+$/.test(id) || id.length > 64) return { status: 400, body: { error: "Invalid workflow ID" } };
  const data = await n8nGet(`/workflows/${encodeURIComponent(id)}`);
  return { status: 200, body: scrubDeep(data) };
}

async function restListExecutions(url) {
  const params = url.searchParams;
  const query = new URLSearchParams();
  const cursor = params.get("cursor");
  const limit = params.get("limit");
  const workflowId = params.get("workflowId");
  const status = params.get("status");
  const projectId = params.get("projectId");
  if (cursor) {
    if (!/^[A-Za-z0-9+/=_-]+$/.test(cursor) || cursor.length > 512) return { status: 400, body: { error: "Invalid cursor" } };
    query.set("cursor", cursor);
  }
  if (limit) {
    const n = parseInt(limit, 10);
    if (isNaN(n) || n < 1 || n > 250) return { status: 400, body: { error: "limit must be 1-250" } };
    query.set("limit", String(n));
  }
  if (workflowId) {
    if (!/^[A-Za-z0-9]+$/.test(workflowId) || workflowId.length > 64) return { status: 400, body: { error: "Invalid workflowId" } };
    query.set("workflowId", workflowId);
  }
  if (status) {
    if (!VALID_EXEC_STATUSES.has(status)) return { status: 400, body: { error: "status must be one of: error, new, running, success, waiting" } };
    query.set("status", status);
  }
  if (projectId) {
    if (!/^[A-Za-z0-9_-]+$/.test(projectId) || projectId.length > 64) return { status: 400, body: { error: "Invalid projectId" } };
    query.set("projectId", projectId);
  }
  const qs = query.toString();
  const data = await n8nGet(`/executions${qs ? `?${qs}` : ""}`);
  if (!Array.isArray(data.data)) throw new Error("Unexpected response format");
  return {
    status: 200,
    body: {
      data: data.data.map((ex) => ({ id: ex.id, workflowId: ex.workflowId, status: ex.status, startedAt: ex.startedAt, stoppedAt: ex.stoppedAt, finished: ex.finished })),
      nextCursor: data.nextCursor ?? null,
    },
  };
}

async function restGetExecution(id) {
  if (!/^[A-Za-z0-9]+$/.test(id) || id.length > 64) return { status: 400, body: { error: "Invalid execution ID" } };
  const data = await n8nGet(`/executions/${encodeURIComponent(id)}`);
  return { status: 200, body: scrubDeep(data) };
}

// ---------- Homepage ----------
function serveHomepage(res) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>n8n Read-Only API Proxy</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#0f1117;color:#e1e4e8;line-height:1.6;padding:2rem 1rem}
  .container{max-width:780px;margin:0 auto}
  h1{font-size:1.8rem;margin-bottom:.25rem;color:#fff}
  .subtitle{color:#8b949e;margin-bottom:2rem;font-size:1.05rem}
  h2{font-size:1.2rem;color:#fff;margin:2rem 0 .75rem;padding-bottom:.4rem;border-bottom:1px solid #21262d}
  p,li{color:#c9d1d9}ul,ol{padding-left:1.5rem;margin-bottom:.75rem}li{margin-bottom:.35rem}
  code{background:#161b22;padding:.15em .4em;border-radius:4px;font-size:.9em;color:#f0883e;font-family:"SF Mono","Fira Code",monospace}
  pre{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1rem;overflow-x:auto;margin:.75rem 0 1rem}
  pre code{background:none;padding:0;color:#e1e4e8}
  .endpoint{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:.75rem 1rem;margin:.5rem 0;display:flex;align-items:center;gap:.75rem}
  .method{background:#238636;color:#fff;padding:.15em .5em;border-radius:4px;font-size:.8rem;font-weight:600;font-family:monospace}
  .path{color:#58a6ff;font-family:monospace;font-size:.95rem}
  .desc{color:#8b949e;font-size:.85rem;margin-left:auto}
  .card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1.25rem;margin:1rem 0}
  .warn{border-color:#d29922}.warn-title{color:#d29922;font-weight:600;margin-bottom:.5rem}
  a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
  .footer{margin-top:3rem;padding-top:1.5rem;border-top:1px solid #21262d;color:#484f58;font-size:.85rem;text-align:center}
</style>
</head>
<body><div class="container">
<h1>n8n Read-Only API Proxy</h1>
<p class="subtitle">A secure, read-only HTTP proxy and MCP server for your n8n instance.</p>

<h2>REST API Endpoints</h2>
<p>Authenticated with <code>X-N8N-API-KEY</code> header.</p>
<div class="endpoint"><span class="method">GET</span><span class="path">/health</span><span class="desc">Health check (no auth)</span></div>
<div class="endpoint"><span class="method">GET</span><span class="path">/api/v1/projects</span><span class="desc">List all projects</span></div>
<div class="endpoint"><span class="method">GET</span><span class="path">/api/v1/workflows</span><span class="desc">List all workflows</span></div>
<div class="endpoint"><span class="method">GET</span><span class="path">/api/v1/workflows/:id</span><span class="desc">Get workflow details</span></div>
<div class="endpoint"><span class="method">GET</span><span class="path">/api/v1/executions</span><span class="desc">List executions</span></div>
<div class="endpoint"><span class="method">GET</span><span class="path">/api/v1/executions/:id</span><span class="desc">Get execution details</span></div>

<h2>MCP Server</h2>
<p>MCP (Model Context Protocol) endpoint at <code>/mcp</code>. Authenticated with <code>Authorization: Bearer</code> header. Add to your Claude config:</p>
<pre><code>{
  "mcpServers": {
    "n8n-readonly": {
      "type": "http",
      "url": "https://your-railway-app.up.railway.app/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_PROXY_API_KEY"
      }
    }
  }
}</code></pre>

<div class="card warn">
  <div class="warn-title">Security</div>
  <ul>
    <li>All responses have secrets automatically redacted</li>
    <li>Only GET / read operations allowed</li>
    <li>Your real n8n API key is never exposed to clients</li>
  </ul>
</div>

<div class="footer"><a href="https://github.com/customaistudio/N8N_API_proxy">GitHub</a> &middot; n8n Read-Only API Proxy v1.1.0</div>
</div></body></html>`;
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": Buffer.byteLength(html), "X-Content-Type-Options": "nosniff" });
  res.end(html);
}

// ---------- Session management ----------
const sessions = new Map();

// ---------- HTTP Server ----------
const httpServer = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;

  // Health check (no auth)
  if (req.method === "GET" && path === "/health") {
    return json(res, 200, { status: "ok" });
  }

  // Homepage (no auth)
  if (req.method === "GET" && (path === "/" || path === "/index.html")) {
    return serveHomepage(res);
  }

  // ---- MCP endpoint (/mcp) — Bearer auth ----
  if (path === "/mcp") {
    const authHeader = req.headers["authorization"] || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
    if (token !== PROXY_API_KEY) {
      return json(res, 401, { error: "Unauthorized" });
    }

    const sessionId = req.headers["mcp-session-id"];
    if (sessionId && sessions.has(sessionId)) {
      const { transport } = sessions.get(sessionId);
      await transport.handleRequest(req, res);
      return;
    }

    if (sessionId && !sessions.has(sessionId)) {
      return json(res, 404, { error: "Session not found" });
    }

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableJsonResponse: true,
      onsessioninitialized: (id) => {
        sessions.set(id, { transport, server: mcpServer });
      },
    });

    transport.onclose = () => {
      if (transport.sessionId) sessions.delete(transport.sessionId);
    };

    const mcpServer = new McpServer({ name: "n8n-readonly", version: "1.1.0" });
    registerTools(mcpServer);
    await mcpServer.connect(transport);
    await transport.handleRequest(req, res);
    return;
  }

  // ---- REST API (/api/v1/*) — X-N8N-API-KEY auth ----
  if (path.startsWith("/api/v1/")) {
    if (req.method !== "GET") {
      return json(res, 405, { error: "Method not allowed — read-only proxy" });
    }
    if (!authenticateApiKey(req)) {
      return json(res, 401, { error: "Unauthorized — invalid API key" });
    }

    try {
      let result;
      if (path === "/api/v1/projects") {
        result = await restListProjects(url);
      } else if (path === "/api/v1/workflows") {
        result = await restListWorkflows(url);
      } else if (path === "/api/v1/executions") {
        result = await restListExecutions(url);
      } else {
        const wfMatch = path.match(/^\/api\/v1\/workflows\/([A-Za-z0-9]+)$/);
        const exMatch = path.match(/^\/api\/v1\/executions\/([A-Za-z0-9]+)$/);
        if (wfMatch) result = await restGetWorkflow(wfMatch[1]);
        else if (exMatch) result = await restGetExecution(exMatch[1]);
        else return json(res, 404, { error: "Not found" });
      }
      return json(res, result.status, result.body);
    } catch (err) {
      const isRateLimit = err.message.includes("Rate limit");
      const status = isRateLimit ? 429 : 502;
      console.error(`[${new Date().toISOString()}] ${req.method} ${path} -> ${status}: ${err.message}`);
      return json(res, status, { error: isRateLimit ? "Rate limit exceeded" : "Upstream request failed" });
    }
  }

  json(res, 404, { error: "Not found" });
});

httpServer.listen(PORT, HOST, () => {
  console.log(`\n  n8n MCP HTTP server running on http://${HOST}:${PORT}`);
  console.log(`  MCP endpoint: /mcp`);
  console.log(`  Health check: /health\n`);
});

// Graceful shutdown
function shutdown(signal) {
  console.log(`\n  ${signal} received — shutting down...`);
  for (const { transport, server } of sessions.values()) {
    transport.close();
    server.close();
  }
  httpServer.close(() => {
    console.log("  Server closed.");
    process.exit(0);
  });
  setTimeout(() => {
    console.error("  Forced exit.");
    process.exit(1);
  }, 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
