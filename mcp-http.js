import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
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

// ---------- Register tools on an McpServer instance ----------
function registerTools(server) {
  server.tool(
    "list_workflows",
    "List all n8n workflows with their IDs, names, active status, and tags",
    {
      cursor: z.string().max(512).regex(/^[A-Za-z0-9+/=_-]+$/).optional()
        .describe("Pagination cursor from a previous response"),
      limit: z.number().int().min(1).max(250).optional()
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
    "List n8n executions with optional filters by workflow ID and status",
    {
      cursor: z.string().max(512).regex(/^[A-Za-z0-9+/=_-]+$/).optional()
        .describe("Pagination cursor from a previous response"),
      limit: z.number().int().min(1).max(250).optional()
        .describe("Number of executions to return (default 100, max 250)"),
      workflowId: WORKFLOW_ID_SCHEMA.optional().describe("Filter executions by workflow ID"),
      status: z.enum(["error", "new", "running", "success", "waiting"]).optional()
        .describe("Filter by execution status"),
    },
    async ({ cursor, limit, workflowId, status }) => {
      const params = new URLSearchParams();
      if (cursor) params.set("cursor", cursor);
      if (limit) params.set("limit", String(limit));
      if (workflowId) params.set("workflowId", workflowId);
      if (status) params.set("status", status);
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

// ---------- Session management ----------
const sessions = new Map();

// ---------- HTTP Server ----------
const httpServer = createServer(async (req, res) => {
  // Health check
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }

  // Only handle /mcp path
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (url.pathname !== "/mcp") {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found. MCP endpoint is at /mcp" }));
    return;
  }

  // Auth — require PROXY_API_KEY via Authorization Bearer header
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (token !== PROXY_API_KEY) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Unauthorized" }));
    return;
  }

  // Route to existing session
  const sessionId = req.headers["mcp-session-id"];
  if (sessionId && sessions.has(sessionId)) {
    const { transport } = sessions.get(sessionId);
    await transport.handleRequest(req, res);
    return;
  }

  // Reject requests with unknown session IDs
  if (sessionId && !sessions.has(sessionId)) {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Session not found" }));
    return;
  }

  // New session — create transport, server, connect, then handle
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    enableJsonResponse: true,
    onsessioninitialized: (id) => {
      sessions.set(id, { transport, server: mcpServer });
    },
  });

  transport.onclose = () => {
    if (transport.sessionId) {
      sessions.delete(transport.sessionId);
    }
  };

  const mcpServer = new McpServer({
    name: "n8n-readonly",
    version: "1.1.0",
  });
  registerTools(mcpServer);

  await mcpServer.connect(transport);
  await transport.handleRequest(req, res);
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
