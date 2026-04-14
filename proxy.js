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
