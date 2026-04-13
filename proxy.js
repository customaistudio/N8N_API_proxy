import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { n8nGet, scrubDeep } from "./common.js";

// ---------- Config ----------
const PORT = parseInt(process.env.PORT || "3000", 10);
const PROXY_API_KEY = randomBytes(32).toString("hex");

// ---------- Helpers ----------
function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function authenticate(req) {
  return req.headers["x-n8n-api-key"] === PROXY_API_KEY;
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

// ---------- Router ----------
async function handleRequest(req, res) {
  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "X-N8N-API-KEY, Content-Type",
    });
    return res.end();
  }

  // Auth
  if (!authenticate(req)) {
    return json(res, 401, { error: "Unauthorized — invalid API key" });
  }

  // Only GET allowed
  if (req.method !== "GET") {
    return json(res, 405, { error: "Method not allowed — read-only proxy" });
  }

  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;

  try {
    let result;

    if (path === "/api/v1/workflows") {
      result = await listWorkflows(url);
    } else {
      const match = path.match(/^\/api\/v1\/workflows\/([A-Za-z0-9]+)$/);
      if (match) {
        result = await getWorkflow(match[1]);
      } else {
        return json(res, 404, { error: "Not found — only /api/v1/workflows endpoints are available" });
      }
    }

    return json(res, result.status, result.body);
  } catch (err) {
    const status = err.message.includes("Rate limit") ? 429 : 502;
    return json(res, status, { error: err.message });
  }
}

// ---------- Start ----------
const server = createServer(handleRequest);

server.listen(PORT, () => {
  console.log(`\n  n8n read-only proxy running on http://localhost:${PORT}`);
  console.log(`\n  Your read-only API key:\n`);
  console.log(`    ${PROXY_API_KEY}\n`);
  console.log(`  Use it with header:  X-N8N-API-KEY: ${PROXY_API_KEY}`);
  console.log(`  Endpoints:`);
  console.log(`    GET /api/v1/workflows`);
  console.log(`    GET /api/v1/workflows/:id\n`);
});
