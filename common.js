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

export { n8nGet, scrubDeep, checkRateLimit };
