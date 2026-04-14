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
const FETCH_TIMEOUT_MS = 30_000;

async function n8nGet(path) {
  checkRateLimit();

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  let res;
  try {
    res = await fetch(`${BASE_URL}/api/v1${path}`, {
      method: "GET",
      signal: controller.signal,
      headers: {
        "X-N8N-API-KEY": API_KEY,
        Accept: "application/json",
      },
    });
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("n8n API request timed out");
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }

  if (!res.ok) {
    throw new Error(`n8n API request failed with status ${res.status}`);
  }

  let data;
  try {
    data = await res.json();
  } catch {
    throw new Error("n8n API returned invalid JSON");
  }

  if (!data || typeof data !== "object") {
    throw new Error("n8n API returned unexpected response format");
  }

  return data;
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
  /sk_live_[a-zA-Z0-9]{20,}/g, // Stripe live key
  /sk_test_[a-zA-Z0-9]{20,}/g, // Stripe test key
  /AKIA[0-9A-Z]{16}/g, // AWS access key
  /ASIA[0-9A-Z]{16}/g, // AWS temporary key
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, // PEM private keys
  /Basic [A-Za-z0-9+/]+={0,2}/g, // Basic auth
  /Bearer [a-zA-Z0-9\-._~+/]+=*/g, // Bearer tokens
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
    if (/^credential/i.test(k) && v && typeof v === "object") {
      if (k === "credentials") {
        out[k] = Object.fromEntries(
          Object.entries(v).map(([credType, credRef]) => [
            credType,
            { name: credRef?.name ?? "[REDACTED]", id: "[REDACTED]" },
          ])
        );
      } else {
        out[k] = "[REDACTED]";
      }
      continue;
    }
    out[k] = scrubDeep(v, k);
  }
  return out;
}

export { n8nGet, scrubDeep, checkRateLimit };
