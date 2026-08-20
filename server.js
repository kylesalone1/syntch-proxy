import express from "express";
import rateLimit from "express-rate-limit";

const PROXY_SECRET = process.env.PROXY_SECRET;
const SYNTCH_TARGET = (process.env.SYNTCH_TARGET || "http://syntch-sandbox.simpay.net/api").replace(/\/$/, "");
const PORT = parseInt(process.env.PORT || "3000", 10);
const RATE_LIMIT_PER_MINUTE = parseInt(process.env.RATE_LIMIT_PER_MINUTE || "60", 10);
const LOG_LEVEL = process.env.LOG_LEVEL || "info";

if (!PROXY_SECRET) {
  console.error("[proxy] FATAL: PROXY_SECRET env var is not set");
  process.exit(1);
}

const ALLOWED_ROUTES = [
  { method: "POST", pattern: /^\/Authenticate$/, upstreamPath: () => "/Authenticate", name: "authenticate" },
  { method: "POST", pattern: /^\/api\/auth$/, upstreamPath: () => "/Authenticate", name: "authenticate_api_auth" },
  { method: "POST", pattern: /^\/auth$/, upstreamPath: () => "/Authenticate", name: "authenticate_short" },
  { method: "POST", pattern: /^\/merchants\/([^/]+)\/tokens\/cards$/, upstreamPath: (m) => `/merchants/${m[1]}/tokens/cards`, name: "tokenize" },
  { method: "POST", pattern: /^\/merchants\/([^/]+)\/tokens$/, upstreamPath: (m) => `/merchants/${m[1]}/tokens`, name: "tokenize_from_pnref" },
  { method: "POST", pattern: /^\/v2\/transactions\/bcp$/, upstreamPath: () => "/v2/transactions/bcp", name: "charge" },
  { method: "POST", pattern: /^\/transactions$/, upstreamPath: () => "/transactions", name: "transaction_token_sale" },
  { method: "GET", pattern: /^\/reports\/transactions\/([0-9]+)$/, upstreamPath: (m) => `/reports/transactions/${m[1]}`, name: "transaction_report" },
  { method: "POST", pattern: /^\/customers$/, upstreamPath: () => "/customers", name: "create_customer" },
  { method: "POST", pattern: /^\/merchants\/([^/]+)\/customers$/, upstreamPath: (m) => `/merchants/${m[1]}/customers`, name: "create_merchant_customer" },
  { method: "POST", pattern: /^\/merchants\/([^/]+)\/customers\/([^/]+)\/contracts$/, upstreamPath: (m) => `/merchants/${m[1]}/customers/${m[2]}/contracts`, name: "create_contract" },
  { method: "DELETE", pattern: /^\/merchants\/([^/]+)\/customers\/([^/]+)\/contracts\/([^/]+)$/, upstreamPath: (m) => `/merchants/${m[1]}/customers/${m[2]}/contracts/${m[3]}`, name: "cancel_contract" },
];

const SENSITIVE_KEYS = new Set(["number","cardnumber","cvv","cvc","password","pin","expirationmonth","expirationyear","expiryyear","expirymonth"]);

function maskValue(key, value) {
  if (typeof value !== "string" && typeof value !== "number") return value;
  const s = String(value);
  const k = key.toLowerCase().replace(/[_-]/g, "");
  if (k === "number" || k === "cardnumber") return s.length >= 4 ? `****${s.slice(-4)}` : "****";
  if (SENSITIVE_KEYS.has(k)) return "****";
  return value;
}

function maskObject(obj, depth = 0) {
  if (depth > 5 || obj == null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map((v) => maskObject(v, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    const mk = maskValue(k, v);
    out[k] = mk === v && typeof v === "object" ? maskObject(v, depth + 1) : mk;
  }
  return out;
}

function log(level, ...args) {
  const levels = { debug: 0, info: 1, error: 2 };
  if ((levels[level] ?? 1) >= (levels[LOG_LEVEL] ?? 1)) {
    (level === "error" ? console.error : console.log)(`[proxy][${level}]`, ...args);
  }
}

const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: "64kb" }));

app.get("/health", (_req, res) => {
  res.json({ ok: true, target: SYNTCH_TARGET });
});

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: RATE_LIMIT_PER_MINUTE,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests" },
  keyGenerator: (req) => req.ip ?? "unknown",
});
app.use(limiter);

function requireSecret(req, res, next) {
  const provided = req.headers["x-proxy-secret"];
  if (!provided || provided !== PROXY_SECRET) {
    log("error", `auth_failed ip=${req.ip} path=${req.path}`);
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

app.all("*", requireSecret, async (req, res) => {
  const incomingPath = req.path;
  const incomingMethod = req.method.toUpperCase();

  if (incomingMethod !== "POST" && incomingMethod !== "GET" && incomingMethod !== "DELETE") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  let routeName = null;
  let upstreamPath = null;
  for (const route of ALLOWED_ROUTES) {
    if (route.method !== incomingMethod) continue;
    const match = incomingPath.match(route.pattern);
    if (match) { routeName = route.name; upstreamPath = route.upstreamPath(match); break; }
  }

  if (!upstreamPath) {
    return res.status(403).json({ error: "Route not permitted" });
  }

  const upstreamUrl = `${SYNTCH_TARGET}${upstreamPath}`;
  const requestId = Math.random().toString(36).slice(2, 10);
  log("info", `req id=${requestId} route=${routeName} -> ${upstreamUrl}`);

  const forwardHeaders = { "content-type": "application/json", accept: "application/json" };
  if (req.headers["authorization"]) forwardHeaders["authorization"] = req.headers["authorization"];

  const t0 = Date.now();
  let upstreamRes;
  try {
    upstreamRes = await fetch(upstreamUrl, {
      method: incomingMethod,
      headers: forwardHeaders,
      body: incomingMethod === "POST" ? JSON.stringify(req.body) : undefined,
    });
  } catch (err) {
    log("error", `upstream_error id=${requestId} err=${err.message}`);
    return res.status(502).json({ error: "Upstream network error", message: err.message });
  }

  const elapsed = Date.now() - t0;
  const responseText = await upstreamRes.text();
  log("info", `res id=${requestId} route=${routeName} status=${upstreamRes.status} elapsed=${elapsed}ms`);

  res.status(upstreamRes.status);
  res.set("content-type", upstreamRes.headers.get("content-type") || "application/json");
  res.send(responseText);
});

app.listen(PORT, () => {
  log("info", `started port=${PORT} target=${SYNTCH_TARGET}`);
});
