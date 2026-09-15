import crypto from "node:crypto";
import dns from "node:dns/promises";
import { execFile } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import dgram from "node:dgram";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import AdmZip from "adm-zip";
import express from "express";
import multer from "multer";
import QRCode from "qrcode";
import { LOCAL_INSTANCE_ID, openStorage } from "./storage.js";
import { generateTotpSecret, verifyTotp, otpauthUri, generateRecoveryCodes } from "./totp.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageMetadata = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
const appVersion = process.env.APP_VERSION || packageMetadata.version;
const publicDir = path.join(__dirname, "public");
const dataDir = path.resolve(process.env.DATA_DIR || "/data");
const sitesDir = path.join(dataDir, "sites");
const uploadDir = path.join(dataDir, ".uploads");
const caddyDir = path.join(dataDir, "caddy");
const iconsDir = path.join(dataDir, "icons");
const logsDir = path.join(dataDir, "logs");
const backupsDir = path.join(dataDir, "backups");
const defaultSiteDir = path.join(dataDir, "default-site");
const certificatesRoot = path.join(dataDir, "certificates");
const customCertificatesDir = path.join(certificatesRoot, "custom");
const managedCertificatesDir = path.join(certificatesRoot, "managed");
const certificateExportsDir = path.join(certificatesRoot, "exports");
const accessLogPath = path.join(logsDir, "access.json");
const activityLogPath = path.join(logsDir, "activity.jsonl");
const certificateDir = path.join(managedCertificatesDir, "certificates");
const iconCatalogPath = path.join(iconsDir, "catalog.json");
const caddyfilePath = path.join(caddyDir, "Caddyfile");
const execFileAsync = promisify(execFile);
const scryptAsync = promisify(crypto.scrypt);
const adminPort = numberEnv("ADMIN_PORT", 8080);
const minPort = numberEnv("SITE_PORT_MIN", 9000);
const maxPort = numberEnv("SITE_PORT_MAX", 9099);
const adminUser = process.env.ADMIN_USERNAME || "admin";
const adminPassword = process.env.ADMIN_PASSWORD || "change-this-password";
const sessionSecret = process.env.SESSION_SECRET || crypto.createHash("sha256").update(`${adminUser}:${adminPassword}`).digest("hex");
const scheduledBackupPassword = process.env.BACKUP_PASSWORD || "";
const activeServers = new Map();
const activeStreams = new Map();
let sites = [];
let proxies = [];
let users = [];
let redirects = [];
let streams = [];
let accessLists = [];
let groups = [];
let settings = {};
let publicIpState = { address: null, checkedAt: null, error: null };
let gatewayError = null;
let lastGatewayReload = null;
let caddyVersion = "Unknown";
const recentActivity = [];
const upstreamHealth = new Map();
const certificateStatusCache = new Map();
const loginAttempts = new Map();
let currentAuditActor = null;
const probeFailures = { gateway: 0, http: 0, https: 0 };
let iconCatalog = null;
let storage;

function recordActivity(message, status = "ok") {
  const entry = { message, status, at: new Date().toISOString() };
  recentActivity.unshift(entry);
  recentActivity.splice(20);
  try { storage?.recordActivity(message, status); } catch (error) { console.warn("Could not record SQLite activity event:", error.message); }
  fsp.appendFile(activityLogPath, `${JSON.stringify(entry)}\n`).catch(() => {});
  try { storage?.recordAudit(message, status, null, currentAuditActor); } catch (error) { console.warn("Could not record SQLite audit event:", error.message); }
}

async function directorySize(directory) {
  let total = 0;
  const entries = await fsp.readdir(directory, { withFileTypes: true }).catch(error => error.code === "ENOENT" ? [] : Promise.reject(error));
  for (const entry of entries) {
    const itemPath = path.join(directory, entry.name);
    if (entry.isDirectory()) total += await directorySize(itemPath);
    else if (entry.isFile()) total += (await fsp.stat(itemPath)).size;
  }
  return total;
}

function numberEnv(name, fallback) {
  const value = Number.parseInt(process.env[name] || "", 10);
  return Number.isInteger(value) ? value : fallback;
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

async function passwordRecord(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = await scryptAsync(String(password), salt, 64);
  return { algorithm: "scrypt", salt, hash: hash.toString("hex") };
}

async function passwordMatches(password, record) {
  if (!record?.salt || !record?.hash) return false;
  const hash = await scryptAsync(String(password), record.salt, 64);
  return safeEqual(hash.toString("hex"), record.hash);
}

function publicUser(user) {
  const { password, sessionVersion, mfaSecret, mfaPendingSecret, mfaRecoveryCodes, ...safe } = user;
  return { ...safe, mfaEnabled: Boolean(user.mfaEnabled) };
}

function activeAdministrators() {
  return users.filter(user => user.role === "administrator" && user.status === "active");
}

function slugify(value) {
  return value.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48);
}

function sign(value) {
  return crypto.createHmac("sha256", sessionSecret).update(value).digest("hex");
}

function cookieMap(header = "") {
  return Object.fromEntries(header.split(";").map(v => v.trim().split("=").map(decodeURIComponent)).filter(v => v.length === 2));
}

function sessionUser(req) {
  const token = cookieMap(req.headers.cookie).webserver_session;
  if (!token) return null;
  const [userId, expires, sessionVersion, signature] = token.split(".");
  const user = users.find(item => item.id === userId && item.status === "active");
  if (!user || !expires || !sessionVersion || Number(expires) <= Date.now() || sessionVersion !== user.sessionVersion || !safeEqual(signature || "", sign(`${userId}.${expires}.${sessionVersion}`))) return null;
  return user;
}

const saveSites = async () => storage.saveCollection("sites", sites);
const saveProxies = async () => storage.saveCollection("proxies", proxies);
const saveUsers = async () => storage.saveCollection("users", users);
const saveGroups = async () => storage.saveCollection("groups", groups);
const saveRedirects = async () => storage.saveCollection("redirects", redirects);
const saveStreams = async () => storage.saveCollection("streams", streams);
const saveAccessLists = async () => storage.saveCollection("access_lists", accessLists);
const saveSettings = async () => storage.saveSettings(settings);

async function clearDirectoryContents(directory) {
  await fsp.mkdir(directory, { recursive: true });
  let lastError = null;
  for (let attempt = 0; attempt < 4; attempt++) {
    lastError = null;
    for (const entry of await fsp.readdir(directory, { withFileTypes: true })) {
      try { await fsp.rm(path.join(directory, entry.name), { recursive: true, force: true, maxRetries: 2, retryDelay: 100 }); }
      catch (error) { lastError = error; }
    }
    if (!(await fsp.readdir(directory)).length) return;
    await new Promise(resolve => setTimeout(resolve, 150 * (attempt + 1)));
  }
  if (lastError) throw lastError;
  throw new Error(`Could not clear ${directory}: directory is not empty.`);
}

async function loadSites() {
  await Promise.all([fsp.mkdir(sitesDir, { recursive: true }), fsp.mkdir(uploadDir, { recursive: true }), fsp.mkdir(caddyDir, { recursive: true }), fsp.mkdir(iconsDir, { recursive: true }), fsp.mkdir(logsDir, { recursive: true }), fsp.mkdir(backupsDir, { recursive: true }), fsp.mkdir(defaultSiteDir, { recursive: true }), fsp.mkdir(customCertificatesDir, { recursive: true }), fsp.mkdir(managedCertificatesDir, { recursive: true }), fsp.mkdir(certificateExportsDir, { recursive: true })]);
  if (!storage) storage = await openStorage(dataDir, backupsDir);
  storage.humanizeGatewayErrors?.();
  if (storage.snapshot) { recordActivity(`Legacy JSON migrated to SQLite. Safety backup: ${storage.snapshot.filename}.`); storage.snapshot = null; }
  sites = storage.loadCollection("sites").map(item => ({ ...item, healthEnabled: !(item.healthEnabled === false || String(item.healthEnabled).toLowerCase() === "false") }));
  proxies = storage.loadCollection("proxies").map(item => ({ ...item, healthEnabled: !(item.healthEnabled === false || String(item.healthEnabled).toLowerCase() === "false") }));
  try { const legacyAccess = await readAccessLogs(5000); storage.recordAccessEvents(legacyAccess.map((entry, index) => ({ ...entry, source: `legacy-${entry.at || "unknown"}-${index}` }))); } catch (error) { console.warn("Could not import access logs into SQLite:", error.message); }
  try {
    const storedActivity = storage.listActivity(20);
    if (storedActivity.length) recentActivity.push(...storedActivity);
    else {
      const lines = (await fsp.readFile(activityLogPath, "utf8")).trim().split("\n").slice(-20).reverse();
      const legacy = lines.filter(Boolean).map(line => JSON.parse(line));
      recentActivity.push(...legacy);
      for (const entry of legacy.reverse()) storage.recordActivity(entry.message, entry.status);
    }
  } catch { /* Activity history starts empty on a new installation. */ }
  users = storage.loadCollection("users");
  if (!users.length) {
    const now = new Date().toISOString();
    users = [{ id: crypto.randomUUID(), username: adminUser.toLowerCase(), displayName: "Administrator", role: "administrator", status: "active", password: await passwordRecord(adminPassword), source: "bootstrap", setupRequired: true, sessionVersion: crypto.randomBytes(16).toString("hex"), createdAt: now, updatedAt: now, lastLoginAt: null }];
    await saveUsers();
  }
  let usersChanged = false;
  for (const user of users) {
    if (user.setupRequired === undefined) { user.setupRequired = false; usersChanged = true; }
    if (!user.sessionVersion) { user.sessionVersion = crypto.randomBytes(16).toString("hex"); usersChanged = true; }
    if (user.mfaEnabled === undefined) { user.mfaEnabled = false; usersChanged = true; }
    if (!Array.isArray(user.mfaRecoveryCodes)) { user.mfaRecoveryCodes = []; usersChanged = true; }
  }
  if (usersChanged) await saveUsers();
  redirects = storage.loadCollection("redirects");
  streams = storage.loadCollection("streams").map(item => ({ ...item, healthEnabled: !(item.healthEnabled === false || String(item.healthEnabled).toLowerCase() === "false") }));
  accessLists = storage.loadCollection("access_lists");
  groups = storage.loadCollection("groups");
  const defaultSettings = {
    defaultSite: { mode: "themed404", redirectUrl: "", redirectCode: 302, preservePath: true, title: "Route not found", message: "The gateway is responding, but this address has not been configured.", customHtml: "" },
    backups: { enabled: false, frequency: "daily", hour: 2, retention: 7, type: "configuration", includeLogs: false, encrypt: false, lastRunAt: null, lastStatus: null },
    certificateHealth: { warningDays: 30, criticalDays: 7, staleMinutes: 10 },
    logsRetention: { accessDays: 30, activityDays: 90, auditDays: 365, certificateDays: 365, securityDays: 365, pruningEnabled: false }
  };
  const storedSettings = storage.loadSettings() || defaultSettings;
  settings = { ...defaultSettings, ...storedSettings, defaultSite: { ...defaultSettings.defaultSite, ...(storedSettings.defaultSite || {}) }, backups: { ...defaultSettings.backups, ...(storedSettings.backups || {}) }, certificateHealth: { ...defaultSettings.certificateHealth, ...(storedSettings.certificateHealth || {}) }, logsRetention: { ...defaultSettings.logsRetention, ...(storedSettings.logsRetention || {}) } };
  await saveSettings();
}

function normalizeDomain(value) {
  return String(value || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, "");
}
function normalizeDomains(primary, aliases = []) {
  return [...new Set([primary, ...(Array.isArray(aliases) ? aliases : String(aliases || "").split(/[\n,]+/))].map(normalizeDomain).filter(Boolean))];
}
function validateDomains(domains, exceptId) {
  for (const domain of domains) { const error = validateDomain(domain, exceptId); if (error) return error; }
  return null;
}

function validateDomain(domain, exceptId) {
  if (!domain) return null;
  if (domain.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) return "Enter a valid public domain such as app.example.com.";
  if ([...sites, ...proxies, ...redirects].some(item => normalizeDomains(item.domain, item.domains).includes(domain) && item.id !== exceptId)) return "That domain is already assigned.";
  return null;
}

function validateTarget(value) {
  try {
    const target = new URL(String(value || ""));
    if (!["http:", "https:"].includes(target.protocol) || !target.hostname || (target.pathname && target.pathname !== "/") || target.search || target.hash) throw new Error();
    return target.toString().replace(/\/$/, "");
  } catch {
    throw Object.assign(new Error("Target must be an HTTP or HTTPS address such as http://192.168.1.20:3000."), { status: 400 });
  }
}

function validateStreamPort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw Object.assign(new Error("Incoming port must be between 1 and 65535."), { status: 400 });
  return port;
}

function validateStreamHostPort(value) {
  const raw = String(value || "").trim();
  const match = raw.match(/^\[?([^\s\]]+)\]?:(\d{1,5})$/);
  if (!match) throw Object.assign(new Error("Forward to must be host:port, such as 192.168.1.20:22."), { status: 400 });
  const port = Number(match[2]);
  if (!match[1] || port < 1 || port > 65535) throw Object.assign(new Error("Forward to must be host:port, such as 192.168.1.20:22."), { status: 400 });
  return `${match[1]}:${port}`;
}

function streamPortConflict(port, exceptId) {
  if (port === adminPort || port === 80 || port === 443 || (port >= minPort && port <= maxPort)) return "That port is already reserved by the gateway.";
  if (streams.some(item => item.port === port && item.id !== exceptId)) return "That port is already used by another streaming host.";
  return null;
}

function cleanHeaders(value) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 30).map(item => ({ name: String(item.name || "").trim(), value: String(item.value || "").trim() }))
    .filter(item => /^[A-Za-z0-9-]{1,80}$/.test(item.name) && item.value.length <= 500);
}

function cleanLocations(value) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 20).map(item => {
    const location = { path: String(item.path || "").trim(), target: validateTarget(item.target), stripPrefix: Boolean(item.stripPrefix), requestHeaders: cleanHeaders(item.requestHeaders), upstreamTlsServerName: String(item.upstreamTlsServerName || "").trim().slice(0, 253), upstreamTlsInsecure: Boolean(item.upstreamTlsInsecure) };
    if (!/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*\*?$/.test(location.path)) throw Object.assign(new Error("Custom Location paths must start with / and may end with *."), { status: 400 });
    return location;
  });
}

function cleanCustomConfig(value) {
  const config = String(value || "").trim();
  if (config.length > 20000) throw Object.assign(new Error("Custom Caddy configuration must be 20 KB or less."), { status: 400 });
  if (/(^|\n)\s*(?:\{|admin\b|storage\b|import\b|persist_config\b)/i.test(config)) throw Object.assign(new Error("Global blocks, imports, and Caddy administration settings are not allowed here."), { status: 400 });
  return config;
}

function applyAdvancedSettings(item, body) {
  if (body.upstreams !== undefined) {
    if (!Array.isArray(body.upstreams) || body.upstreams.length > 10) throw Object.assign(new Error("Add up to 10 upstream targets."), { status: 400 });
    item.upstreams = body.upstreams.map(validateTarget);
  }
  if (body.lbPolicy !== undefined) item.lbPolicy = ["random", "round_robin", "least_conn", "ip_hash"].includes(body.lbPolicy) ? body.lbPolicy : "random";
  if (body.accessListId !== undefined) item.accessListId = String(body.accessListId || "");
  if (body.compression !== undefined) item.compression = ["off", "gzip", "automatic"].includes(body.compression) ? body.compression : "automatic";
  if (body.hstsSubdomains !== undefined) item.hstsSubdomains = Boolean(body.hstsSubdomains);
  if (body.blockCommonExploits !== undefined) item.blockCommonExploits = Boolean(body.blockCommonExploits);
  if (body.requestHeaders !== undefined) item.requestHeaders = cleanHeaders(body.requestHeaders);
  if (body.responseHeaders !== undefined) item.responseHeaders = cleanHeaders(body.responseHeaders);
  if (body.upstreamTlsServerName !== undefined) item.upstreamTlsServerName = String(body.upstreamTlsServerName || "").trim().slice(0, 253);
  if (body.upstreamTlsInsecure !== undefined) item.upstreamTlsInsecure = Boolean(body.upstreamTlsInsecure);
  if (body.healthEnabled !== undefined) item.healthEnabled = body.healthEnabled === true || (typeof body.healthEnabled === "string" && body.healthEnabled.toLowerCase() === "true");
  if (body.healthPath !== undefined) item.healthPath = /^\//.test(body.healthPath || "") ? String(body.healthPath).slice(0, 500) : "/";
  if (body.healthMethod !== undefined) item.healthMethod = ["GET", "HEAD"].includes(body.healthMethod) ? body.healthMethod : "GET";
  if (body.healthExpected !== undefined) {
    const expected = String(body.healthExpected || "200-499").trim().slice(0, 80);
    if (!/^\d{3}(?:\s*-\s*\d{3})?(?:\s*,\s*\d{3}(?:\s*-\s*\d{3})?)*$/.test(expected)) throw Object.assign(new Error("Expected status must contain HTTP codes or ranges, such as 200,204 or 200-399."), { status: 400 });
    item.healthExpected = expected;
  }
  if (body.healthTimeoutSeconds !== undefined) item.healthTimeoutSeconds = Math.min(Math.max(Number(body.healthTimeoutSeconds) || 4, 1), 60);
  if (body.healthRetries !== undefined) item.healthRetries = Math.min(Math.max(Number(body.healthRetries) || 0, 0), 3);
  if (body.customConfig !== undefined) item.customConfig = cleanCustomConfig(body.customConfig);
  if (body.locations !== undefined) item.locations = cleanLocations(body.locations);
}

function expectedStatusMatches(status, specification = "200-499") {
  return String(specification).split(",").some(part => {
    const value = part.trim();
    if (/^\d{3}$/.test(value)) return status === Number(value);
    const match = value.match(/^(\d{3})\s*-\s*(\d{3})$/);
    return match ? status >= Number(match[1]) && status <= Number(match[2]) : false;
  });
}

function caddySiteAddress(item) {
  const domains = normalizeDomains(item.domain, item.domains);
  return (item.tls === "http" ? domains.map(domain => `http://${domain}`) : domains).join(" ");
}

function caddyQuote(value) {
  // Caddy's Caddyfile lexer only special-cases \" inside a quoted string — it does NOT
  // collapse \\ into a single backslash (confirmed in caddyconfig/caddyfile/lexer.go: "all is
  // literal in quoted area, so only escape quotes"). Doubling backslashes here, as this used to,
  // corrupts any value that legitimately contains one (e.g. a regex like eval\( becomes eval\\(,
  // which Caddy then reads as an escaped backslash followed by an unclosed real group).
  return `"${String(value).replaceAll('"', '\\"').replaceAll("\n", " ")}"`;
}

function accessDirectives(accessListId) {
  const list = accessLists.find(item => item.id === accessListId && item.enabled !== false);
  if (!list) return [];
  const output = [];
  if (list.deniedNetworks?.length) output.push(`  @blocked-${list.id} remote_ip ${list.deniedNetworks.join(" ")}`, `  abort @blocked-${list.id}`);
  if (list.networks?.length) {
    output.push(`  @outside-${list.id} not remote_ip ${list.networks.join(" ")}`, `  abort @outside-${list.id}`);
  }
  if (list.credentials?.length || list.groups?.length) {
    output.push(`  @protected-${list.id} not path /_site-gateway/*`, `  forward_auth @protected-${list.id} 127.0.0.1:${adminPort} {`, `    uri /api/access-check?list=${list.id}`, "  }", `  handle /_site-gateway/* {`, `    reverse_proxy 127.0.0.1:${adminPort}`, "  }");
  }
  return output;
}

// Static, general-purpose ruleset for the "Block common exploits" toggle — not a full WAF. Rejects
// requests whose path matches common exploit-probe patterns before they reach the upstream: directory
// traversal, WordPress/PHP admin and scanner paths, dotfile exposure attempts, and SQL-injection-style
// query strings. One named matcher + one respond directive per host, so it's cheap to add or remove.
const COMMON_EXPLOIT_PATTERN = String.raw`(?i)(\.\./|\.\.\\|/etc/passwd|/wp-login\.php|/wp-admin(?:/|$)|/xmlrpc\.php|/\.env(?:$|\?)|/\.git/|/\.aws/|/vendor/phpunit|/phpunit(?:/|$)|eval\(|base64_decode\(|union(?:\s|%20|\+)+select|<script)`;

function exploitBlockDirectives(id) {
  return [`  @blocked-exploit-${id} {`, `    path_regexp ${caddyQuote(COMMON_EXPLOIT_PATTERN)}`, "  }", `  respond @blocked-exploit-${id} 403`];
}

function commonHostDirectives(item) {
  const output = [...accessDirectives(item.accessListId)];
  if (item.blockCommonExploits) output.push(...exploitBlockDirectives(item.id));
  if (item.compression !== "off") output.push(item.compression === "gzip" ? "  encode gzip" : "  encode zstd gzip");
  for (const header of item.responseHeaders || []) output.push(`  header ${header.name} ${caddyQuote(header.value)}`);
  if (item.hsts && item.tls !== "http") output.push(`  header Strict-Transport-Security ${caddyQuote(`max-age=31536000${item.hstsSubdomains ? "; includeSubDomains" : ""}`)}`);
  if (item.tls === "internal") output.push("  tls internal");
  if (item.tls === "custom" && item.certificatePath && item.keyPath) output.push(`  tls ${caddyQuote(item.certificatePath)} ${caddyQuote(item.keyPath)}`);
  return output;
}

function proxyBlock(target, item, indent = "  ") {
  const targets = Array.isArray(item.upstreams) && item.upstreams.length ? item.upstreams : [target];
  const output = [`${indent}reverse_proxy ${targets.join(" ")} {`];
  if (targets.length > 1) { const policy = ["round_robin", "least_conn", "ip_hash"].includes(item.lbPolicy) ? item.lbPolicy : "random"; output.push(`${indent}  lb_policy ${policy}`); }
  const timeout = Math.min(Math.max(Number(item.healthTimeoutSeconds) || 4, 1), 60);
  const httpsUpstream = targets.length > 0 && targets.every(value => /^https:\/\//i.test(String(value).trim()));
  if (httpsUpstream && (item.upstreamTlsServerName || item.upstreamTlsInsecure)) output.push(`${indent}  transport http {`, ...(item.upstreamTlsServerName ? [`${indent}    tls_server_name ${item.upstreamTlsServerName}`] : []), ...(item.upstreamTlsInsecure ? [`${indent}    tls_insecure_skip_verify`] : []), `${indent}    response_header_timeout ${timeout}s`, `${indent}  }`);
  for (const header of item.requestHeaders || []) output.push(`${indent}  header_up ${header.name} ${caddyQuote(header.value)}`);
  output.push(`${indent}}`);
  return output;
}

async function writeDefaultSitePage() {
  const selected = settings.defaultSite || {};
  const title = String(selected.title || (selected.mode === "welcome" ? "Gateway ready" : "Route not found")).replace(/[<>]/g, "");
  const message = String(selected.message || "The gateway is responding, but this address has not been configured.").replace(/[<>]/g, "");
  const html = selected.mode === "custom" && selected.customHtml
    ? String(selected.customHtml)
    : `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark light"><title>${title}</title><style>:root{color-scheme:dark light;--bg:#08101d;--card:#101a2b;--line:#25344c;--text:#eef4ff;--muted:#95a4ba;--green:#62e6a7}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 50% 0,#163829 0,transparent 42%),var(--bg);color:var(--text);font-family:Inter,system-ui,sans-serif}.card{width:min(620px,100%);padding:44px;border:1px solid var(--line);border-radius:22px;background:color-mix(in srgb,var(--card) 94%,transparent);box-shadow:0 28px 80px #0006}.mark-stack{display:flex;flex-direction:column;align-items:flex-start;gap:8px;margin-bottom:26px}.mark-icon{width:48px;height:48px;object-fit:contain;display:block}.mark-wordmark{width:140px;max-width:60%;height:auto;object-fit:contain;display:block}h1{margin:0;font-size:clamp(34px,7vw,56px);letter-spacing:-.05em;line-height:1.02}p{color:var(--muted);font-size:17px;line-height:1.65;margin:20px 0 0}.foot{padding-top:28px;margin-top:30px;border-top:1px solid var(--line);font-size:13px;color:var(--muted)}@media(prefers-color-scheme:light){:root{--bg:#f3f6fa;--card:#fff;--line:#d6dfeb;--text:#132033;--muted:#637188;--green:#138a5b}}</style></head><body><main class="card"><div class="mark-stack"><img class="mark-icon" src="data:image/png;base64,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" alt=""><img class="mark-wordmark" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAeAAAACgCAYAAADU+79NAADc3UlEQVR42uz9e3Sk2XUfhu59zvle9S4AhVeju9Hd090zwLzIITkckiKbFEVaoik5tnriWLEVKZFiybHv9UpWHMfLboyTlbuysuKV69w4iXxt32TZSkxIiWRKlGxRZosUSfEx5DwIzEw/0Y3GswDUu77HOWfv+8f3VaHQnCFFmZQouX5rYXUDKFR9j/Od/frt3wYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGOOPDDi+BGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjvAUQxvySMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcY4xniaxxhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhj/MnAWHP4W4CZ3/L6ICK/2etGfz7GGGOMMcYYf6IM8JsZxu+m4Xuz919ZWcH19WVcWlrjkZ/xtzPOY3xfLZzvfL2P7+UYY4zxb7MBHhjElZUVfMgoflcN4MOGd2VlBZeXlxEAoPHphoBnnhn57Yuwvb3Ny8vLvLa2xqPHMjbA34fGdmUFrwHA+vI6AlwFAICltTWEKyf/bOfGPM5d2ub1+jIvXc2crRWAFwb3d3xvxxhjjD/JBpiZcWBshwawkRrA6p07g++HG+GlS5cYrl8HuHIFAK5DvZ4axYGRRkQAAP5OjO/q6qpoNBqiWq3izk4B5+a6Yh9A+q6LAABuEJDfatFOoUD+5iZVq1Vau3qVYWVl8JknUtRjo/yHa3ivrazg+vIyXgWAtdoa7tyYx7nqNh4VJnBi7wghmRfdoI2hH2De9REAIOr0EABgYkESdBxqR10+6rV5MQ+005jnD1erNFhXQ4M8eIQQxvd3jDHG+GNrgJGZYQUA4fp1sVyvi0KhgHtBgJOdjiAimSR54TgKAZrQ7XpULJbYddt4CABeNyAAgHI54VarRTs7BZqb6/L58+e50+lwvV7nq1ev0lsZwlEDnBrf8+L06X3R7VaE6+4rIcpeLud5xihBHnEAaDqdvokioxt+qE8rZTenp2n7k59kAKBRI/xWBnhcO/7uG9+B4a02GmKuWkXorQlYXAToJKJPUkqVKI/KMl90lLQgNYP0lBVGSIQIwLiWUSVk4sAiGNNN6sSRIM8n3a4YbZqKHp/2abuzzXAdYH15mVevXqVxZDzGGGP8sTPAg2h3eXkZa7UahmEoD6RUfkuoXM4X+XwgI9FzfM+T1LPSKCl8ADDKIZeYAQCMY0gbh2yny0miyfNyut3uWdftUXsQqe7s0JNPPmmvX79Og3TxmxGpBsbXdTsynwellPEK0xPe/Y27TuOgXwyKpbwViEkYdt2cG16YmjGOA2EYcpgk2wYALADYgbHn77DuODbEf3DDu7y8jJ9uNMScuy27siCTKVfmyZFT+bIkcBQ7RhwdddSOiZzQRCpJYjdm7QsWjhQCEwRSQFai1NJIXcsVTVnluJgLKJCcgAnC7daRMXHfuJxY8gWVoG1hDQgAKI2K8d+WaDg9y3HkP8YYfzwN8LVr18T68jL+fK2G9Xpd+L6vhKh6AMaDwPUcJUWr2ZTNXuxFoVGIIKWjXM9zPKMBwBgbkTZgKSY2Ud71bCXIUbFWNiikFXFiO9wzou8mugLG7xQpiu6YtbU1AlihlZWTm8fq6qoAAAmwIONC05mW835HHwb3t48K7332yffMTVU/6rvOaUAQSWz2D1rtr629cffLYM3NfKnQ5p7uS9lJdnZ29Pb2tn2rGvXvB0IIZh7vbd/O8MLKCl5bAdj5hXm5fDoSR8aXTdt3F3KTrqS8fKOzIV4/3Hf6tpM/VZ0pLU8vnpkrT56ZDEpVXzklpWRVoswJYCFZxqFNOj2d9Jq60zrotvd3+63D/V6z2+l2WyXPP7xYmgqLwVRsw2a8H7e11o7xNm/bXuFR06hWaWltjV9YWeE/sRExAgB9m31jbJTHGOP71wCPRr2N8+fFpU5HtlotJ1HlfOBi8bAVugetrlvOBTMzk9XzE5XyuWIxN5vPeWXfc8sCsYDpsXOsjYkT04tivd/th81Wt3fUbrZvtnrhpkLoVCaCKOd4kZ8v9jqhjlRokm6XdKHQpM3NTapWf5YAVgEAoNE4L05/sCTg1pGHeZXvHDWmhOs/8d53Lv/0VLV0RSkpHz6XZru7+dL6nX+y+WD3U9NTxcPDTtw8N+X1Xn31VVMdqRmuwAqsLq++6fVeW1sb1Ls5+54friOP8ZDhhbTOCwAClpcFwL4bq6JXqYqgq0Xw9d3bOU164snZ84+8be784xcn5y7NFatnfdebEVIUUQnHIAMBg4X0XwIACwTIAGCJXRIJGdtrhd32Zutg943m7utrOxu3dntHd0rKv/VIfqqjwO8dQbfXSyjyVGQngictXLlOL8CfICP8kNG9tnLtW+4bL6y8wGNDPMYY34cGeIRgJZaXl4Xvn1dChB77Mlff2871IzHz2KWzl84uzL27Wsm/z/e8xcB3g4xI9W0RRQlEcVLv96Obh432N7b3j17dPTi6gSDq85VSz3UxJBKhMaCJlNl2GzZfqxGsr0Oh8DRK2Vc2oJyN4oo25j0/8O4n/+upamnBWmsBgGCQY2QGgQBCStXrR8nvvfz6f1vfO/rNcsnbo5CP8nkT3igW7aVOhwEA6llN+/hIH4G9vS2cnOwIAIAdAOhGEZ+GJdtofJ4HxntsiN886r26vI7VxofFnOtKmGm7QTBR2o9N4eu7d/KL1YlLHzz75Aeemr7w3HS5clHl/CAECy3owxH1oQ/GRKRBg2HLDBosaLaQZPZCgQQfFeZAiZL0RFXkoAIBeCQg6vbDncP6xle2b/z6b2+8+ruuMQ+eOvVoI9FRxyQcmaRleo2CaVQ/TUtrS/zCCy/QH+/rDQgrgFeXryLAVVhaW8Od+R2cuzTHOzfmU0Lk9jZW5+c5/XeH39ie4ysA9AK8APAC0HjRjjHG94EBHhjfK1euiDAMZbcbOLOzMthttdxb9xrBh5575v3nzs7/ZLVUeMZxVB4AAIiImLNqL2dlJ0z/xzBCQkVABBCICEIMI9U4TnrdXvTaxvbe7925u/3FZrf18sW56R4EORMmrTi2Vp/uFJNkKuFOpyPE5KQqGqf48q071Y/94Pv+u1OzUx/V2sQC0RmU90bLugxslVLOwVH79r/87Ff/zuRE+XXo93biuNEtl8s6DE9xt3sgAGJZrRZl7IdC9ST2+z3M5fKcJLGAIoBpGEZUFtGx7XaPrN22GxuLBuA6jY3wsfEdkqzON0Q+qappq32MTPFzBxtnF8u1x37s4nPvuTx96sN+KX+qATFsUsPs2Tb1bIQaOC2yMyAiMAGBYUab/guUGWABCBIRJCNIlCwAQYHggvRgWhTkBTkpilrqo1br9c9vvvZbq+uf+zXH9W780MR5sxs1E33US5Ip10x86cjCoDb8x/H+MWAW7Yr1ZRBLvUXRzh9hqVFAmAPoegEWWm0EAOhGJYYZANjbA/IFPYC23V8DugIv0AtjIzzGGH+EBpgZGQBWVgDn51+UANvO9HTRLRa9/I2NB4XLj5x/8qknHvmLlXLhI1JKj8gyE9ss2EQEyOjE2RGPGF7gY6MMCMDMgIAMCIyAgALVIHpuNDr72/sH/9fLNzd+xUHnYLaUD1tJ1Kp4tt9xHBuHoSj6k16n2QuqE/l3vvupy/9YKZUD5G+im2ROACIAEwMzsPjKqzf+31sPDn+lWHTu+eA3ARwDANBTDUd2ye9Z5YKrXYhYElmBnoeKrNAAANpYrThK+o0+QcH6mszubj9qt9c0ANAf+0jqu2R8AUAcTUxI/2zenZrKFb+6vZEzUlz+85ff89PPnX3sA/lCcfI2HMJNc5C0qA8xGLREaMGCJUBCzJYVMQGD4fTuEh47dJjdX5G6dalBHnyPyB44MKNKcFlNqRnKQa/ZffE37n7tn/zz166/8s7q4oHreq1W0/by0E16jTfM3Pac/WN3/wbG98oVARsb6ki13Qd85AeJCSAoSCUkAgCQNkgSCdhYK4GSNpqKQkMi0f2jUrz09rZ+4coLdpyOHmOMPyIDPIh8d+bn5TMAztzcXE7lJ8q37+2Vn3tm+WeWLi7+xSDw8tZaBmYLWSCbGlMAwOzpHYQu8M1GGAYp6uHPGYERGIARgRAQhBQKAOCo2X5w4+7ur27s7P3mRKW0IZEbMrZxksQiN1n279zf8X/gHU/8B+dOz/xNa61BRJEG3Dxy3TA7NmAmJqmkunn7wae/vHb7f16Yrr3ajsJGEaQxJpExYFnbcNZz8+dQwCQCF1FiwASOMUYRsWBmQiF6TPqo2wtvQD++CYAHSVIP8/m8vvr884Twb+EmNqj3wgru/MK8zD9RVd7RgY+Oe+rrRzvz7zv92HNXl577ianqxMXb0KAN29QHti1i1piwBQ0WLBBYYOCM+w6AQEjHMS8hps7byIOBJ40wAg//56DM0tQO1WQRHlMzzpR27IubN77xz1757G8IwE+dK5S3jkLT7jfbYS68mcxtz9nv+0iYYfgQXVtZwZ35HQkw58jCjBfZ1plKofpxlKJmkVGiipQQsa8ckoiWAIzRBMYa3ei2X+1y/4bn5DpdMN2ltXb8b70DOcYYbwL1h/EhA8LVs4WCiIPA5Rgqt+/uVH7kQ+/5+fPn5n8KANhaqwFAAqAAzDbLzAgfRyb4kOFN/88PeRI42EsQQKTRs2RgtsZaRKSJSmnhmSfyPz89WXrkSy/d+u/L1WJSyHsi76BVSklk5Qa+M5/6DnzCV0EcmMH0NziSjnZcdxpQzjlS3/DcWBilZKBL3s7O9ux7n13+y6emJz5OTICALiCItEUJmZkw8yNICOHUDxtf/41//cX/6tR88Wv3jvJ6sVYzJ5yMf2vcw/R8rz7/vNj5Gx8WxcXAdZudnBay9JWDzUd++qkP/eRHLj710X03Cv6VuRV3OBYRJLJPEURsQAMDZwSr1BMDwCydwQBATAAMmZGVwMhAkOYzgAEQBApAEAOPD9N0jGUGgQQarNDWwpHt6GlZhKfOX3zqPytOnv3Fr19vf2nnzqeenbuoHJMcTp1+zsKlDb62skIvpPfx+9MIj9ZXVgC8v+8JcWbR/cytLzk///4fe+6HHnvmb0upDDMBMSMIBEdIFpheI2IGF6S3329+6W/+5j/5zycgz4WCiteXl5Pj1NUYY4zxh2aAmRlXV1cRAKSUUuUdJ/fa7fvFj/3g+//q+cX5v2StNdlWK2kY4A4DTB6NbHloXbOkM0IWl4w82wjwTQ87j0b7LI0xRiLC+TOzH52oFHNfefnG305isel6LigAEAJRG07guNcxi7IHx8HDwxv96FjHJCV6AC4AAHgxCT9nlXLF2cBz3+55ToWIrABAECL9IyIAIQZvQQAgc4F3znH9x+JQvZ53ar0wDOXKygo9vIP9iVbYQgQgwqurq2Lp6pLsHgYOurbYNrb00u79+b/7ob/wH12YP/Wxz9kH+l7SiAWDNEgQkwYNFkwW9RIM7enJNcJpyDsk+DIBIzExDzMdktP1ZRFSq4SMAhAYCAQwEFswYEGjFJHVvGvbyeO1U+W//IGP/z9+5eXPy1/6xud+68rCZb3ZskknWSZYBh6u6e/HFrMRcsP66jLmSms4KRPld41rSs6Z7WLidm2LEUEQABomzK4vCkQQgFySOdnH/tmJfGEWpHdIUeJUG58WwDQWKxljjD9MAzwQoWg0GiIIFp3Z2SD3tdd2pn7wfc/+3IXFU3/JEpnMyA0CyczGZpHvMNl7HOkOrTC+SQZ9UCwWDINHnflEwjg1noiCGEikeeqaJusWfMFSelYbg9IB02r11uamKwYQEQGZsyPMjO+xgEf6fmythWa7fyfwnLssVOgmfbLFApCLSiqnbIkkADAREyMINgaHvgQRIiJnaXJmBus4Kh/4ri9Aym7eE8vLy8h/kGEC3+G9+r4x6JnxBViTO/68moziQtPC9IPo8Nzf++Gf/mu5ydKHftPcTBq2BxZIaLZsmdEAwSC5TNn9eTj3iSdr+dk1HZheBs54BYzEYrje0lVpAUEgp1EzI0pkMEwg2aCHJF+M7psLTm3mx55+79+aylXO/PrNL/+TU8WZdnl60/ReLTAA0B+a8R2sl+/wnl5bWUG4ArgOJZyvKJybnVR71PZvQJ1DE6Hg9LJx5pUSIwghGAjAxZCNiUzEIAo2cWxeSs9fFrCygvD9HP2P8W+wzgbpwXGK4zuF+F5/wPOrq+L06dNierro3do69JcuLb7nkXMLP0WUmaIsqzuScUyNL45WpOBE9XVgf7NtMv138NpBdDNifGH4Kh7YYVBKYrfTpS+9fONXmt3oiNhjjGJDPaFP1Sr21sb2y1EY31ZKSga2J6NpHjoIDEBSCnlw1GxtHba+XCkWdy3FiVKu9RJDUgihlJICUWTnigiIiNmmLtJEZ2oXGAdnqDzXcx2lfM8R5U5H1Go1/FaG8w9qdAdfb/azh3/3hxmJMQBUGw2xsLAs867wO0jV+939pf/yfT/+t9zJ4oc+o28nTeoLzUZEbCABAg2WDTNbJiZmtsxAKRtvuIY4SzMQMBBmsmUAYBDAcvpzxnQJETBYHBjz9L0oS0FrYDCcfmkgSMBCCBoiMOJmsh9/xd1zeSH3lwLHPRvZhB888CQ88z0ysm/19SaR7beKeh9G1S9gLyFBylcRGj8EwggthGihhxo6rLHNGnuooc8aQ9QQosY+GCFRCJXzpE9SqsqcuJppun/PHY5vdR3+OBu379V7/0Hff/C3PPJ0vdX1Hr52PP72DyUCHp1e9PNXruDmZqLOnnW9nTe6xY/90IWrvucqa60WCHKYHjyZQz4RrfDAu2JgFDga8A4MIZ744wFnGU++GQIyp0QuAgC1dmtrY7/RfX1hdtICJyZJDOVyrk1QGHZU/42N7X/55OXFy46jHCIywCAYGImHATkribLV7sDa7a1fI8KbDEYzC00FwzIUaIwQEtEKIcwwlY4jx5xGW4yIQGktmAGFcqTyDHroJn2R2LKs1++LlZUV+jdR1xq9PysrK7iysgIAxwMvRrG2tsaDn1+7dm042OJ7HiWPSIJ6pyPRe3DHnaudyv3m4etT1648/1dlrfDO307eiBIwMmEDMdhjA3nsFMGQQnAi4MVBejn9cRqQITMPshxpMobSmjyNVN0xcxBxdDEKZmCByKkRJzYQkWbfD+TvHd4Wb3xx/auzcf4AHICq76SBeMrk5j/otbm2soKDQRDXVlYQsnv4rfDCygq/ZTQ8+P6kuAns3JhHmANwiwqlKx1ikAkYiNmiyPIFhMSWB3S1NC8UWwbNibAAQWLZUYDS7dwTAGeP7+93Y/08tNG/1bX4luf+3TKC/yaR38lq1rd6DX+3n7GT7/8m1+ZbOS/ZdDGA42u+nu0XS8wMsHL8qxWAF9K/4eNo+Tu4F6MR9sPR9vc6+n6rey9GObnfpyno5eVlvL6xod5Ze8S9vb2p3vfuJ99ZLRXeS5aImWUaCzKc4DnxcaSJWSQCiCwR5UiInL3goQCewBITZ3EunriMxxszCwD1+q17R3d3G5+enipv6jDpCRPrSmVaN6ABLuTCWgHjrZ3W7zLdnbm4OPsj5VKxOPyU9C0lAMLe/kGydnv3U0fd8Ndr5dyOktjQoEzRBtxxGyLHnkM4pJUBQ5q+zBhc2RafZqOzVEAaIUspPJcdmS+LKDyU0AV55coVWrl+HZbr9ROKWYNa8LepCWP6XKzg6uoqXrlyBW/cKOIzzwDcuXMHR0VCbt68CRMTE7BTKMBct8vz8/N86dIlXl1d5bW1Nb527Rp+T3qTswf+6urz4nOF9ykA8GozZ0u/vvGVqb/2nn/nJwrzE+/57eRmnFAiNRjUTEA4WA2ZTWWAQbE8XQmYJZgBBCILIQCFECBBMiIQp04cE6dPleD01hIxMBqyxCKLiRlOFiEYEMwwOYIQM7H0XDw6PNA7X7v/iar2f9mrONum0yVTadJiBxhWVhheeOE7uh6pcQGAlRUBAPCJ1VVeq60hXLkCOzdu4CCybtzZxiUA2Dk/z/AiwGCs4tXnn8fVT3yCrq2s4Au/j/T39SsgrtSqCHUQRxwr33F8QlIaCAxTRtQg4JE9aOD0iDQljyREoJQrrbQyFAEu1dbSev7aEr9wkm7O3+n6GBjb4Ya/toY78/PpdXjx+OVzl7b5Wvq6dLTktWMFr28aL/lmxmZgZFZWsq+Hf599XQM8MR3r92MMMoGTayvX0gu3ArC+vp6xDq8CrK7C0tLS8eQtxu/c0DzspMDASTlpHNNzuDZyDt+iNLGS8gOuLi+nCn5X0t/tFOdx6c4aHhUm8Og3/j5MdJd5fXkNqo15nru0zZ+oL/Pa4FoCwHANfBvDf8Kx4pHjvwb4AgBcy371Aq/Av/FksszYjiq9rT+/jktLS7y+vI5La0vD932BXviuOGDfk5TAaNvR+4JFt3bWL732xv7E1T/9gf9qYa727xhtjBAo+CGbOyBTDeJDZgClJFtrZKPdbTVbnXvtXrRjDR9aYnYdkfddZyof+FO5wJvJBV45n8+JtIRoLfND58jAUklxeNDof+7lW/8jgPxCzhebCLRfUsWu2m+b7XmAopx0A6EL2tiZ/aN2reC6T5w9NfWRiVLwlOM4RQZGY2yz0erfv7tz8Ll+Yr9UzfnbGpI9R7gdLw9Ju92GKbfiJVKe3j9ovvvZJy/+5dnp6mPGWIMAmTPBo34HMzMrpcTBUbvxuRdf/z+KheBXwMIdzaYD3d1Yynkbx4ajqYQLzSZNT0/TYNLTwzOJj/eQFVwBgNVs2EWxWMT9/X1hjJGe52HLdTEOQ1GIA6GDWCiZ9ncaa7kXhlTFmm0HParEMR8eFumJJ4r2zp079NC4R/5uGeBrKyu48/F5qe5oT1WLE7e7D85eri3+2T/1jmd/7mW5Lzq2z8QWY7BIzFmn2eDZSQ1pVvdFyvIUApGFq8BYUlEYU6/X73Lf3KJEb+tIJ4AiJgKLwHnhqZrjq4kgcCe8QlBVgedKRABrLTPhsHCPg+xbulkQM6vA46O9ptr56t3/dUIG/9/8ZLEte+12W6pe9cYr8bftBz4xSjGdW7xUW0OogwBYhqPCDk4EJSx5eWy7DeweBijCRESuhyI2InBCDPMBU6jIlWw7cchzRZeOwjbHmz7NbW/z+vIyL33TSMXBZgcIV66Lo/AV6c5XVf9B13Ung/LOVv3U7ONnf27+8pmfiKJQAzLSiecWswo5snKUCnvRzs3Prf2/5vOVrwtlttmII+EdxaapaKI7xzvnGzz3yeNj+bazlgea31mUtVSr4U7xBnr7kWjvldCbTISKtIAaANQBoAYgH1gBAGA9SbVa3hyFbQYAmOjO8TqswVINaL2+zqtXP0HfbGgA15dXcam2hjs3drBRnUMAgOr5eR44OrOFieG+MtGd451Gg0ev7wt/9+++da3/xNSuTwuAZ6BRTZ2nLHQBgDVYBxgasOWREavftp3toZGcQwcFIPucZTja2UG4ePwn33QOV9d4YKTXl9fxKlwdjvVsVLdxducI4eIjMBGUcKezIYreBRThjog6PvrFPPfKEQMABEmJO/Ftjg+BFvPLNPiMwRz1N1+H2XEPP6+KszufQ7gIsNudYMiuy+B8qtmo0NXUGfvOtNhHjO7gfjSqc+n5DfEIANyCmwBQnJvgamOe57Z/kdeXpzl1AJf4hZUX+A9iiL+nBnh5eVlBFQKPZibCxF762Aef/V8KudyisdYKzGqePJSXyoguWXqPAYQA7HX7yRsbO69s7h99PgzpFSllQwjQQggBTDIx5DqKC0qqU4XAOzU7WTo/PVl6eqJaqimpgIg1M4i0zRY57Ef48o37v1hv9n61lPN3rOUdK0WzBKWwVGpbAABjJp02dXKC4pIlmElCqrXjeEIgLkop5gQAJGR3kcVuIe83XcmHgt1d4ZimSGykPZ+sTiShLXvCOXvY6D7z7FMX/+JMrfKY0caiOBm6P2SAsX7Yan/hldu/Us75vwom2TCs24ZEKJSytkUcOYfk66I2RhmlSjYItk5MeRo1vsvLy1i7ehXD3/gN2a1UBMSxrAGoUJadwHOltVrKOEZjtNAicBKIlAcAUkpiRMMgDENouIeGimjM4aFJksQAgF2r1Wg5M/7flT5PZrwKqyJ3vecUjMhriObrvc77f+J9P/Rf1qtm9l58aBAJEzKpARhZ8DySk4K09osAyEopsADOYb0RN+/vv9pvRa9oQ7cCDW94QrTJUSSEJTAAJNBhy76JdQGQp6XrLntT+ceq85OL+enytHBAkNaUeU9D5gITk/Bcsb97IPe+fPdXp/zi31cVb1u0ey2o1npJwYuWVtfMt9wYsrr386urYqlWQ6jXBdR6YjBGMTfr4Yyuyn5AkpUWcQtkX3eEZZSGYkmMMi8kysCzATgG0TUCrel2rDmi2LiSLRXrVHpw2kJtjdbrJ43f1dVVsVRbw6NwQtrunIPV0GNFjpNX5b3N/XMzjy38RzOPnflzUdTXjINsAAIjA3JKIQRgVspR3V64t/GFN/7bU/nKyyBoDyU0vR5GoSJbCRT1d2OmdoMObNcuLl4x6/X6SUP8UOpqJSWFifniPG53XNn28qj220qqQE3NFiV1IpVYkEemKxQZNkIjGk8UPIeBHeP6SicKbHyk+ajfJQXaehDbEpy26wB21CG5trKCyyvLuLa6Jnd8UJ6aULmujw0AmIsjPgKA2PNxQltRdxwsQRtcKNjO8D0fmo718P0emdy1CmtyAUoyBk8OZlIDAERuD/0kzwCHkEvy3C2HfOBOWa+Y2A8/U6XnV9bSTMpbRI8DAwawJnO1RbHYSQREWvRdH0ViBeasiPvOyN7fBi8XcK+hrfKMNgVF8bRP8CIAPAMw51cRvrImdpJ5oapayIIVeXKkR1JOVKrYTYzoaSsMh9IIhYoMa9flEhnOOyXS1rAn2R4osPYwNC2xaecOFwnemaedzze4Ua3S0tWrDACwvrqK1fMN4e1Hwj1IlCiRSNiVAABJP8KSM0H9Qmrc466PVQAgt0kmUWZw3I07Vfp9jwgdCPxcuSKOwlfkbvfIqUIgA8fDpB8hQBnK0IIw53Ozmf5Jqd2kRrVgc2GXYxfIS+Zt49OfptVPrNJ3aoS/Zyno5eVlLBQKKKyQR51+bu7U7GOu68wQE8GwLoeDGCZNnfLxb4RAiMLIfu2Njc/sN/qfnSrm789U3R2U2GVtNDvMqBFRIFoAN4mTjW4/zn3jzl5ebuyeP1WrPHNuofbuudrkKUvEQqpEIHt3Hux9duuw9esTpXyLhWjmcl43aURJM/wGxXFA9XpNlMt7UKm4ZJQw0lF9Hzhx8w5Zgn1rqQUWIO9gH4gjFKhRKYMGMInZidBiBS0IlJ5GniOiUyBxAhCcb0qz40gZI6tDZkQy6SisgSOqBKqvGAvCUCfqx6HJs8awbFzXT7piW9c8PwnDELI2pROG98qVK1iv14X3xS/KVqmkSm1wgqDoGRW7/UZP3j7cUZr7ju8EvhTg+UGUc1Hm+0zCWk76UdjqxlErByIqTZdtOclZr1pNWodJInpaL3ueLhQKBFeu2GvfhRpxunGANIUJVxYr+Ve2tqv/3ts/8N5kUs3di/cTAisSMkBp38txX9igXzxjK6ckKyBUUh0222L35s7NaL/zmQK6vzdZLt4NArfBLmijrdEoTc61TIlEmxgkoVFgxSGjczYya1G9O7tfb5/2q+UrpcWpHywvTLoURxaZs3WMVviOc7B31N/+8u3PzHilX3YLXlMiddDHsH9/XwOctm+Z3huJVlauXBGzhR3Z9kCUaiAjk8jyTE0VDMvbW3vwf+99HupJz58s13JnCtWJSVWsBL7jKxDKEGHPEHV6R/oo6jRbYautWEZzxdlwqXY2dCXYjp01/fm2MaJkqucbBtaArwHQ+uoqVhsNcVSYEK6sKlpoue1+TzEpz0ROJQYzKYQoExCYURL3YC0PBHOAU4UxJmmYy302FSAyypDTAejHhqODRkOTIF2ZyFvPK9Htza/KJb+rl5eX7WgldJDuXF1dxvmPz4vtjitf7vRUSRWcKTRut5CDL2x+DV996Z6cmJwoP1pZWCh5XhCgR0IJjKhLbzR7Yb191G3GvWbOzUfvnjxP52slDnvGtJWX1L39ZDa0Gq5csXD9epravwK4trYmuuWCY1vCa0SJavuxAADY8NJj82QHO24Z0WrREIwu9YyM4sidnpDrDc/mFutmcRFM2vc9Wq88VnP7xzs7cqpaUFQUTrPfwRhilJqF8FlQKOUR7AJFWqvAMuwCFCZDwjrpz31+R39iedmsrazACw9XjkeM+zqsyaKb86Z7rnoQHSGBkkXsihisEtoX1u+hDwAm0QgA0BHaulVpYvKNB1FSPGxbeuIsicNIgI1ls7IoJgpdWXArLit0Nw8P+MWdO1DfOJKV3ET+XHlmJu96gQcAAh1MdJ/vJv2kGd/r7bbrLaMpPD1ZNM/NPmHm5LI9MHtafL2ti0HVxrWehdVVWoc1yPVAFNfTUaL3fYuqFzqM4LpKoesjNt0uq8RlIxMk2cC9RCEnqHO5IHbjmPuHbQ2wra+ursIqM327TME1APy1+Xn5+MZ1Kas557Rf9PqaxQH1pHRACNsXIRjQ3Zg9D6kPALslIBV2zZaNbbzHNCvbpvrhDydXVwFW+Tszwt/LCFguXrmiFqFYeOP+g8V3v+Pxn3zi0XN/hSnt5BghIA1Kn6OzeVkpJW/c2Xzj1dvbvzg3WbphyW4KVgcWTF9bTqTjWmOJlRQI1iiTgBt4MkCQOWsot99qB0LyxKPn5n74zNzkj+fzucKde9ubX1/ffKE8mVsXmo+EI1umHYVKTcYAiwbgOoThKTkxAV6sTH5n53A6seIxzxPTEkAJIUBK9BnAsdYSM2hDHAFjSzDtl4uFDklgYPSYzFkU4py1tIhCnHn2yQtPTpYLJWMMDwQ2H9a0zs4bDhqd+Iuv3L4hgX9Pa3tIzBbIxhYoZkuRtdwy2t7MV5y6K3SvD9CtAUTXr1+h1PkBbDReFKdPl4SUd5UQFR98mY9C7d3f3g8C352bm6s9MjtZvVgp5c8HgTfjOqqkpHCZ2QEANtqaxOjDMEq2Gr3w3v7+wZ2t/aMNa+3BRK3ULRXcTrfV6lkhYmjkk1ot1qOp8O/YCDPjJ2BV/Pr1nuN1kkLHjaeE6/7IR9717r+56bYrDdsjy4TElBbhcUSVdNhXi1ktUjA40tm+s9Xff237XwSkfqU8V70HArtskq4WXlQ0OjlytC2GksKiQ5XDNsZugPGsj4WDRAkBTozoeJ4KOJalpNM+G8bmQ8GZ2tsnL868DRX6ZKx2fdc93N5r7X7t7v8451c/J/LyyMaq7gjZ6teP4mqjYOa2t+1bRUODmjfAkvTKF5yilm61SH4gVW4zbOdu7z7wlXLzT88uLrxtavHiqdLkuXJQmANX1Xwpy8zkC5QAgpktUd8kOkzCZifs72932nu3mzuvv3qwsRYnycHyzJleOci3GqHuROBEvY2e8Z5IbONOFRcWNuVRPOGVQBfqrbBWcN0lFnAhljwXJcncuQuLb5+4OLXQjvuW08V7guOIINIBJY6AXj+K7v3eG18ukNpSSjQliSMGbrKGGIBAABrWekcbeScnRF1Y6suC1bvdObO0tsbr6+u4//NLeLk4j/Grrszne0oWgqBUypX2Dnf8l+oP3LP52pnnTj96ebl2ZnGiWLqArjyXcz1foUCJCA5IywRJJ+71GmFv843G1t0Xt2/febn+4I0J5TaWJs/EoLBDvbgVRTqqQ2xnC4raeyXM53vK+I6vW+3pfD73qJBySjgSGDmx1kpj2bVsXQIWAAIEQ98i73Sj1oNSUGposg2oNKOP1Zf184NIDBHg7/ydjA2+JmtQc0mK3G7nsDhbLJ9lJaY0WQ9RKKmk45BwGBk1a2LLph131wLh3DYFr38IED/7w0f6Bfhmp+7q6vNitvA+JQIKjupY6lK7Ol+sTRNQXgDmgMAhZGUJHCmkQ8AKmVkKEUHCr5Pl+76HsZFukncUaepJJaSfF7ngXtz23tjZDDwli09Mn3vkUm3h4mJl6tRMoTrrue5sQXkBIghGBMvEminpxVE/iaP6dqex99rh1vbX9+++dGtv++4jUzP98xO1PnTCjvGTyJAyR4cAaoEE1B2fbT/v5f1LzDAjhAgQpERhWDMbSwCC2WVkxRalkqIbW3u/FbZ3TrmFVl+2jvbuT4TFud81wxLDW2Qifm1+R56vXlZV0C741fLG0b3ZGa+64AZ+GYGVYRDEVpBgAcRI2jJYtkBGS4ldCnnbxMmmSuAomYMIVtftdxIJf08M8LVr18T8/LysVquqXD5VvLW3/8hH3vfOv/7IuVM/boxJpR1HpIkywchMvWooVCS//PKtX290+79Szge3ydg95TktK/1+kRpJo1y2p7RmAICDgwMRx7GEyqKSrB2F7CKbnI5lcHdvx71wqvYD5xdmr756e/uXWlH8u5OV8qEAajkRx0d+z84D6Dt37lDj/HlxaXJS5sIwv3OvO/XY5fn/zHXcHyJgKxETFBgBs0RIdfqZWACgFVJSGCebt+/v/XqiTbQwM/GuS4uzP87MkhkUIkjfc6UUxx1XA2nNQT8zjqh9GCIKo8QggE4pnAPdaURiYkSBewfN1c9/ff1/PjtTbuuuqS8slLr1ep0A0slLAAuyUBBOEGAuIixv7uwH1Wpp4bFHzvzwzFTlw/mcfy7wPef3e0/DKNGtbndza+/wK7c2Hny22e9+fW6y2pYguuBSu7+zEzXOnzfbn/wkA8B3PEDi2rVrYufj89JETT+v5ssvb9yZ+9C73r1SOTf5Iw/Cg9iwFSZtEcqI7zwUJUPEoTEgBkZHyQd3tvbrX7u/OjM3+Wuq6N/tmbjr9HVUrBotG2k6743ONk/X0xGQS1fXeB2Wcel6Ddfr10Xn6QksHhgRk1GemHBcwTmFztTRg/qsP1v54NQTZ37OLxaKB/c3j3a+evMfzBYmfo0D2bHCaXq60+/XKV6qtTVc/9apyPXlZZwt7CgA8NCtBVUXy7eaO4V7h/Xq07PnnnvP/OVnl2YWL1ZKhTNO4AcxMPRAQwdiCCGBEBKwRCAwHSDhgIQcOFCBHFTBBxNHttHpbq7tb7x6/d76i/f69c+/fe78gyjUnSjq93MLhWRvbw+qdlYGE1C6ubU798HLT/+FD55d+pnYatciokIB26oLX1d70DdJKr4xJJ+evP4WiYsQ8NuTWTrFOcgJxQoEgWCrmVmTVRKEbCf91j/8ym/999Tr/VKuPNnyCaPOZJg07lSp2mgI73QkGjJRk65y8raaP7L96s16/cIz02cv/qlzTz03Pzn9vnyxMK2UC22I4RD60IYI+qCBiMFDCXn0wAcH8uBBAAJsN9JHndarX9584wuf21xf9wDuLFZmd5qm1xCS+kKTBgBwZdX/ws2Xg7/4gY/83EfOv+OvCZtWjRDRUsrMk4YJGYElCEZmG0iHP7Pz2m/9n1/8rV+4WJt9/eAgOZo4gnh3xAhk/dVivV5yHpmtFH79pa8X/puP/dRfe3L23E/1bYLErIYSqCgQiRQykiOE+3v1m7+68q/+z//8Qxee7LETtdegHv3OlRX7Ten66ytys3U6KORt9W7j4PLffv/z/8V8ceJtBpiRUVmwmHlQApgFpqaJPSGdN/p7n/0fPvsrf/Oxymy/m5hYOpbzTt672zrw99sHc0/Xzr/jfQtLj12eOf1okPMvy7zvxkDQhRg6kIAGAybNkQCAAA8cCMCBAriQAwdcZui02oc7Rwdf/cLmG1//4s7rL00Xq7fm8tVWo9sLWQnyfJSbu3ve0+cffd9feOwDf89BEWi2qRrDsDuQmAAlMAtERAFopRD91dc//0u/c+OVX5mvTr2+E7cPvaQfAyzbN01HM2c6AyDdwo4/R6Xci7u3Lv3pp97zV3700Xd+1LIViCgkCEAGFBk5VrMFA8zAZHPKh68e3r353/3aP732dPHUl27Dbu8o7CQv/uwvmN+vAf6esqB930ciI8mC6/tu6WT7UMZyHjzM2SyFQTRIDIBCHIGQfSImqxQ5UpkgMdSfnqAb+/u2fucZAgBonG+L080pChYXze7GmqmB1m61qLUbJ+fO1PL1eu8z24c3Pu96HlWL+baJ+x23rCLdyZv5tZ69U71DAFfhvf4abrVaclIUVcSH1bla9YPFQu4sfLPa5ZsYqHj21sbODa11Nxd4S8V8UAEiC0IgEIGlYYXyuP0IM2FEhJEtDUBJIcrFnAsA3jeVxIgIhFBJos9qbQuErlHKOu12SYanXAy2tvD8+fOi05EuBKLQOGzlOmF8+n3veuJHz5yqfTyfCxZTS0VkjTHp4zeym/KgPwdS7ZFMCyzwlQz8ifOzUxPnL5ye/9CDnf1f/uqrt34pKHiNSTeQW9XqYTW5A9XjVCL/vpW6mHF9dRVznZ4kk3NbQd+bqU4s5KeLT+8lLUprvgyEyCnJajDUaESINO05Yuk48sHGVnf3la1/Orcw+3tA+tBEzXY+Cfo5qBjPJLZxJU+LsMG/cCKCuArXUrYlL60Ara/O4X6thtO1us3Ve9oEbdO3lktzU6K9c/CZPUOLhTOTP3jw6v1fnMpXP2tLuSOR6K6nZdj3KN6vtfXSFaAXrrw1s3RgfGPH9+fUVPFBb7f4hXsb0x8698RTf/mpj37k9OTsD3BelfagC1+2u/ZQ95KYDVu2mHVQ4bAlCga+a9qlrkCAhwrKMifmJkuLb59cWnx64ZEf+Nr2rXP/dO2zvzxTnNieniy347DfrhUrOukRakLfA55M8nxuvdDKt2wYMaC0bLFJIfRMjHaoFJaVwQUzskCR8sRZMIARGm4GddHEPPjoAAErS5SJpAALiRR5ZjpW9mnD9FuOiULdARO7rl1aAmyvd+U+KKcIM34FbO7/3nrdfa52/qm/+dyf+ZnluTPvTAKVuw2HvG3vJZ0khIjT9WHpWOE75ZCklWkHJBeEg7WghGcK1bf/+PT7lz9w/vF7v3HrxU/9q7sv/ct3zF50hKF2C3XXdwQZaYOF6tTkTtiauplrBjFpbdkKAnABkU12DRCBFQgQzCqQrjJT7g+4ufyLbaN3xKzo7HpI1caHadA5sb68jFBfE7MF5dS71js/e2ZWzBR+7EauV+5RX1sgMdAtFwwgULArJJYgwEBU3nmpNn8+tJ2NhD0T2Al9bWWFRksbKysruH4VRBWst3l0UHpq/vz7exX84KvOIWlOywfJcOZX6jQpRPZYciB9+dX2Vs0xONsF2/Jy0nRiTWv126X3Tj/61H/yto/+qbnJ2rOUV8EudGHP7tumDnXMhhM2aAGAKBVzRUx7TQQKVoigCNAVkosigFqlWJ2rnP7ov79w5soHD5586ZfWP/+Ln9+9/dX3TJ/ptZI4IqN4rjzh77UPvZfFnsrl835M2uKw5yXlDdl0MiyjRGbLWJD+ZPVU7UfghrhjQW5W2W16fkXNFdcI4OpJUZrs//u1NZyul6QvQPU96+UK/ukz505/8HYhLLeopxFYOIAgQGRytalqngGGhImE7Isv39s4nevhvK46GPSFeIiI/0drgJtND6vzjpCu8pjTGiif2HdHqM+DHt2MRqOUhFq1cPrB/lG1UvD6ysqOSaDfzcUmuJ/QpVOTXL+zhrXaMtU6HYagY4uHbazVnqE70YukIiIH0TrkR1OT4CUxYpBTxnR6yZEIIutKHcCG/eTPXieAFbhy/bpw3VOYb0rRL1qHQeSNYSIitkQGAQTC8cgcBh7UrVkqKbS1VmtbAURFltI0LhEB0UCAAwZzhIedR3zSrtMgiUoMNi2V0+gIxtQxYXaEYCIyUjoOs5Dsu3Kf7quFtm87UBPbncifKKry67e2g8WF6ac/8O6n/tOJidLTAABkrU7NKwsAEENBk0GXw7BGjSMZRgZjGBDYAAJUSvlapXTuL8/WJt/5pVdf/9/v7da/cOHUfNyJVa9TTrTfasHq6ipcvXr190PMSpnP8/OiAVpVz1fcO/e33Kcev/xM7Nq5jg41ASEjclp2hePhHGlvUXr8BKBcFxoHbdxb2/oXU9OV3ybUh9Kj/XwLenGrrvtXp21qeH+WAa6+ec/osT3ma7CC66vLvFjboKOJZ3n33ibKvICJmQolPf1PWy/d/Y3pSnnXumrH0dxMerl4ouJpz03M0nNt+tatVqsCltakqC8GVSVKv3rjC4X3nL781N/7of/gJxamZ6/0PM5/lfbtA91I+iYRBgmYWA7p/INOgaE/N3BE0qZOwQACNDRNBFumaQJ0eLEwUXrHo4//5LnJubf/by995h/fPtz/2rnSlNOyYdtjTcagi45y9nWXTHJoQpugBYuaCSwz0oiqGOKxEA5iqhA2lPYkwsQmcAAdkJDqzQlEGjDXhBUAFi0I8AlFLlTguCUh89BTt7ckUy5wJwOVD6Oo/KmNu7P/xTs+9kPveWTp3w99ceqLds/u6HYSUoKGrTBESMiZjtmIgz8UhGeIQUOXYjhKQr6Hh0lF5vDC1NTFf6/8ob/yjvlHL/0PX/+1f17zS5u1UrHeMlHPS7QzWSs797e39opHk10oqiCxlii7d3wstIcy61ETWuqKGxRLxeLb2u3m52cKs3uiBjbubZhrKyt2PZtfDXPzSsvA3+lsBE+ff+zxlqvndpNNQ2DBMBMBARFlvm+6c3jgmGm3OHlh4cxTNzfutOZKwkzJpLe+vGyujfY+XwFRvTOv/AByUUzTxanKUzfFERwmXU3MktL94/gGQioaqFAxggtr9+4euNKdYImFbxzuR4+Uphb/1nM//qPna/Pv6nnsf4327XbSSkKKkRgEIwo+3g+ziWKclRZNqmjACApSkl7TxrxtO7SOe2ZSFeXy/MyzPzfx8Uev33zllz6x/nu/tlxb2O9FvcQPcnJvb/fgy/dfuzd/+fQTSZKQZZaExMypygTxsRaiQAGOVclkOTc9WZt653bz6HdnZmr7jd0631cT9oSjMjLcZb0OolbzJAC4mzvbhcfOX3hUlNzqbbMXhzYWhi0bhswlGqwtCUIIkIicGOI7tzfuTVTK3R70wItyDE7r+6MP+NKlS7y5mYCUAiUqLzaGhjlvHJiyoQrHsOc36ykR1lo+NTv57t3Dtqkfdr9YLQWe6yonHzqH2tc9r9eLz5xxTRiuUbFYpMnJSXpNa+4ma1wolWzlwOdczrFdrymclht25BEIp0DFHFG3JO0PX7xoVi5e5BW4wgAreD1raGsriQFZhZY9RHaFEEhEAgealMNgEUeapQCRwUOFOaExAQQ16M4Qg9CMR/S8ONsoH5rghHz8tgMRCQAEwQjHvNMs6yeElEIIBwCsEJh350QDQOTcjleV3tydewdzTy9f+MjjF0//tOe5ZWut5jRlI2HkHgyK8McpcTz+fuge4GBTE8AM1lgLADw1UXrmg+968tGvvXb7H6zf2fjlM2dPN0Nbb0blcvd3NzZ4Le1R/nakLAYA9E5HIheTAiBHMCz4lfwPdTBGw5YZEJlsqgE50CTAkYkcWQOqNkbt3tr6umv4nwmPbzBTXxVULy6c1dACuwrPp7UZXsFRT/ithAZgJUtNry4D1L/E1fPzGhpxV3sqyZVwpzZXhSixAkDocj6M963RD0oeXV2u0hpsv2Wv6zVYwZ3z88I0T3sxhTMvb+w88v9815/+s++/8PifCQM58QX7wG5HzSRGg8QkDPNx5JkGF5loyEA1bnBFcDhcIv2ibIyiwJgtvhLt0A1xZJ+qnX7iP3z2oy/8o6/99v9yo1P/F+dyU6LnxJFCdAxZSshChIQJMhADkACwmbLYUDZndCBK9gPMnGlCAYQIlgFkVv4crGAEYCEQmJg1sY0lCNdFCRqcjmG0boiTvio2Qj3X1ckHr125+ucvLp55/Gt8APd1MzFkhCYrNRIQpKyAoVoZAiBnFa00lZOlx9NrYhmQEISxfejQlt4UBfH0mdM/8reCq0/+Ty/9y1/dbB19qpYrbUZsje/5Sbve3KoftR+UKxOXE2uJUyWfE73PQIwMgAKJfNd3ypPFc3tH9YkyWY8o1FOXSwiLbXHnxofxcdeVUGy6QqlCdKCnChPlD7Uc43fjJAEAwUzZQBBGTgV7GABRM5OrYj83VfohfdvepSCISDlH0AK9vrxsl9bWeH15GTvhjjwzD063I0ue416SlWCpiQnHTAIwXUP0UDKPgVlKgY1mPalv11t5N7j42t62/NOXn3ns/Zef+KDOuYXPmi1bj9o6ZisYQaazswlGW9GOlQF5qNMwcOZjABAgQQKhQAIkI/vawJ7p6BlVKL3vibf9h67rPfW/vfKZv395YuFBbBPOFfLRwWb9pdKZ2qPGISRLzATIWZgyjBOYUYBAIqYkQGduYfZtd/e3z2i2O6pW7ajOtl5fXjYPS52sry5jrrYmjHGk9FUuQnvq9Pz8cz2HVDuOWLMVlild/8AjmyEBkGHluM7+1n6nv9f61+Vqacu2E4Lpkm3AMgH8wh+9Ab5+/Tosf/SjpLqGhMIkiU3vuNeXB+XfwTjfk6N+U1Yr+57rPbN8/v2v33kweX/7oKCNNfl8ISjmVNcl1dWejTzP0TH6emenZ6bdwJYiSb1en6DoU7kc2f5OgwgWAKYmqJYkDL4PwdYWwcWLvDK8KSsMcB22HAenFWFkQQqVOm6jZuihSQjHXjYRZklbKUCgGApP8/GwpCzixdGUL48qjpycdpRtqMzM6daVbi6j0geOQFBWCOEoFAQNp9exygvyExt7R3Nvf+L8Tz56YeHPCwAw2hhElIMRj2Lw8d8kVXKirwdwVH/75LgpBAa0xupc4OXf8filvy5QOq8/2PyVU5MT2O4c6LlLl+zyz1YJvr3qEwIAtIMS0qSQrUbsV6vVJQ7kxZ6NDCFgmg3Iwo5UlhuZ6Xg4FiMrJXHz9oN+uNP8wvTpU7vhUbfrnitEHdnTxYtgV5evHhMjcFTLG2AljXQRrgLsr6zhlSsAO/PzCNcvpT2H52/g/f0JXEiq3Ara5Pgm6YZWQLeHrs1x3yTc65QYoAcAAKura3LQM/qBzgpfuXYtrYmPPPyzhR2Rr8w5a42b83/jQ//uf3pufuGDX6JtupccJQlr1GyF4WygBKZ+PzGPDAIb0TbPauPZQ5XWrBiyxBkAQiqeIQAwIoPXwxvJE6XTpR97+/t+9p99+V/fPkh6a77r+NqyYwAlKECDwAbtUGFs4AAwwwkBjpE68GBEClBWxhAAJ+U6snGiwMgEDAlZRyIrxVZZh1zUSvlGeQ3dmbQk3vEz7/rIf1KcKc/+hr6VdChCZpCURuNggYAGBj/LjFAafw/i1AE5DDGN9EACARFjggQJSxlxi3eom7yzdmbh597xp/7iP/jKr201k+goUI4OKUEVuI3Do6M7ubOVizrTGGfONMYfMsTIFtqcsD9ZnIE7zgRJ7bKRst4h0Zucx/PVKnp+Q2hZcoDBLxSL87LsPXlEPYhYIw2dycF9zT4PECRbPNBdtkV5yQ2C0zHwDnYj3yvfS+LWWVhfXrb7tTUsFuel7kduuwelYrX0GBad6baNLIHNjO9I0JM59amiOYmD/cOGSkQ38XH2P373j7zj0pmFJ77BddqOW9qSFQZI2KFOevpe6UTtYyIpn5h6w6Oz2hnZokAJgi0AIyRgIQYjelrbI47pPZeX3vHjJv5z/8crn//Hj9bmLfgSG4et282Dzq5/qnhKW2MHOZ9RY586WgQCCI3pWlnLnSrnixeSMHoNQRpBubjaaIhrKys8qiC3Mz8vtv15UVOR20YuVEqVs7KSu7xjm9DjBJkZ7OhaR8ieovTMtSTcerB3Dwy+TIqbiUh0vLNLz/619nfUD/xd14I+oR384AEwo1ECO51uf9cYwyeiviEdiY8nHA3TtAjWWvI9KZ9+7OzTP/COpb/w+KUzfz4fiA81W/23b2y1ztYP+nO9vpkGYSZETpWNY4vasfnJST+wtulvbUXOgeticyqibpJwFEVcr9fpypUrb5oe9HZ28CAJpQyEUEqNNAzxyBSmY9bnMEcrRCpvmUpOWiEkjQSUI61HQwoWj4hsjmxQJ0SF+Fjjmh8SwwawhiUAS0exMgm4oucFhVKlenf7oPzkpTMfffT8wvMIYCyxEelUveNYFh8yvjAso34TPQ+/afzjiE+CIK0l4yop37F84acXp2ffs3NwOOlMTORPO46z8xtPq9XVVcHfWosY1peXse8dYSCF2wubk/mJ4mOxQ8XEWjKDmnR2PYbiG5iKVzEDEwB3oljU7x3eyxdLNxI36XsBaa9RMmfaPq2urL05CQpW8PnVVbHz4rzsFHZUbqPnTH902dkpzrvwDDg7xRvu7WTTa3S0N1/Ku0bEjs1LKUMrgp6DJSiDcI1QXl70oKdMqNwzJnJgYVk2kqqCbXDe7pWc9avLauX6ivzAyooc9Nvudo0wpiNVQt5N2Trzq/wGvJJsJV2KRJ81RmAhyTSmDRBoILbIrJFZM4NmCwkRWGY2mVEyWZuQAcsaiTVn78EEMVuIwEIfNGjQ8uXoftIoceUjT73r+YN+cxYlTxkFRYvkJZalBguGDWim1NhBaoQJjwdWDNK+lBnB1DimalkaGBJgSNhCSlwhMMhgMg0tQywI0WNfqsha1yZOYNEphKwnmgld+onnfvAnoxk1+1vxzfjQdkVotehTAmEmP5oAsUkJMak+d7qP8FAFDTDV+AbiwbXR2VfMBrqgoc0xdjmSnwlvJu0qlv7SMx/5C/txeyFGXU2IStJXUaPevNnrhomViBqINRNoyt6LGbLaKmsk6FLEohSU/Xy+3I9jj13tsnVl404VZws7aCaaEgU7h1ErNzE5uUg5Z65rQqvZomEL2XujBgsaCAwwGLaQsMWeTazJYzlXLpxK+mGFlR80dN4N/TVVPd8QQTghy/uRcpXr9sNOebJWXYgUBRFp0tka0JweswEGjQSGASwK1mQhrvcOHc/rlwM/F88H5z5Ft/Vr8a7t2lh0KIEeawg5gZAMRGwhAQsaUh10k11fm60RC9lnZFrp2T1nC8TpOkjndEdsIAaNh6YrflfftUsXL374bfNnnzuI2kUUKoeeOtrb3r1rCFOt9ux9bbbONaefnTBBAoRdExKVHL96enqx3Q4rwlN5z1dOo7qND3MvGu+tYllFivNFv9XsFWsz0xe6vp1qJD3STBiPnOPw3LLPtEJgs9OB5mb9a14hvxvrKHTzYOr+4/TCyveJFOXy8jL3ajVWjb4teW6rftReN5Y6rqOKlIrvZt40DlMVg9Aw/V3aHJzpWdlqOT9TLed//NypWtyL4oN2p3/joNm7e9js7G9vde8B0T0/73TLhWJiBES5aqUX6zCcSXIRH4GWLWM77qSt1Xy6fh2gXge+ejUTOFtZwSsrK+C++CJ6oASFRkoh5ElbMxIhHke/WT9qOtRXIkRGYESU6hNmAecg1h+JLvFYXBjeZIIiPjxQcbTON3wRITqE6KAUcY5dVWo2GpXzp2euPHbh1M/AgIiCKEZHKcJbhKQnMhE44nYgDgdfvEVELJjYuq5Tembpwl9tdDqse8lv5myUQGkfoAsDha63lJyrNhqiAZ6MTxtPa5rwqv4jRoEiy/HgSg9HQDIgpeeDhAhMjMKR0Gl2NITmi8Fk6Y7tibgJjpkugW2sf5pg5RMn5R8HohewjJ2nd5R7NOEtz0/5XtM6sScUujVF/VhKX2JhUqPSk2jRoEWJ1a4EAA+cokGABD0DysEYhesxuAAqEnQeEmIpyE5X2aEgeaRjOreCR8Lpj3oaSmB3onkGrwux63N5Inf021/70icuve+Jv8o+BqHRRAOh6kGVdSBimt3DbI4xAyBnCTkGYMEn1utgDjIOWcrHfhQDgBWvJ1tmoVJ53/KZC5uvbd37ykS53LeS3YjBDxBAZxEfIwwjn2H8nTk0RJSVBnhEly9L/w7SwsdJk+GyJwQ2wICWVVBwHW2MK5Uq1A9bj/30sx/5mc4Ev2093koMWWWzTMCJ1O9Quyc7x9SrzS4aD3orgICRkBgZ09nO6fMKIh2+gYYJFAv5pWhDPzV55vE/99QP/Ow/f/G3f+l0qdbEwEmSeu9up9XdKhQrFwyToUw+djQdypgNIiDDge/l8hOFmaPt/cLU3GQUe9DPPdYT8au+iNhROdcp9PvR/IXTZ99lFBcTY61FEnzMiRmZJ5NlHBAA2JLjevn8dPmp/Zs7t4r54F5JQdtATcQdV56ZBtE4EKpjhYcopvLV6oUeGtRsBm/KNCAtHtcPmKTCdqulj/abr0yVy7cPOu38v1z/yvLik+cfTwRpJjtSGuQTvIOMq3lihhhmMTVn/eJZ5iXbMghGsjQD/gC4wHigO3wjUPknL13+sxtfvN7ROdpxc36n1Wi+VOn0n3RKbtFwkgqJMw7ZCHzcwwnAFslDmJyvPb59e3POgo1j4bY9KIXXr7Tp2goQwArszM+L7TugdCCcgognLNGlwlT5/X3UnmZrGWGE78CjgUg2zV3Jo42De7oXfdZOF9ociS5A3p6vVunFn/2PGV74IzTAmSYxrK6uYvuVkN0poup0NdzarL/c60V3/InS02ytRUCRquiMbug84E0M60nZvUJjjEVEVlI61VLhVLVUOHX2FHyw2+1zN4yPOv34RqPZff2w2b0dxvq2cLr1aj7ouz522ei2LIko5p6uAySwuGGg1qPr1+s0UJC6nh2/FGlXJYCQg5XGw1mIA4LHiZBwxIJhZK0NmTkmGjw7SMwsBidyYnTECSY0nkjzjhhfHgotDtQWiRiQjVQiSeJYSIa8NiZvtH388Yunf851VH7Q7nVstHFoQEfdAURJQmRlMmB8qDvNWGuBGURaF+Y3bV5DRGGMMeVibu5tly/89G+9+PLawqlq22c2dxcWzHJaQnxTRvS1lRU8evZZAc6mjLR2Uckp6XtnNBkmzvSrT4zrGNSoEZhT2gchO7oTbSgLX7MONnTU07HHdr++Rr9z9RNv2oy/AitYfXFeQMP3VcFUv7z52rQRetpnryqFKIAFjxkEALOTLmnBWcuDkMqytYIRhAThMoDHiA5bEmSymRvplAdtgJuC+dbZ4swd108Ouu1iF1wwubjN4BZ0cWry0GwdfGbvte1zladPX9XI6YzogfEdsZqYDSRGoQCymbypMUEmBmYi5pSnIgQOm+2HHMeBu2dSigxom/AD1VHBqcqfos2NpK/jLWshNkyuJUBL6fNMlgbKY8P7P0ydZQbNjtYVeWT68gnSjwCBzJIsECBZYOMKKYxhJ6d8f6t5cOGDl97202o2/45X9GaSpuEtGD55LQbmlgCAiUFKycpxAAAkMwnMBEOBmcEasjZNiiMwCJYgEIHBZoxYBCMYFCG+HD9ILszWfvDy9LloY//Bb1UqxR2Qcq9/1H3VnytfoOHU6BFngwmYBlURZi9A4Vdyl2iTKgahLwE6/Y2eMtNWCOs4Xa1LAsRSvlx4pg8aDdOJQSInZ6+eSIEiIqE/UVwGsfeGlvCq6fYOclWZbLcO5LRxpVd0VDuKnXyxtIgl91yPE2sy8zkIBGAkDc2ALJFUq97cB20+Dz7czbkF7G/ux61a9aeC+fIFHUUaU67W8ew5prTFARCklIBSjOzfDEzpo8lE2WUfPPonZz4MypEJMjggcCs60tPVwsXTs6feu3148KlCKdewobndqTfuVSqzT1lmM7rzMp4Y0w4IiGESUVDKPVaqVh+Per2OKjiHsVvuTNfbdn15lQGWoVPYEZMToGxbeN2+ns8VCu9xqrnlPifWZrwHPuH8ZpI7LAARKGErW3uNL7uOfwMAOzkIQoB2qqj2/PeJEtba1au8vLrKrjtvHA41WTrc2Tv67ORE6WlmHhHy++ZID/CbJF4ge6iQ2AIZsoiCABgKOV8UCrnJWYDn7Cn77ijRjXY3vLXf6Ly0u9u4sX8UvZ7zcWtyajo2YRIrUr3u4WHkA+gwPGXnP/5xXF1dpatXr8KLMAdShBgZLYVAmUW3JwzmkADAJycDE0PaiYEQSyVYCEAiUAgMUmC6L+LxJGMe4bI8POokC72RgNMIdlS5MhtiwcwyNLGxmHeYhbfbaFXf9/ZLH6uU8zVrbYKI6mGqE+OAcJWuMJnqPqtmq21anf5RL0x6ljhRApzA9wqVYq5aKuYFI1g+6TqclNFkBgQU1lqzMDv5yGNnzz59e2d3o1Rx7LSUunH+vAEAeqtWnFywh44qCEp6jnLdSXRF0VBa+aXR65N53Nn4qGHZmhBQd/UtieoosWzdfF5X9iMqdpffugVodRlztZ6sVlXuG0fbU3/jbT/6M+fyk8+2TYQA4DGAICIUiOyiGFx0kdU6yTLYdOsEBQBCDkqt6caGxIQWmQKh7K1+/dY/fv2z/9N5rMYUb+lG6ZSFO9tkk7bJuaWWnC7vHdzb/ZQoB+crl2rviqJezMDSEgExEggBoNBBRKRuwnGojUlMky1rYkZHSCkDJ+/mXdcJXElEhqxlZ0RvfLCZpHExgmACDYih7pJfcqvlyfJi2OkdAmIilATleDIBDcQsECSCMekMFUyt4Wi4nTqHI06SEMAqvSTII2YbRVaHFGwkIEiBjGhZSdXsdYKZ0sTl0uLEU6+aLd23Gi1bsDS68o59xIwYw9J1MNHWOdxv9pNWr8FhdChYEjii7OS8Sn4yX3DyvgPGaiKDgATExxkBBgImAAkAkbFwxzuy8xcW3n5vb+eWIbHrFvy4s9e6U7ow3ScPPGOOC0ZIx2wgTnugISINqhqcJeAJtLZFrusmoGPdUTKvlNuOW8VCPndWlPzJtD6bxoo84Itw2uxyYmNMo3zUVrNT9Kuy4J9Nuv28n6uohBpq2rrA2pFSohM1O/7U2XNnEx8LsdEa+DgzcmxAs0AJgWNrRWO3ecP3c/cZuKGQQgj88PZXXiufeu9jP6+qgc+JZoUCiQgImISQQjpSMSDEseGok5BJjCWyJBFAOUq5gaecwAVAJJNoFowoMzUDHrWaPJisxaAY4VBFWD41eW5jd6dAAvdc12+1Nut38wsTS6yEAEuDYITT0aFZ1jSjF5AlIxQVi/MTS/fWDt+YKudL8WRyALJk7rz6aYZnnoG57SOZNEsKgqLXaezXzpw+fcH6IheZiABYHDPqR8ioLEAAgJBKNHYPuPmgvj49MdXRJolE+0h7pQ37wsrqdxT9fm/bkFZW4NPz8/yn587bfqzj2nTevPTa/X81MzP58dpE8Zy1VmPKFUnrxogP1TrhIdbPYBaVyGwgS85qDEBkAYAFCsjn/Go+579rbrr6rotnZtqtdv/F+zuHv7xxb28973u9mqr6KIstNzwMcb4fX2pM2vqSj6tra1BWBgtQAF8I0QVwRno8RhyD4zBW4PGvmBkTS4kU2Gu2+/fubu2dI8OIiAExedMTJbeQDwQRMQ5cdHwoIwQAKBFanZB36k0DDBoQEkAmATLl5BFbz3Vlo9m5mfdzCZPwe1HiLkxX3nZqZuJ9RGQ4FQs5jqr5OLpmSmuoSgrZaLbo/nb9q/d3W2vdfrTDhE1CJmD2UeJEJe89tjAz8ejiwvRCIRcIZiCBcDKc5BP1f3AdhY+enfvBl+5s/O7kRBGTbiM6fSaJV7JpTG/FiJaRET1KHOmIqpUcaLbEPCD9DD4m3ZjEKOtSICbasu5EO56SIfgQc8/aM9M+zf3w1bcwwCsIV5fh8MVEzBrt5wxMd6v4XD1Hyx3ghABE6gFbZGCQgKBAgAIJkDZbZKyFdGcUAKBAksyYAQCIMtsWOoCiHuKUuC0+1YrMXc8rdXL1ntiogQlC1xRr1SjYPTwszJbuHL1+/1/4BfecO5OfipIwYSEFOOj2oxg6W62DaLd9Rx9G+w7hniV7VyJ0AKQEgLJw5Dw48nRhtnyucm7yvPIdZS2bobQNwjDSGpR6RLqG2SpQuaniQuuw+aLjqqhz2Loj886ZKAkDYnYFMzolP8Cc46TJl5SKkoZVeIINCwIhiRPu3GtE0ne0EsogA9HQBxWGpTBhLxRxP9rwgnyPgNRhv1Ncevyx9xz6id8Mo4TYCiIe0u9xhPg0nBfuCKd+d8ce3am/YkPzOUV2XwC0gFXMrItk+JRwxWPlC7Vnpi7NTzrKMWRtmgIf8k4y48kEEhkbumtLlUKtNjf95N7u3tcrU+Xe0W5jq98Jd70gd8ECa8hcaRSjU9bSIDtKEha+mpNFb6HTiw8UicCVpSiyJDBgp9tKKjNnZhcTB4LYaAZmYYdpThy2dg0IazyQ+kQAJmbHl24wWTy9v9EqYDHn2r5MQBgw/UQptxKE2paDmfJZ47AgPSCnZSl5Ppa+JSIUSolWs0O9w+5LxUrlUGvRBFeE7Fpghq9uvXjzywvvX/6gcJQ22rJUApUrnV6zw/3d/n5/r9WNmmEziZJ9G+uuRCRPKA+VysnAKeem8rXKqanp3FQpIJ1kGXA+oXvII7oQFggNJVaW/DnPD+b7SXJb5vx+9+Dwjc5B+7n8QnXaWmMHXRo83JcZOJ0mms5WZ8P5WulRKdxzSUKHLGArRmPOP3EZch2X+8WagNBKYC4Q8Xxpsnw6Ag2G7YBkx0O+DOOwDIcCyUpwDrb29p2+ec1MmEiGUeSVZs3SWu47jn6/ZwZ4mIZ+/nm6+1On7VRESdEr90zUu/3KjXv/6LmnLq7kAg9SOUcWaTtZ5gE+PB6JT3Q+DmsROJQgHFKk0ib8tN2JARBygVfMBd4HpyaK7z23MPX6zfsHv7tR3//N2WrlgacmW8Zwu1r1Q6gDhKc0w5YBmAGwAgWCUIhCwEnWaXqcw3raMGWODGCJKCmVcq16s/Obd7cP/pUQqopAFxNL7/zwux5bKhVF3lrLmfd5PBWYj9M3DjjcCxPzpfX72zlHfVaTvQkM3diwZWMZBRhE6gZKbVYqvpECuBdFlXc8ce4jrqMCY4we2PdByzGMTnFMxzGK7d2D8MX1u7922Il+tVYuHJ6dr/WFhJiISUohteVCos0Xbtyvzxy1+8+9/bHFHy3kg3w2+nY4lfmE8wACjbVULeXedfn03Ht2u93PlSqV3p2tTu/K1nW7cv06vZkR7nt59HMh8AEr9kQtRnKJmG2WOMxqtjxgixNnja7ZU2K11TaxW56DHalNaDtk3zB7PDectfZQ3XllBaofb4iaXxU93eMceN5LehvB7CVam2GkntKeeHj3hZAgAEAO4idGfri2yllEk07PRDBC2I6OkInLmijQnpC5fibeEhzZmXoJQfo9heEO+M4Xtr+xkZ8qXvx5UQrKFEZwdK9+q3n74Ndpt/dFT8mtynwl8pXSjuNqKLvW9CPBFiVT4lFCld6Do9nwsP2B2XdcuIqBUwJjLMLAYh5fhQEZkoDBgGGn4C2QhDx66jBqtq7f2977YqRN4KLyTZxU5t7/6I8VyvklimMN2ThNMagDj1IFhZA6sq3tz9/4ZFAo3WcFh8zQZyYj2BIBJMLayAEvyU+X2qyg2+m2g7mpmUveRPGZo6RrDdvMKPGwvWn4/A/qkFKIB2sbt1rf2P3MZLX0r/Oz5U1gkQCCVdIlbY0LCGXd7n21fXPvS9TT75l72/lnCUXA6ezJ4QPCWW0Y05q3iISRE6cmH9/a25tNDG2igMNeq/eaO1O4wGnyG0fVhEayM0gWbOA6E8FE8Z293aNtJ+fuGeIO+hL7bJSyfNavFp/qYyKsJbY4uB3iTTot6KGSD4JBYrfon04MzbKBnJCeNY4QSoCTmLhQKBYuOIVgKTIJE6aZGB5hKA+iOgJklEKFzd627Jmvy1rQMi41k1jEbMM4N5mHVr39qwdrD4q1t51/BgOFphdB8+7uVw8fHHwyOeptKiGTXM7XhXK+C0L2mZBQsJBImPQSv7t1VGvdO1iqLS1crT0yv2h0YmHQKvZNxNL0XA1Zcl23pHLeU91O96t+ETvgyNdau0df9merH7eILDjNDsKIU4bHWgpoyZpc0Vso1Urv77S6Yb6UuwtOTje9MjU7e1CZLEnwpNtutSfLxcozcqKw0KXYUqojM9zjsy2HB84/C8n9Toc7243PFSqFDav7oYUgzEPbvrDywncc/X5PI+DMCNP169ft5maSQMX0zyzWcHNr/3Mvuc4nn7585s/kgsBoMgO1xRPTu46f6BMNSjAihJGOchgRcRopNg1G6qVZCgHO9FTlyWq5+OTcbvHs179x538tlycUKFIN2DoC8CPTjig45SMYAACdTodgK06IhmTGA4ckGcEDb5yy4YdsuVMI3L1SIZdYY7YtcxRG5rQj1cX06MRIAh4eZjdz9jSS77qHpbz/ohRwE4WMJVudMLMgJleoOAGtiaTs9kJvqlI8N1EpLNu02CWY3yT3nH2QEgoPm634y9+4+68J4HOL81N7wHzAlkKUmHiuY7UWAk3k+TnZOu1PdXf2W/2121veM0vn/oxSarjzPNyOwswIzNZxVLBQq77nxu7ea7mCaucBDuu1moCVN0lDXwWAL2Z/bxIFbj5nMEsD8WDKEQ7P42R/ckoZM8YQJabHUiWGWYNM7HR9mV+At4iAV1YYXvwFiJptjKQGowT2rFbCgrRsIe2gGaWWZOQSskM6k8i6OEa8KB60qBAwMqYmBB2HNVlHEPoCSJGNJICf6iZcAdp5MbHbAIlq2Fa+7D5oPGj/9t5rW+XCYvVHD2/v/I7Z6n5yolq+o56Y6EVMCevQso5tP5SkyHKiE+EKhdbzlJOnfrmQC492D+3Bje3pqSfOfHxAiBokbQfOjx22o6ThkHVEnoUoxQxN13UTv5g3DhAjkttvhjPSc/uZRGLmLCMft6VkqmSpoUTrSJubKL9RnCi/ITy1L8j2EKUxbFlKJLKClEIibdBxcmpvfy//+NLjzyU+5MPQJIwgiI4fCBhtO2FgdJXafv3+zdba3j+cOzezIYTc6sfxkQQn8gVZqxwQaKQm0XaKXmui5B0dbdYPDwPPrTxx5r3aaBLMI0uIs3QGsgDG2Cbklr3JfLFwRsfJlpt3TbjXuV84PWVZIbAVDEN62XGdnbMqmRGgvGrhkcZWfY7BbjDQkYm1CE3oecXiPFaDqb5J2MDxRj80tienXJzc1RgwtoZk2S+5gTuv434OPNc4BKDRuGHcy1Wq1cvsiVpiY2uZBY3Odz3WTAMEwQkTdvear3h+sJXoJE50JzIqjiuyYqyE3fz0xFcbd3bJmSwrcnG2/sqdX+V28pniRGGnMj9jNbJVgm1CNrExaUHEINNGb6eSF46Eho1s+OC1jVnMuZXyfKVkYg0KJQySGANGFqduDTARgGIEX9XskfGsVQcy77V7B+1Xok50xSk6OWMtDZ0xPhZQHBaAiCFxwcnNVR893D+67XEwKaO4m+tbG5ddCjsdB71y0Av7tZkLCxcST7g6MfpYFXCgh8wnGqZBgNzZ2q0nh+HnYbrQi8JuWGmA3r8Ef+BJcN9TJaysH5iWl69qoqY4bPVwbrLQvnlv5/+yxvDjFxd+rFIuSUukKVVmwmGbDDzUuvPw4hz1PI9Z0zDK/xioWjABJ2SMQMTzp2c+Vinmal9+9c7/Bw2/4XoF7eeIA1PSKmqjdgmt9Rgxy0SOJMZHxCp44KFmGxozkwBiCYhGgOgnkQkREZXEbQQ+yAirx4pFw26kk723g4yKENATAnelEHVGijRjolwmCoGFkmBNKHzfDXYO+nRxceZy4Lm+1sYM3xBHmLMjiR5ttLi1WX+FGNemyoWQCLpOEIQ2TBIdCV1UsbWIiJKYjKsEms78dLly1Oxs7B2298/MT81aay0zn6BTHBM70tOarpQXPXBmrHF2jeeJXr0ulmEZH85gwyoALGyC6c+iAZSSgDktN0kaqVmNSnWm9iSNHVAJsEBM1jI7LiIAdIqCfusja6na1Wi0PaxHriDAPMAkQNQEYCSMwTJyqjJLfNzDeMwLz9KCIEaZCozHRIZM0jzN/gxF81hAxIa1McJIX1Isse8d4fRzywywBo07VQqWwIDajyPiVun01EF40P1k/Xb9c07OaxQWyhEnUiXtvvRdHzzhAwYeSLKoKQHXczhRjAQGk8hKZsuFyZJtHbRv63b/yC0HVWKb0XUZiHGkHpxeW20IjLACpPDIGG091SJKQkaBgkWRdBJKxgSFTOuVMBCkyNK4AmEw4owZgRDRIJLRpk9ALYGiycrGXiKJigCxtYKABMTgWewXC/niKaeae7Kte6zZDqVQjzfXNOXFhCgcBc29Bhyub39jemGybq01gqVV0ifPV5ZMTGBiACsQQCVGxH3S3FQTpb3De/uv+GennxBFp2SNsRlVbhAwpJE8M1iyBJ6rvMn8RPPejvCrRds76BwWWv2+O5ULgJkYHuqnzBJhCAgJaRJ5VUWAOZ3oCSBv2/Uc1T5q5+cvz85SgE6SmDilsVtEfKjFPhXAO7Hmh4I51pIqOm5uujLReXDk+55IDLKR4Kl+pxfMLp59xCh2TGz1oHecHyKdMAAIB7Fdb0Jvu/F6rTIRkTJJ3plOknZP22mfOLQoWG8Xp0uq+dq9f6hDrVzH3VC1PBNZJ9KJUShZOYIES9auAIAEAQCkZEEcKxuiYonsBt7m4eb+7cJ0+W2EAHawB/KQYwrMaXGHmSFmA8YDL7aGlRB9gQ7HSX+vUz/aq5bnHyGjbdZ5MmIgs0wZEgtETNiymMxXwFM1rXXe+l6g/FaiQmODnK/6SZiX4Mx408VaBAnb0RZaHtEmZJE11ivuJqE8vLuzkXfdrTi2cSF2Y3P6yP7OlQn6g8wC/p4b4EEqemVlhRYXr+iZmQATa+sTxfIbtzb3/lEY6ztPXj79k7XJak0AWgCwlkiMEpPwpC4EPMzSylh3g2lCWSUl22RolFXIkpg50UZPVIrves/bLl774ku3/5skir9Cnstu0O8nVGLbDx1wSAGwGkxtGraB8Eg4nNVXmTnLniCjEMjpTPhEsOlLIYRh1QMUPSGRT2hvDB+vIbErUxpKN24m6hHojmCnrRzRE3E+iuUhhSCRdOjkPc8HIfJKiPzMZOUSjGoU4VAykwcDDhmYhRDisNVpHra6b0yUC0YgeKhERWrNgBgLFzXIwCqhBbDneBIDJFWwZP18zi8eNjvxqekqDbfFEVUOPs6aobVEOc+brxbzS11tHqhAugdJEn/xxYbld2QKGhmWrl7l9S/+PYAiAIfSEtmEGNM+zhMSg6PhLw5EOYCJQQjJKGWSGLYcxwCOgGsA35wRGqhfrQDAxwEODgEMOszCCI2MlNWAUhrncA1n93twv+hYhxB4WAbBEWnIAVEso4uABmaNoI0DACId/7Z/fQ2XrgAvXV3j69ev0LS3aSmYSLibNIKiL91yLmJiDyLjJ2BUZBJ3v9vkHhmKEmJwAJQldF1FSinIy0DkXNcVUhVAYwWBZdyNum41Vx22j6Rs6UEdmAERDAAiM1iJaJGAWMSIpueDbEXsgUQNwFhlgoQRwdBAQIyzmr5gpmMOBxMhAlpm7rGQfUTqCs+0wrCUyLDNEAIkQQllq+3KiitbR01vfv7UE9rDub5JDDEP23sG4tYDwiMgs5UMja2DqOIFHReEgwwSUAQOgGFNrgLfKGGQHIPasgAjXctWCs+1GsNm0ugcFsq1SkLa4lBDe9BKhMN6MChAp5I7ldyyKkARkzV7vYPWljNVuGTBpJ1iQMMnbTDaHJgQDbDM+xWV8x/RZG+yiu8zkCdcPhVMlS4naMFm28bQyA5170b2tocMFQIBWAJ0FfiTxcXDG9uVoBIYS2xZ2ACUc8EpF5Y1ExEj2JSOPCQsctaBl3mIqr3fakBsX7dl1ZUtHYdJgyrdLu8HQEE4YYXLfVLOflBQIleWBbLWYbYU2zjXT6J8YrQMbZy2AoKQiCBcVxrP8UPPdVla8AVj2ZEOmn7Y1Ym2wpWSDHxTTySlY2aAmYCAWAN4pK1iQUlkLDmee9B+cLieOz29CFIgWDpJgT7+PxISmCQRTuB6+bnqQntzv1TKVXJsgkg4iYki8jrtTqk0Xb0sil6tq0NiAjEkEqaeUeYYpcGtcAQe3j+00X739yanpzfDbq/X9NraCyYswAv8fRsBD1yJxUUw9TohVHtdafSDhVPT3Waz3/idr906urgw9WOn5yaWi4V8QUlpeaS+Tjyi3YGjzNsTnKgTTiTxsMkMHpYbRAYRJyYpFXIXnlle/Ou//Xtrf2Mm8Lcjk5OA2ggn5whrXKGkBwBqeCAP99DySEclEAAKK4QCgSiEZVKur62SUsY6G1d+3Fj1cE8wHg9mTEU2LLPW1gp2tGVItOE4DxCGO3maqByIOJjjyJIvk0TNTU3WCjn/dFbPwhFJpGybHX4sIwjcb7TrFoQ2xLlY21lUUIpAhRI5hoiNEZYBCIWwMhGYE1IVlZQTvoeLjuP6hoiUkoJ42Jd7rLCTOT6GgYSQuXwQPNVsNG4UVW5duW4051f1N4+1WIFcvMh9cEgSaGsgMmkUDCblOZ4UK8m+kzh47ggYUanAMdAJDUABip1YZMpWg55QfjgF/cb16wywxsWiw6ZjRMLpi4iPe1gH8jdD2iWmSks40swFQ18Mj6OWYWaDAYgxsYQ2FRVHdBAATgNADdZX67hfW8PpWl2EdwooTwMIclhKQ70wgt1eo0ixnppAf2oyKM6eyi/MlHJ5P+d4wpESNRL2TWJ6cdhr6qjX1X3T1SGAQCUkTgqBEjP/NFX2wZF+Xh4KVjBgJmYBlg0mLJw4QjDS9jhxvdgaYgOMmi3YTAHp+HnKSGlZDRSZkYgNIYcGrCECDWEpma5/Si9dXeL11XUMgyW08wUZ4ATqrd2iWw7eFknr6sQmxzpW3yxSw1JyEicQxmHf8SHfDZvzjCKwxpQSph6RTbRli0CWEAgRiIAkIHu+cMpSShXE/X6VkRM85lcOnHga9fCsBQjc04wiZ7RuCN8/7B10v5E39hxJRLYM4uEQgSwOkgPKVb4q5i73D9q33CnvTqK15+eDt4mcuhwnMVkmwcBIIBiJhk1+qbYxHpMP+VgEiCkVxLVxwpz3HmcXH4mJ+lIICMOoFhRK78S8dza2xlpgHE5FIR5GvulyZkp0InpH3TUnl7/LVve4zLF3UOLO0y4WXz8SnSKJEDQWEjAycMNmpxU0up2iBDlR9vIzE0FhoZALJgpuzhcC3MRorx2Fohv1Ex3p+zqK6j1jBCl0hMSc5zgKAQkAlR1kbAd7q0gZzcd6+MAWyLGCHctKW9Ja5VWjW++81Gv03h5MF0+RSXRWooUTUTAyIFtkECCQsDhTPXN0b3/GWNwiDnuedBU5Mq/10UJ+uvq2xGHPRlYzAxIfU8OQByWbrBoFpDr11n3X0BfI4SMngH5dl+z6lczP/n42wCsrK7y6usqNRsO4tUucbyTQLyZYdF1h0H5t7c5u897O4eOnapVnaxOlS5VyoZjPBanTLgcKaIycNn8OeoMGl2gwSne0DJxOzWHG0ba6kT5cGScmmaoWH39m+dyPf/WVu//7wnxFhgn1QSSCAJSUDkKmZ8tvIooxzLdm/Y3WWmOZBQvwCIwwwiJpiVICS4sGANlmY1oGPu/Aa6BRKiAAGGMEA7tEVkghIW+J4znL026bOp05NC6xkomIEytrleKckqJqjGXihxq4RkhtRICJNTxZLVXLpeI7BHKSPY8CM04VIrMAkc6sScd6pmPyED0lZd6RWBQCkWiYbj6OTjJiDjMAEoOQAj1HThvmqUSim9OgKvWaWIGVkxojsAIA/z9wrGZ2pLU66RKTtsyOTVtbB+K+WYQwmIaSXUAiAild8lXNHICQ0rq9PInKRzI95xdeeMv6TLHoEMUSDREmbBhJAqVEaxZDtWVkZpGJ41O6CIfErIdOhY/b9pEo9bkEs2WDVoBAKTgEBus2sP4ARPd8gwudRblf31eeG7tVPZ8/6G1M1RuN6cXa2Uc/duEd7zldnrzs5v1p62IxdMhhZClRosyoDpYsJEy2zxSTsRoSk8Rx0m9126SLMt9lIM3pBp8OVEhPizFrHkZIWQNCAAuBKFOCUr8PID0AZZGM0dYSC00Elmwqm8g0nNaBg3uPaRZPk0GrLZIAchxBWm/A0tUlfgFW+NrVFdi/Dpg0AgyDEARCBXy10NcRGyamtBCAQxcHB9rfaXpSguClxYvODBaeyaN7wSWRKBQaATQAWJuOACBEJoXCCkYWAlGzdWMwlYZvZ46sJksDNvtJARHKVO7IWjISJqzkiTDWD8BTSa/V3sl3wp5b8UvMdiiAOahSZEF0OkwBBIiyX7W7jVkgOZlEoSpPTz5CjihYm1gCxixCHfC8MyJWKoGYsZ6Pn7FjfWtkZiMCOe1MFp5Omr0tr1rIxWE4WZ4+tcCedJMkssSMNHSwspKKkMxp3xr0D9pGH/TuFgqFNsccO17AnaIWej+SQeC5XmxzOT9fuNc9qET7/eknZ88//p5Lj71zqjqx6JVyU+zJohHsMLKklLoEhpnJMhPZJ7S2fYqN7Ye9uNXrRF3d833Hg5BtKmt6IjV+PAqPMo1AYpDA6JDQxDrRLJwjluJ248HePTWVXyBIHSAcqLHxcd+WEMACCROTGFkJKsFkcTFshzf9gt9PBBibxBXHDc641fzZyMRsBxwJHhkTO3ykCVA53Ov1sbt98KVKMX+/c9TXeQfMMizbdXiefx9yu3/kEXA2GWeFr1+/xBs1BY5uY18VOScdMzPlhP3YHN3cOrx1b6d5tlzyT0+WCxfLBf9coRAUivk8OEoCpqEZEQ3bKY61pBAzkUIePhDDWtzJPXIQgwptiE5NVz9+d7L+Sruj13JFB10pbaKtsJYZMC0HEo/oGQwFLDKPMlVrAGa2ZK0gQ55whYAknfUFwCAkxsBAlL3XcVZ81LBk7RAE6QsZHQusUEoRKxD1nR0sui4sLgIcHgKQFKJtIqeY905JKXxtyDCwwOygMQ19BqomAzobzUyWJxBgUog0MhIDFisRCiGGJXU65u1kM+4BgAiN5RFGKsCJFOGIF6uEAF+pnLWUR7JSWCsPrJUAKzAchpC1q+09O8ETxSmQEimMqZ1onbCLBctss5xZ5pVmdxyHQ1dSc+xLYM99xCa2KIxNOFLO/vU1hBVgWHmTCDh1AgC25yGcjCCyGgJrSTKSIGJKU7Mj5ECb9U2kWSqZUXOPy5ScPari2F3LNNAED2QamW1CDE760bVaT0wnXewEynE4Fwg/H7x062tTy9NnP/ADz737h6dqk09LX1SaIsK6PeKOjSg2hnXajTuU5kGBiCAQhfSUI73AU+AWZdWbrDBRAl3dA0E0dE7tQ9kb5vQYQYh0eA2xiOMYpFdkAA3ascwMRqexL2gmGFwXHBie0YiakQ1ZQWwVJsSx8FnAIgBsDK97tziPXtRERxuhHHfSOrJKVpMmRjs4HoQTLOi07G9QCAW52ZIn0T0lhbPAAGhBADKjQJEOnxAyY9SaVJwSJRM66Q2lCPpxlzVlKtWIJ3TPCQBTVgFQotgnKUuJZnY8GRtDG52D1m65ElSZWYusJW1IfBikmoCBrAVRDnLsyBmjkzmbaMcrF89pZGGI0k8/brNLE/gCwEQakoMels5OMsXHStqjbTfMxNKR0p0sXGrvd15ThntEthJMlOYi0hjb1PQOWs4GJ0eUydcAyub9oyMI6ZY774RRFLM1famMJ6T1lCOwEHJU3XyweeFtCxfe/e53P/7uQrX8aM9JSg2I4J5tUp8Sjq1hMyzbACCm4gmIkJOeyOdyLgQTOZiAAk0x0gH1ZWQ0IwPa480jtZ6pXh9k9CqwCGAQpWHJ5Ko4NKz9cn6zu3P4hn926l25ah5tbLLiWipNNtDTJcranBmYfOV5c9XH26/eedEpBgkbskm3M1WuTj3CgTupbWSICXkkNzlK92UGRomqeXOvY/d7X8CFmb7biaIY2jYlsPyb4XtugAesyzRCXeHr14HgynWzuAFR9WJkLbtRv5O0i4HYyZULtzTpfKvV93ab/aLv4NmiHyxWS/65XM6/WMoH877vFvK5QCghQEppU70EOyjIZ5P2MkN8bIR5RNF52FZiia3rupOnZ6f+7NqtXZMn/w1tTBdQKpB2oOEOo2vlmE14svxAxANSEMWEhEqQAJIACpgNcTbbBBCZjrOYJ/r/MN16gFKeAjGhsEqLJA6E77l4x/cRXFckfkMaEyggmfMcdQ4RgTIi50itZzRRP+SkxTrtnB4I6OOIIApYO8I2G/RnDxnHiMdpuxGGKg7ZwgNPAtMvFFJKawmVlSJ0HEG+L1YGtdmHSgMtABDoWDC9ZhKbnnDVFBPbYdsJj6QyBvKI2ecKa0FW/UcN2VMuuLEKjBf0JiSs/i7DVeCHhT0BAKavLHP4yUZ6PtoSOSKHvlJGGI2USQMipt3lWWQihoMGBICxx+yRjBtNPKprDgCWAQSxRcGWiTSypcSg8YwqO01ugXKcyJ3s62jqYP9g5kfffuXfnTsz/6O9wObWo33TjkJjUtUhzAoqmO4qhIMpSJAF2mkgpqEFzMwkKKUEYdqnO2B0p3VK4lH5OUJiRKYsGrMCbcDEOiSSLkLMkACA4bRjxsJQ+CCbPnTMFR0wW9NWEERGQoAe1GvbNKjHvwAAS3e2UZ6ZwKhjFbjuI4niChDbQe2Jj3PDQ7nC9OwFWNK4HTdgFwAUIAkc6puzwJOaAYO+Z2JAiwCWCZEh69GGE0pHwzWcDZVgZialXC54OduKQiYZowOvhAftzwRnpy4KRCQ7Sm8czMfLkr0WQRZ8FzxnLunHy8pxc241v2iYaDjakUelJhlYKOi1ejHdPUxy52pFCzTi+I8IaRAjMLFbKZySjrhstInQd+ah4i1ENiYLdkiSYx6dVJTWg5M4kf3D5lo5578e9yLrOw5G2rhJEjn5gl86aDZnAiPf+bF3XfmJ2dPTjx65Wq7Hm6YXxiaNXlMGOKdtO3Cs0W5h0CXw/2/vz4Msv67zQPA7997f8tbcMyuzFhQKBEBWkiApCBRFUSIkUWO1bdmSx8Vpt8cO97RH7mh3z0R0T8R09EwMEhOz9Ex0zETHhN09jHa33aFwj1ketWV7JNmiLIAUxU0ASQBZQBUKtVfu+V6+9bfce8+ZP36/t2RxkUQRFGy9L1BAFZB477fec8853/k+IUg3T0sjGaUUkSZWhYrNVEY/rkLL6AhHn1cYZ3hPzJlkrB0Joo7P3FfTg96PxAuNjwhgITQeSRoL9UwV/5z1Xs/Fm6TNU86mpDSRy935ymrzOaslsrn3BTXk1Lhpma4QWCtxXlT3QesNrfXrLrNDMki7aPqr25e/r9nfP5EMuCRk0dYWZGvreb74/EsuWV2V+aPYPYi7NhCb5Io7tcCEJojiuUzFPvT304F99f5+v+Ll5ExgzJNRqC/WKtH5ejXeWGhUVufq1Voljkgb7Uu3kmlNvAlh6lSmOdarJRbwfLP2IRPqW07kCJocCUIlpAmkimx7qs0zXgknSzoz4FiUELFm8iLCUl5Z7z2NBLCkJPeMS+djSR2ZImYVlScBiTGGkDNpNaTo2JB5PKReu62QGqWVNwqoG2MWH90hn9px0FSRbdITLwirLKcYmN/ZLGHiUIXJTO5UuVUmwXG8GJb7biJiFp/5REEBcbdLV69eJVw5PR7U6K9LXhmIjgNPLX2UD/NDMxdcLAczx6W4qd1A4cRQBGbFufeoBY9LM7xEA3/g53Q1qejes6uf5lewJZN5Spq4X129Sr3nQg4e5jaoVfe694/fzBSLy60YL6S0UqwoJqNJK+3hGAIxYJaAyFTPLdeUKmPDdCltelBqZFDADO9FOHRsDZSQDsCxUoib3Wxw3iX5B//yT//cX1drlWdfz3Zd0rOZgMhDlB/1pZnptN9MOcfLRKQgBWlECqEQAURUQZJSPCZzS/l+yEi4qizrQgTOeTjvldJeKSbxSKHimrDVYKO8U2BV2rNNe0mNqzhjNw8BQxSz1956TZEBrgHYHLHer1Fe/yR5ExO7k4CMXsvhwhGfDlJWcHCaYz+2ghNAl+rWQkR+JAIwZfJTllzHKrdcvKMkosZ/JrDIKRGcR0caSViR8ooabJ2LdJRQs5oM99uvVpP0OKzFq+TFY+pQR+I6pSgBEGilG5W5ZKd1obI2Py+xaeQuZQGRY6Gik1MeRxGFVb/V6wfHgwc2d8+AUGyMpiZCRloJ4lhMPZyjOHrM5fkwmK9dtBFVrXPMwjTWkT4lISkQE6iTw2PH3WSblmtHzntmz0aDtYr03MHB0dq56uJP/9hPfOzfHSxi5dV0J7d968Fc+v+edoIq95kkp2zUJjoWVGqRQwBFjFFuNJmaL+ewIeMADGZY68mDodmyjzOnOZCh46GuRneT3ePfqz6+ehlEWrEvp7pp0hYaF/2ExOWeYr0SLdU/mLfSRFeDUIXRk2q+eiGzOTNO75lReg2XMUJIK+odnUi23329uVA/GiY+aWRDu3K/yvg+Z39/6AF4OihubYE2N68SsIJ+ngtOwCuVmuQLHfE7KaMS5boaJKbKAdjElcUg9hahE9di5++nqcztJsM5f9BZio3aaNYqT8836x9aW26en59rQGtyhVb9yEyQMG6TT/qIozyWHLPEURBFobmQWr9Yi4MT7/JQm2Dcn53uc05E4CdOQQLAeQZ78UzKa9JEunBtddYpL6R8WV4rNgn0bYQuKj9QGLCeSYi0tayiiChVimpnFeFhQFiZg1Yd0kopBowx2sj4OKeIQOUqWfQ0CwnzUaA8nWXQ6enpcU2VpseLisOjqTKNnE6wS/JIocVQztNJIZ7rmY3kdki1Zi5X+6efjRe3tuTK1S0A8ximVSs2P87agz0+Uy3mbkcvLE1kKCf/KKscnr0Ow3pwpvFMenfwerBQq/aRxkGe+U+9BHn5+aLy+mjWvTqo8a4kCcVyf/Ctnf+jeHmcCctCCHVgDBTVROvQaSJyXrH3gcp8TerRenB+9VMKHCkp5Zp4QrPDdE7IniyzcM6QqiLAGeogSgIO4YeNQTdZ/pmf/OTf6Kyqj97q3ElFSEmh81xOVhTZLo/Z9qP7WRoNCgN+ZOE8lY2O5IYKVrI8IqVaaheXU6LlJsFZ0caTUlEEwAIDQNWMFIY2xWjuxDZvsq+Z1EMKqUhvi1lqL6SlK2rc6geAzSs4u79NqMxTN8lUpVEzFiDxXhTTeJgYIkSFLi+NCNFKkRRylqOWxKj/zNN67DTZD44y/mLhhyKMx45G13S8f6DxO1BmceJEwM5WRKBs7hxHxvs0P8la/SPViM8Isx95orEIKSKhManLExkFasSVfJg3g/nGQk6srbUQCBz70Wa8WKW0Yps7leycdJHb+7aTPKXn4hp79qNRbpFRRqwg8MKhNjJXWUnvHA4XH19byJUn530hk8OnVMPGuYgTMb0HR/s6dW/DwCkxQgEbx2F1cNKvL4b1Dz3zE8/9jXuV4cpRp5sqiC4clyebmclUyog++oh042h9ITXaKpWbkqloV16nUfaqeJI0MDNsoUHPXhHbHOzFOR3I0NQqnf7Do1vhwXG7urGw5hN2pSvOeA2S8V5NwOyhAq3Ncv3pbLd3ZMmb6kL9ko9NxdqMUc5KewZNFvapnjSJOr72INVDt5MvmkGQDzNuOvfyqL2Ofw0C8BQZi4DnVbt9ier1A7VyeEioXEQU7VI0BGMe/AAJ4n1PUWTS2oW1Qb+9H7ALtVE6qIQmqtYozh3XNFR1mGT1Xpa/2np4+MrOcefj66sLH3j87MrZOAoZcmpYD6ey4ikhNC5klXRozFIvSZvem8BDGQMFlpGTx/Su7bQsyOh58p7Fe7aeyQlbIhJVKEgasHXjLtE4oE92COM5ZgigFSbC7OXdibkiOEzKEzgE+jl8vc6MwnmJMSnrTJcCT+l9jA0OJwunTCWFaqK3LDLN6H1kPZ/S2KdpIlrRw2FMVw+tF289p6K8JxXwfTsnwOHUHHWx+BysgOc6Dc9xllMc9nE0vGFzl2lSmmTywo7VCGTSqykWUQ9i4mBj/ieSB/1tM/B7FOIkyZQ7OrvIV65elatXrpwiY129coU/9dIWaVxMApezenolYQl3c7FxAATsRVmICRwCIRfAU6CUClXm1yigDysTfNL7nBhgMJMqtDsmwWkksSACzwKv4DImdpkYr22sw7javrNf/8gnf+yvtJflo3udnVQJtIAL4p+UQlujDdNoT8SjKzDWSB+33wuDHoGSws9l0qAdMaSmNd14ZIUCiBQWe+wZ2jiDDIkPpVa3EPHivWMRCHNxLoCcGo6faLszChKfeEgxKsXeUl5fJKA11l05uAhkEStltFgWZ4uRDyldnmg8hjjerBZsBSUYtQqnxnQm82+n3JKkdAIeLfTiAa9H75xMeuCj6yogpaaTt8KLmYkUs5Cm3FpxOg5O0v3uTb0+v0kEqHKRKWfHSRVMxuJx9Qw1H8US0hk1X20kNlWOC49lz6c1unVAlHb73nXT6xzqm3m7dzmerzzlmf242iEMP9oCi4eDVlisreDuYRIuz9Wtl8L6s2xxcUlm4/JRUCZgl1vyB91rlXr9Xm5tpgjsnAoVXBWZPf/4Jz/4N+/Fw9V2/yTTRCYXX5zbSDlNpjm/xSZCjfoEpdb8eDpChEoHJKIRZW+0/nG5FpXlX6XK6gkXGw3rGd6Ld57YqshTaGzWHaqggo6E4TvDu4d3wvWFNSrqNXp0/4lp5Cc/YoCTc05oqXbBaerzIOfw/fOXcoh23pcZrxSjZ6N3eDQSFhrpd/oqeXB8Y36+fj1Lu0ktrGbd7ZseuPwDiYnmh5X9bm1tEZ5/Xm0eriica2ooF2RcNzpk79ohKudqHA+aHnHb7YapPAsHDO5ipxlnK4eByptDraNIJYNAETLjLUdVE1eqcVT3XnYT5965v3P8WDWMfuH82eUfHc17C0YCHaVrGtGkalbWf0kpUkY30pzrlViMEtJFuWW0yE+yh7Hu69RzyMXgDnvACazzihiWSJFS0IAixaMHTTBVFpqIchCJgFSh1lEapHgA0D7goOo5qTjxVSt6uCSNRevZO0+SJp4l8aeIYo+a0EzIaBBAay2FnHZhT0Zl+AUxqZF50rivxXi0sHpK2VLKvjCVzOFSqnFC3PSpF38SOJ8PbOLhHF/BFHWhDMTPv/ACv/S8tpUkTlWDExz3vkGpPPB1/QRlzkoh0jIqLkFh1CQf3QtF5JwP5hsr/sLCX86uH1/DhXpL2dSvHsBvX96WT720Tc8/j7IXWRhzv/z8lr9y9arcupT7IM/yYTXpuXaFAMAHA1oCkFlRMCZg50NdCeJA8o7R8RkWVkVmVQRHKh0oJ45vBW+NlMACxCxWSDxCMY4k6By3grMfuPjJdEX/wkH30EFE2yIoTp4RnlIuKiOuigygtPLek3VWJC+CI4xW2igKjCEoLQKGWC/gcls0KZaXDGYU+3shESXIixJ0TjrMnQGrIJRBP6d4LvCKwEXGVnijjom/Mi1JMlaoIwewExHrmVQFsGjSlc11urq9XT5GF2GPjhWlXqyyHesFAdFkunyKTTzSXKfxCA3GQzqiTvVXMFH9mv6pspJAVNrHn56Ck3HGO1VRGQmRFh62Ft6lrFWO7tCreq2XH3RfCRP7M6oS1BV7X5DjZSL2MlpfnIOOTBDN11fzqlGc56NqBk2Xv4shD+jhYadHqbvm56sPsuPBG/o8P8Wl5Q+PC1ZSUpQU4BiYixu6HtekGgbOpiN9UUzGuaYSCKXM8Kib+Xb2NXN+oZOTDI1jRqDizu5+/PiPPvMXOsv6qe5JK1MgbUtRmqmexaRaIL6YUjFG2BB54UA8g0SYVKnXr7RobYqqgHcibtLT9sI0yn+FFOB9qaNUVC28MATsmbyPyPoB+i5ozkO5k0G0Wn+YHrR/PztJfiRuVpTkxQTIuD8+spwsWxdsBapWqar56tP+oOvV6vxcajMarW++vB+n/GKIRIxS3YfHA+pl/8Ivzb2j/SDdv4787iY8PvOivOcD8KngiyL4pnMuWHZ3qv3chAetQ/+hi+cCW2twemJcX9p2pYd8BUvu1sqAVw4PGbee5RuXXpEFE7O/fZsqlQ9QozFnD2RgA8O5Q2ADJd4TURgGdNzu/s7qytz7K3FYZ89+zKooKe6lkLrQKYcQAoCIFMUEZaz3gYaEKMhNUztrGfffZEqMwQvDeS5WXGgBGGEYgV1GUKQy4VCElECV5bDTwXdMHSlsh8iyFCkpNKwicgkRasX3LTmWRIkYH7AVkdz6nHmySZDpbghNsgQigvcerZM+FbOs5UNWGmGUgXrkdDHZRRZErJLOg0LJgSauwYpOk+2K7iOJtc50usOOF7/bUzbjrGIXo8RvjxfhbytD80Ewb6NKPVHZyT4fJW/z/PwTkrmyXz5J791Ep2YyXwYiym0eXVx5UvXcRzvd5J1wpUatNBc5qeLh2Tj/56/EhGd3/KOZMLAln3oJ0n0AhcuPIb+3S0hiPKw0ab3WIjuwCJXXwhXJOGetI1YqJOsyMJf2dIJTXtYyuoUgcc4rz6KZFFlHAZlQ6+FgVW8s/k+7kunc+5xFNOMUB27K+INBSokLlc47XeGH3ZO8mz7kJDsKMk7JivehNiYyFVWL54J6tKbmo7lgoR6Q0SOC1cRkZ5plXAaA3Fo4JxzF4CR3pKMQQdjkTIYCB+TMSgvg/en+CY2zyOKXEhGbW+198TZwZsg3W3SwcoeubG7iYGWbssMm+XpAOtbknGszs2WYAOWGY1IlktL6kMb2h95ZFK48Rfk2VJqUoqLxUW5aPLEUP6FkRNgjUhNGMINMSdpy43bSiBPCxGARBiUuo2TQb1cp6LpMMhUEIlE4zA/at/NO0gobUdPn1p++HhPWMphhCaQurOiMPMQzpnvG0yNGHkzJbmdPQ99mQ3n/qHOfkizVmgL4UVeXJl0iAsR5SKB0+PiKysmSy914MRur1dOY7S4g6MHO8X1ibHvkGZTkokA5s4rrzfOy0fxEe9AViKgccsp9bEy2LB90pbXoQCPp9lVy2OnnJ+ltldou5d4KUQBDDWOCejhXaeqFxlwwXzOBKd7jUW+aSyKf8GgyuOgFs2c458EanAFwPpJKknHSOHHCSFmo55x8K9lp3QvmLzwhAltYQpZVQB6JexQZcJEIC9RitaJzLz5SKu/no+xpQjOVab0JkszlpnNn704tDK5lw3RQFZVdBNzd7ct/rNGjH5YW9Ljs/Pzzz6vXkkSjfxhsNJdqJ72guVBprD3zoyuP/+72zW9szM1xFLMPdDVNwzSfy3W2gpU8ipq+Xn+bL8expGkqvUqFgTu4Fa+oehh65I6rzihWgdEWJ1rUgnjbFXZdbeK6c3xKvXJMYKFRHjzFNWfRwmKEWXtFWgShgJTnUXlpMk+HKT/gQiNYwXkRsIIT1qEmsjYnHYXIrScRKGZRnnmKBXi6iUxlMBMBHBMKa1NWKZyOYtGNfqTUMFbH1UOS/iJVqzmJiCTOJ8wjNv+0AOeUnCyNyVj6zdu7947bvXvK6MJtgGABEa0VAIoFqEEQEEGpopPkiCgvj9YULwt5GdXJizKpAsR4z2ydSz2kR0qfJM59M46j+4lzCaqw/bDiX3zxO+8cD1bAOAxclkiaVYIuP2h/nTaqP8sQRaeEgaf6v5NcvPhNngNhSObymV/UX7t107WS62a+qgMfkOqGgyDv58++soFXnt06FYSvXN0srtbKNuNwG/3VDUpu7ZCttGjYqyupiuKkqUNR8aA7qIS16mIIGA9IyX4XkUfngaWgHjDDsShrfZTnWegqALdPVGVt/tlBhT7k09QxsypbIdNBESMPZQJJDlYnbz48zL6x80Yk+mZQj68FsWkH1SoRgwPHzqdS9Z3+iufeB2yev7/yzMYT4eUz85Q4GW0aqbQkHPUfisBMcCwiLN6JLgWE+xi4gVQ4kFyccoBiKWfpRh7WU/egEJj2pBXBOwdhKGcMNFlaO0oIjcnleXAOWD4BONbEraztcjdEaBYme2Q5RSostrSFK3X3oMfDL95J1VzcokD3Q60KBWHvc1X4FmuWkZ6SKIJo9qIVFX95BUUCFZASTeStc5mARJVKeYA4EGWkVM+ye5tS9xv5UqNvOUs5CakWZEnuZT/b7xzoc/MXC2/4UvimJDVK2YIoLwrUUkxZno2H1KadjkQEShtJkgz2eHA/iMM91j6wreFB0Bl049XGKpzYYry+NNYtR2+4/J5ofY6SPCPxxUAWKQUIE2NSdVPaSDIcIr3fuldpVg8cUa5YiwtEp/snZul9F55xkV63aeZQGjg84gwBHvXRtBLxXne+9U6SPewcBaK/SILfhDFWASF5F3jH9dzzuvX8uNVyKZivbqx+anOVNMjziIwKsOexr+9IYd+zwDF78ciVeAEMjhpg3AEvn6tkw0ySeK56e/Dg6Ovh+eVLJlRgbx/RvD4lhEBsrfiVqqnUqkizjNgVvXKZ/qnyWjEzKNDo7xzB7XZeNY3mocslHfZz9xrwAyFfvesBmMvZw83NTTo8PFS1cCOMFnU1S+35dtc99RMfPfe3Vhcbn5yfq3zhG2/vfamf2NuNmO9UdbWdx3kv0DIYaJ1hEfahW/KN3HJytsmr3S6vFIutpOkCt6vi65nlyAgTlORQoVEkhTnvFMNtqo04kcEoJ0yFYL1kTMo6RQq+KGuWHr8lc28sTTu97tBIxdQJ4IVZRIQ5EARa0iwVEnIQPSjaxCDPMs7IJ2MWk9nWMo1iRcTK6FBDQptwIHMN0+OA59KqTnQ3BIdGiZY0tS3nT/NGZVTDmzazcIIgCLEwV0/2271v1YMwAXOfRRJFKmcSTySsy3hd7LnJMcNT2VlhYVJGK2KJtVGhMCj3nh0Ls3fWgTMQ0szbnnV5O9K6HWq00o7KKnXrNg8Pv+vOcfVwUw5WBg6941RWG73s5sGraM3dojP1p5XnnACFKfZlyRefZAVl488mmQsr4fuqHz33n3Zfuf8b2Ol+RS/X3so76XEmaZ+zaPC+32jZudUPjutNty61kdzaIRwCeX2RLHZoOYbyQVXnzoaVTlDHPFaOdvafmG80PjF/+fFfPPaJ9tZLWc4d91NJpidomDSU+CJLJscU+NwHeT+vxI/XPuzIR865nJnVmLBAdFoBWETEkG5fu3+UvfLg788/duZ1XTGHKsRe5vTQB14qoZEMgMpR0VJbVOIPcTg4hlA9835eMQuRokIysNCzKQocUmhXlRNTjsV7Ys/Ke86I0QPykJgda8dcFLbpFMdv3C/jUlACQlRo4LAShsqdGN9YUWgEBGyj39igc3kfLdeSuN7wNs2P8pxb0GoZVrgcvB/x6McMcwFDXCZmrqrMfNxTDr+hQnlT5T4FyUCsGxDYaxgoFnKkSRETQQKQCkEw5NgoJQGIInipOC1aRDK2PieBI6/6HtwjocTDnWhd2VercSqJzdl1Xa06r9LUZ3oxPh7utq7r7tpzFFE5vFqSjcqNOstEYpJ9DkUEd4pnPSYyioqVDO63WHr5TZxvtBxgPHuTtvq39Jm5VQEX7heY6qOOHZFBmcvHmxUFHs3lCI8c5gBRhtC9e+xdP/8mnZvvuDRLlYlYlA44lUXM1z+WQQwz58KsxrqBU8kLCyCKhL3TJ1+9/ro86P6L+rnlO4ija97YHfJgJ1rrQOlAKKIsmxeYc9ra95Fzzzp2P8OkAil1HEZSA6MphyJvU+K9V47Fi+PEOmJOMwp4UeY+FPPOzo5dsUikWdnP7rZ/a7B/8vHK4yuPSZ57NWKJCEiUknG/mQC2VqlqDKmHsNlgImcrmNosjVuKImDTvXNwIxj6f5Uv+j3KTW8uzhhbWwJ68QcWJ827nf1ubGyoysWLwQKoEoTR0p29zvt+/Jkn//0zy3M/Oci9W1tsPP8Tz4Q/dme3e+PBYedll6a/VwmDY5X5HgVZr8G1vjNprucDu6q1O3BNaWov1i/KmZqiLHNaAjaag4jBjUatslaNwkZui/0sM6b9G047LpXMx9w5ynKfKEIuXDixcNkbUOX79ahhwkiMYDRO5IXApCygXCa5BEISKe09weUutyxFuBiNNAlPFpjpYvTomSi0i6hCLBEZijpJLze+SXlc15y0I2+0iaNQ95PsyDrOGQhk7M1Fp+aWi0xKSWa9LC3Or0e7rSCMzINI0wlBdxmSgJE5cpkCrLWQqhZxAAxM4QylvBKPUJQLwagNE1vLvJNaHJJjDMTrjiczYORZhVViLQ87WT8hpMnaynxWO2y771R+HvVbrorws5/9rF+pBnka5ElYDR4kt46/LCvVp41WAs+l4L9MyX1MMS6n5p05Ta2pho/Vnn383/PX9i+0b+3/SryyUIvn59pk/FHFfGAAgDsulUUAHZcKwiqwvASYAdW4aTKvg9BSoIOwkqWdhezO3tPrZzf+ytIzj//UoUqqaZI6ElaYrjpM68KXD4tjptx7uNyBhbVjDrRSDa6qjUJZalJyLZ4QNTX3LCCjkPUTZe+cvNU4v/xqFspumKZHvlY/ySUfxseJHwLILyyqeg+R09mQhWJhu6hDNfTC4JG8VzEpXmRRk7lLIi1iPYOZHQs5b8GhigRVAIghAuVLNvbpzeN05jCpCjkvWkRCgjXQKtCDXnCEM66TLIrFDs3ldQUAzucsue9l3eG+Wms+JYXymZpuN5AajQ0VFF6KDJlLi2H6zZ0d06zf8oa6WukTqWDga5VcDZykoRPFgcTKkBWrdRwa5DYASwjLsbW+EUDN99sdZYzmqFHznn1fwMciUY+ryIVcVgvruT08cd1zTY8HqwjcnnE076L5+UH/xoM3klbvJD672BR4FmalyiDMo/J5CQ0qp4NpVGAfa3MTSNhblTxoHQfK3MwV9SWzCkFE6WHvtSB3H1OlU0TJnjyl4DWiiZ7iCkx8ckeTDyLWm+Rh+25A9C1nOAsoSq3OmPJQB2G4YWN90Vsr5IsZ5dO2Y5MythhN/bf3nHun9a+izTO/ba1vUdo/1BV0c4bjoELa9XUuQUTCfcUu95ajgNTjnogdC7hsicijIkmT9g15x540cquJTTWS8FxLXrm2ye+rp75fSbLAJT0t6vrg7uGr+rHFi0opYV+O4gkgnmkc4Etms+Q5POUjbdapVhtOG/8YLWlnSNnto99pLtavI3VdTUjrO+unezfv1QDMzLS1tUXXNjdpsV5XC9KISOv5B4ed5lOPbXxs89LaT6SObe6EUutsHJjo/ReXP3xmqXb2/kHvyf328Btp396JA9r1seuEuU7zyA9paNK5RsXled9X9dANpEaBokriuWkIa0J0cX2x+Rxp3UjTolg2uriESY9uIm5eGKwlmcUgyYYmMLa0DifHTBNi06QXTPg2WS2owgyYxMOy81brgJmdpJyJ+JC5aL+p4nPo1JzuKXHLYjZQADLMHDNLVakgCjUiFQfeeB9bn2odV0PrOVJGh62TfivJbSeOo1VnvZsMC05Gbqbmf/3iQqN5cWPpQzdu7z9YX5kzXiQj7wfQaqi9SrVRVikR7yyBtYaB9t4pUtpAQWsd4WSY0NJCfWNlvrrx+vWd63ElyJQh59nm4pFYFQwTDIZx5LN9Pp+foOe2rlzhz1y5Arz43XePlxYW+GBlkPPgMKXFplUPj77mdoaftmebZ5XPLZcBT6bs6Sb3VkaFDWGAbJrZsFpR9R+79OloZ0GfXL//1c6t9i2pB29XlmvHNAjtnIq9B1BVmtS5QAAPZ0MlToW5TsPBUTvGSbowP7/01IUf+eAvBucWf/KB7VE2SCxR0Z6YlFgmc7AjDWghCEMhd56YRbPz2puS0BsHNV/2s9lLSfqVolerSIQI5AsSUt5PocQcShAOYJEhDnI3SFzcz/1gBc4fNqmZtJCmESujPMdBrhR5qUa1UWrOU8xTEhApGk+SgZksO3j2OYt1IIB1RspHkuSWnAOcMDTzVCWIT3VjRsIg7L34UAeOKHKeaixUAXQ0f3Iig0ixPqxQtal0EMwFg2GqEJss3W8dBI8tlWV3LjcKU/Muo/lvApA5DtcX5rO7rbW8Y4NKI6o4yvtaIqCVICfHAdcYAFLXVT4E674whSKGhCBBqIBqd++48cxzP/Jcr9tq37xx5/WFtSWfstOEFDQwogOwwFkA9kHW5WfbG7S/cAZsMqeGObPCHbt/cjc6t/wRISpUZpkn12Jqx86FK9ZYFGW6OqqMkqyXaHc4vFdpVHetS5NQh+C5OEgP2jfDXtKJ6pU5dpaB00TLERN5LMI4Km2PJW5LEqXRkvb6ZPf7N2q1+mE6tHkewEUwxOI1B2jmAVXIOSF2U7t3Gi+XZc1DvDDlrWEa1KtdycVacBaxzQ67QV4dwOFigmOu6wVtyffESaS896xUpBo5wXjPwp7V9Da61OoYC+wUc9viSMgTOwGl47MNv9qSw+fhq22keqPZtfda38qP+j8XLFSq8IXg+dQxTz2bOM3ePzUeUnJwaJQYad25vZ/r48FNPFlNk2ObqZUf3OjRux6At7a2aHNzk7ANrTcrgW9QM89wplapbj63+dhfdspQL/XlcDwocyJae1+vxEsffDz+MxfX8+cOToa3W53kW4PU3k6d64JVK1DqRHxiDQUudeJz7iilTZVIna9UgmcvLjc/Nt+IP9C3wl5OS2SPuDqTXuuYwUntfpoPMvdwLjB9y+IBgvdgLtdDlmnVHPo2M18uJdScZ6e0sc4zCzGDDSmQg6i81BQu7dqnMoZxK7UQknQemJ+rhdroBoSXlZJlo7X2eVYnCoih9cFJn0Ota9VKUB8kebfTH75Tb1RWc8elF8BphVua7IzJOc/ve+zMRzu9pHvYSb4534wyrTSTNqwDZ0UFFlkObQIh0fCOlSIdkNY1693SST9bubDafPojT539s/U4XK+F4Te//Madfx5Fpqfgc+slFcs+YDi9OO8Wuwd+/bAvp4UwvnMWfPmFF+TWxobHAid6Dl1uVG/incN/xsuNf89qXSxzwlPXjEmmpD2LxWciCZsmqVhjde1s4+eXVzc/Lge928Pdoy+d7B6/1snzPrRKOVBWQ0PAGtYrETYQxM2o1jyzdv6x6oeWPiLL1Wf6xq/0BkeeHRdf5d0jI25CwgArEipHg8tmORx7Zs+510o850zwsIqMeAfvuKS5SslWHQVvktEIlmgCa7HesVAIyUaUpJWVYiztHJAOKlq0NyoMQsltXYfqQn2hspZYLyJEXjydIv+JUMEiFgg0ihLNVD7SA7iREauAPDl25bUvy0plIULGAvij2R/vhKleqfvF8P15kvdULVYcCKPGw4iVVBpNuf7gpvVdG26c3WhIo2rdfvta2hn+PDWCmEazR9OCHzQiUhUJsYpC0/zI4z9/9MVrR2mqHkaNiHLnfVDRAwNkEoGVt8J2TkKbK6nlgXZxLKzq/dbxioJ84EM//eM/Wz+/+KlFuzYEqV+7c/fh15pzzawv6Osky4fecHbc93drmx4vbcsr2MGz2EDnfNcOM5OpRrSXH3e/ZdP8Q6KKmgLJpL10Spii6AXLRHN9FCAFrDUlh70cQ/cmloJDcWmaKU+RDhKf2ntZe/hQLTQWJLNeyRTbenrnzqNO52jKZ2JlwSIgo3Ry3EuR5K9ho9kLkWaC2KdIjfahEXBowUpBycj+7dt6/Fw8L54LyXSvyCqB06R9ZnJW9boE9VCQ3ES+uiFoH0OUI6urlXzYPW+WVi95bYxNkynyDabsyicbE4/CRcM4kRSAuFjCezsEACvPg7uHTW9NZhWyzDv/erbb2tYrj33c586qkuww3hzSI8zGR1116HQwJqU5dzZI7x/uVKuV23aYDMF+2Nw+8Ni6+gPr/b5rAbhQu9pCu91WG8+um4rNq0bFa4cngyf/3E99+G9Va9H5w56zLFDsx3MFgAe6KXNkSCpRuPTUuXg5Wc4/Mkh9qzNI24PUHibWHTrHCYkwaQrmTaUah2auUYnOzjeis3EYVHo5e1syNU9tREeBaHpCVolY7/Xe0clB7t3rAjlWUKkVF0C0k/HsLk+LZ9BUaglhIa2IPDORgrMCYc9sxHgJNES8Y5EEhWjPiIA1kS4YS98Vdao0d7TcrIYX15c2bj04fmJhXouA+iDyQ5cqbyW+dGb+fD/N3zk+GR4rrfzuwcmri/Pzz3mektGddrMdP+UE77xEoQmf27zwc9+8sXt+/2TwUiUwexXle4pUi5h6CCsOcHDCWmsV5NbVXGafCIx+7kMX15564uzCBdGhPkm8e9+F1Y9ZlvkvvX5X4lDfI5IdMTJE1MDxUYrH875cuXKF6XsF31Ns6M/wN+qfTGvD4zY15u/JvaNfdXePLvin1/4cbJ4Tj0RzRtOwj5QRvCcuXV4JIG898vzEBmHQrJ6rfTQ+U//ImfSxju7bAYbZsJ/kHe/8UDkmTVSL4rhRazaqZr7WsDU0B8ai2++ITawr1SuIBaLkETOGUX/DC41KXqV8JcGogt+kxAprFgeX2hwSBRDmYoSShQoNjvGsZDFOyV7MXA1cCeeyTlZVa/WKtj6mps5cL5Va2OQ0Z4MMsQ9QJ7aL6f3DZ9efu/xLNg7m8n7OYKhp9r1MsnWSQqkCDCJm0V60VolH32cCD4RQQh7svBRDQVx0jSfvFpeOXuX18CI61qZ5aeN/Mvza7UVKshs60htOqMc25ZPcVZ998vKleq05fOWd7S/HlRpzYt9wh71X1eL6T6rMufHs98jkgYvNacGIhnKJdVE9fGL5Y0/9Byev3Xuzf9D93bBe/TLCYOi9GqqEut4Yy8RaKRW7PGgO+926T5Lm2bPn//z8By78ObdUmb/XObRxENZWPvrUXxlk/MzDO/f/++bi3FCiqBVonet6XfBvbQuuFGNrr1y9yuf6b1mJm4lUgk6+3/tq3k1+Ti1W1iHi1Ji8RJO3b5Sxjsw8phnKALx3Jts92QtFv5qTHIszGapV2DwLjDGH+VHvZnzpzAdZkbDj0zVbnuIhjmilU5vTQluL2ArrbLd9p0rqdSt5Rt5YpxOnfEWJsGIGHCB6ojw0ZZEopySbGUrCxYax77QDCVTkh3mFQlXVA+sQ9y0HZ6mx0wtyqKqE0VLeaj+pnHy69sS596feF6TFqV6gjKbaiSeuXFK0ZpSwV0gBxAgvLAqubsvLm5u4fHnb5/dg3dBlaj7eTe8ffSF44sxzFBpI5kSYiyBMCqWh7FTyNPFtk1MM3dLLyxB6Oy2L/cHv0Nrc/azf70Vr0fDaGvwPOvv9wQfgidKQCsOndNIbRHG90bz94KTxiR956tPnzyx++Hjgi+DLE12HESOOFIgtkDhmnbGEWqtaLVhr1uM1EXmq6FGJQ6Hgo7TSSinSIFK5B7cTdlx6SvEj8mKjlq2a6lZpUjjpDenhXvt+ZMwhEfUtIYVn8sTFjD3JqbrDRN1ycuO8EHzhg1tMwmvDVluOPFEumq23uffiVSDkx+QolMP+YyUsKSnzsCzyzJPry7VK+OxRN1lUhCw2muYbc3PrC9XHF+ZqT7xyY/f/c3+v8xv1amTu77Z311aWDxYW59addZ6m55vGWtPFa6pU0QuuhAF+/EMX3r971KncP+i90x2ku4Oc9xT5Y4jKS3ZioDXV5qvxxtpi7bkzi/X312uVsJ8xZ7lzWoFaibfvv7j2VCUM/tpvv3rz18JQUyTqsOVtLxSrt1dW1PbWFv2h+iaTXjBjfSNP9nY6amMxplfu/TNpVjZlufYYDRKHUquZpjMBwVgR6ZRvc1FdUC71nKSJh9EIg6hZXY7nYlVDLBCQHoUl5RTTMXtk+YlkvdSx96KK51rxhEJG09sb+ra6VtGuU0oLK63Su61+xdKRhc8de1KOkyTJU9UMQEXkpYnD0rTyCSCOiY2R4PLGh7ovX79k9j1kqaEDp0OuSpaHAp9I6BRH9qTfjPp89txzH/w5/8TiYyeDTk4saiIUJackJGmkGCFU9qKZLXthJNA2FkpSsSs15/MHPnPWmYKbP5Jlokn5Tgpx8aIESj5JffXsysLyJ+eeG97aWbG5PWug+vWFleryY+ffP/f4+ubtnbt3/DeSe1KrPTQLjcS+vfNNfXb540oZrdieUjYv2+NFebIIZJQMExsvxYtrn7j88eTGXqP/8CDp7rX3OOS+gxyKRyI+12DVaFSrl86cW7+w8eSlH0sWwx8/tF2TtY9yJUr1Xc5deJz9xAc/XImin31ze/vm0pl18plNG3Hex0vweGmrIN/gKuLdM9xaRB7XdCJpfi/dP7kfrtY3ICXL+VRjc7LxxZRzz2j/I0ZJmqSUH3TuVufqt/OhHwDIJT8hq1Qa1ILu8PDkWtpL/oIyBQmRxhsTmdabBetTbunlPWJIECDpD0l2O9tmbv4wt5IrhnNxYDUlinzgpS+ZeM8MPZYmPS34Pqabks89m43FKs51N7tv7b5ReWwpMKgY05QKm6oVq8kHKnBpMjfcPzlf8eaZ9Z/8yGY6F5is12OFkdYun05ESQBFYCY4LtqYXkjswEgYA5V0Q7D1y4KtLVxbAZ/rN63V3SSo08DdaV1P906OosdXV1hyP1EvncysSylePpn3fkQ3AQJWStg7M7i5c7/i8C3nfT+vBencrmO0Lsu7US0270b5eWNjg450rpfnatG9h0fm/Pkzlz789Pl/6yRjzl1RpuHpsskoIBVTu0UQ8kK5Exnk7AggrZUokFakNFFQzAJyYX9V/FVwqnhq8/Zor1XGQ16jqQxFN+8d5Sf99MbacmPgvR9ozUMRMo4K2r9ikrHKlIyJc8WLUN47L4Lcg0SMCLSwsAQcCbMTE4h0+j7PrM+DmMqJp1H1jsZlcSoZi4oI1hfOIk9fXHv/U95dAoQVkVHKhEJAygCp4HxubUQSMoDh3YcHN+bnmxuKqGA/8iQxO8UdY5AiwiD34kTz2vLCxbWlxkY/sSfD1J0470+8cKoEKgpNtRabxXocLiut6qlXfDxw3kshMueLnqJqD527uLH41J8JnvpLv/HVt4ae3fUFjejEJly/r+1jm5v0HX15v0sQvvS5K9wzn/SHtTTJs7hn5us33e/f/jX3iUv/IcdGI/Vcbpuh8UhPeLzbKm33pv6mSBE5wdCmfoCk1DvBROWh/LsSgiY1pg04PqWxNM5gSvZ6yQqe6DLKSI04UGr4+j0lbxz882B96a7LXOpD7VViA0ndnlMaGm6K8zyeTSvOxpe8GuccL8VnKz/71N/kawdfd63uO4O9ZNuT78KyKK2jarU2v3Lh7DO1J84+n88FH2wNuhYeaqxROrUjnbDupRihKWzkwI5zKs3ZqJpKrw82ja7XziR2kPeoXM/U9PM/pc09ooETAb1hj+VMvdk4+9QHA1FPAiRaq6hHZHbzPdei4ZoKzFM8SO75OGL74OCGvr13P3rmwiXbtg5SZNrjkXNmYqXGGtYEUG+YcB6HVP+Rc8+sbm6c5052l/v5LqzfU0YnlUpUj6P4rK+Yp6USnDnQNjrsHzh4doagudglUZ7lsqdP3PpzT//sZhzuvva1V//J3LnV/tHguPs+P3A3n18EtrYYuCw3N3Z5TfpeXD1VzVor32nfxNNnfkyTKtS2pspuRFT085lptDDxaG8sXqA08sOuSHt4Uy4t9DjpZnlsbDOIacA2D6pR4u8fvZX2ekfhytwKUvE0khxhmRLAlslAfskgH/kAA9DZzsmATpJX3ZnFBEM/9C7LQp/4JKnqoKGt9LMuD7O+qgarYPanGO7jrXuRpUKEbKA5fPbizy3GIffe3n1l4PJdF1CHgcwIS2jUXLVWe3ztfY9/uPH0xU/2K67e73e9ApEbi9eMiFDl5kQR4AEhR14bcMlkU3UwJangFQDPAtjaEnzmM9K8ctnvVZByXyc60DvJ7b23cWFpjQiOAFElxe2UZvlUYDgdH0pqXKBleNIhuXd8Q83VH2bO9uNKy96Mq/xuTQv9YAMwAXgB2FlYoPnBMBic2GjAsvQzH3/6f6WiYG7YdZZZ9LdpEk+VhUlNKzgV1TkiKYw+SyIJxE8Kj6Nq2jSFGI8EX5qUH3y5OIZG8eHJMHj73sGX42r8VWbeg4pa1jknrIw4Tj0Xyu/MUrJicEpqcUwC4uJzHftiBhJWOIoZ3pMWJey8Tazr1MdONAVRaIpDND6HYq0U8jkj9yxGUWy0gjCDxTERsTY6jCvRWu5gco9OrVZLdg/aL6+tts+vry4+4ayzAPSpbLD8Jl+uuUSgJPeUWubIKBNE0epSpbKm1eneiGeglzuxiR+Ny1OpKVuUBFmQA5Ra69aW55/4+Y+9/3/xj3/n63eP2+6wuVphDoN0ey78I1lWX73yOf7US1u+g420tt9qoVHVUZL+//Jv3V/On7v0GRUFClkugNDEyHvU65apjRYmi8dEP3PSGh9Zqo8F43k8oebHzOTJHNuEdFSWFEmXu0k5rR5GJD4yKnnjLsy39v9RY33+H+VkD7xEJwCDImY5Sd60Hj/PShH5gvNeyEiO9EnL81BKFECc5k41oyern3jiiVqKTpjxPZ/7EyJlgkpYzypmOQtppc02TDt9R8WMZendLONsYMSULQo4XEpnCJx1wtZ7Yi/kA+l6I6pBQp2hSCNMuDO455wr+BM8ZZQwbW1Y6GGOtMfR7XalaxRpreNS9lUUyBsTwMWm4iv6bD50Dg30sbZww964/6v+3MJ/pGJtVGJFTSTjRg8jjcf2in9SluaSZbkEQbAULcfLwUoFhophupSAPjGG2QDpIHPivdWkCcLKlQsDC0MJU9Zz0g8zc+YDZ/76+/mZ5dtfev1/CM/We+yq7n1opTc39wTblwVPrYu6AXExclqK+/ZB51VqJ39e5uIGnGea4p4Qkagxebm8TjTWBhERMXb/5FCl7us5so4nn4YpXD8cqjCt2rSOTAs/yA+6b+LMwmoRWDCh7Y5G1wSAdVQKgk9Y+IVVQeD2Oq9WlP5m5nxHke8S2dRXDUxXdKZ8Qkm+z0f9B2q1+YSUXtg03b+j0Qw5FQlS7iUPdS1+9vG/vPb+x55XvWyPh3kL7LMwimNVi5cwF6/msVk8zoc676ceopQVP1EpeXRDyOW1ISWOGd47zoV9xIFoG8greGWyQFy+LNdWwGt53TP6fb++suvu778kx/2Pxgu1WLlcphxIvk2ulEYl6Ym5WuF+paHT+4d93bFf4pX4YaXbG1TTI7e/3mD88md/4P3fdyEDJgFeoMXdXZo/f1n/y6+84rf+o//l31xdaG4+6LicWUy5FEAe0SXG1ChJ6Tw2zgWKhbV0eSkZGeWc6jjLmxgFAI9ODE3bVJXrqzgv+tU33mn1+/1fWz8zfw9QLSHfg/fKKwrheOAZrHQ5PkATRrScIlkUz5L3As8MKxBvgUhZP/QWtShywsjbvWR/eWluLJ+IsQXh6AGfFvcozpkZ5LyIcjwamSKIaGIWbcxypRY2Eps9iOOAgzBw127c+x/DMPpbzUal5grJovEQAT1atiovt1agYc4gCEM8lIIIqfF4T6FmNsr1ZJrkJFPygABAh12Xr6/On//Mp3/8P/rcF75xq7V/fHd+HnqI+dMtij8oEyaSl0X8latX5RtrSOx+6zCYb3DlqP0P3NdvO/vsY39VIqN0aj2XAq5jN1bBtHTj1H0aXe+JD+uIikrsT7lC0bTy1tRLLKUAxcQD1hMw5YvLAtGKOVQme+Nurl8/+IfxhaV/mAF7VgXtyNqMNZRdmYe6e/yqf99aywdqSVnvFReSbSxT869lL6+8kyTD3CXGwQbBgq6FC6SCcRDJ8wH8wHlwIe7kebRZHbFzZawmNWYWl0IOAoG1DuQZmdKUYwC0PdRCLMqC3VzFYu/kph2kmY60VpZl5NOsxgWE6Wd33OIh5QmeR1ttVh6AE7CPA9hKsIrDHqMZDxkmRSYvZ79/87L+iaf/rFaUq9zrydQCjWytx6XpUneYCAqZsz5L8hFTo+A7jVQhi9ErIgKVfsaTOfJSB1opRTbL+IE/xtqzj//F9Yjmbvz6V/+TMx94stc72nOfOn/ZvwwIDq9JGF7mnu25KKzmNExuuNbgbbVc/1EktvCvHhsMCHFRX5gsj6NJQaWFnSe3379RqVbfytNsGJ/EeVCPvM+7PAhSFWdxbpuNrts92bZPbvyUVkTMk0oLTVumcPEmiqZyPygAKco6A7jd7ktYmt+lxPUcRUkrDi18ixZVbqWbJ7puDvlB5zW5tPZTUEQ07g+emkQak0UJQpyx9K33WRyu6LnailFz0ErDEyF1Fi7P4Hs9VixeCg2Bcn/Lp0WRxuchY7MHywxnPRkSTryTIQzw1F+ZEDkFwNXPSYD73LNZFqmoJ8P8626nfcOvzX+UU2upUMGZahON5qhwyqhmpAUNInHOGbnXumEq4asuT04ojdObX2s4fO4qvxv933eNBX0TwAeSjN+3eBbXbu/t7fcZaysLoVFkrWPFp3LS6U6ajIkFJDS1QzrVihi3oGiqqT6d8Yxr21MOwMVrWkjjkDL42mtvq3fu7H59ZbV521lumUC6NqNMU2iI2FrrPJf2WDwlwjEdfEfHVLDfmUW8FEIcImnu2KZaEp1lYZV6OwftGxurSz9DhbZ7+TJOC9ed7g0XgUFOyT2OpjEM4In0XBSEjw2Gg9cjH1itVbfV6b35+lt3fuuZD77vlxrVQJzzpzP2sZrXpG/KI0Ho0faZR4MA0+EIY/+o8b0otR2KKlth9g2jcO/YybeuHz6eJ9kygLvpMCB88yXg+ef/yM/R1e1t+dTzz/s7eClVyaCTzTePqgcn/2z41buUPHfu3/aNODS9zIIUMQriRVFb0OOFCWOf3kdKUaMA5D2NMudxcJKCbjvWeZ6SXKEp0hVNiUUIiyAKRESC7PdudoObx5+tXFx7mS13PPyxDNOhW+h55xuaKnFodtq3+GH3NXzgzM8gdeLLPjBJmZdPbRymZnJIWY/MeseDtDAvKGVER3/xlOvHKLhMNhBqLEVJp3xwC/UfzaLEQyFzRNWKmBg8DOBiZby91dlzD08OzZNrZzWck7Fg3xTTd+Q0Vm5ufNFTGrtUjkJT0e4LoZqVM7azR2qlamFTK6u1trp99KtJNdzQP/rER4wbWONFFzeHx1a7k6BQ+IlOxBmLSubIy3XqRo1F5ybPAY+NAUgV/rOkNIlW7ub+w8C/dXtjOY5p6FvC3YRevtEjYB0AcLcGXkBgXaIzFQctd/fwHVxc/FEFnk53CzXp8sWe9GXLJU4T8qMuePfkG3Ru+cSmLk9CcTs1MPAAa3MXnD2w1lcqObdObrle1qN62IBnT+Xmh0a7f5oqr/rRpgoiQjp/0BroTnrbr89bHGdZ2LAe7Z6gDYkA1/VhFi3XEr518A1qXThUK9UVsexRkvBJTpuwjHkKTARm2EHqeJiK0EjJrfx/Cg03VbiicckwVjTRjBslTMV9LXgEhRa9K2bjyTlA52CuVwR4CaCfngTB7W2JF1ucPBY7l9tMrTX389u731BPnfmoNoRiRnBiiHKqrC5TgXfEHQkMpQ+OgIfdV9TG8lHuBkljOfW4/O70ft/VALzXakmc1tzy8jJ/8Stf+0dnVjeWLl669Bcfu3B2tVkPWUO886Imc5PjDflU62FyoU4z70/7hNLUSJGMegqPDCApIjAzlFHiBeqV199Rb7x1+4vz9ervhNC7Gq5tmRKfE4cVgEWxx8hDlMZzwJgyDKcpmlNhxk6OvWS5yx2LdWYgHlUv3K8kJg6Pj49Ofn9nv33j4vnVTc6tLYrbMjFGlEemFso5DMKUEIGMdJpFKtWQatX48ePDo7AaBIn3tjU/V3WHx63ffOPNW2c+8szTn6gG2uXeE5fcDXmkIjOmdPNEbP2Uri1Nrve4+0kylTkWn0skEoUB9zMXfuWbN4avvXXjv2zU+WYUGGolzlUfyW7/kGouAhG8vLXFz27s+p18fWga6b4s1FR80P8fzUs3XfLxi78kawsL3Bs4cc4Xw5YjhZvxlZ0Sj5DJeZbjNDg1djHFmB9dL5ZxoJ1mWpGayg20FolNwIc94JX770Q7/f9WP732hTyzQ4Y70J1+r+21xa7GehxzzyJ155YOg9fu/ao70/gJW9FGDYrGtQLD8yOPMMlpJyM1KiKrU+OMUvZs4AExCuinxIGWckEEKxkzlsc32DP5ggUtCsK590TeCLmhhMdVdjU451wmjXDHvf3wFbm4es5rLcr5U+QKomlHVppk3jQ9NlBWUCAUOIY04lVPXGGnD8k7lg6crM+/pd/Y+a9cFP0HtHn2wzIYOvKeJmS3if/wiI09zrpp+t0vNyfjkvvEXpPGC2+ZCbtCa5trIexxK7YvXX+nujf4FfeBld6wk/pmFnlsrgh2AGxfFmzsirHGD+ayLFppdHj/+C173PHUiBXlfEpUZ/TOqDLTK9nK4oSV3WklQSLbiaIsypAEfeewAwYOEGye4yHXczSyTO73b3Jn+I5bqn8UuRWFSZ93VE6lsUVk+b5qSM5C/v7xbhyED1yW5TUXpXs+9Nj5fcHmquzisltop5n3PGSNa3T9/u/5jQ/+IhvL8KxL363xnMa4IjlFQRxR6knR+N3iSXpZEEuFBVqRtg4cqlLZiKYFQ8r3rTh+RwJhZsBDtCUct4BzU3RLgkBexM2XXvDrPfge8jxcqHTVm7u/nz08+sXgibV5nQmXi/e3kdOksCopFbCKPQELm/ztvd1w6L5oOR+4zCV394aF7OS7lP0WymU/WBo0vfjilmBz0x8MtR322sOLiyttxdl/ff3GW//rV19761ev394bDjMfhIEWrRX7st/muShn+nJTxyOt0JIByaUmM08LeY/+Ox7596d/iQAchoEfpM586Rs37Pabt/7eYiX4L6vV6IsQtT8k1QuyqJ+wy5zkziVpKR5EwuUHyMiRZPrlGhtdEpjFO+eG4iUnC5s67YasXCY+yyHHiuj6O3d3//7B8WAQGK0KX4NJ0jkipnEpMjfScZ3m0PjyV+6FuGDZXhpmdiXzOXvots3c/bl67Y293f3/7mvfeusrByepIVIEIvFln5rLicSRgQOzjK9jYTc3yvhl/L2TXzI+DscCxwJokjAKZO+oF/zW737j7lvX3/o/b6zF/1RXq52B1idV3babm5vf3wNMJNh6UV7ZWfdP7SAX021zx9+WteZrIdT/u/HSrf+kcqf7WxJVyVVNWDrmiS8XAS9FW8Czh/cMN1KeKtV4xr+EyyrG5BqPftaLwEn5/07/jBPxALs4UE5T4L5594j+xZt/J2rn/zG/f+mfZ+3BbiLBAx31Tw4Dl2F9z6H1mt9dgIuSYeYaMpST7r9yr9/9l3m1oV2omEXghApvXuby2Hl8vJ4FTgDrBZYFTgSOeeRFXVgfWhEXBcgfHIt/9X7fxYFYARyK8Q4eq2/x+HscM7xjsGMHlzM5KyZkvlu7xtUBnJMs0euLR3Lv6Ff89Qdvca0SWiLPpbCEJ4EVhistvCwEruDUlLq+IMcgV4rse8+wScYMWfAKS84OrXMqg047nCW79NjSV9UX3/zf21dvfSWrV4yLw6K+xIoYqry3DCtS3uPRtRA4X143weTfC2AFsFL+GYAnQFTx3nljODGkezd3JPv1b/3jSjv7T+Xy+j+1qetWIpU9qL/f4fDa5BneWZcoi7xJKeMKDYJu8g1/0HuQB1p7MDvh4txLboIHwQLFNSmqZWJzq3m/d4cq+r5WNnMGyX6Yu2Ln8Dw/QNObtOPs0GUq1Lu8330tR8EwynlyLr48F4viHjuUzyuR+JME6nj4Gq00Dm3q0nwxzFArPh/blwXtXakt5Lnv2j49tnjsr937x+n13T3XbIZMYE9UCMUUCQb5yThSYRs4WpfL6+68wLviWfK+MFXwEHb1ANkbd9Lhw3aWBYas5/K+MByK3+elapwXBjsH9uLhAckD+vaeYonDa1Izi15bccOhDLXWr/M7ey9bT8orXUyniEzWOhld/7IN5QXeezhFknYH4LuHX1OL1Wti027UThPgMuNdxrvQAxa6vL0twPMO80gfJDu0VlmketVcP3p4+78+Pjp67cHO6l/YWF+5vL4yH1erIQdGMxeLXUEWnCoTyikaM42zMirn3giP9vqAQiBfoLWSKDCcWavfvnuotq/fabVarf9moRb9hoqCkzz1J06nAwzCLJ/zjo2YoYNVmqxia0etKy69hadKsjIeci9LnLl1kllvBexz69gj87FrcNo5QGA3+nGgg+Pjg5e23w5/dfMDl/7afN3k7EV5FkUTQ46p3uSIWDSdfxa73sBodgz2wDkmWs6suybeDT3lPqYgrVeqwcHDvc/2Tvr3n3j8wp8/u75YiUPtigVKppx7cXre7xErt5F6/JQ2wigDh9GKlSIkuTdv3HiI19546ytp0vlvVubq28Ne3gWybovbGQCPO39DcOX7JvYJ5EW8vPUCf2qlae8MIPr4xOcLjYxCPaj+9rUHwePL3xx8YPV/li7VLzifs8qsI1+Sk4UJnmnkBgRFgKZyHmyikjNuZsjod6Ny9dQ94LJJohRQrQQUGqg7BwP1+oN/ZXYHv6YfW3iDAxqg0+9RPeg2+8h2E2exs+7xy58VbL9A2AaOL1bt3H6WDp/e6AfX739Oh+Yx99z7nnEydGaYl15dk/bLNHNzTFscq2+NZk09SBlGJdL+/hHo82+9TJ/YXPTN6oeVH/rCCGSS/U0+s3DJ4tyBvBSuhKnwnO8J3rnMdzd2ZU03ctfyfXPhzA3/ytufzZeb/wecXZnznZ7TPNJuKDYnp9jiMjVjeOpcGGKdo3ocu8Xa2XC/a9VK5JxFIqFNbafrzPvOWP3KO/8v2+4N3XOXfkoWGkb3c6etAwnIl4kV4VFpzNONrelZeJo4kxTFJ63EG032pB+4N+6dqOsH/31cqXzOnZ07wYNhlwI7PFxftIg/z7hylcfP8NXPyQNs+8Xdlkv6gTPa7GO/e12eXn+MVSGbOtGen1S4Sr+mQq2tk0Ad9m7JfKVjE5/XdGTxTNPj+RcFWy8QVsBh6lxmfebnakO5f/SO39zwPjSkvRX2MimGlBv3USWHPISJFe4cJSbxr/qAU91BFlT6Hiv1IqsDgM9c4QefhluxJu0fD5Lg3MJ1/N5b/x3H4X/oLy43cNK3mkXzIx7JOC2lUfJCaNzuGNvABgGjHgb+2t22fOXe78i//fGfJOaKFjhScqqmNBKIIYh4yyDnvDfCBkNQY06A4akKeFGGviw3N1uyVPPO9lSebyydyIO9L3Cr/3PcjGvkvEfRgJ5UsGT0HstYDMVrIn9zj003e52fWu3xYWfYaeYW56+9q9kvRkzZHyxexMsvv4Tnn//7wMlFuaFTaSQ5A/AmjrxS0kq63Zu7h8cPDw67YWeQr5GOTBCGKlCktC7bWALxXko5KpoYIUwRY3gccEdjEMXSZYwSUoYci9496uqvfvPtwfabt7+UDnv/eKFR/V1PtE+QNrTqu3SQ6uUN6965L7nkVI1YO8eht7L62IX1nydSlSJxKJpLVHYslCpMpI0m1krT/b2T48Pdg99pNM2xc/lJEDfS9PaBbwYVVlXPaa641qipVqvVP+mmT+uotl6vhirQyhcZWFny5okOgy+5EEKAUiRGawmMke4gC954e4duvH3vlvjsCwHUHWN0S6eUKufyXPk0DsNs2B/c2tk/2m+dDJ6koNKoVCoq1MQKxCNZ2bLHPR6vkimyFpWUC8cjC0eCNloIoCTz+ta9I/X1b77Vu3Hj7V8nyf6r5fm5G4l3R1nSPjGqkd7fCVx6ocJ/929vFrXRrS36XlKU3+ORAl56GXf//vP4yEcg/Ydd7ol3HLD1C7WMWyf3Grf6b1fyIFf1yrzMV+Y5VNpnljx79iRcqJApiFJgIojShbvLqPWNSXthpOXLBCmF4wteaBAoqceGwkDTcdI2v3/vd/Wr938lUPqf4OLyDZclfa2CLlPW6/ijtH9/3qL3/2BsvVy8yC+/XPTCq7uYrxm4PFW62UzMO/u3JJMVf3bhIleNQs6+oBMAviDZn670TP8qZtTExyH5ODB064DpW/f/B6Lgn+Li8pN8pnkRSe7EM4nn0gKOxhV4Zi5s2zqpBLu939KN6DUMh1mruprh7DWPW/cweGoZ4Q4DNVEiYYev3+9Kvfoj/vxSzMxenB+FVTpFch2pPRVewsUaq7V4o4xXMP7GPuidw98M5iqv58M4r9Y5jdLEihdvvSdZnh+YO0dvyt2jrmh90Z9rNiQ0ShwXZr3F9SAmGs/q8xRxerRtnXjpUtEuMARLYrLuQOfbDzy+fuebwX7vV8Izi7/pK3rfZmk7IOm3gAy/+aNFrf35l6fICZeBQyBZOKHIw8hcHPJh94I/t/IcBZrFMo1GF0V4rPsOrYsqa2jA7xxKcKf1sqw0v0Z9dLpDShHcdNi8VnzX11dpcFhBlWOV1wOj7u4tufPLn5KFWizWMZflPi49e3nKS0+EvGc28tbedSP6V21DHgbaDFptsTDveHzwWsHovXIF+Op9DM83UbOBZIZJkWrJ9t22r9efwvnFBklRZhlrN5eJxyi753J9YqiyusLCQmCtNbPT/JXrJ/zNh/+tatZvyAfOPIfQ1Cl1jJIkWPojFy0+pYRB4pm1etjZIet/3QXhUUScDb8Oh+dfPh0MX3qeEOxSk0Nl4Q3FuqL2+kaa1Y/JuaVlGWa+HMcqOKY8qWTyqPmpNbNjI1+7cxw4/FMb+xuhSwbZgDMcXma8/PK/fj1ggOTFF4EXXgBf7sLewUVZdV1r4mayENcHYV13Ve5ud4/3vtg+aT9178H+k41m433zjeoH5ufqi4sLTVSjEFqP9V6kMHwvXI7GhJiSVDKStPTe6yT3dNIbYv/gmA+OO/tHx+2vZIPB5+fnwttxUOnnmTsMVNoKRA1baSXfzZf8p/vf5O3WCjXdocplQVLNWRzyoBZRBK2p23fBmJ9Ukrs0F70dEkYYaWTOxc77YTLMk2HmbK1+4FvPVHwLwMU7Fv08SWqNiqpXw5vd9t5/8fp29vGD1dU/e2598cJcLYbWxFAjwaLi8dCkCARSBHKedaufYnfvGHd3Dq8f7B/9poH9nblG+DCx9jgdmsQ0dx1wDhGydJhgENfqJ2GWnOzvPrh71Or86MqZtedWlueeWl2aD6pxAE0kuugA83QAUlAorrUQEcGIgWOvM8s4bHfxcHef9w5PXj86OPpd+OEb83Phm0YHu0f2qKt8b7B3FGYX8Yq7DPCLV7Ym3jl/2P7v98yEwdi8Imgv8DlTc3oQZm65MugBXfPWzevzb9Z+XZ5Y/vHs8cUfc83VS2lFqkNKkGcpxDoPy1y4lRfkmxEjVjzTmIwuJYuWlEasFZkAGga6k+bmfvu6vtv+Bu22vubJ38KFxWPLqi2HrZOoFqfHEljkicfCkIEXBVs4bVS19SKw9YLf39jNV6yhQY326NySjV67e6Aftn8p2zzzi/axlVUyGipJBLnzo0H0ggCqAKUATYBRBGU0CISHR15t735dP+z8U7mw9GU6emhZ5MRXKwqZDYRIkXeA90Uao0rXchFwZKCiDjhNj6W2NAiTao4aijIlLgu+CnSa3WzOu3beMFAS/Zr6zW/03HH7r7rNi5tqZQmUDBmZZfF+QpIQAJoJwlSI/UJJmgP3Wx16++iG2jn5TRVXPp8mwpXmfrofn7dIeoLKkNFt+qrt5XhsfsBHwwPzL771+/76/T/nLl/4GJ1d3ZDlQFFuhaz3cF7gHJgnvfxxj94ocKAJipQINJwH77QFNw93ce/om0En+VKwNPeWX1/eS7L8INK+NTxyyXDDWSy0GZc/c/oeCghbLwo+c0UAuGjxTDJcUl3aa39BeskvucfOnUdnyBBW4+ybypdY6bJ565XcP7rLWfZldrZbyWyKqnHYvjypFBW9Zu5Yb2s0N/C95Kbsdx/yR55YYN0VCGtiP9npTPVRSRslDw+VOuh8gZcXb6kkSSPvc9Rd8R2jvcmLLwpegELrU77T/JFszuetNK6yCuVq8Jtfvy47F/9dd/ncj2N1wWhrhTLrJbeF8IH3RQBTCoCGaAWJDEEpTVCE2zsZff2dV/Rh/ypfWnsddw7PsfVK6jEJQ4+nKkpegCgFaA0xisUFJMJ9k3HHaWETg/E8gK0XTo8zbl4jXPo0cO0GyIYC8UKN2NHDdks+/DhEKZB1RFPqgNNuaiIkpA383V3IwclXZW3+pk7zpHOkcvwYPD7zorzbJWh6dz++KJNcuXJVHVzepr+0uKhbWIwQVGPoII5UGIqBgcvC3Mu8o3DTqPijcTVer1Si89VK5WytGtfjOArjMFQmMNCqoDp6lqKX5Dyy3PJgkGbDYZqedAad/qD/VjocfsvAv9loBO8EUbWTpz5XRvrWugScp9hp5MBLp2v8m5tmfrBSZfI1CdSZJ568+H/aO04+aDPrAqNU0Sdldl7YeyEuDJdygqj+YPg6ZZ3/e70WHvbb/ngjvp98/vMLfPnytmxsbOh+f8HUzy+EJ05qmuK62CTsJvxYvb5wZW5h7hNzzdpKtRI2q5WK0rrYYVjrkCQ5Ov0kaXV63U6nf2c46H1BfP57a3OVuwgx8APpi6dB5fxjaeurDz3wEjY2foHS9EAl60EcA3Matbmk26n3rF81lcZzjVr9E3E1PN9sNFbm6pVGpRKrIDDQWhe8HO/hvEeWO6RJhk536Dr9waDXHx4Ner2bNkte0WR/r1aJ9nSsEs540D7pDEh80msmefvzC3z1c1f4jxVwv9cTKwBeeEFh8xpd3r6su82ujk0z6K6ElaySV6K7g2bFm436+sYz5szSB7PF6GKvRmfzwC85g8AraBApR6KceAUIyJcufcoQsXOUWa9zzlTCHWoN99Ru97p52HnVH3VeSxbDI1ppeMWSBz4bIHe9VmsxxeY1j+3LMi7xfbfylYCAFwif3dXrWA/6+VHFrC3X+F5viVvdD/mLy5+QJ9Y+Jmu1x6kRNyQItOjCUJ69A3IHyiyoPYDsdTq0e/Ka2et+nkz4e3Rxfgd5DrQz9heW/4xbn//3ZZhVwV5DPOCYRDyU0iwMZmsBo5Q57L8TvdP+36oLazc6Osqwgxx4kbEFKRc+hYt3zNzJfJzXoroC5uTGznlZm/uUPLX+s3Kh+TTioAETEBldZEvWA2kGnPQdjgeJHA926bD3Zd1KvhJWzU1/YXHHn3CnYlyvBWRY/0mH7c8INq8QtqGBBbNQQZA3VeQqc9V473hJuu5pXmx8zJ1tfoLXao+r+VodtShEJVIS6BG9FWIdtGNIksP3hoxuMpTj3hG1k3fU0fDVuJ9/BQvNO7xR7eVZ1+pEsoAqSefkJMXm0OLKVf6u91BAxTV5SQEXTeNSvZbf6izwk+f+Gs4u/M+ll0TinaHSd4e1YhUYJkUCLwppSnj13j+kSv0fmIq0hzV0sLOeY+vFiU/16Jo3u8FCPQyHO3sLXK/+Dfngub9OQCgGAk2A0hDvy75b2Z8Llabbe/eDb+68yE+svBlmUa+72Bqi9ucsrnzm20dqXnhBFfcXZrHbClPtqz6o1szN3YscVn6aP3Dmp3Bx8f20Ul9AtWJEGxS+pQTyDHEOklrgqAvsdbp01P+y3uv+S1OtvSLnw5aceM27hzX/wcf+NxLpT8E6gdGAUmBViAGSL+XYAm0pYw5uHP49btb/ftC0/Ua/MdzFrsUvf5rx0jbhxi5h57pgc1VQP2OW8nNhOjypQoUruHHvMn1i8z/zH37swzjuWGI/9hOXkVHKqBJNxKLJyO+8vqPePvy/8tmll+ue77eTdgJcdii8y+Vf4wA8CcQvvFC4Iy2026rWXzBmrmuqnWaAxWpoPKJQhaExuuoob+ZDHznvqjljjcQskjE1IqqAVAWk6kqhCsB4z54ZCbM7hvfHIr5PhJNqZPYrcXjiEaTW+qGH76FzkuL8So7BHYc7Fx3wEm9tbclpFa+XdLN5GHSbzUol1PXdneOLyqgnQ62rJjBQ5byCg/cFuZi9s+IUcb8e6QdRpdoKLHVV0umdP4/8ypUrPFIHex7Pq5cuwlR9J9BeRSZeqIrKK0mWL2ZeHvOMdehgg4jWFJlYAPIuJ2YZiLeHYN4JQrodR+ZIgIGosKNsv1+Pg8RFfVtvt93Ozo7f2tqSrS0QsKUuXrxo9vNapMKVitaoe/ZVVq6eJ/mqEyx4r1fImHOa9KoKdEMpFYEoLOeMcpvbgc1tx+bZkbDfJYXDSqDaJgi7pNWJT21vKDLU2iRZMkwH9bZrL3yer1753LsTfL/rQgh1eROq3YYJw5Nw0Fyp5N7WXK9bo5N0MbTBWt3U1oK4ukbzlUXTqM2ZWqWZGQ6tpiBAELK1YPaJYtX1g8FATvp97qc7tj+4x2m2k8d0zEvVXh5qT5mzOkkyI5TFS8but3OH9Z90uPKH3HSMBqi3XiBs7Gr0a2ZOcZQv1GqaXFPdP6lJJ19FNX5KlmqXqBGtusA0RFPAzmo1tFb6WYeOe7s0zN+hanCDHlvYsWxSrdOE+tpzU4fc7tfozsmqcrQgJBUhFUGrEBG0gmJy3nvxTJ4TM1954DaWb6d9fYI4zbG+58ZB6NGAYAdhWgtqvtmoB+1OjJ3eGgw+wJXonARmAaSWmLgq1jtKbV+S7JAS/0AF+naw1HjAi5W+Isqcd73qsNo7Hlazb9u8fOaKwqcXFNJIoeWDZjMK85hqJqYGnQyaeqe/4sSfk3p1Q+YrS74ZzyMMGiQcMXME64UyN8TAttFLdmmYHyrvDqhWuSfLjSNVDzOb5ZnhZGjaLuvUvUW44Mbn/Qf3/ggvvEDANYNhI6qumzrtdRflaHiRlZ73JJFSWgMerBRDyGmI9cJCirtmfekBV+NWGlMbgcvwy591p7LsQpFGYRsazXO6LoMahn4lv996kgydEa1jkDIgEngnBHgIOQilCq5NzfCuX14+CfJBvx/P99FtWgCMF1/8zsSiF6Cw+TlC/YsGb7eiWtCInQ4aesBzeNheE+sex3LzMazMbUgtXPK1MEYYaMocSy9JpN3r0IP2nkqzdzBX3zZPrBw6T4miLJMhKa5wle61z6CVPyEKdaVUAKXIEbniaRQh8hZCwyCMWnx+7q5odRg2o6FJvDNhMQDN3YQOASBwDKxjsQqTR3lkB1xTEa3hYfcT+Isf+88koGUMUwcIqVIHfZL5Fj0dDoznziCkf/bqvwgq5u9yoN/Iwv4uugcWL77s3+3g+0MNwJPNVhGIL2+vEDYPVfc+tHGhqYaiEXFY0UHMlTDUFGglLpDMKwug4PkBHjogRgQlYeGTqZ2Qy2DC3Ijy0OKsuDzQlayTdq3Yfh7pRoaF1O2229JeWOCrZWCc8OmL43tha4t2Nzb0OtaDuK6iiosaVlHdZXnktRbNIggCeF9YdoWkmTkTYpUPvUmAZNjvRkn9R8Ns6/nn/fTFfaHQQ1Ybv/AL1H/5lumaetBYroQiXPPeVwPSYc6J8Va0dxwoowIFFTARKW28BgYg3bO5GyrSQ82SJju3LDYXHLZXGHiJXxxtKIoRHrpy9ar69KVLaueVnaCCSpD4blTRQUy6VqFqELk0iwQuZmsr7GxgvQRe2ABGmYC8IpOoQLJYBbkXnztImqeUS+BTHg6GQ8ky47StPxZbbG8zAH7xxa1pH5sfDl54QWELwBYUFlt6PV7UKdIgrLgIiGuZdc1MSUUyH0qWVyXzkbZOa1EUplY8WIkOlQKlVuUDhKF4EznXoKEK9JAQpCpXmVZpFiCwYde5/X7dY2PXY2ddsHlN/pCL9nfYQICAFxQWW3pF+yBJXeyb87E3UjHDvMbtvKrzYUWs0z5nQhgSAuNVLeipRn1om4GjXpKavDcYSD1DYB2SisD3DCpRWF1sGLZkxMCIJAGG1ohjPdUtYtIm17kk4dANOukwAS4W5NetR0pwoyC82NLQPmhmUWjDPOYojgx8VdrDSIbeSJ5GAhNCMVHVWBcEeVTTAyfxkNI0M5lJdbVrO27ZotnLsdBmbF8dlXony97WC4TNa4T2gsJOpldQM0nDxYGJq65qYo4p5I6PpTcMXHtgTMpKPBtoCiRU5EPlqBok1KwPEJAlzU5ZTnQnSxXFLshObKu5atF94EvGK/+Rsp5R5rjY0kvpIExVWPEVVREVaiHWgASiPZHXAlGe2HooYRJYNRjaeNActjayBL+87oFHxl1Gz8bmlfL8EaDp43hhrsaprwa5RDnlxX0kw9BeIORJ+1wDQ52Heb819KjPZ2j2cuys+z9wpEZARdC/rFHvB3PmKLC2FvtqVOcgr5jDJJJeWpXMhci9OJcBJgJFoUMzzOjsfEpRlNEgz3Q/HwZBkHbynl+Ma5QDkYupIpVqKNaGwtYgI4UQgFeCihaEypMJHaWSqzzPTKAzNQBjDvDpwHAj0hVXU8MhQHrAQA1iE2NqUiFdn0/fuXc+uvzEX+WPXfol3+74UnBsMnZGU6NnDJHQkLx+L8VLb/4XwZNLv62Gyc2hzY9xDR5Xr/K/QQH4O46YAMw0Cky7G79A6zuva2wsqaFmXe2JzozoZrOBLE0oNIbyhDVqQJAXyuNhGMtA5xxaL7lzAhVyhbVPFtoe7ZhbqfFZfJ/bCwt8eXtbXtya6kd+28Mn9ELpYfzp9iW1E76ukS8p2FTBZyqNI1oAACwgGfYJANKqlUUdsgor3E8ywU7qNjfht7e35cVHd5plkL/ymavq8uUVAg4VLq6o/lGu66HXWcC6WYuUuEiJGxhETgGAdV5yIR92Mzt0XetM0zmzy4utZ/y1zUMZn9d3mrMtzwlbW8DWS6q1mOiLrq+6ETR8XcXLrHnow1yCoK5YpxwoxADSFE7II2cXxuRz6wSJd0PXtdXhqsfFY8adGgPbjK0txtYWvue1/aHs8cqMcvMaYfsyYWOXsLNO5za7erjbDOpBpjnIKEccuIAMACR5QJUKgCgQlYEpsjLs5NKshn4wBGtOvbGxPwx2GTvrI+4GY/NaIUtYnDP+WC/qqWznMmGxpdHKNKpzumlagefASKWuUCtvbxQITtoySKyD1R6J8WhGHsYxWosem6NxmSvA9lWNJjT4gkI/Kb6nmhKGGaEaFT83jItB2MXII84YO+syDr6PLtaja3ztGuHyZUKrpXHRKESZnrMDw0ldczU1wlqhVoXklqhjZaiSHBlboOZwMWN0m4I44yLwllnvdyv1Tgfi0fWJM42TOT0X5poTpznwmlUlgHEkJiDJvUYM0CD3iskOdZbDag/dcFD3GF14PH+ZcfjHvo9FK+HK1PVYzDTqw3KMIVQY1gjoKlQiATmGWuDxMeCgGAn6XkF/qsoDXFNontPoPtBYDBWSGqEyELQAYBGoDuTU/dzOGOvX5Q/8ju/2fRu7hDDTGNQMehLUq8aw9hpBSMKkhFMFExCcFZV5N0ysQ960WLEOhwOHjcjjqXXBjV0qKhnFc435jkKrr4C54jvjsDiuaixIh4JaLEgHshTXyOlcu8SEOuCmPxmeGyRuMVyb46ASDUibXEhpgl/MD9tPRBk9W/1LP/FzXZM3uJcKiCcj7zIpQYuMxRQD+pevvyQPW/+53li8kwvvIbk+KLNf/JsdgL+NYiO4cvWqury9TRsbG7SzsEDYHihcLH6g26rR++sx7Yxn8YBuM5Xm4kBwB1hcXJObeBtZHDMAPBJ0/3AXc5QJA7R59Sptr6zQ7o0bBDyLZ/EKdnYWiuu1CbR2d+mD8U/wzk5PgJewubkpZeD93g/6KChiC9c2r9Ll7RXa3WjQ+sItau3WabG1T7h4EbhzQ2FjHd1+KhdNnVutvryEbV7d3JRTmwmZkgD7HpuLIgsHbW5epc9/vq3w7LNYX7hFGAwU8iXVr0R0Zh/oVzoEAP0klV4/kfWLT/FiN5FWqy/ANgPAtc1NuXrlykhxQPBewvSYwqkMqk3AZWCxRYgzXWgarWMXu0C/JlhsCu4AWFwU4CYQf5CxsyPY3BTgKr5noPiBvQOPHHMaKbS6xfPQ6hK6zeK7F1syDpbf6fimA9coWI6wu0t4djLPWpJZBFc+x9jaovIz/qD3pTjWz1xRuDzZ7GCxRWh1Cc3F4hO6A0K3JvjxBx7bl4uNy5XLUlQrXhR89wnPP2CTtUlof764p5sAds8QWpkGjJpsMmJBvStY1h53hjye6Rxtnl58UX6Ai2xRjr52jXAFwPYBAc9Prvd6uzjT3QXBelkx+cy4vC9/6HX6yhVVfP7omrcJGwsylkkeffZVYKzg9P32Mac3tO0FhYV1wuCOwp1IoT8k1JuE0o4a9a5ArXCxCdwT4DLj2jXB58pzHG+gDggbT1P57BE2rwHblwFcAzYWZPzvi2ecsBCauX4QqgVdb79x8/zHP/Pv/O+QpotvfelLr2eD4Z4w9RVBA34jWl58rvnTz37gZJ4qSacHcqyKNPf02B2oUH0TowV3jxT/1uv/F7Mx9/81Axwl2GvhWiX7YWW/76UAfLpcXV6zrTIjvQJge3t78lBPeOi4Voo8XN6+IkCZif1xGbcjQ8+tLXqhOA7ZKjL1R1DUPf9I3zkdME+Vp7dQBLerRaaMK7iKq5g+NwD4tmz3D+syNP395XmVwbTcBNwgAFh/6inZvXGD1neeks3NQ7l6Fbh8eVtOffd7MfA+ung8Ws6bXG3C1iMCNJvXBNsHhM2/XQSzEQv1DyJTvdvv5vSCW5AEi+MbLbBb5czodw8m9EjJ9Du/7y+++B0l1P/IwWcalw/KY16dBIRiBE2+7W59P2vW6FyKDYaMM+TdXcJ6ubHAS8C1VSkX1D/Od/5Rjm10fN/9p77/4E/l9X70877Xeckf+3zG3/eSwu7TpzcUALB+XXBtVcZB/ztvVAkvgIDvcl1Gz/K1a4TLB4TFZzQWQlO3YdUm6VyQy/PVf+dT/8+5Zi0O2kkn2T869N1hR2DA87U1v1Ld6FNOWWcgBCh4R/KIkcpYfraQR9T44vUjefPhf2weW341z/ND3LjVwz94OcfY1udPZQD+7v3j73hJ/rglwD/uMY3UKn4gH3sqmE4ESR4NsCNz4+87CE6cf773U/EeDrI/qCz5e+d4f/KVoe91Fj+Yz5Yf4loi78K1kR/CtfpBXxd5D33eH/07Xyj//OJ3/V75np/0iKw01Kn5oKIPvXvGoBaHlWbQtN+8tR791LN/23/s0t/g7kkShGEQBKHR0AA0rLeSD/reZ7aQtC/kuYoxJ5lY5BXcUgCBZhz1AvrNb/0ThOo/d4p2UQ3aeMek+Oxn3Q/zeTF4z4PkvbddeJcC0+lAKyD6w/zc9xWBSmsZ+jc60L63g+sf8kb9a/PZ8id8beRPyT2UP/FzePGPxXn4w7+HvVxzqCskuOTOrf64OA9YGJtlyP3QFdpZCqV2ezli7U95U4wc7MbKNUSsnGj+xq3bfDL8XPDY0rHLjrp4kOVoN/iHfWEVZvhTDJI/dcF3hhlmeG9j+zLBGYUoC/mwVaGzZz7gGtULvjdk77xi5sIjAopYSLFAsYDEj9RPC+30kdKWjPT8WSAmELm1o/jNBy+pM/N3M04H6IYZFhP/w+z9zgLwDDPMMMMM7y0Us/GEbqbjuBqpO0fL/PjGj3AkFUkzFu/B3hcB1jOJdxDHZeZbaFqObERHwbdw3PCAIkZ3EPqvvf0mheG/JM0dWAwwWHDA8z/04DsLwDPMMMMMM7xXULCldzINDAz385qvRR+gsysfJZvL2ERhYo+HkYg+xIuwQ6H5zCMv0bFntBBYvDf43WtHtNf7O3pj8Zr1yTHwIMf6un+EiPhDg5nd8xlmmGGG7zNgALMWzg8azSFBFozcP6jShY0PymLtjKR9B5RelADgR6Z0RaAVxQCfZngVWucMKMUEKPryDcG1/b/nn1z7Mne7J+BsgE7f47Mvyp/UfZxlwDPMMMMM3x9mwfcHjb9zQOgmhIUlksOTmD/0xCYbaEozX2S6KKdES4fyacPyiUExxDPIM2A0i/cBfeGakt+/+6s4N/ev0E/66NsBDjoW63/e/0nex1kGPMMMM8www3sDq6uCLgTDLpOSLoZpl5kV5hoR0twjtQL2RFAQ8USACPHYFYqEAVICrURIabR7AX3lxh7e3P8V2lh8ybPdwUDasC7BRbg/qdLzCHp2x2eYYYb3KCbCFjP86cC1a8AzFSATitcXvf/S9ddpt5UhUAs0H89RLQphjAJBCFQY0RZewiBSBK0hjjV1BprefJjQF976bdxu/9/04ysvOTfcRd8dotfoo4ccf/fX+b3wgM8wwwwzzDDDe2PTdeWKwpmegdPVymPrNXfneJ56yfvl/NIneGPh49iYf1zmG/OohBEAgvfAMAN6CaOXZthrd2i3fRsnw5dQCb6gVhfu2yQZIrVdhMEQD5D/SYwcfSfMStAzzDDDDDO8d1BIizp8GWmy3yEshRSen78me8MdfPXt31aOz/hKdI5q4SqMroAZyGyKzOXsONOgfWmEd2l9btcBbd/vnUA4QRhmaB5YXH7+PdO7n2XAM8wwwwwzvLey4BdeIOAlhVZFI1w2cL0A1UqEuSCCrQShY53niUGaa+QAYnhoTQgB6EoCmyfoDHKo1CIzDu2KA+BLTfI/MdbzLADPMMMMM8zw3g/CAMaBGKsKXWioSEF1FXLSUOHpKZ4oELQsA4lF5Dz2GoKFW4JPX+IpByx5753kDDPM8F54F7+bm5H8G3ROM8yu+fcXiEdOSSNHpjsHZQC+COBO8dtmRZAdMtqX+BFLxvfkezQLwDPM8N5cOKffzVkQm2GG7xiQL0/ejdGf34OZ7gwzzDDDDDP8mxmQZ5hhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlm+NcdM5/KGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZ/rRj1jufYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZphhhhlmmGGGGWaYYYYZZpjhTxH+/506IRZflb6VAAAAAElFTkSuQmCC" alt="Site Gateway"></div><h1>${title}</h1><p>${message}</p><div class="foot">Host. Proxy. Secure.</div></main></body></html>`;
  await fsp.writeFile(path.join(defaultSiteDir, "index.html"), html);
}

function renderCaddyfile() {
  const email = String(process.env.ACME_EMAIL || "").trim();
  const lines = ["{", "  admin localhost:2019", "  persist_config off", `  storage file_system ${managedCertificatesDir}`];
  if (email) lines.push(`  email ${email}`);
  const logging = ["  log {", `    output file ${accessLogPath} {`, "      roll_size 10mb", "      roll_keep 5", "      roll_keep_for 168h", "      roll_uncompressed", "    }", "    format json", "  }"];
  lines.push("}", "", ":80 {", ...logging);
  const defaultSite = settings.defaultSite || {};
  if (defaultSite.mode === "abort") lines.push("  abort");
  else if (defaultSite.mode === "redirect" && defaultSite.redirectUrl) lines.push(`  redir ${caddyQuote(`${defaultSite.redirectUrl}${defaultSite.preservePath ? "{uri}" : ""}`)} ${[301, 302, 307, 308].includes(Number(defaultSite.redirectCode)) ? Number(defaultSite.redirectCode) : 302}`);
  else lines.push(`  root * ${defaultSiteDir}`, "  rewrite * /index.html", `  file_server {`, `    status ${defaultSite.mode === "welcome" ? 200 : 404}`, "  }");
  lines.push("}");
  for (const site of sites.filter(item => item.enabled && normalizeDomains(item.domain, item.domains).length)) {
    lines.push("", `${caddySiteAddress(site)} {`, ...logging, ...commonHostDirectives(site), `  root * ${path.join(sitesDir, site.id)}`, "  file_server");
    lines.push("}");
  }
  for (const proxy of proxies.filter(item => item.enabled && item.domain)) {
    lines.push("", `${caddySiteAddress(proxy)} {`, ...logging, ...commonHostDirectives(proxy));
    for (const location of proxy.locations || []) {
      lines.push(`  ${location.stripPrefix ? "handle_path" : "handle"} ${location.path} {`, ...proxyBlock(location.target, location, "    "), "  }");
    }
    if ((proxy.locations || []).length) lines.push("  handle {", ...proxyBlock(proxy.target, proxy, "    "), "  }");
    else lines.push(...proxyBlock(proxy.target, proxy));
    if (proxy.customConfig) lines.push("  # Administrator-provided custom configuration", ...String(proxy.customConfig).split("\n").map(line => `  ${line}`));
    lines.push("}");
  }
  for (const redirect of redirects.filter(item => item.enabled && item.domain)) {
    const target = `${redirect.target}${redirect.preservePath ? "{uri}" : ""}`;
    lines.push("", `${caddySiteAddress(redirect)} {`, ...logging, ...commonHostDirectives(redirect), `  redir ${caddyQuote(target)} ${redirect.code || 302}`, "}");
  }
  return `${lines.join("\n")}\n`;
}

async function syncCaddy() {
  const nextPath = `${caddyfilePath}.next`;
  const previous = await fsp.readFile(caddyfilePath, "utf8").catch(() => null);
  const previousDefaultPage = await fsp.readFile(path.join(defaultSiteDir, "index.html")).catch(() => null);
  await writeDefaultSitePage();
  await fsp.writeFile(nextPath, renderCaddyfile());
  try {
    await execFileAsync("caddy", ["fmt", "--overwrite", nextPath]);
    await execFileAsync("caddy", ["validate", "--config", nextPath, "--adapter", "caddyfile"]);
    await fsp.rename(nextPath, caddyfilePath);
    await execFileAsync("caddy", ["reload", "--config", caddyfilePath, "--adapter", "caddyfile"]);
    gatewayError = null;
    lastGatewayReload = new Date().toISOString();
  } catch (error) {
    const rejectedReason = error.stderr || error.message;
    let rollbackSucceeded = false;
    await fsp.rm(nextPath, { force: true });
    if (previous !== null) {
      await fsp.writeFile(caddyfilePath, previous);
      rollbackSucceeded = await execFileAsync("caddy", ["reload", "--config", caddyfilePath, "--adapter", "caddyfile"]).then(() => true).catch(() => false);
    }
    if (previousDefaultPage !== null) await fsp.writeFile(path.join(defaultSiteDir, "index.html"), previousDefaultPage);
    try {
      sites = storage.loadCollection("sites"); proxies = storage.loadCollection("proxies"); redirects = storage.loadCollection("redirects"); streams = storage.loadCollection("streams"); accessLists = storage.loadCollection("access_lists"); settings = storage.loadSettings() || settings;
    } catch { /* Startup may not have completed database initialization yet. */ }
    gatewayError = rollbackSucceeded ? null : rejectedReason;
    const friendly = /upstream address scheme is HTTP but transport is configured for HTTP\+TLS/i.test(rejectedReason) ? "This host forwards to HTTP, but Ignore upstream TLS certificate errors is enabled. Turn that option off or change the upstream to HTTPS." : /upstream address scheme is HTTPS but transport is configured for plain HTTP/i.test(rejectedReason) ? "This host forwards to HTTPS, but its upstream transport is configured for plain HTTP. Use HTTPS transport settings or change the upstream to HTTP." : /duplicate.*address|already.*site address/i.test(rejectedReason) ? "This hostname or address is already used by another host. Choose a unique hostname and port." : /dial tcp|no such host|lookup .* no such host|upstream.*(invalid|malformed)/i.test(rejectedReason) ? "The upstream address could not be reached or is invalid. Check the hostname, IP address, and port." : /invalid hostname|host name.*invalid|malformed.*host/i.test(rejectedReason) ? "The hostname is not valid. Use a valid domain name without a protocol or path." : /unrecognized directive|unknown directive|parsing caddyfile tokens/i.test(rejectedReason) ? "The gateway configuration contains an unsupported or malformed directive. Check the selected host settings." : /certificate|tls.*(config|handshake)|no certificate/i.test(rejectedReason) ? "The TLS certificate configuration is invalid or unavailable. Check the certificate, key, and HTTPS settings." : "The gateway rejected this configuration. Check the host, upstream address, and TLS settings.";
    const detail = `${friendly}${rollbackSucceeded ? " The previous working configuration remains active." : ""}\nDetails: ${rejectedReason}`;
    throw Object.assign(new Error(detail), { status: 400 });
  }
}

function siteStatus(site) {
  if (!site.enabled) return "disabled";
  if (site.domain && gatewayError) return "error";
  return activeServers.has(site.id) ? "running" : "error";
}

function publicSite(site) {
  return { ...site, domains: normalizeDomains(site.domain, site.domains), status: siteStatus(site), url: `http://${site.host || "localhost"}:${site.port}`, upstream: upstreamHealth.get(site.id) || null };
}

function publicProxy(proxy, includeAdvanced = false) {
  const { certificatePath, keyPath, ...safe } = proxy;
  if (!includeAdvanced) { delete safe.customConfig; delete safe.requestHeaders; }
  return { ...safe, domains: normalizeDomains(proxy.domain, proxy.domains), certificatePath: certificatePath ? "installed" : null, hasCustomCertificate: Boolean(certificatePath && keyPath), status: proxy.enabled ? (gatewayError ? "error" : "running") : "disabled", upstream: upstreamHealth.get(proxy.id) || null };
}

function publicStream(stream) {
  return { ...stream, status: stream.enabled === false ? "disabled" : activeStreams.has(stream.id) ? "running" : "error", upstream: upstreamHealth.get(stream.id) || null };
}

async function walkFiles(directory) {
  const output = [];
  for (const entry of await fsp.readdir(directory, { withFileTypes: true }).catch(error => error.code === "ENOENT" ? [] : Promise.reject(error))) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walkFiles(fullPath));
    else if (entry.isFile()) output.push(fullPath);
  }
  return output;
}

function certificateNames(certificate) {
  const names = [];
  for (const part of String(certificate.subjectAltName || "").split(/,\s*/)) if (part.startsWith("DNS:")) names.push(part.slice(4).toLowerCase());
  return names;
}

async function certificateInventory() {
  const configured = [...sites.map(item => ({ ...item, kind: "Hosted site" })), ...proxies.map(item => ({ ...item, kind: "Proxy host" })), ...redirects.map(item => ({ ...item, kind: "Redirect host" }))]
    .filter(item => item.enabled && item.domain && item.tls !== "http");
  const configuredDomains = configured.flatMap(item => normalizeDomains(item.domain, item.domains).map(domain => ({ ...item, domain })));
  const parsed = [];
  const certificateFiles = [...await walkFiles(certificateDir), ...await walkFiles(customCertificatesDir)];
  for (const filename of certificateFiles.filter(file => /\.(?:crt|pem)$/i.test(file))) {
    try {
      const certificate = new crypto.X509Certificate(await fsp.readFile(filename));
      const stat = await fsp.stat(filename);
      parsed.push({ certificate, names: certificateNames(certificate), updatedAt: stat.mtime.toISOString(), filename, source: filename.startsWith(customCertificatesDir) ? "Custom upload" : "Caddy / ACME" });
    } catch { /* Ignore non-certificate PEM files and unreadable entries. */ }
  }
  const certificates = configuredDomains.map(item => {
    const found = parsed.find(entry => entry.names.some(name => name === item.domain || (name.startsWith("*.") && item.domain.endsWith(name.slice(1)))));
    if (!found) {
      const customForRoute = item.tls === "custom" ? parsed.find(entry => entry.source === "Custom upload" && entry.filename.includes(item.id)) : null;
      return { domain: item.domain, name: item.name, kind: item.kind, status: customForRoute ? "mismatch" : "pending", daysRemaining: null, expiresAt: null, issuer: null, updatedAt: customForRoute?.updatedAt || null, source: item.tls === "internal" ? "Caddy internal CA" : item.tls === "custom" ? "Custom upload" : "Caddy / ACME", mismatch: Boolean(customForRoute), coveredNames: customForRoute?.names || [] };
    }
    const expiresAt = new Date(found.certificate.validTo);
    const daysRemaining = Math.ceil((expiresAt.getTime() - Date.now()) / 86400000);
    const warningDays = settings.certificateHealth?.warningDays || 30, criticalDays = settings.certificateHealth?.criticalDays || 7;
    const status = daysRemaining <= 0 ? "expired" : daysRemaining <= criticalDays ? "critical" : daysRemaining <= warningDays ? "warning" : "healthy";
    return { domain: item.domain, name: item.name, kind: item.kind, status, daysRemaining, validFrom: new Date(found.certificate.validFrom).toISOString(), expiresAt: expiresAt.toISOString(), issuer: found.certificate.issuer, subject: found.certificate.subject, serialNumber: found.certificate.serialNumber, updatedAt: found.updatedAt, fingerprint: found.certificate.fingerprint256, coveredNames: found.names, source: item.tls === "internal" ? "Caddy internal CA" : found.source, mismatch: false };
  });
  for (const certificate of certificates) { const previous = certificateStatusCache.get(certificate.domain); if (previous && previous !== certificate.status) recordActivity(`Certificate status changed for ${certificate.domain}: ${previous} → ${certificate.status}.`, certificate.status === "healthy" ? "ok" : "error"); certificateStatusCache.set(certificate.domain, certificate.status); }
  const latestError = recentActivity.find(item => item.status === "error" && /cert|tls|acme|caddy|gateway/i.test(item.message)) || null;
  return { checkedAt: new Date().toISOString(), thresholds: settings.certificateHealth, latestError, summary: { total: certificates.length, healthy: certificates.filter(item => item.status === "healthy").length, within30Days: certificates.filter(item => item.daysRemaining != null && item.daysRemaining <= 30 && item.daysRemaining > 0).length, within7Days: certificates.filter(item => item.daysRemaining != null && item.daysRemaining <= 7 && item.daysRemaining > 0).length, warning: certificates.filter(item => item.status === "warning").length, critical: certificates.filter(item => item.status === "critical").length, expired: certificates.filter(item => item.status === "expired").length, pending: certificates.filter(item => item.status === "pending").length, mismatch: certificates.filter(item => item.status === "mismatch").length }, certificates };
}

async function pruneOrphanedCertificates(candidateDomains) {
  const domains = [...new Set((candidateDomains || []).filter(Boolean).map(domain => String(domain).toLowerCase()))];
  if (!domains.length) return;
  const stillInUse = new Set([...sites, ...proxies, ...redirects].filter(item => item.enabled).flatMap(item => normalizeDomains(item.domain, item.domains)).map(domain => domain.toLowerCase()));
  const orphaned = domains.filter(domain => !stillInUse.has(domain));
  if (!orphaned.length) return;
  const files = await walkFiles(certificateDir).catch(() => []);
  const removed = new Set();
  for (const file of files) {
    const directory = path.dirname(file);
    if (orphaned.includes(path.basename(directory).toLowerCase()) && !removed.has(directory)) {
      await fsp.rm(directory, { recursive: true, force: true }).catch(() => {});
      removed.add(directory);
    }
  }
  if (removed.size) recordActivity(`Removed stored certificate data for ${orphaned.join(", ")} (no longer in use).`);
}

async function domainReadiness() {
  const routes = [...sites.map(item => ({ ...item, kind: "Hosted site" })), ...proxies.map(item => ({ ...item, kind: "Proxy host" })), ...redirects.map(item => ({ ...item, kind: "Redirect host" }))].filter(item => item.enabled && item.domain).flatMap(item => normalizeDomains(item.domain, item.domains).map(domain => ({ ...item, domain })));
  const certs = await certificateInventory();
  const [httpResponding, httpsResponding] = await Promise.all([tcpProbe(80), tcpProbe(443)]);
  return Promise.all(routes.map(async item => {
    let addresses = [], dnsError = null;
    try { addresses = [...new Set((await dns.lookup(item.domain, { all: true })).map(value => value.address))]; } catch (error) { dnsError = error.code || error.message; }
    const certificate = certs.certificates.find(cert => cert.domain === item.domain) || null;
    const upstream = item.kind === "Proxy host" ? upstreamHealth.get(item.id) || null : null;
    return { id: item.id, domain: item.domain, name: item.name, kind: item.kind, dns: { healthy: addresses.length > 0, addresses, error: dnsError }, ports: { http: httpResponding, https: item.tls === "http" ? null : httpsResponding }, tls: item.tls === "http" ? { status: "not-configured" } : { status: certificate?.status || "pending" }, upstream };
  }));
}

async function checkProxy(proxy) {
  if (!proxy.enabled) { const result = { status: "disabled", checkedAt: new Date().toISOString(), history: [] }; upstreamHealth.set(proxy.id, result); return result; }
  if (proxy.healthEnabled === false) { const result = { status: "unmonitored", checkedAt: null, history: [] }; upstreamHealth.set(proxy.id, result); return result; }
  const started = performance.now();
  const attempts = Math.min(Math.max(Number(proxy.healthRetries) || 0, 0), 3) + 1;
  let result;
  for (let attempt = 0; attempt < attempts; attempt++) try {
    const target = new URL(proxy.healthPath || "/", `${proxy.target}/`).toString();
    const response = await fetch(target, { method: proxy.healthMethod || "GET", redirect: "manual", signal: AbortSignal.timeout((proxy.healthTimeoutSeconds || 4) * 1000), headers: { "user-agent": "Site-Gateway-Health/1.0" } });
    await response.body?.cancel();
    const responseMs = Math.round(performance.now() - started);
    const accepted = expectedStatusMatches(response.status, proxy.healthExpected);
    result = { status: accepted ? "healthy" : "unhealthy", httpStatus: response.status, responseMs, attempts: attempt + 1, checkedAt: new Date().toISOString(), error: accepted ? null : `Expected ${proxy.healthExpected || "200-499"}; received HTTP ${response.status}` };
    if (accepted) break;
  } catch (error) {
    result = { status: "unhealthy", httpStatus: null, responseMs: Math.round(performance.now() - started), attempts: attempt + 1, checkedAt: new Date().toISOString(), error: error.name === "TimeoutError" ? `Timed out after ${proxy.healthTimeoutSeconds || 4} seconds` : error.message };
  }
  const previous = upstreamHealth.get(proxy.id);
  result.history = [{ status: result.status, responseMs: result.responseMs, httpStatus: result.httpStatus, checkedAt: result.checkedAt }, ...(previous?.history || [])].slice(0, 20);
  upstreamHealth.set(proxy.id, result);
  return result;
}

async function checkAllProxies() {
  await Promise.all([...proxies.map(checkProxy), ...sites.map(site => checkProxy({ ...site, target: `http://127.0.0.1:${site.port}`, healthPath: site.healthPath || "/", healthMethod: site.healthMethod || "GET", healthExpected: site.healthExpected || "200-499", healthTimeoutSeconds: site.healthTimeoutSeconds || 4, healthRetries: site.healthRetries || 0, healthEnabled: site.healthEnabled })), ...streams.map(checkStream)]);
  return proxies.map(publicProxy);
}

const SENSITIVE_QUERY_PARAM_PATTERNS = [/token/i, /secret/i, /password/i, /passwd/i, /auth/i, /session/i, /api[-_]?key/i, /credential/i];

function redactUri(uri) {
  const str = String(uri || "");
  const queryIndex = str.indexOf("?");
  if (queryIndex === -1) return str;
  const pathPart = str.slice(0, queryIndex);
  let params;
  try { params = new URLSearchParams(str.slice(queryIndex + 1)); } catch { return `${pathPart}?REDACTED`; }
  let redactedAny = false;
  for (const name of [...params.keys()]) {
    if (SENSITIVE_QUERY_PARAM_PATTERNS.some(pattern => pattern.test(name))) { params.set(name, "REDACTED"); redactedAny = true; }
  }
  return redactedAny ? `${pathPart}?${params.toString()}` : str;
}

async function readAccessLogs(limit = 100, host = "") {
  const files = (await fsp.readdir(logsDir).catch(() => [])).filter(name => name === "access.json" || name.startsWith("access.json.")).sort().reverse();
  const entries = [];
  for (const name of files) {
    const content = await fsp.readFile(path.join(logsDir, name), "utf8").catch(() => "");
    for (const line of content.trim().split("\n").reverse()) {
      try {
        const raw = JSON.parse(line); const request = raw.request || {}; const requestHost = String(request.host || "").split(":")[0];
        if (host && requestHost !== host) continue;
        entries.push({ at: raw.ts ? new Date(raw.ts * 1000).toISOString() : null, host: requestHost, method: request.method, uri: redactUri(request.uri), status: raw.status, size: raw.size, durationMs: Number.isFinite(raw.duration) ? Math.round(raw.duration * 1000) : null, remoteIp: request.remote_ip || null });
        if (entries.length >= limit) return entries;
      } catch { /* Skip incomplete lines while Caddy writes. */ }
    }
  }
  return entries;
}

async function importAccessLogsToSqlite() {
  if (!storage?.recordAccessEvents) return;
  try {
    const entries = await readAccessLogs(5000);
    const events = entries.map(entry => ({ ...entry, source: crypto.createHash("sha1").update(JSON.stringify([entry.at, entry.host, entry.method, entry.uri, entry.status, entry.size, entry.durationMs, entry.remoteIp])).digest("hex") }));
    storage.recordAccessEvents(events);
  } catch (error) { console.warn("Could not import access logs into SQLite:", error.message); }
}

function tcpProbe(port, timeoutMs = 1000) {
  return new Promise(resolve => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    const finish = result => { socket.destroy(); resolve(result); };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
  });
}

function tcpProbeHost(host, port, timeoutMs = 4000) {
  return new Promise(resolve => {
    if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return resolve(false);
    const socket = net.createConnection({ host, port });
    const finish = result => { socket.destroy(); resolve(result); };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
  });
}

function stableProbe(name, responding) {
  if (responding) { probeFailures[name] = 0; return { status: "ready", healthy: true, responding: true }; }
  probeFailures[name] += 1;
  return probeFailures[name] < 2
    ? { status: "checking", healthy: true, responding: false }
    : { status: "error", healthy: false, responding: false };
}

async function loadIconCatalog() {
  if (iconCatalog) return iconCatalog;
  try {
    const response = await fetch("https://raw.githubusercontent.com/homarr-labs/dashboard-icons/main/metadata.json", { signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error(`Icon catalogue returned ${response.status}.`);
    const text = await response.text();
    if (text.length > 8 * 1024 * 1024) throw new Error("Icon catalogue is unexpectedly large.");
    iconCatalog = JSON.parse(text);
    await fsp.writeFile(iconCatalogPath, text);
  } catch (error) {
    try { iconCatalog = JSON.parse(await fsp.readFile(iconCatalogPath, "utf8")); }
    catch { throw Object.assign(new Error("The icon catalogue is temporarily unavailable."), { status: 503 }); }
  }
  return iconCatalog;
}

function iconLabel(slug) {
  return slug.split("-").map(word => word ? word[0].toUpperCase() + word.slice(1) : "").join(" ");
}

async function cacheIcon(slug) {
  if (!/^[a-z0-9][a-z0-9-]{0,100}$/.test(slug)) throw Object.assign(new Error("Invalid icon selection."), { status: 400 });
  const catalog = await loadIconCatalog();
  const metadata = catalog[slug];
  if (!metadata) throw Object.assign(new Error("Icon not found."), { status: 404 });
  const response = await fetch(`https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/${slug}.svg`, { signal: AbortSignal.timeout(7000) });
  if (!response.ok) throw Object.assign(new Error("The selected icon could not be downloaded."), { status: 502 });
  const svg = await response.text();
  if (svg.length > 512 * 1024 || !/<svg[\s>]/i.test(svg) || /<(?:script|foreignObject)\b|\son\w+\s*=|(?:href|xlink:href)\s*=\s*["'](?:https?:|\/\/)/i.test(svg)) {
    throw Object.assign(new Error("The selected icon did not pass safety validation."), { status: 400 });
  }
  const filename = `${slug}.svg`;
  await fsp.writeFile(path.join(iconsDir, filename), svg);
  return `/site-icons/${filename}`;
}

async function dashboardSnapshot() {
  const hosted = sites.map(publicSite);
  const proxyHosts = proxies.map(publicProxy);
  const enabledStreams = streams.filter(item => item.enabled !== false);
  const streamingPorts = { total: enabledStreams.length, listening: enabledStreams.filter(item => activeStreams.has(item.id)).length };
  const certificates = await certificateInventory();
  const tlsDomains = [...sites, ...proxies].filter(item => item.enabled && item.domain && item.tls !== "http").length;
  const [storageWritable, gatewayResponding, httpResponding, httpsResponding] = await Promise.all([
    fsp.access(dataDir, fs.constants.R_OK | fs.constants.W_OK).then(() => true).catch(() => false),
    tcpProbe(2019),
    tcpProbe(80),
    tlsDomains ? tcpProbe(443) : Promise.resolve(false)
  ]);
  let gatewayProbe = stableProbe("gateway", gatewayResponding);
  if (gatewayError) gatewayProbe = { status: "error", healthy: false, responding: gatewayResponding };
  const httpProbe = stableProbe("http", httpResponding);
  const httpsProbe = tlsDomains ? stableProbe("https", httpsResponding) : { status: "unconfigured", healthy: true, responding: false };
  const attention = [];
  if (gatewayError) attention.push({ kind: "gateway", name: "Gateway configuration", message: "Caddy rejected the current configuration." });
  if (gatewayProbe.status === "error" && !gatewayResponding) attention.push({ kind: "gateway", name: "Caddy gateway", message: "The Caddy administration endpoint is not responding." });
  if (httpProbe.status === "error") attention.push({ kind: "http", name: "HTTP · Port 80", message: "Port 80 is not accepting connections inside the container." });
  if (httpsProbe.status === "error") attention.push({ kind: "https", name: "HTTPS · Port 443", message: "TLS domains are enabled but port 443 is not accepting connections." });
  if (!storageWritable) attention.push({ kind: "storage", name: "Persistent storage", message: "The data directory is not readable and writable." });
  for (const site of hosted.filter(item => item.status === "error")) attention.push({ kind: "hosted", name: site.name, message: `Hosted site is not responding on port ${site.port}.` });
  for (const proxy of proxyHosts.filter(item => item.status === "error")) attention.push({ kind: "proxy", name: proxy.name, message: "Proxy route needs attention." });
  for (const proxy of proxyHosts.filter(item => item.enabled && item.upstream?.status === "unhealthy")) attention.push({ kind: "upstream", name: proxy.name, message: `Upstream is unavailable${proxy.upstream.error ? ` · ${proxy.upstream.error}` : ""}.` });
  for (const certificate of certificates.certificates.filter(item => ["warning", "critical", "expired", "mismatch"].includes(item.status))) attention.push({ kind: "certificate", target: "certificates", name: certificate.domain, message: certificate.status === "expired" ? "Certificate has expired." : certificate.status === "mismatch" ? "The uploaded certificate does not cover this domain." : `Certificate expires in ${certificate.daysRemaining} day${certificate.daysRemaining === 1 ? "" : "s"}.` });
  const disk = await fsp.statfs(dataDir).catch(() => null);
  const databaseIntegrity = storage.integrity();
  return {
    checkedAt: new Date().toISOString(),
    gateway: { ...gatewayProbe, lastReload: lastGatewayReload },
    services: {
      http: { ...httpProbe, port: 80 },
      https: { ...httpsProbe, port: 443, activeDomains: tlsDomains },
      storage: { status: storageWritable ? "ready" : "error", healthy: storageWritable, path: dataDir }
    },
    hosted: { total: hosted.length, running: hosted.filter(item => item.status === "running").length, disabled: hosted.filter(item => item.status === "disabled").length, errors: hosted.filter(item => item.status === "error").length },
    proxies: { total: proxyHosts.length, running: proxyHosts.filter(item => item.status === "running").length, disabled: proxyHosts.filter(item => item.status === "disabled").length, errors: proxyHosts.filter(item => item.status === "error").length },
    tlsDomains,
    certificates: certificates.summary,
    upstreams: { total: proxyHosts.filter(item => item.enabled).length, healthy: proxyHosts.filter(item => item.upstream?.status === "healthy").length, unhealthy: proxyHosts.filter(item => item.upstream?.status === "unhealthy").length },
    streamingPorts,
    throughput: { liveRequests: storage.performanceLiveCount(60) },
    attention,
    system: {
      uptimeSeconds: Math.floor(process.uptime()),
      memoryBytes: process.memoryUsage().rss,
      dataBytes: await directorySize(dataDir),
      diskFreeBytes: disk ? disk.bavail * disk.bsize : null,
      diskTotalBytes: disk ? disk.blocks * disk.bsize : null,
      appVersion,
      caddyVersion,
      nodeVersion: process.version,
      databaseEngine: "SQLite",
      databaseStatus: databaseIntegrity.length === 1 && databaseIntegrity[0] === "ok" ? "Healthy" : "Needs attention",
      databaseBytes: (await fsp.stat(storage.databasePath).catch(() => null))?.size || 0,
      publicIp: publicIpState.address,
      publicIpCheckedAt: publicIpState.checkedAt,
      publicIpError: publicIpState.error,
      jobs: [{ name: "Upstream checks", enabled: true, schedule: "60s" }, { name: "Scheduled backups", enabled: Boolean(settings.backups?.enabled), schedule: settings.backups?.enabled ? settings.backups.frequency : "off" }, { name: "Log pruning", enabled: Boolean(settings.logsRetention?.pruningEnabled), schedule: settings.logsRetention?.pruningEnabled ? "15m" : "off" }, { name: "Access-log import", enabled: true, schedule: "30s" }, { name: "Public IP check", enabled: true, schedule: "60m" }]
    },
    activity: recentActivity
  };
}

async function startSite(site) {
  if (!site.enabled || activeServers.has(site.id)) return;
  const root = path.join(sitesDir, site.id);
  const app = express();
  app.disable("x-powered-by");
  app.use(express.static(root, { extensions: ["html"], index: "index.html", fallthrough: true }));
  app.use((req, res) => res.status(404).sendFile(path.join(publicDir, "site-404.html")));
  const server = http.createServer(app);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(site.port, "0.0.0.0", resolve);
  });
  activeServers.set(site.id, server);
  console.log(`Serving ${site.name} on port ${site.port}`);
}

async function stopSite(id) {
  const server = activeServers.get(id);
  if (!server) return;
  await new Promise(resolve => server.close(resolve));
  activeServers.delete(id);
}

async function restartSite(site) {
  await stopSite(site.id);
  if (site.enabled) await startSite(site);
}

// Streaming hosts relay raw TCP/UDP on a specific port straight to a host:port target — no domain, no HTTP,
// no Caddy involvement. This is the same pattern as startSite()/stopSite() above: a dedicated listener Site
// Gateway owns directly, just for a plain socket instead of an HTTP server.
async function startStream(stream) {
  if (stream.enabled === false || activeStreams.has(stream.id)) return;
  const [targetHost, targetPortRaw] = String(stream.target || "").split(":");
  const targetPort = Number(targetPortRaw);
  const handle = { tcpServer: null, udpSocket: null, udpSessions: new Map() };
  try {
    if (stream.tcp !== false) {
      const tcpServer = net.createServer(socket => {
        const upstream = net.createConnection({ host: targetHost, port: targetPort });
        const destroyBoth = () => { socket.destroy(); upstream.destroy(); };
        socket.on("error", destroyBoth); upstream.on("error", destroyBoth);
        socket.on("close", () => upstream.destroy()); upstream.on("close", () => socket.destroy());
        socket.pipe(upstream); upstream.pipe(socket);
      });
      await new Promise((resolve, reject) => { tcpServer.once("error", reject); tcpServer.listen(stream.port, "0.0.0.0", resolve); });
      tcpServer.on("error", error => console.warn(`Streaming host “${stream.name}” TCP error:`, error.message));
      handle.tcpServer = tcpServer;
    }
    if (stream.udp) {
      const udpSocket = dgram.createSocket("udp4");
      udpSocket.on("message", (message, rinfo) => {
        const key = `${rinfo.address}:${rinfo.port}`;
        let session = handle.udpSessions.get(key);
        if (!session) {
          const outbound = dgram.createSocket("udp4");
          session = { outbound, timer: null, connected: false, pending: [] };
          outbound.on("message", reply => { try { udpSocket.send(reply, rinfo.port, rinfo.address); } catch { /* client socket may already be gone */ } });
          outbound.on("error", () => {});
          // connect() is asynchronous — sending before it completes silently drops the datagram, which would
          // lose the first packet of every new UDP session. Queue until the callback confirms it's connected.
          outbound.connect(targetPort, targetHost, () => { session.connected = true; for (const buffered of session.pending.splice(0)) { try { outbound.send(buffered); } catch { /* upstream may be unreachable */ } } });
          handle.udpSessions.set(key, session);
        }
        clearTimeout(session.timer);
        session.timer = setTimeout(() => { session.outbound.close(); handle.udpSessions.delete(key); }, 60000).unref();
        if (session.connected) { try { session.outbound.send(message); } catch { /* upstream may be unreachable; drop this datagram */ } }
        else session.pending.push(message);
      });
      await new Promise((resolve, reject) => { udpSocket.once("error", reject); udpSocket.bind(stream.port, "0.0.0.0", resolve); });
      udpSocket.on("error", error => console.warn(`Streaming host “${stream.name}” UDP error:`, error.message));
      handle.udpSocket = udpSocket;
    }
  } catch (error) {
    if (handle.tcpServer) await new Promise(resolve => handle.tcpServer.close(resolve));
    if (handle.udpSocket) handle.udpSocket.close();
    throw error;
  }
  activeStreams.set(stream.id, handle);
  console.log(`Streaming “${stream.name}” on port ${stream.port}`);
}

async function stopStream(id) {
  const handle = activeStreams.get(id);
  if (!handle) return;
  if (handle.tcpServer) await new Promise(resolve => handle.tcpServer.close(resolve));
  if (handle.udpSocket) {
    for (const session of handle.udpSessions.values()) { clearTimeout(session.timer); session.outbound.close(); }
    handle.udpSocket.close();
  }
  activeStreams.delete(id);
}

async function restartStream(stream) {
  await stopStream(stream.id);
  if (stream.enabled !== false) await startStream(stream);
}

async function checkStream(stream) {
  if (stream.enabled === false) { const result = { status: "disabled", checkedAt: new Date().toISOString(), history: [] }; upstreamHealth.set(stream.id, result); return result; }
  if (stream.healthEnabled === false) { const result = { status: "unmonitored", checkedAt: null, history: [] }; upstreamHealth.set(stream.id, result); return result; }
  const started = performance.now();
  const [targetHost, targetPortRaw] = String(stream.target || "").split(":");
  const healthy = await tcpProbeHost(targetHost, Number(targetPortRaw), 4000);
  const responseMs = Math.round(performance.now() - started);
  const result = { status: healthy ? "healthy" : "unhealthy", responseMs, checkedAt: new Date().toISOString(), error: healthy ? null : `Could not open a TCP connection to ${stream.target}` };
  const previous = upstreamHealth.get(stream.id);
  result.history = [{ status: result.status, responseMs, checkedAt: result.checkedAt }, ...(previous?.history || [])].slice(0, 7);
  upstreamHealth.set(stream.id, result);
  return result;
}

function validatePort(port, exceptId) {
  if (!Number.isInteger(port) || port < minPort || port > maxPort) return `Port must be between ${minPort} and ${maxPort}.`;
  if (sites.some(site => site.port === port && site.id !== exceptId)) return "That port is already assigned.";
  return null;
}

async function installUpload(site, file) {
  const destination = path.join(sitesDir, site.id);
  const staging = `${destination}.staging-${Date.now()}`;
  await fsp.mkdir(staging, { recursive: true });
  try {
    if (file.originalname.toLowerCase().endsWith(".zip")) {
      const zip = new AdmZip(file.path);
      for (const entry of zip.getEntries()) {
        const normalized = path.normalize(entry.entryName).replace(/^(\.\.(\/|\\|$))+/, "");
        const target = path.resolve(staging, normalized);
        if (!target.startsWith(`${path.resolve(staging)}${path.sep}`) && target !== path.resolve(staging)) throw new Error("Unsafe path in ZIP file.");
        if (entry.isDirectory) await fsp.mkdir(target, { recursive: true });
        else {
          await fsp.mkdir(path.dirname(target), { recursive: true });
          await fsp.writeFile(target, entry.getData());
        }
      }
      const children = await fsp.readdir(staging, { withFileTypes: true });
      if (children.length === 1 && children[0].isDirectory()) {
        const nested = path.join(staging, children[0].name);
        const nestedChildren = await fsp.readdir(nested);
        for (const child of nestedChildren) await fsp.rename(path.join(nested, child), path.join(staging, child));
        await fsp.rmdir(nested);
      }
    } else {
      await fsp.copyFile(file.path, path.join(staging, "index.html"));
    }
    await fsp.access(path.join(staging, "index.html"));
    await fsp.rm(destination, { recursive: true, force: true });
    await fsp.rename(staging, destination);
  } finally {
    await fsp.rm(file.path, { force: true });
    await fsp.rm(staging, { recursive: true, force: true });
  }
}

const portableCollections = { "sites.json": () => sites, "proxies.json": () => proxies, "redirects.json": () => redirects, "streams.json": () => streams, "access-lists.json": () => accessLists, "users.json": () => users, "groups.json": () => groups, "settings.json": () => settings };

async function protectBackup(buffer, password) {
  if (!password) return buffer;
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12), key = await scryptAsync(password, salt, 32), cipher = crypto.createCipheriv("aes-256-gcm", key, iv), encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return Buffer.concat([Buffer.from("SGBK1"), salt, iv, cipher.getAuthTag(), encrypted]);
}

async function openBackup(filename, password = "") {
  let buffer = await fsp.readFile(filename), encrypted = false;
  if (buffer.subarray(0, 5).toString() === "SGBK1") {
    encrypted = true; if (!password) throw Object.assign(new Error("This backup is encrypted. Enter its password."), { status: 400 });
    try { const salt = buffer.subarray(5, 21), iv = buffer.subarray(21, 33), tag = buffer.subarray(33, 49), key = await scryptAsync(password, salt, 32), decipher = crypto.createDecipheriv("aes-256-gcm", key, iv); decipher.setAuthTag(tag); buffer = Buffer.concat([decipher.update(buffer.subarray(49)), decipher.final()]); }
    catch { throw Object.assign(new Error("The backup password is incorrect or the file is damaged."), { status: 400 }); }
  }
  return { zip: new AdmZip(buffer), encrypted };
}

async function createBackup(type = "configuration", includeLogs = false, prefix = "site-gateway-backup", password = "") {
  const safeType = type === "complete" ? "complete" : "configuration";
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `${prefix}-${stamp}.sgbackup`;
  const destination = path.join(backupsDir, filename);
  const zip = new AdmZip();
  const manifest = { format: 2, product: "Site Gateway", appVersion, database: "sqlite", schemaVersion: 1, instanceId: LOCAL_INSTANCE_ID, createdAt: new Date().toISOString(), type: safeType, includeLogs: Boolean(includeLogs), encrypted: Boolean(password), files: [] };
  const databaseSnapshot = path.join(uploadDir, `database-${crypto.randomUUID()}.sqlite`);
  storage.backupTo(databaseSnapshot); zip.addLocalFile(databaseSnapshot, "database", "site-gateway.sqlite"); await fsp.rm(databaseSnapshot, { force: true });
  for (const [name, getter] of Object.entries(portableCollections)) zip.addFile(`portable-json/${name}`, Buffer.from(JSON.stringify(getter(), null, 2)));
  if (safeType === "complete") {
    for (const [directory, archivePath] of [[sitesDir, "sites"], [iconsDir, "icons"], [defaultSiteDir, "default-site"], [certificatesRoot, "certificates"]]) {
      if (fs.existsSync(directory)) zip.addLocalFolder(directory, archivePath);
    }
  }
  if (includeLogs && fs.existsSync(logsDir)) zip.addLocalFolder(logsDir, "logs");
  manifest.files = zip.getEntries().filter(entry => !entry.isDirectory).map(entry => entry.entryName);
  manifest.checksums = Object.fromEntries(zip.getEntries().filter(entry => !entry.isDirectory).map(entry => [entry.entryName, crypto.createHash("sha256").update(entry.getData()).digest("hex")]));
  zip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2)));
  await fsp.writeFile(destination, await protectBackup(zip.toBuffer(), password));
  recordActivity(`${safeType === "complete" ? "Complete" : "Configuration"} backup created.`);
  return { filename, path: destination, ...manifest, size: (await fsp.stat(destination)).size };
}

async function listBackups() {
  const names = (await fsp.readdir(backupsDir)).filter(name => name.endsWith(".sgbackup"));
  return Promise.all(names.map(async filename => {
    const stat = await fsp.stat(path.join(backupsDir, filename));
    let manifest = {}; const header = Buffer.alloc(5); const handle = await fsp.open(path.join(backupsDir, filename), "r"); await handle.read(header, 0, 5, 0); await handle.close(); const encrypted = header.toString() === "SGBK1";
    if (!encrypted) try { manifest = JSON.parse(new AdmZip(path.join(backupsDir, filename)).readAsText("manifest.json")); } catch { /* Report unreadable archive in UI. */ }
    return { filename, size: stat.size, createdAt: manifest.createdAt || stat.mtime.toISOString(), type: encrypted ? "encrypted" : manifest.type || "unknown", appVersion: encrypted ? "protected" : manifest.appVersion || "unknown", valid: encrypted || Boolean(manifest.format), encrypted };
  })).then(items => items.sort((a, b) => b.createdAt.localeCompare(a.createdAt)));
}

async function restoreBackup(filename, password = "", createSafetyBackup = true) {
  const source = path.resolve(backupsDir, filename);
  if (!source.startsWith(`${backupsDir}${path.sep}`) || !filename.endsWith(".sgbackup")) throw Object.assign(new Error("Invalid backup selection."), { status: 400 });
  const { zip } = await openBackup(source, password); const manifest = JSON.parse(zip.readAsText("manifest.json") || "null");
  if (!manifest || manifest.product !== "Site Gateway" || ![1,2].includes(manifest.format)) throw Object.assign(new Error("This is not a supported Site Gateway backup."), { status: 400 });
  for (const [name, expected] of Object.entries(manifest.checksums || {})) {
    const entry = zip.getEntry(name); if (!entry || crypto.createHash("sha256").update(entry.getData()).digest("hex") !== expected) throw Object.assign(new Error(`Backup integrity check failed for ${name}.`), { status: 400 });
  }
  const safetyBackup = createSafetyBackup ? await createBackup("complete", true, "pre-restore") : null;
  const staging = path.join(uploadDir, `restore-${crypto.randomUUID()}`); await fsp.mkdir(staging, { recursive: true });
  try {
    for (const entry of zip.getEntries()) {
      if (entry.entryName === "manifest.json") continue;
      const target = path.resolve(staging, entry.entryName);
      if (!target.startsWith(`${staging}${path.sep}`)) throw Object.assign(new Error("Unsafe path in backup."), { status: 400 });
      if (entry.isDirectory) await fsp.mkdir(target, { recursive: true }); else { await fsp.mkdir(path.dirname(target), { recursive: true }); await fsp.writeFile(target, entry.getData()); }
    }
    const restoredDatabase = path.join(staging, "database", "site-gateway.sqlite");
    if (fs.existsSync(restoredDatabase)) {
      const candidate = new (await import("node:sqlite")).DatabaseSync(restoredDatabase, { readOnly: true }); const check = candidate.prepare("PRAGMA integrity_check").get(); candidate.close();
      if (Object.values(check)[0] !== "ok") throw Object.assign(new Error("The restored SQLite database failed its integrity check."), { status: 400 });
      const activeDatabasePath = storage.databasePath; storage.close();
      await Promise.all([fsp.rm(`${activeDatabasePath}-wal`, { force: true }), fsp.rm(`${activeDatabasePath}-shm`, { force: true })]);
      await fsp.copyFile(restoredDatabase, activeDatabasePath); storage = await openStorage(dataDir, backupsDir);
    } else {
      const legacyRoot = fs.existsSync(path.join(staging, "portable-json")) ? path.join(staging, "portable-json") : fs.existsSync(path.join(staging, "legacy-json")) ? path.join(staging, "legacy-json") : path.join(staging, "config");
      storage.saveCollection("sites", []); storage.saveCollection("proxies", []); storage.saveCollection("redirects", []); storage.saveCollection("streams", []);
      for (const [name, kind] of Object.entries({ "access-lists.json":"access_lists", "sites.json":"sites", "proxies.json":"proxies", "redirects.json":"redirects", "users.json":"users" })) { const candidate = path.join(legacyRoot, name); if (fs.existsSync(candidate)) storage.saveCollection(kind, JSON.parse(await fsp.readFile(candidate, "utf8"))); }
      const settingsCandidate = path.join(legacyRoot, "settings.json"); if (fs.existsSync(settingsCandidate)) storage.saveSettings(JSON.parse(await fsp.readFile(settingsCandidate, "utf8")));
    }
    if (manifest.type === "complete") for (const name of ["sites", "icons", "default-site", "certificates"]) {
      const candidate = path.join(staging, name); if (!fs.existsSync(candidate)) continue;
      const destination = path.join(dataDir, name); await fsp.rm(destination, { recursive: true, force: true }); await fsp.cp(candidate, destination, { recursive: true });
    }
    if (manifest.type === "complete" && fs.existsSync(path.join(staging, "custom-certificates"))) {
      await fsp.mkdir(customCertificatesDir, { recursive: true }); await fsp.cp(path.join(staging, "custom-certificates"), customCertificatesDir, { recursive: true });
    }
    await Promise.all([...activeServers.keys()].map(stopSite)); await Promise.all([...activeStreams.keys()].map(stopStream)); sites = []; proxies = []; users = []; redirects = []; streams = []; accessLists = []; groups = []; settings = {}; recentActivity.splice(0); await loadSites();
    if (manifest.type === "complete") for (const site of sites) { const contentRoot = path.join(sitesDir, site.id); if (!fs.existsSync(path.join(contentRoot, "index.html"))) throw new Error(`Restored hosted site “${site.name || site.id}” is missing index.html.`); }
    for (const site of sites.filter(item => item.enabled)) await startSite(site);
    for (const stream of streams.filter(item => item.enabled !== false)) { try { await startStream(stream); } catch (error) { console.error(`Could not start streaming host “${stream.name}”:`, error.message); } }
    await syncCaddy(); recordActivity(`Backup ${filename} restored.`);
  } catch (error) {
    if (safetyBackup) {
      try { await restoreBackup(safetyBackup.filename, "", false); recordActivity(`Restore of ${filename} failed; the pre-restore state was recovered.`, "error"); }
      catch (rollbackError) { error.message = `${error.message} Automatic rollback also failed: ${rollbackError.message}`; }
    }
    throw error;
  } finally { await fsp.rm(staging, { recursive: true, force: true }); }
  return manifest;
}

await loadSites();
try {
  const result = await execFileAsync("caddy", ["version"]);
  caddyVersion = result.stdout.trim().split(/\s+/)[0] || "Unknown";
} catch (error) {
  console.warn("Could not detect Caddy version:", error.message);
}
for (const site of sites.filter(item => item.enabled)) {
  try { await startSite(site); } catch (error) { console.error(`Could not start ${site.name}:`, error.message); }
}
for (const stream of streams.filter(item => item.enabled !== false)) {
  try { await startStream(stream); } catch (error) { console.error(`Could not start streaming host “${stream.name}”:`, error.message); }
}
for (let attempt = 0; attempt < 10; attempt++) {
  try { await syncCaddy(); break; }
  catch (error) {
    if (attempt === 9) console.error(error.message);
    else await new Promise(resolve => setTimeout(resolve, 500));
  }
}

const app = express();
const upload = multer({ dest: uploadDir, limits: { fileSize: 250 * 1024 * 1024, files: 1 } });
const certificateUpload = multer({ dest: uploadDir, limits: { fileSize: 5 * 1024 * 1024, files: 2 } });
const iconUpload = multer({ dest: uploadDir, limits: { fileSize: 2 * 1024 * 1024, files: 1 } });
app.disable("x-powered-by");
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.get(["/", "/index.html"], (req, res) => {
  const html = fs.readFileSync(path.join(publicDir, "index.html"), "utf8")
    .replace(/\/(app|features)\.js\?v=[^"']+/g, `/$1.js?v=${appVersion}`)
    .replace(/\/styles\.css\?v=[^"']+/g, `/styles.css?v=${appVersion}`);
  res.type("html").send(html);
});
app.use(express.static(publicDir));
app.use("/site-icons", express.static(iconsDir, { immutable: true, maxAge: "30d", setHeaders: res => res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'") }));

app.get("/api/session", (req, res) => {
  const user = sessionUser(req);
  res.json({ authenticated: Boolean(user), setupRequired: Boolean(user?.setupRequired), installationSetupPending: users.some(item => item.setupRequired), user: user ? publicUser(user) : null, username: user?.username || null });
});
function checkLoginRateLimit(key) {
  const attempt = loginAttempts.get(key) || { count: 0, resetAt: Date.now() + 15 * 60 * 1000 };
  if (attempt.resetAt <= Date.now()) { attempt.count = 0; attempt.resetAt = Date.now() + 15 * 60 * 1000; }
  return attempt;
}
function issueSessionCookie(res, user) {
  if (!user.sessionVersion) user.sessionVersion = crypto.randomBytes(16).toString("hex");
  const expires = String(Date.now() + 12 * 60 * 60 * 1000);
  const value = `${user.id}.${expires}.${user.sessionVersion}`;
  res.setHeader("Set-Cookie", [`webserver_session=${value}.${sign(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200`, "pending_mfa=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"]);
}
function issuePendingMfaCookie(res, user) {
  const expires = String(Date.now() + 5 * 60 * 1000);
  const value = `${user.id}.${expires}.mfa`;
  res.setHeader("Set-Cookie", `pending_mfa=${value}.${sign(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=300`);
}
function pendingMfaUser(req) {
  const token = cookieMap(req.headers.cookie).pending_mfa;
  if (!token) return null;
  const [userId, expires, marker, signature] = token.split(".");
  const user = users.find(item => item.id === userId && item.status === "active");
  if (!user || marker !== "mfa" || !expires || Number(expires) <= Date.now() || !safeEqual(signature || "", sign(`${userId}.${expires}.${marker}`))) return null;
  return user;
}
app.post("/api/login", async (req, res, next) => {
  try {
    const key = req.ip || req.socket.remoteAddress || "unknown";
    const attempt = checkLoginRateLimit(key);
    if (attempt.count >= 8) { recordActivity(`Security: sign-in rate limit reached for ${key}.`, "error"); return res.status(429).json({ error: "Too many sign-in attempts. Try again in 15 minutes." }); }
    const username = String(req.body.username || "").trim().toLowerCase();
    const user = users.find(item => item.username === username);
    if (!user || user.status !== "active" || !await passwordMatches(req.body.password || "", user.password)) {
      attempt.count += 1; loginAttempts.set(key, attempt); recordActivity(`Security: failed sign-in attempt for ${username || "unknown user"}.`, "error");
      return res.status(401).json({ error: "Incorrect username or password." });
    }
    loginAttempts.delete(key);
    if (user.mfaEnabled) { issuePendingMfaCookie(res, user); return res.json({ mfaRequired: true }); }
    user.lastLoginAt = new Date().toISOString(); user.updatedAt = user.lastLoginAt; await saveUsers();
    issueSessionCookie(res, user);
    res.json({ ok: true, user: publicUser(user) });
  } catch (error) { next(error); }
});
app.post("/api/login/mfa", async (req, res, next) => {
  try {
    const key = req.ip || req.socket.remoteAddress || "unknown";
    const attempt = checkLoginRateLimit(key);
    if (attempt.count >= 8) { recordActivity(`Security: sign-in rate limit reached for ${key}.`, "error"); return res.status(429).json({ error: "Too many sign-in attempts. Try again in 15 minutes." }); }
    const user = pendingMfaUser(req);
    if (!user || !user.mfaEnabled) { attempt.count += 1; loginAttempts.set(key, attempt); return res.status(401).json({ error: "Your sign-in session expired. Please sign in again." }); }
    const code = String(req.body.code || "").trim();
    let matchedRecoveryCode = null;
    const isValidTotp = verifyTotp(user.mfaSecret, code);
    if (!isValidTotp) {
      for (const entry of user.mfaRecoveryCodes || []) {
        if (entry.usedAt) continue;
        if (await passwordMatches(code, entry.hash)) { matchedRecoveryCode = entry; break; }
      }
    }
    if (!isValidTotp && !matchedRecoveryCode) {
      attempt.count += 1; loginAttempts.set(key, attempt); recordActivity(`Security: failed two-factor code for “${user.username}”.`, "error");
      return res.status(401).json({ error: "That code didn't match. Try again." });
    }
    loginAttempts.delete(key);
    if (matchedRecoveryCode) { matchedRecoveryCode.usedAt = new Date().toISOString(); recordActivity(`User “${user.username}” signed in using a two-factor recovery code.`); }
    user.lastLoginAt = new Date().toISOString(); user.updatedAt = user.lastLoginAt; await saveUsers();
    issueSessionCookie(res, user);
    res.json({ ok: true, user: publicUser(user) });
  } catch (error) { next(error); }
});
app.post("/api/logout", (req, res) => {
  res.setHeader("Set-Cookie", "webserver_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
  res.json({ ok: true });
});
function accessSession(req, listId) {
  const token = cookieMap(req.headers.cookie).site_gateway_access; if (!token) return null;
  const [storedList, username, expires, signature] = token.split(".");
  if (storedList !== listId || Number(expires) <= Date.now() || !safeEqual(signature || "", sign(`${storedList}.${username}.${expires}`))) return null;
  return username;
}
function accessUserAllowed(list, username) { if (list.credentials?.some(item => item.username === username)) return true; return (list.groups || []).some(groupId => { const group = groups.find(item => item.id === groupId && item.enabled !== false); return Boolean(group?.members?.some(userId => users.some(user => user.id === userId && user.status === "active" && user.username === username))); }); }
app.get("/api/access-check", (req, res) => {
  const listId = String(req.query.list || ""), list = accessLists.find(item => item.id === listId && item.enabled !== false);
  if (!list || !list.credentials?.length) return res.status(204).end();
  const username = accessSession(req, listId); if (username && accessUserAllowed(list, username)) { res.setHeader("X-Site-Gateway-User", username); return res.status(204).end(); }
  const original = String(req.headers["x-forwarded-uri"] || "/"); const safeReturn = original.startsWith("/") && !original.startsWith("//") ? original : "/";
  res.redirect(302, `/_site-gateway/login?list=${encodeURIComponent(listId)}&return=${encodeURIComponent(safeReturn)}`);
});
app.get("/_site-gateway/login", (req, res) => {
  const listId = String(req.query.list || ""), list = accessLists.find(item => item.id === listId && item.enabled !== false);
  if (!list) return res.status(404).send("Access policy not found."); const safeReturn = String(req.query.return || "/").startsWith("/") ? String(req.query.return || "/") : "/";
  res.type("html").send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark light"><title>Sign in · Site Gateway</title><style>:root{color-scheme:dark light;--bg:#08101d;--panel:#101a2b;--line:#25344c;--text:#eef4ff;--muted:#95a4ba;--green:#62e6a7}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:22px;background:radial-gradient(circle at 50% 0,#17372b 0,transparent 44%),var(--bg);color:var(--text);font-family:Inter,system-ui,sans-serif}.card{width:min(430px,100%);padding:34px;border:1px solid var(--line);border-radius:20px;background:var(--panel);box-shadow:0 24px 70px #0007}.mark{width:48px;height:48px;display:grid;place-items:center;border-radius:14px;background:#18362b;color:var(--green);font-weight:900}.eyebrow{margin:25px 0 7px;color:var(--green);font-size:11px;font-weight:850;letter-spacing:.13em;text-transform:uppercase}h1{margin:0;font-size:34px;letter-spacing:-.045em}p{color:var(--muted);line-height:1.55}label{display:block;margin-top:17px;font-size:13px;font-weight:700}input{display:block;width:100%;height:46px;margin-top:7px;padding:0 12px;border:1px solid var(--line);border-radius:10px;background:#0a1423;color:var(--text);font:inherit}button{width:100%;height:46px;margin-top:22px;border:0;border-radius:10px;background:var(--green);color:#05251a;font-weight:850;cursor:pointer}.error{color:#ff7185;font-size:13px}@media(prefers-color-scheme:light){:root{--bg:#f3f6fa;--panel:#fff;--line:#d6dfeb;--text:#132033;--muted:#637188;--green:#138a5b}input{background:#fff}}</style></head><body><form class="card" method="post" action="/_site-gateway/login"><div class="mark">SG</div><div class="eyebrow">Protected by Site Gateway</div><h1>Sign in to continue</h1><p>This service uses the <strong>${String(list.name).replace(/[<>]/g, "")}</strong> access policy.</p>${req.query.error ? '<p class="error">That username or password was not accepted.</p>' : ""}<input type="hidden" name="list" value="${listId}"><input type="hidden" name="return" value="${safeReturn.replaceAll('"', '&quot;')}"><label>Username<input name="username" autocomplete="username" required></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button>Sign in</button></form></body></html>`);
});
app.post("/_site-gateway/login", async (req, res, next) => {
  try {
    const listId = String(req.body.list || ""), list = accessLists.find(item => item.id === listId && item.enabled !== false), username = String(req.body.username || "").trim(); const credential = list?.credentials?.find(item => item.username === username) || ((list && accessUserAllowed(list, username)) ? users.find(user => user.username === username && user.status === "active") : null);
    const safeReturn = String(req.body.return || "/").startsWith("/") && !String(req.body.return).startsWith("//") ? String(req.body.return) : "/";
    if (!credential?.password || !await passwordMatches(req.body.password || "", credential.password)) return res.redirect(303, `/_site-gateway/login?list=${encodeURIComponent(listId)}&return=${encodeURIComponent(safeReturn)}&error=1`);
    const expires = String(Date.now() + 12 * 60 * 60 * 1000), value = `${listId}.${username}.${expires}`; const secure = String(req.headers["x-forwarded-proto"] || "").includes("https") ? "; Secure" : "";
    res.setHeader("Set-Cookie", `site_gateway_access=${value}.${sign(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${secure}`); res.redirect(303, safeReturn);
  } catch (error) { next(error); }
});
app.use("/api", (req, res, next) => {
  const user = sessionUser(req);
  if (!user) return res.status(401).json({ error: "Please sign in." });
  req.user = user;
  next();
});
app.post("/api/setup/admin", async (req, res, next) => {
  try {
    if (!req.user.setupRequired || req.user.source !== "bootstrap" || req.user.role !== "administrator") return res.status(409).json({ error: "Initial administrator setup has already been completed." });
    const username = String(req.body.username || "").trim().toLowerCase();
    const displayName = String(req.body.displayName || "").trim();
    const password = String(req.body.password || "");
    const confirmation = String(req.body.confirmPassword || "");
    if (!/^[a-z0-9][a-z0-9._-]{2,63}$/.test(username)) return res.status(400).json({ error: "Username must be 3–64 characters using letters, numbers, periods, hyphens, or underscores." });
    if (users.some(user => user.id !== req.user.id && user.username === username)) return res.status(409).json({ error: "That username already exists." });
    if (!displayName || displayName.length > 80) return res.status(400).json({ error: "Display name is required and must be 80 characters or fewer." });
    if (password.length < 8) return res.status(400).json({ error: "Password must contain at least 8 characters." });
    if (!safeEqual(password, confirmation)) return res.status(400).json({ error: "The passwords do not match." });
    req.user.username = username; req.user.displayName = displayName; req.user.password = await passwordRecord(password);
    req.user.source = "local"; req.user.setupRequired = false; req.user.sessionVersion = crypto.randomBytes(16).toString("hex"); req.user.updatedAt = new Date().toISOString();
    await saveUsers(); recordActivity(`Initial administrator setup completed for “${username}”.`);
    res.setHeader("Set-Cookie", "webserver_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    res.json({ ok: true });
  } catch (error) { next(error); }
});
app.use("/api", (req, res, next) => { currentAuditActor = req.user?.id || null; return req.user.setupRequired ? res.status(428).json({ error: "Complete the initial administrator setup before continuing." }) : next(); });
app.use("/api", (req, res, next) => { if (req.path.startsWith("/account/")) return next(); if (req.method === "GET" || req.user.role === "administrator") return next(); const operational = /^\/(sites|proxies|redirects|streams|access-lists)(\/|$)/.test(req.path); if (req.user.role === "standard" && operational) return next(); return res.status(403).json({ error: "Administrator access is required for this action." }); });
app.post("/api/account/password", async (req, res, next) => {
  try {
    const currentPassword = String(req.body.currentPassword || "");
    const newPassword = String(req.body.newPassword || "");
    if (!await passwordMatches(currentPassword, req.user.password)) return res.status(400).json({ error: "Your current password is incorrect." });
    if (newPassword.length < 8) return res.status(400).json({ error: "New password must contain at least 8 characters." });
    req.user.password = await passwordRecord(newPassword);
    req.user.updatedAt = new Date().toISOString();
    await saveUsers(); recordActivity(`User “${req.user.username}” changed their password.`);
    issueSessionCookie(res, req.user);
    res.json({ ok: true });
  } catch (error) { next(error); }
});
app.post("/api/account/mfa/setup", async (req, res, next) => {
  try {
    if (req.user.mfaEnabled) return res.status(409).json({ error: "Two-factor authentication is already enabled. Disable it first to start over." });
    const secret = generateTotpSecret();
    req.user.mfaPendingSecret = secret;
    await saveUsers();
    const uri = otpauthUri({ secret, username: req.user.username });
    const qrSvg = await QRCode.toString(uri, { type: "svg", margin: 1, width: 220 });
    res.json({ secret, otpauthUri: uri, qrSvg });
  } catch (error) { next(error); }
});
app.post("/api/account/mfa/confirm", async (req, res, next) => {
  try {
    if (!req.user.mfaPendingSecret) return res.status(400).json({ error: "Start two-factor setup before confirming a code." });
    if (!verifyTotp(req.user.mfaPendingSecret, req.body.code)) return res.status(400).json({ error: "That code didn't match. Try again." });
    req.user.mfaSecret = req.user.mfaPendingSecret;
    req.user.mfaPendingSecret = null;
    req.user.mfaEnabled = true;
    const codes = generateRecoveryCodes(10);
    req.user.mfaRecoveryCodes = await Promise.all(codes.map(async code => ({ hash: await passwordRecord(code), usedAt: null })));
    req.user.updatedAt = new Date().toISOString();
    await saveUsers(); recordActivity(`User “${req.user.username}” enabled two-factor authentication.`);
    res.json({ ok: true, recoveryCodes: codes });
  } catch (error) { next(error); }
});
app.post("/api/account/mfa/disable", async (req, res, next) => {
  try {
    if (!await passwordMatches(req.body.password || "", req.user.password)) return res.status(400).json({ error: "Your current password is incorrect." });
    req.user.mfaEnabled = false; req.user.mfaSecret = null; req.user.mfaPendingSecret = null; req.user.mfaRecoveryCodes = [];
    req.user.updatedAt = new Date().toISOString();
    await saveUsers(); recordActivity(`User “${req.user.username}” disabled two-factor authentication.`, "warning");
    res.json({ ok: true });
  } catch (error) { next(error); }
});
app.post("/api/account/mfa/recovery-codes", async (req, res, next) => {
  try {
    if (!req.user.mfaEnabled) return res.status(400).json({ error: "Two-factor authentication isn't enabled." });
    if (!await passwordMatches(req.body.password || "", req.user.password)) return res.status(400).json({ error: "Your current password is incorrect." });
    const codes = generateRecoveryCodes(10);
    req.user.mfaRecoveryCodes = await Promise.all(codes.map(async code => ({ hash: await passwordRecord(code), usedAt: null })));
    req.user.updatedAt = new Date().toISOString();
    await saveUsers(); recordActivity(`User “${req.user.username}” regenerated two-factor recovery codes.`);
    res.json({ ok: true, recoveryCodes: codes });
  } catch (error) { next(error); }
});
app.get("/api/config", (req, res) => res.json({ version: appVersion, minPort, maxPort, adminPort, storage: { engine: "sqlite", databasePath: storage.databasePath, instanceId: LOCAL_INSTANCE_ID, backupsPath: backupsDir, certificatesPath: certificatesRoot }, gateway: { enabled: true, error: gatewayError } }));
app.get("/api/users", (req, res) => req.user.role === "administrator" ? res.json(users.map(publicUser)) : res.status(403).json({ error: "Administrator access is required." }));
app.get("/api/audit", (req, res) => req.user.role === "administrator" ? res.json(storage.listAudit({ user: req.query.user, action: req.query.action, status: req.query.status }).map(item => ({ ...item, actor: users.find(user => user.id === item.actor_id)?.username || "System" }))) : res.status(403).json({ error: "Administrator access is required." }));
app.post("/api/users", async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const displayName = String(req.body.displayName || "").trim();
    const password = String(req.body.password || "");
    const role = ["administrator", "standard", "viewer"].includes(req.body.role) ? req.body.role : "standard";
    if (!/^[a-z0-9][a-z0-9._-]{2,63}$/.test(username)) return res.status(400).json({ error: "Username must be 3–64 characters using letters, numbers, periods, hyphens, or underscores." });
    if (users.some(user => user.username === username)) return res.status(409).json({ error: "That username already exists." });
    if (!displayName || displayName.length > 80) return res.status(400).json({ error: "Display name is required and must be 80 characters or fewer." });
    if (password.length < 8) return res.status(400).json({ error: "Password must contain at least 8 characters." });
    const now = new Date().toISOString();
    const user = { id: crypto.randomUUID(), username, displayName, role, status: "active", password: await passwordRecord(password), source: "local", createdAt: now, updatedAt: now, lastLoginAt: null };
    users.push(user); await saveUsers(); recordActivity(`User “${user.username}” created as ${role === "administrator" ? "Administrator" : role === "viewer" ? "Viewer" : "Standard User"}.`);
    res.status(201).json(publicUser(user));
  } catch (error) { next(error); }
});
app.patch("/api/users/:id", async (req, res, next) => {
  try {
    const user = users.find(item => item.id === req.params.id);
    if (!user) return res.status(404).json({ error: "User not found." });
    const nextRole = req.body.role === undefined ? user.role : ["administrator", "standard", "viewer"].includes(req.body.role) ? req.body.role : null;
    if (!nextRole) return res.status(400).json({ error: "Invalid user role." });
    const nextStatus = req.body.status === undefined ? user.status : ["active", "disabled", "archived"].includes(req.body.status) ? req.body.status : null;
    if (!nextStatus) return res.status(400).json({ error: "Invalid user status." });
    const removesActiveAdmin = user.role === "administrator" && user.status === "active" && (nextRole !== "administrator" || nextStatus !== "active");
    if (removesActiveAdmin && activeAdministrators().length === 1) return res.status(400).json({ error: "At least one active Administrator is required." });
    if (user.id === req.user.id && nextStatus !== "active") return res.status(400).json({ error: "You cannot disable or archive your own account." });
    if (user.id === req.user.id && nextRole !== user.role) return res.status(400).json({ error: "Another Administrator must change your role." });
    user.role = nextRole; user.status = nextStatus;
    if (req.body.displayName !== undefined) {
      const displayName = String(req.body.displayName).trim();
      if (!displayName || displayName.length > 80) return res.status(400).json({ error: "Display name is required and must be 80 characters or fewer." });
      user.displayName = displayName;
    }
    if (req.body.password !== undefined) {
      const password = String(req.body.password);
      if (password.length < 8) return res.status(400).json({ error: "Password must contain at least 8 characters." });
      user.password = await passwordRecord(password);
    }
    user.updatedAt = new Date().toISOString(); await saveUsers(); recordActivity(`User “${user.username}” updated · ${user.role === "administrator" ? "Administrator" : user.role === "viewer" ? "Viewer" : "Standard User"} · ${user.status}.`);
    res.json(publicUser(user));
  } catch (error) { next(error); }
});
app.delete("/api/users/:id", async (req, res, next) => {
  try {
    if (req.user.role !== "administrator") return res.status(403).json({ error: "Administrator access is required." });
    if (req.params.id === req.user.id) return res.status(400).json({ error: "You cannot delete your own account." });
    const index = users.findIndex(user => user.id === req.params.id);
    if (index < 0) return res.status(404).json({ error: "User not found." });
    const [removed] = users.splice(index, 1);
    groups.forEach(group => { group.members = (group.members || []).filter(id => id !== removed.id); });
    await Promise.all([saveUsers(), saveGroups()]);
    recordActivity(`User “${removed.username}” permanently deleted.`);
    res.status(204).end();
  } catch (error) { next(error); }
});
app.get("/api/sites", (req, res) => res.json(sites.map(publicSite)));
app.get("/api/proxies", (req, res) => res.json(proxies.map(proxy => publicProxy(proxy, req.user.role === "administrator"))));
app.get("/api/redirects", (req, res) => res.json(redirects));
app.get("/api/access-lists", (req, res) => res.json(accessLists.map(({ credentials, ...item }) => ({ ...item, credentials: (credentials || []).map(({ username }) => ({ username })), groups: item.groups || [] }))));
app.get("/api/groups", (req, res) => req.user.role === "administrator" ? res.json(groups.map(group => ({ ...group, memberIds: [...(group.members || [])], members: (group.members || []).map(id => users.find(user => user.id === id)?.username).filter(Boolean) }))) : res.status(403).json({ error: "Administrator access is required." }));
app.post("/api/access-lists/:id/groups", async (req, res, next) => { try { if (req.user.role !== "administrator") return res.status(403).json({ error: "Administrator access is required." }); const list = accessLists.find(value => value.id === req.params.id); if (!list) return res.status(404).json({ error: "Access List not found." }); list.groups = Array.isArray(req.body.groups) ? [...new Set(req.body.groups)].filter(id => groups.some(group => group.id === id && group.enabled !== false)) : []; await saveAccessLists(); recordActivity("Groups updated for Access List “" + list.name + "”."); res.json({ groups: list.groups }); } catch (error) { next(error); } });
app.post("/api/groups", async (req, res, next) => { try { if (req.user.role !== "administrator") return res.status(403).json({ error: "Administrator access is required." }); const name = String(req.body.name || "").trim().slice(0, 80); if (!name) return res.status(400).json({ error: "Group name is required." }); if (groups.some(group => group.name.toLowerCase() === name.toLowerCase())) return res.status(409).json({ error: "That group already exists." }); const group = { id: "group-" + crypto.randomBytes(4).toString("hex"), name, enabled: true, members: [], createdAt: new Date().toISOString() }; groups.push(group); await saveGroups(); recordActivity("Group “" + name + "” created."); res.status(201).json(group); } catch (error) { next(error); } });
app.patch("/api/groups/:id", async (req, res, next) => { try { if (req.user.role !== "administrator") return res.status(403).json({ error: "Administrator access is required." }); const group = groups.find(value => value.id === req.params.id); if (!group) return res.status(404).json({ error: "Group not found." }); if (req.body.name !== undefined) { const name = String(req.body.name || "").trim().slice(0, 80); if (!name) return res.status(400).json({ error: "Group name is required." }); group.name = name; } if (req.body.enabled !== undefined) group.enabled = Boolean(req.body.enabled); if (Array.isArray(req.body.members)) group.members = [...new Set(req.body.members)].filter(id => users.some(user => user.id === id)); await saveGroups(); recordActivity("Group “" + group.name + "” updated."); res.json(group); } catch (error) { next(error); } });
app.delete("/api/groups/:id", async (req, res, next) => { try { if (req.user.role !== "administrator") return res.status(403).json({ error: "Administrator access is required." }); const index = groups.findIndex(value => value.id === req.params.id); if (index < 0) return res.status(404).json({ error: "Group not found." }); const [group] = groups.splice(index, 1); await saveGroups(); recordActivity("Group “" + group.name + "” deleted."); res.status(204).end(); } catch (error) { next(error); } });
app.get("/api/settings", (req, res) => req.user.role === "administrator" ? res.json({ ...settings, backupDirectory: backupsDir }) : res.status(403).json({ error: "Administrator access is required." }));
app.post("/api/settings/verify-admin", async (req, res, next) => { try { if (req.user.role !== "administrator") return res.status(403).json({ error:"Administrator access is required." }); if (String(req.body.username || "").trim().toLowerCase() !== String(req.user.username || "").toLowerCase() || !await passwordMatches(String(req.body.password || ""), req.user.password)) return res.status(422).json({ error:"Administrator username or password is incorrect." }); res.json({ ok:true }); } catch (error) { next(error); } });
app.post("/api/settings/verify-username", (req, res) => { if (req.user.role !== "administrator") return res.status(403).json({ error:"Administrator access is required." }); const username = String(req.body.username || "").trim().toLowerCase(); res.json({ valid: Boolean(username && username === String(req.user.username || "").toLowerCase()) }); });
app.get("/api/dashboard", async (req, res, next) => {
  try { res.json(await dashboardSnapshot()); }
  catch (error) { next(error); }
});
app.get("/api/certificates", async (req, res, next) => {
  try { res.json(await certificateInventory()); }
  catch (error) { next(error); }
});
app.post("/api/health/check", async (req, res, next) => {
  try { await checkAllProxies(); res.json({ dashboard: await dashboardSnapshot(), certificates: await certificateInventory(), readiness: await domainReadiness() }); }
  catch (error) { next(error); }
});
app.get("/api/readiness", async (req, res, next) => { try { res.json({ checkedAt: new Date().toISOString(), routes: await domainReadiness() }); } catch (error) { next(error); } });
app.get("/api/support-report", async (req, res, next) => {
  try {
    if (req.user.role !== "administrator") return res.status(403).json({ error: "Administrator access is required." });
    const certificateReport = await certificateInventory();
    certificateReport.latestError = certificateReport.latestError ? { present:true, at:certificateReport.latestError.at } : null;
    const report = { product: "Site Gateway", generatedAt: new Date().toISOString(), version: appVersion, caddyVersion, nodeVersion: process.version, storage: { engine: "SQLite", integrity: storage.integrity() }, gateway: { healthy: !gatewayError, lastReload: lastGatewayReload }, routes: { hosted: sites.map(({ id,name,domain,tls,enabled,port }) => ({ id,name,domain,tls,enabled,port })), proxies: proxies.map(({ id,name,domain,tls,enabled,target,healthEnabled,healthExpected }) => ({ id,name,domain,tls,enabled,target,healthEnabled,healthExpected })), redirects: redirects.map(({ id,name,domain,tls,enabled,code }) => ({ id,name,domain,tls,enabled,code })) }, certificates: certificateReport, readiness: await domainReadiness(), recentEvents: recentActivity.slice(0,20).map(item => ({ at:item.at, status:item.status, message:item.status === "error" ? "Operational error recorded; review the protected in-app event log for details." : item.message })) };
    res.setHeader("Content-Disposition", `attachment; filename="site-gateway-support-${new Date().toISOString().slice(0,10)}.json"`); res.type("json").send(JSON.stringify(report, null, 2));
  } catch (error) { next(error); }
});
app.get("/api/upstreams", (req, res) => res.json(proxies.map(publicProxy)));
app.post("/api/upstreams/check", async (req, res, next) => {
  try { res.json(await checkAllProxies()); }
  catch (error) { next(error); }
});
app.get("/api/logs", async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 100, 1), 250);
    const host = normalizeDomain(req.query.host);
    res.json({ entries: storage.listAccessEvents(limit, host), hosts: [...new Set([...sites, ...proxies, ...redirects].flatMap(item => normalizeDomains(item.domain, item.domains)))].sort(), activity: recentActivity });
  } catch (error) { next(error); }
});
app.get("/api/performance", (req, res, next) => {
  try {
    const host = normalizeDomain(req.query.host);
    const hours = Math.min(Math.max(Number.parseInt(req.query.hours, 10) || 6, 1), 168);
    const bucketMinutes = hours > 24 ? 60 : 15;
    const breakdownByHost = new Map();
    for (const row of storage.performanceErrorBreakdown()) { if (!breakdownByHost.has(row.host)) breakdownByHost.set(row.host, []); breakdownByHost.get(row.host).push({ status: row.status, count: row.count }); }
    res.json({
      checkedAt: new Date().toISOString(),
      liveRequests: storage.performanceLiveCount(60),
      routes: storage.performanceRoutes().map(row => ({ host: row.host, hourRequests: row.hourRequests || 0, hourErrors: row.hourErrors || 0, hourAvgMs: row.hourAvgMs != null ? Math.round(row.hourAvgMs) : null, dayRequests: row.dayRequests || 0, dayErrors: row.dayErrors || 0, dayAvgMs: row.dayAvgMs != null ? Math.round(row.dayAvgMs) : null, errorBreakdown: (breakdownByHost.get(row.host) || []).slice(0, 3) })),
      trend: storage.performanceTrend(host, hours, bucketMinutes),
      hosts: [...new Set([...sites, ...proxies, ...redirects].flatMap(item => normalizeDomains(item.domain, item.domains)))].sort()
    });
  } catch (error) { next(error); }
});
app.get("/api/icons/search", async (req, res, next) => {
  try {
    const query = String(req.query.q || "").trim().toLowerCase().slice(0, 80);
    if (query.length < 2) return res.json([]);
    const catalog = await loadIconCatalog();
    const results = Object.entries(catalog).map(([slug, metadata]) => {
      const aliases = metadata.aliases || [];
      const searchText = [slug, ...aliases, ...(metadata.categories || [])].join(" ").toLowerCase();
      const score = slug === query ? 0 : slug.startsWith(query) ? 1 : aliases.some(alias => alias.toLowerCase() === query) ? 2 : searchText.includes(query) ? 3 : 99;
      return { slug, metadata, aliases, score };
    }).filter(item => item.score < 99).sort((left, right) => left.score - right.score || left.slug.localeCompare(right.slug)).slice(0, 30)
      .map(({ slug, aliases }) => ({ slug, label: iconLabel(slug), aliases: aliases.slice(0, 3), preview: `https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/${slug}.svg` }));
    res.json(results);
  } catch (error) { next(error); }
});
function entryLabel(item) {
  return item?.name || item?.displayName || item?.username || "item";
}
app.put("/api/:kind/:id/icon", async (req, res, next) => {
  try {
    const collection = req.params.kind === "sites" ? sites : req.params.kind === "proxies" ? proxies : req.params.kind === "redirects" ? redirects : req.params.kind === "streams" ? streams : req.params.kind === "access-lists" ? accessLists : req.params.kind === "groups" ? groups : req.params.kind === "users" ? users : null;
    if (!collection) return res.status(404).json({ error: "Entry type not found." });
    const item = collection.find(entry => entry.id === req.params.id);
    if (!item) return res.status(404).json({ error: "Entry not found." });
    if (req.body.url !== undefined) {
      const url = String(req.body.url || "").trim();
      if (!/^https:\/\//i.test(url) || url.length > 2048) return res.status(400).json({ error: "Icon URL must be a valid HTTPS URL under 2048 characters." });
      item.iconSlug = null; item.icon = url;
      if (collection === sites) await saveSites(); else if (collection === proxies) await saveProxies(); else if (collection === redirects) await saveRedirects(); else if (collection === streams) await saveStreams(); else if (collection === groups) await saveGroups(); else if (collection === users) await saveUsers(); else await saveAccessLists();
      recordActivity(`Icon URL updated for “${entryLabel(item)}”.`);
      return res.json(item);
    }
    const slug = String(req.body.slug || "").trim();
    const icon = slug ? await cacheIcon(slug) : null;
    item.iconSlug = slug || null;
    item.icon = icon;
    if (collection === sites) await saveSites(); else if (collection === proxies) await saveProxies(); else if (collection === redirects) await saveRedirects(); else if (collection === streams) await saveStreams(); else if (collection === groups) await saveGroups(); else await saveAccessLists();
    recordActivity(`${slug ? "Icon updated" : "Icon reset"} for “${entryLabel(item)}”.`);
    res.json(item);
  } catch (error) { next(error); }
});
app.post("/api/:kind/:id/icon", iconUpload.single("icon"), async (req, res, next) => {
  try {
    const collection = req.params.kind === "sites" ? sites : req.params.kind === "proxies" ? proxies : req.params.kind === "redirects" ? redirects : req.params.kind === "streams" ? streams : req.params.kind === "access-lists" ? accessLists : req.params.kind === "groups" ? groups : req.params.kind === "users" ? users : null;
    if (!collection) return res.status(404).json({ error: "Entry type not found." });
    const item = collection.find(entry => entry.id === req.params.id);
    if (!item) return res.status(404).json({ error: "Entry not found." });
    if (!req.file) return res.status(400).json({ error: "Choose an icon image." });
    if (!/^image\/(png|jpeg|webp|gif|svg\+xml)$/.test(req.file.mimetype)) return res.status(400).json({ error: "Use PNG, JPEG, WebP, GIF, or SVG." });
    const extension = req.file.mimetype === "image/svg+xml" ? "svg" : req.file.mimetype.split("/")[1].replace("jpeg", "jpg");
    const filename = `${req.params.kind}-${item.id}.${extension}`;
    await fsp.rename(req.file.path, path.join(iconsDir, filename));
    item.iconSlug = null; item.icon = `/site-icons/${filename}`;
    if (collection === sites) await saveSites(); else if (collection === proxies) await saveProxies(); else if (collection === redirects) await saveRedirects(); else if (collection === streams) await saveStreams(); else if (collection === groups) await saveGroups(); else if (collection === users) await saveUsers(); else await saveAccessLists();
    recordActivity(`Custom icon uploaded for “${entryLabel(item)}”.`);
    res.json(item);
  } catch (error) { next(error); }
  finally { if (req.file?.path) await fsp.rm(req.file.path, { force: true }).catch(() => {}); }
});
app.post("/api/sites", upload.single("files"), async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const port = Number.parseInt(req.body.port, 10);
    const domain = normalizeDomain(req.body.domain);
    const domains = normalizeDomains(domain, req.body.domains);
    const tls = ["http", "automatic", "internal"].includes(req.body.tls) ? req.body.tls : "automatic";
    const hsts = req.body.hsts === "true";
    const id = `${slugify(name) || "site"}-${crypto.randomBytes(3).toString("hex")}`;
    if (!name) throw Object.assign(new Error("Site name is required."), { status: 400 });
    const portError = validatePort(port);
    if (portError) throw Object.assign(new Error(portError), { status: 400 });
    const domainError = validateDomains(domains);
    if (domainError) throw Object.assign(new Error(domainError), { status: 400 });
    if (!req.file) throw Object.assign(new Error("Choose a ZIP file or index.html."), { status: 400 });
    const accessListId = String(req.body.accessListId || "");
    const site = { id, name, port, domain, domains, accessListId, tls, hsts, enabled: true, createdAt: new Date().toISOString() };
    applyAdvancedSettings(site, { accessListId, compression: req.body.compression, hstsSubdomains: req.body.hstsSubdomains === "true", customConfig: req.body.customConfig, healthEnabled: req.body.healthEnabled === true || (typeof req.body.healthEnabled === "string" && req.body.healthEnabled.toLowerCase() === "true"), healthPath: req.body.healthPath, healthMethod: req.body.healthMethod, healthExpected: req.body.healthExpected, healthTimeoutSeconds: req.body.healthTimeoutSeconds, healthRetries: req.body.healthRetries });
    await installUpload(site, req.file);
    sites.push(site);
    try { await startSite(site); } catch (error) { sites = sites.filter(item => item.id !== site.id); await fsp.rm(path.join(sitesDir, site.id), { recursive: true, force: true }); throw Object.assign(new Error(`Could not start the hosted site on port ${port}: ${error.message}`), { status: 409 }); }
    await syncCaddy();
    await saveSites();
    recordActivity(`Hosted site “${site.name}” created.`);
    res.status(201).json(publicSite(site));
  } catch (error) {
    if (req.file) await fsp.rm(req.file.path, { force: true });
    next(error);
  }
});
app.post("/api/sites/:id/toggle", async (req, res, next) => {
  try {
    const site = sites.find(item => item.id === req.params.id);
    if (!site) return res.status(404).json({ error: "Site not found." });
    site.enabled = !site.enabled;
    await restartSite(site);
    await syncCaddy();
    await saveSites();
    recordActivity(`Hosted site “${site.name}” ${site.enabled ? "enabled" : "disabled"}.`);
    res.json(publicSite(site));
  } catch (error) { next(error); }
});
app.post("/api/sites/:id/files", upload.single("files"), async (req, res, next) => {
  try {
    const site = sites.find(item => item.id === req.params.id);
    if (!site) return res.status(404).json({ error: "Site not found." });
    if (!req.file) return res.status(400).json({ error: "Choose a ZIP file or index.html." });
    await installUpload(site, req.file);
    await syncCaddy();
    recordActivity(`Files replaced for “${site.name}”.`);
    res.json(publicSite(site));
  } catch (error) { next(error); }
});
app.delete("/api/sites/:id", async (req, res, next) => {
  try {
    const index = sites.findIndex(item => item.id === req.params.id);
    if (index < 0) return res.status(404).json({ error: "Site not found." });
    const [site] = sites.splice(index, 1);
    await stopSite(site.id);
    await syncCaddy();
    await fsp.rm(path.join(sitesDir, site.id), { recursive: true, force: true });
    await pruneOrphanedCertificates(normalizeDomains(site.domain, site.domains));
    await saveSites();
    recordActivity(`Hosted site “${site.name}” deleted.`);
    res.status(204).end();
  } catch (error) { next(error); }
});
app.patch("/api/sites/:id", async (req, res, next) => {
  try {
    const site = sites.find(item => item.id === req.params.id);
    if (!site) return res.status(404).json({ error: "Site not found." });
    const previousDomains = normalizeDomains(site.domain, site.domains);
    const domain = normalizeDomain(req.body.domain);
    const domains = normalizeDomains(domain, req.body.domains !== undefined ? req.body.domains : site.domains);
    const domainError = validateDomains(domains, site.id);
    if (domainError) return res.status(400).json({ error: domainError });
    site.domain = domain; site.domains = domains;
    site.tls = ["http", "automatic", "internal"].includes(req.body.tls) ? req.body.tls : "automatic";
    site.hsts = req.body.hsts === true;
    applyAdvancedSettings(site, { accessListId: req.body.accessListId, compression: req.body.compression, hstsSubdomains: req.body.hstsSubdomains, requestHeaders: req.body.requestHeaders, responseHeaders: req.body.responseHeaders, customConfig: req.body.customConfig, healthEnabled: req.body.healthEnabled, healthPath: req.body.healthPath, healthMethod: req.body.healthMethod, healthExpected: req.body.healthExpected, healthTimeoutSeconds: req.body.healthTimeoutSeconds, healthRetries: req.body.healthRetries });
    if (site.healthEnabled === false) upstreamHealth.set(site.id, { status: "unmonitored", checkedAt: null, history: [] });
    else { upstreamHealth.set(site.id, { status: "pending", checkedAt: null, history: [] }); checkProxy({ ...site, target: `http://127.0.0.1:${site.port}` }).catch(error => console.warn("Hosted site health check failed:", error.message)); }
    await syncCaddy();
    await pruneOrphanedCertificates(previousDomains);
    await saveSites();
    recordActivity(`Gateway settings updated for “${site.name}”.`);
    res.json(publicSite(site));
  } catch (error) { next(error); }
});
app.post("/api/proxies", async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const domain = normalizeDomain(req.body.domain);
    const domains = normalizeDomains(domain, req.body.domains);
    if (!name) return res.status(400).json({ error: "Proxy name is required." });
    const domainError = validateDomains(domains);
    if (domainError || !domain) return res.status(400).json({ error: domainError || "Domain is required." });
    const proxy = {
      id: `${slugify(name) || "proxy"}-${crypto.randomBytes(3).toString("hex")}`,
      name,
      domain, domains,
      target: validateTarget(req.body.target),
      tls: ["http", "automatic", "internal"].includes(req.body.tls) ? req.body.tls : "automatic",
      hsts: req.body.hsts === true,
      enabled: true,
      createdAt: new Date().toISOString()
    };
    applyAdvancedSettings(proxy, req.body);
    if (proxy.healthEnabled === false) upstreamHealth.set(proxy.id, { status: "unmonitored", checkedAt: null, history: [] });
    else { upstreamHealth.set(proxy.id, { status: "pending", checkedAt: null, history: [] }); checkProxy(proxy).catch(error => console.warn("Proxy health check failed:", error.message)); }
    proxies.push(proxy);
    await syncCaddy();
    await saveProxies();
    recordActivity(`Proxy host “${proxy.name}” created.`);
    res.status(201).json(publicProxy(proxy));
  } catch (error) { next(error); }
});
app.patch("/api/proxies/:id", async (req, res, next) => {
  try {
    const proxy = proxies.find(item => item.id === req.params.id);
    if (!proxy) return res.status(404).json({ error: "Proxy host not found." });
    const previousDomains = normalizeDomains(proxy.domain, proxy.domains);
    if (req.body.domain !== undefined) {
      const domain = normalizeDomain(req.body.domain);
      const domains = normalizeDomains(domain, req.body.domains !== undefined ? req.body.domains : proxy.domains);
      const domainError = validateDomains(domains, proxy.id);
      if (domainError || !domain) return res.status(400).json({ error: domainError || "Domain is required." });
      proxy.domain = domain; proxy.domains = domains;
    }
    if (req.body.domains !== undefined && req.body.domain === undefined) { const domains = normalizeDomains(proxy.domain, req.body.domains); const domainError = validateDomains(domains, proxy.id); if (domainError) return res.status(400).json({ error: domainError }); proxy.domains = domains; }
    if (req.body.name !== undefined) {
      const name = String(req.body.name).trim();
      if (!name) return res.status(400).json({ error: "Proxy name is required." });
      proxy.name = name;
    }
    if (req.body.target !== undefined) proxy.target = validateTarget(req.body.target);
    if (req.body.tls !== undefined) proxy.tls = req.body.tls === "custom" && proxy.certificatePath && proxy.keyPath ? "custom" : ["http", "automatic", "internal"].includes(req.body.tls) ? req.body.tls : proxy.tls;
    if (req.body.hsts !== undefined) proxy.hsts = req.body.hsts === true;
    applyAdvancedSettings(proxy, req.body);
    // Mirror the Hosted Site PATCH handler: react immediately instead of waiting on the 60s
    // background checkAllProxies() timer or a page refresh to pick up a Monitor toggle/edit.
    if (proxy.healthEnabled === false) upstreamHealth.set(proxy.id, { status: "unmonitored", checkedAt: null, history: [] });
    else { upstreamHealth.set(proxy.id, { status: "pending", checkedAt: null, history: [] }); checkProxy(proxy).catch(error => console.warn("Proxy health check failed:", error.message)); }
    await syncCaddy();
    await pruneOrphanedCertificates(previousDomains);
    await saveProxies();
    recordActivity(`Proxy host “${proxy.name}” updated.`);
    res.json(publicProxy(proxy));
  } catch (error) { next(error); }
});
app.post("/api/proxies/:id/certificate", certificateUpload.fields([{ name: "certificate", maxCount: 1 }, { name: "privateKey", maxCount: 1 }]), async (req, res, next) => {
  const files = Object.values(req.files || {}).flat();
  try {
    const proxy = proxies.find(item => item.id === req.params.id); if (!proxy) return res.status(404).json({ error: "Proxy host not found." });
    const certificateFile = req.files?.certificate?.[0], keyFile = req.files?.privateKey?.[0];
    if (!certificateFile || !keyFile) return res.status(400).json({ error: "Choose both the PEM certificate and private key." });
    const certificatePem = await fsp.readFile(certificateFile.path, "utf8"), keyPem = await fsp.readFile(keyFile.path, "utf8");
    const certificate = new crypto.X509Certificate(certificatePem), privateKey = crypto.createPrivateKey(keyPem), publicFromKey = crypto.createPublicKey(privateKey);
    const certificatePublic = certificate.publicKey.export({ type: "spki", format: "der" }), suppliedPublic = publicFromKey.export({ type: "spki", format: "der" });
    if (!certificatePublic.equals(suppliedPublic)) return res.status(400).json({ error: "The private key does not match the certificate." });
    const certificateDomains = normalizeDomains(proxy.domain, proxy.domains); if (!certificateDomains.every(domain => certificate.checkHost(domain))) return res.status(400).json({ error: "The certificate must cover the primary domain and every additional domain." });
    const destination = path.join(customCertificatesDir, proxy.id); await fsp.mkdir(destination, { recursive: true });
    const certificatePath = path.join(destination, "certificate.pem"), keyPath = path.join(destination, "private-key.pem");
    await fsp.writeFile(certificatePath, certificatePem, { mode: 0o600 }); await fsp.writeFile(keyPath, keyPem, { mode: 0o600 });
    proxy.tls = "custom"; proxy.certificatePath = certificatePath; proxy.keyPath = keyPath; await syncCaddy(); await saveProxies(); recordActivity(`Custom certificate installed for “${proxy.name}”.`); res.json(publicProxy(proxy));
  } catch (error) { next(Object.assign(new Error(error.message || "Could not read that certificate."), { status: error.status || 400 })); }
  finally { await Promise.all(files.map(file => fsp.rm(file.path, { force: true }))); }
});
app.post("/api/proxies/:id/toggle", async (req, res, next) => {
  try {
    const proxy = proxies.find(item => item.id === req.params.id);
    if (!proxy) return res.status(404).json({ error: "Proxy host not found." });
    proxy.enabled = !proxy.enabled;
    await syncCaddy();
    await saveProxies();
    recordActivity(`Proxy host “${proxy.name}” ${proxy.enabled ? "enabled" : "disabled"}.`);
    res.json(publicProxy(proxy));
  } catch (error) { next(error); }
});
app.delete("/api/proxies/:id", async (req, res, next) => {
  try {
    const index = proxies.findIndex(item => item.id === req.params.id);
    if (index < 0) return res.status(404).json({ error: "Proxy host not found." });
    const [proxy] = proxies.splice(index, 1);
    await syncCaddy();
    await fsp.rm(path.join(customCertificatesDir, proxy.id), { recursive: true, force: true }).catch(() => {});
    await pruneOrphanedCertificates(normalizeDomains(proxy.domain, proxy.domains));
    await saveProxies();
    recordActivity(`Proxy host “${proxy.name}” deleted.`);
    res.status(204).end();
  } catch (error) { next(error); }
});

app.post("/api/access-lists", async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    if (!name || name.length > 80) return res.status(400).json({ error: "Access List name is required and must be 80 characters or fewer." });
    const networks = String(req.body.networks || "").split(/[\n,]+/).map(value => value.trim()).filter(Boolean);
    const deniedNetworks = String(req.body.deniedNetworks || "").split(/[\n,]+/).map(value => value.trim()).filter(Boolean);
    if (networks.some(value => !/^(?:private_ranges|(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?|[0-9a-f:]+(?:\/\d{1,3})?)$/i.test(value))) return res.status(400).json({ error: "Enter IP addresses, CIDR ranges, or private_ranges, one per line." });
    if (deniedNetworks.some(value => !/^(?:private_ranges|(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?|[0-9a-f:]+(?:\/\d{1,3})?)$/i.test(value))) return res.status(400).json({ error: "Enter valid denied IP addresses or CIDR ranges." });
    const credentials = [];
    for (const entry of Array.isArray(req.body.credentials) ? req.body.credentials.slice(0, 25) : []) {
      const username = String(entry.username || "").trim(); const password = String(entry.password || "");
      if (!/^[A-Za-z0-9._-]{1,64}$/.test(username) || password.length < 8) return res.status(400).json({ error: "Access usernames must be valid and passwords must contain at least 8 characters." });
      const { stdout } = await execFileAsync("caddy", ["hash-password", "--plaintext", password]);
      credentials.push({ username, hash: stdout.trim(), password: await passwordRecord(password) });
    }
    if (!networks.length && !deniedNetworks.length && !credentials.length) return res.status(400).json({ error: "Add at least one network rule or login." });
    const selectedGroups = Array.isArray(req.body.groups) ? [...new Set(req.body.groups)].filter(id => groups.some(group => group.id === id && group.enabled !== false)) : [];
    const item = { id: `access-${crypto.randomBytes(4).toString("hex")}`, name, networks, deniedNetworks, credentials, groups: selectedGroups, enabled: true, createdAt: new Date().toISOString() };
    accessLists.push(item); await syncCaddy(); await saveAccessLists(); recordActivity(`Access List “${name}” created.`);
    res.status(201).json({ ...item, credentials: credentials.map(({ username }) => ({ username })) });
  } catch (error) { next(error); }
});
app.patch("/api/access-lists/:id", async (req, res, next) => {
  try {
    const item = accessLists.find(value => value.id === req.params.id); if (!item) return res.status(404).json({ error: "Access List not found." });
    if (req.body.enabled !== undefined) item.enabled = Boolean(req.body.enabled);
    if (req.body.name) item.name = String(req.body.name).trim().slice(0, 80);
    if (req.body.networks !== undefined) {
      const networks = String(req.body.networks || "").split(/[\n,]+/).map(value => value.trim()).filter(Boolean);
      if (networks.some(value => !/^(?:private_ranges|(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?|[0-9a-f:]+(?:\/\d{1,3})?)$/i.test(value))) return res.status(400).json({ error: "Enter IP addresses, CIDR ranges, or private_ranges, one per line." });
      item.networks = networks;
    }
    if (req.body.deniedNetworks !== undefined) {
      const deniedNetworks = String(req.body.deniedNetworks || "").split(/[\n,]+/).map(value => value.trim()).filter(Boolean);
      if (deniedNetworks.some(value => !/^(?:private_ranges|(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?|[0-9a-f:]+(?:\/\d{1,3})?)$/i.test(value))) return res.status(400).json({ error: "Enter valid denied IP addresses or CIDR ranges." });
      item.deniedNetworks = deniedNetworks;
    }
    if (Array.isArray(req.body.credentials)) {
      const credentials = [];
      for (const entry of req.body.credentials.slice(0, 25)) { const username = String(entry.username || "").trim(), password = String(entry.password || ""); if (!/^[A-Za-z0-9._-]{1,64}$/.test(username)) return res.status(400).json({ error: "Access usernames must use letters, numbers, dots, underscores, or hyphens." }); if (!password) { const existing = item.credentials?.find(value => value.username === username); if (!existing) return res.status(400).json({ error: `Enter a password for new user ${username}.` }); credentials.push(existing); continue; } if (password.length < 8) return res.status(400).json({ error: "Passwords must contain at least 8 characters." }); const { stdout } = await execFileAsync("caddy", ["hash-password", "--plaintext", password]); credentials.push({ username, hash: stdout.trim(), password: await passwordRecord(password) }); }
      item.credentials = credentials;
    }
    if (!(item.networks || []).length && !(item.deniedNetworks || []).length && !(item.credentials || []).length) return res.status(400).json({ error: "Keep at least one network rule or login." });
    await syncCaddy(); await saveAccessLists(); recordActivity(`Access List “${item.name}” updated.`); res.json({ ...item, credentials: (item.credentials || []).map(({ username }) => ({ username })) });
  } catch (error) { next(error); }
});
app.post("/api/access-lists/:id/assignments", async (req, res, next) => {
  try {
    const list = accessLists.find(value => value.id === req.params.id); if (!list) return res.status(404).json({ error: "Access List not found." });
    const collections = { sites, proxies, redirects }; const kind = String(req.body.kind || ""); const collection = collections[kind]; const host = collection?.find(value => value.id === req.body.hostId);
    if (!host) return res.status(404).json({ error: "Host not found." });
    host.accessListId = req.body.assigned === false ? "" : list.id;
    await syncCaddy(); if (kind === "sites") await saveSites(); else if (kind === "proxies") await saveProxies(); else await saveRedirects();
    recordActivity("Access List " + list.name + (host.accessListId ? " assigned to " : " removed from ") + (host.name || host.domain) + ".");
    res.json({ ok: true, accessListId: host.accessListId });
  } catch (error) { next(error); }
});
app.delete("/api/access-lists/:id", async (req, res, next) => {
  try {
    if ([...sites, ...proxies, ...redirects].some(item => item.accessListId === req.params.id)) return res.status(409).json({ error: "Remove this Access List from all hosts before deleting it." });
    const index = accessLists.findIndex(item => item.id === req.params.id); if (index < 0) return res.status(404).json({ error: "Access List not found." });
    const [item] = accessLists.splice(index, 1); await saveAccessLists(); recordActivity(`Access List “${item.name}” deleted.`); res.status(204).end();
  } catch (error) { next(error); }
});

app.post("/api/redirects", async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim(); const domain = normalizeDomain(req.body.domain); const domains = normalizeDomains(domain, req.body.domains); const target = String(req.body.target || "").trim().replace(/\/$/, "");
    const domainError = validateDomains(domains); if (!name || domainError || !domain) return res.status(400).json({ error: domainError || "Name and primary source domain are required." });
    try { const parsed = new URL(target); if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error(); } catch { return res.status(400).json({ error: "Destination must be a complete HTTP or HTTPS URL." }); }
    const item = { id: `redirect-${crypto.randomBytes(4).toString("hex")}`, name, domain, domains, target, code: [301,302,307,308].includes(Number(req.body.code)) ? Number(req.body.code) : 302, preservePath: req.body.preservePath !== false, tls: ["http","automatic","internal"].includes(req.body.tls) ? req.body.tls : "automatic", hsts: Boolean(req.body.hsts), accessListId: String(req.body.accessListId || ""), enabled: true, createdAt: new Date().toISOString() };
    redirects.push(item); await syncCaddy(); await saveRedirects(); recordActivity(`Redirect Host “${name}” created.`); res.status(201).json(item);
  } catch (error) { next(error); }
});
app.patch("/api/redirects/:id", async (req, res, next) => {
  try {
    const item = redirects.find(value => value.id === req.params.id); if (!item) return res.status(404).json({ error: "Redirect Host not found." });
    const previousDomains = normalizeDomains(item.domain, item.domains);
    if (req.body.domain !== undefined || req.body.domains !== undefined) { const domain = normalizeDomain(req.body.domain ?? item.domain); const domains = normalizeDomains(domain, req.body.domains !== undefined ? req.body.domains : item.domains); const error = validateDomains(domains, item.id); if (error || !domain) return res.status(400).json({ error: error || "Primary source domain is required." }); item.domain = domain; item.domains = domains; }
    if (req.body.enabled !== undefined) item.enabled = Boolean(req.body.enabled);
    for (const key of ["name","target","accessListId"]) if (req.body[key] !== undefined) item[key] = String(req.body[key]).trim();
    if (req.body.target !== undefined) { try { const parsed = new URL(item.target); if (!['http:','https:'].includes(parsed.protocol)) throw new Error(); } catch { return res.status(400).json({ error: "Destination must be a complete HTTP or HTTPS URL." }); } }
    if (req.body.code !== undefined && [301,302,307,308].includes(Number(req.body.code))) item.code = Number(req.body.code);
    if (req.body.preservePath !== undefined) item.preservePath = Boolean(req.body.preservePath);
    if (req.body.tls !== undefined) item.tls = ["http","automatic","internal"].includes(req.body.tls) ? req.body.tls : item.tls;
    if (req.body.hsts !== undefined) item.hsts = Boolean(req.body.hsts);
    await syncCaddy(); await pruneOrphanedCertificates(previousDomains); await saveRedirects(); recordActivity(`Redirect Host “${item.name}” updated.`); res.json(item);
  } catch (error) { next(error); }
});
app.delete("/api/redirects/:id", async (req, res, next) => {
  try { const index = redirects.findIndex(item => item.id === req.params.id); if (index < 0) return res.status(404).json({ error: "Redirect Host not found." }); const [item] = redirects.splice(index, 1); await syncCaddy(); await pruneOrphanedCertificates(normalizeDomains(item.domain, item.domains)); await saveRedirects(); recordActivity(`Redirect Host “${item.name}” deleted.`); res.status(204).end(); } catch (error) { next(error); }
});

app.get("/api/streams", (req, res) => res.json(streams.map(publicStream)));
app.post("/api/streams", async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    if (!name) return res.status(400).json({ error: "Name is required." });
    const port = validateStreamPort(req.body.port);
    const portError = streamPortConflict(port); if (portError) return res.status(400).json({ error: portError });
    const target = validateStreamHostPort(req.body.target);
    const tcp = req.body.tcp !== false, udp = req.body.udp === true;
    if (!tcp && !udp) return res.status(400).json({ error: "Enable TCP, UDP, or both." });
    const stream = { id: `stream-${crypto.randomBytes(4).toString("hex")}`, name, port, target, tcp, udp, healthEnabled: req.body.healthEnabled !== false, enabled: true, createdAt: new Date().toISOString() };
    try { await startStream(stream); } catch (error) { return res.status(409).json({ error: `Could not bind port ${port}: ${error.message}` }); }
    streams.push(stream);
    if (stream.healthEnabled === false) upstreamHealth.set(stream.id, { status: "unmonitored", checkedAt: null, history: [] });
    else { upstreamHealth.set(stream.id, { status: "pending", checkedAt: null, history: [] }); checkStream(stream).catch(error => console.warn("Streaming host health check failed:", error.message)); }
    await saveStreams();
    recordActivity(`Streaming host “${stream.name}” created.`);
    res.status(201).json(publicStream(stream));
  } catch (error) { next(error); }
});
app.patch("/api/streams/:id", async (req, res, next) => {
  try {
    const stream = streams.find(item => item.id === req.params.id); if (!stream) return res.status(404).json({ error: "Streaming host not found." });
    const next_ = { ...stream };
    if (req.body.name !== undefined) { const name = String(req.body.name).trim(); if (!name) return res.status(400).json({ error: "Name is required." }); next_.name = name; }
    if (req.body.port !== undefined) { const port = validateStreamPort(req.body.port); const portError = streamPortConflict(port, stream.id); if (portError) return res.status(400).json({ error: portError }); next_.port = port; }
    if (req.body.target !== undefined) next_.target = validateStreamHostPort(req.body.target);
    if (req.body.tcp !== undefined) next_.tcp = Boolean(req.body.tcp);
    if (req.body.udp !== undefined) next_.udp = Boolean(req.body.udp);
    if (!next_.tcp && !next_.udp) return res.status(400).json({ error: "Enable TCP, UDP, or both." });
    if (req.body.healthEnabled !== undefined) next_.healthEnabled = req.body.healthEnabled === true || (typeof req.body.healthEnabled === "string" && req.body.healthEnabled.toLowerCase() === "true");
    if (req.body.enabled !== undefined) next_.enabled = Boolean(req.body.enabled);
    const portOrProtocolChanged = next_.port !== stream.port || next_.target !== stream.target || next_.tcp !== stream.tcp || next_.udp !== stream.udp || next_.enabled !== stream.enabled;
    Object.assign(stream, next_);
    if (portOrProtocolChanged) { try { await restartStream(stream); } catch (error) { return res.status(409).json({ error: `Could not bind port ${stream.port}: ${error.message}` }); } }
    if (stream.healthEnabled === false) upstreamHealth.set(stream.id, { status: "unmonitored", checkedAt: null, history: [] });
    else { upstreamHealth.set(stream.id, { status: "pending", checkedAt: null, history: [] }); checkStream(stream).catch(error => console.warn("Streaming host health check failed:", error.message)); }
    await saveStreams();
    recordActivity(`Streaming host “${stream.name}” updated.`);
    res.json(publicStream(stream));
  } catch (error) { next(error); }
});
app.post("/api/streams/:id/toggle", async (req, res, next) => {
  try {
    const stream = streams.find(item => item.id === req.params.id); if (!stream) return res.status(404).json({ error: "Streaming host not found." });
    stream.enabled = !stream.enabled;
    try { await restartStream(stream); } catch (error) { stream.enabled = !stream.enabled; return res.status(409).json({ error: `Could not bind port ${stream.port}: ${error.message}` }); }
    if (stream.enabled === false) upstreamHealth.set(stream.id, { status: "unmonitored", checkedAt: null, history: [] });
    await saveStreams();
    recordActivity(`Streaming host “${stream.name}” ${stream.enabled ? "enabled" : "disabled"}.`);
    res.json(publicStream(stream));
  } catch (error) { next(error); }
});
app.delete("/api/streams/:id", async (req, res, next) => {
  try {
    const index = streams.findIndex(item => item.id === req.params.id); if (index < 0) return res.status(404).json({ error: "Streaming host not found." });
    const [item] = streams.splice(index, 1);
    await stopStream(item.id); upstreamHealth.delete(item.id);
    await saveStreams();
    recordActivity(`Streaming host “${item.name}” deleted.`);
    res.status(204).end();
  } catch (error) { next(error); }
});

app.patch("/api/settings", async (req, res, next) => {
  try {
    if (req.body.defaultSite) {
      const value = req.body.defaultSite; const mode = ["welcome","themed404","abort","redirect","custom"].includes(value.mode) ? value.mode : "themed404";
      settings.defaultSite = { mode, redirectUrl: String(value.redirectUrl || "").trim(), redirectCode: [301,302,307,308].includes(Number(value.redirectCode)) ? Number(value.redirectCode) : 302, preservePath: value.preservePath !== false, title: String(value.title || "").slice(0, 100), message: String(value.message || "").slice(0, 500), customHtml: String(value.customHtml || "").slice(0, 250000) };
    }
    if (req.body.backups) settings.backups = { ...settings.backups, ...req.body.backups, hour: Math.min(Math.max(Number(req.body.backups.hour) || 0, 0), 23), retention: Math.min(Math.max(Number(req.body.backups.retention) || 7, 1), 100) };
    if (req.body.certificateHealth) {
      const warningDays = Math.min(Math.max(Number(req.body.certificateHealth.warningDays) || 30, 8), 120);
      const criticalDays = Math.min(Math.max(Number(req.body.certificateHealth.criticalDays) || 7, 1), warningDays - 1);
      settings.certificateHealth = { warningDays, criticalDays, staleMinutes: Math.min(Math.max(Number(req.body.certificateHealth.staleMinutes) || 10, 2), 1440) };
    }
    if (req.body.logsRetention) {
      const value = req.body.logsRetention;
      const days = key => Math.min(Math.max(Number(value[key]) || 30, 7), 3650);
      settings.logsRetention = { ...settings.logsRetention, accessDays: days("accessDays"), activityDays: days("activityDays"), auditDays: days("auditDays"), certificateDays: days("certificateDays"), securityDays: days("securityDays"), pruningEnabled: value.pruningEnabled === true };
    }
    await syncCaddy(); await saveSettings(); recordActivity("Administration settings updated."); res.json({ ...settings, backupDirectory: backupsDir });
  } catch (error) { next(error); }
});
app.post("/api/logs/prune", async (req, res, next) => { try { if (req.user.role !== "administrator") return res.status(403).json({ error: "Administrator access is required." }); if (!settings.logsRetention?.pruningEnabled) return res.status(409).json({ error: "Automatic pruning is disabled. Enable it and save the retention policy first." }); const mode = req.body?.mode === "scheduled" ? "scheduled" : "manual"; const stamp = new Date().toISOString().replace(/[:.]/g, "-"); const snapshot = path.join(backupsDir, `pre-prune-${stamp}.sqlite`); storage.backupTo(snapshot); const counts = storage.pruneEvents(settings.logsRetention); settings.logsRetention = { ...settings.logsRetention, lastRunAt: new Date().toISOString(), lastRunMode: mode, lastRunCounts: counts, lastRunSnapshot: snapshot }; await saveSettings(); recordActivity(`${mode === "scheduled" ? "Scheduled" : "Manual"} log pruning completed: ${Object.values(counts).reduce((sum, value) => sum + value, 0)} records removed.`); res.json({ counts, snapshot }); } catch (error) { next(error); } });
app.get("/api/logs/prune/preview", (req, res, next) => { try { if (req.user.role !== "administrator") return res.status(403).json({ error: "Administrator access is required." }); res.json({ enabled: settings.logsRetention?.pruningEnabled === true, counts: storage.previewPruneEvents(settings.logsRetention || {}) }); } catch (error) { next(error); } });
app.get("/api/logs/download", async (req, res, next) => { try { if (req.user.role !== "administrator") return res.status(403).json({ error: "Administrator access is required." }); const payload = { product: "Site Gateway", generatedAt: new Date().toISOString(), access: storage.listAccessEvents(500), activity: storage.listActivity(500), audit: storage.listAudit({}) }; res.setHeader("Content-Disposition", `attachment; filename="site-gateway-logs-${new Date().toISOString().slice(0, 10)}.json"`); res.json(payload); } catch (error) { next(error); } });
app.post("/api/settings/reset-defaults", async (req, res, next) => { try { if (req.user.role !== "administrator") return res.status(403).json({ error:"Administrator access is required." }); if (String(req.body.confirmation || "") !== "RESTORE DEFAULT") return res.status(400).json({ error:"Type RESTORE DEFAULT exactly to continue." }); if (String(req.body.username || "").trim().toLowerCase() !== String(req.user.username || "").toLowerCase() || !await passwordMatches(String(req.body.password || ""), req.user.password)) return res.status(401).json({ error:"Administrator credentials were not accepted." }); settings.defaultSite = { mode:"themed404", redirectUrl:"", redirectCode:302, preservePath:true, title:"Route not found", message:"The gateway is responding, but this address has not been configured.", customHtml:"" }; settings.backups = { enabled:false, frequency:"daily", hour:2, retention:7, type:"configuration", includeLogs:false, encrypt:false, lastRunAt:null, lastStatus:null }; settings.certificateHealth = { warningDays:30, criticalDays:7, staleMinutes:10 }; await saveSettings(); recordActivity("Gateway preferences restored to defaults."); res.json({ ...settings, backupDirectory:backupsDir }); } catch (error) { next(error); } });
app.post("/api/factory-reset", async (req, res, next) => { try { if (String(req.body.confirmation || "") !== "FACTORY RESET") return res.status(400).json({ error:"Type FACTORY RESET exactly to continue." }); if (String(req.body.username || "").toLowerCase() !== String(req.user.username || "").toLowerCase() || !await passwordMatches(String(req.body.password || ""), req.user.password)) return res.status(401).json({ error:"Administrator credentials were not accepted." }); await Promise.all([...activeServers.keys()].map(stopSite)); await Promise.all([...activeStreams.keys()].map(stopStream)); storage.close(); for (const directory of [sitesDir, uploadDir, caddyDir, iconsDir, logsDir, backupsDir, defaultSiteDir, certificatesRoot, path.join(dataDir,"database")]) await clearDirectoryContents(directory); storage = await openStorage(dataDir, backupsDir); sites = []; proxies = []; users = []; redirects = []; streams = []; accessLists = []; groups = []; settings = {}; recentActivity.splice(0); await loadSites(); await syncCaddy(); res.setHeader("Set-Cookie", "webserver_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"); res.status(202).json({ ok:true }); } catch (error) { next(error); } });
app.use("/api/backups", (req, res, next) => req.user.role === "administrator" ? next() : res.status(403).json({ error: "Administrator access is required." }));
app.get("/api/backups", async (req, res, next) => { try { res.json(await listBackups()); } catch (error) { next(error); } });
app.post("/api/backups", async (req, res, next) => {
  try { const backup = await createBackup(req.body.type, Boolean(req.body.includeLogs), "site-gateway-backup", String(req.body.password || "")); res.status(201).json(backup); } catch (error) { next(error); }
});
app.post("/api/backups/import", upload.single("backup"), async (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Choose a .sgbackup file." });
    const { zip } = await openBackup(req.file.path, String(req.body.password || "")); const manifest = JSON.parse(zip.readAsText("manifest.json") || "null");
    if (!manifest || manifest.product !== "Site Gateway" || ![1,2].includes(manifest.format)) throw Object.assign(new Error("This is not a supported Site Gateway backup."), { status: 400 });
    const filename = `imported-${new Date().toISOString().replace(/[:.]/g, "-")}.sgbackup`; await fsp.rename(req.file.path, path.join(backupsDir, filename));
    recordActivity(`Backup imported from this computer.`); res.status(201).json({ filename, manifest });
  } catch (error) { if (req.file) await fsp.rm(req.file.path, { force: true }); next(error); }
});
app.get("/api/backups/:filename/download", async (req, res, next) => {
  try { const filename = path.basename(req.params.filename); const file = path.join(backupsDir, filename); await fsp.access(file); res.download(file, filename); } catch (error) { next(Object.assign(new Error("Backup not found."), { status: 404 })); }
});
app.post("/api/backups/:filename/restore", async (req, res, next) => {
  try { res.json({ ok: true, manifest: await restoreBackup(path.basename(req.params.filename), String(req.body.password || "")) }); } catch (error) { next(error); }
});
app.delete("/api/backups/:filename", async (req, res, next) => {
  try { const filename = path.basename(req.params.filename); if (!filename.endsWith(".sgbackup")) return res.status(400).json({ error: "Invalid backup." }); await fsp.rm(path.join(backupsDir, filename)); recordActivity(`Backup ${filename} deleted.`); res.status(204).end(); } catch (error) { next(error); }
});
function humanizeGatewayActivityError(message) { const text = String(message || "Unexpected gateway error"); if (/upstream address scheme is HTTP but transport is configured for HTTP\+TLS/i.test(text)) return "Gateway configuration rejected: HTTP upstream cannot use HTTPS transport. Disable upstream TLS verification or change the upstream URL to HTTPS."; if (/upstream address scheme is HTTPS but transport is configured for plain HTTP/i.test(text)) return "Gateway configuration rejected: HTTPS upstream requires HTTPS transport settings. Change the upstream URL or transport setting."; if (/duplicate.*address|already.*site address/i.test(text)) return "Gateway configuration rejected: This hostname or address is already used by another host. Choose a unique hostname and port."; if (/dial tcp|no such host|lookup .* no such host|upstream.*(invalid|malformed)/i.test(text)) return "Gateway configuration rejected: The upstream address could not be reached or is invalid. Check the hostname, IP address, and port."; if (/invalid hostname|host name.*invalid|malformed.*host/i.test(text)) return "Gateway configuration rejected: The hostname is not valid. Use a valid domain name without a protocol or path."; if (/unrecognized directive|unknown directive|parsing caddyfile tokens/i.test(text)) return "Gateway configuration rejected: The gateway configuration contains an unsupported or malformed directive. Check the selected host settings."; if (/certificate|tls.*(config|handshake)|no certificate/i.test(text)) return "Gateway configuration rejected: The TLS certificate configuration is invalid or unavailable. Check the certificate, key, and HTTPS settings."; return text.replace(/^Gateway configuration was rejected:\s*/i, "Gateway configuration rejected: ").replace(/\s+Details:\s+[\s\S]*$/i, ""); }
const GATEWAY_CONFIG_ROUTE = /^\/api\/(sites|proxies|redirects|streams|access-lists)(\/|$)/i;
app.use((error, req, res, next) => {
  console.error(error);
  const rawMessage = error.message || "Something went wrong.";
  const isConfigRoute = GATEWAY_CONFIG_ROUTE.test(req.path) && ["PATCH", "POST", "DELETE", "PUT"].includes(req.method);
  let logMessage = rawMessage;
  if (isConfigRoute) {
    const humanized = humanizeGatewayActivityError(rawMessage);
    logMessage = /^Gateway configuration rejected:/i.test(humanized) ? humanized : `Gateway configuration rejected: ${humanized}`;
  }
  recordActivity(`${req.method} ${req.path}: ${logMessage}`, "error");
  res.status(error.status || 500).json({ error: rawMessage });
});

app.listen(adminPort, "0.0.0.0", () => {
  console.log(`Site Gateway dashboard listening on port ${adminPort}`);
  if (adminPassword === "change-this-password") console.warn("WARNING: Change ADMIN_PASSWORD before exposing the dashboard.");
});

setTimeout(() => checkAllProxies().catch(error => console.warn("Initial upstream checks failed:", error.message)), 1500).unref();
setInterval(() => checkAllProxies().catch(error => console.warn("Upstream checks failed:", error.message)), 60000).unref();

async function runScheduledBackup() {
  const schedule = settings.backups || {}; if (!schedule.enabled || Number(schedule.hour) !== new Date().getHours()) return;
  const last = schedule.lastRunAt ? new Date(schedule.lastRunAt) : null; const elapsed = last ? Date.now() - last.getTime() : Infinity;
  const due = schedule.frequency === "monthly" ? elapsed >= 27 * 86400000 : schedule.frequency === "weekly" ? elapsed >= 6 * 86400000 : elapsed >= 20 * 3600000;
  if (!due) return;
  try {
    if (schedule.encrypt && !scheduledBackupPassword) throw new Error("BACKUP_PASSWORD is required for encrypted scheduled backups.");
    await createBackup(schedule.type, Boolean(schedule.includeLogs), "scheduled", schedule.encrypt ? scheduledBackupPassword : "");
    schedule.lastRunAt = new Date().toISOString(); schedule.lastStatus = "ok";
    const backups = (await listBackups()).filter(item => item.filename.startsWith("scheduled-"));
    for (const item of backups.slice(Math.max(Number(schedule.retention) || 7, 1))) await fsp.rm(path.join(backupsDir, item.filename), { force: true });
  } catch (error) { schedule.lastRunAt = new Date().toISOString(); schedule.lastStatus = `error: ${error.message}`; recordActivity(`Scheduled backup failed: ${error.message}`, "error"); }
  await saveSettings();
}
setTimeout(() => runScheduledBackup().catch(error => console.warn("Scheduled backup check failed:", error.message)), 5000).unref();
setInterval(() => runScheduledBackup().catch(error => console.warn("Scheduled backup check failed:", error.message)), 15 * 60000).unref();
async function runScheduledPruning() { if (!settings.logsRetention?.pruningEnabled || !storage?.pruneEvents) return; try { const stamp = new Date().toISOString().replace(/[:.]/g, "-"); const snapshot = path.join(backupsDir, `pre-prune-${stamp}.sqlite`); storage.backupTo(snapshot); const counts = storage.pruneEvents(settings.logsRetention); settings.logsRetention = { ...settings.logsRetention, lastRunAt: new Date().toISOString(), lastRunMode: "scheduled", lastRunCounts: counts, lastRunSnapshot: snapshot }; await saveSettings(); recordActivity(`Scheduled log pruning completed: ${Object.values(counts).reduce((sum, value) => sum + value, 0)} records removed.`); } catch (error) { recordActivity(`Scheduled log pruning failed: ${error.message}`, "error"); } }
setInterval(() => runScheduledPruning(), 15 * 60000).unref();
setTimeout(() => importAccessLogsToSqlite(), 8000).unref();
setInterval(() => importAccessLogsToSqlite(), 30000).unref();

async function checkPublicIp() {
  try {
    const response = await fetch("https://api.ipify.org?format=json", { signal: AbortSignal.timeout(6000), headers: { "user-agent": "Site-Gateway-DDNS-Check/1.0" } });
    if (!response.ok) throw new Error(`IP lookup returned HTTP ${response.status}.`);
    const body = await response.json();
    const address = String(body.ip || "").trim();
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(address) && !address.includes(":")) throw new Error("IP lookup returned an unexpected value.");
    const changed = publicIpState.address && publicIpState.address !== address;
    publicIpState = { address, checkedAt: new Date().toISOString(), error: null };
    if (changed) recordActivity(`Public IP address changed to ${address}.`);
  } catch (error) { publicIpState = { ...publicIpState, checkedAt: new Date().toISOString(), error: error.message }; }
}
setTimeout(() => checkPublicIp(), 4000).unref();
setInterval(() => checkPublicIp(), 60 * 60000).unref();

async function shutdown() {
  await Promise.all([...activeServers.keys()].map(stopSite));
  await Promise.all([...activeStreams.keys()].map(stopStream));
  try { storage?.close(); } catch { /* Database may already be closed during restore. */ }
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
