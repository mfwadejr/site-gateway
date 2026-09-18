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


// --- Small utility helpers (activity log, dir sizing, env parsing, passwords) -----------
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


// --- Sessions & auth cookies --------------------------------------------------------------
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


// --- Data loading (hosted sites) and shared validation helpers -----------------------------
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
    backups: { enabled: false, frequency: "daily", hour: 2, retention: 7, type: "complete", includeLogs: false, encrypt: false, lastRunAt: null, lastStatus: null },
    certificateHealth: { warningDays: 30, criticalDays: 7, staleMinutes: 10 },
    logsRetention: { accessDays: 30, activityDays: 90, auditDays: 365, certificateDays: 365, securityDays: 365, pruningEnabled: false }
  };
  const storedSettings = storage.loadSettings() || defaultSettings;
  settings = { ...defaultSettings, ...storedSettings, defaultSite: { ...defaultSettings.defaultSite, ...(storedSettings.defaultSite || {}) }, backups: { ...defaultSettings.backups, ...(storedSettings.backups || {}) }, certificateHealth: { ...defaultSettings.certificateHealth, ...(storedSettings.certificateHealth || {}) }, logsRetention: { ...defaultSettings.logsRetention, ...(storedSettings.logsRetention || {}) } };
  await saveSettings();
}


// --- Domain / target / stream-port validation -----------------------------------------------
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


// --- Header / location / custom-config sanitizing for Proxy & Hosted advanced options -------
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


// --- Caddyfile generation: turns hosted sites/proxies/redirects/streams/access lists
//     into the actual Caddy configuration and reloads Caddy with it -------------------------
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


// Writes the themed default ("no route configured") static HTML page to disk. Keep
// this HTML in sync with the client-side preview in features.js's
// defaultSiteThemedHtml() -- see the comment there.
async function writeDefaultSitePage() {
  const selected = settings.defaultSite || {};
  const title = String(selected.title || (selected.mode === "welcome" ? "Gateway ready" : "Route not found")).replace(/[<>]/g, "");
  const message = String(selected.message || "The gateway is responding, but this address has not been configured.").replace(/[<>]/g, "");
  const html = selected.mode === "custom" && selected.customHtml
    ? String(selected.customHtml)
    : `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>${title}</title><style>:root{color-scheme:dark;--bg:#08101d;--card:#101a2b;--line:#25344c;--text:#eef4ff;--muted:#95a4ba;--green:#62e6a7}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle 260px at 50% 0,#163829 0,transparent 100%),var(--bg);color:var(--text);font-family:Inter,system-ui,sans-serif}.card{width:min(620px,100%);padding:44px;border:1px solid var(--line);border-radius:22px;background:color-mix(in srgb,var(--card) 94%,transparent);box-shadow:0 28px 80px #0006;text-align:center}.mark-stack{display:flex;flex-direction:column;align-items:center;gap:16px;margin-bottom:40px}.mark-icon{width:88px;height:88px;object-fit:contain;display:block;margin:0 auto}.mark-wordmark{width:290px;max-width:100%;height:auto;object-fit:contain;display:block;margin-top:0}h1{margin:0;font-size:clamp(34px,7vw,56px);letter-spacing:-.05em;line-height:1.02}p{color:var(--muted);font-size:17px;line-height:1.65;margin:20px 0 0}.foot{padding-top:28px;margin-top:30px;border-top:1px solid var(--line);font-size:13px;color:var(--muted)}</style></head><body><main class="card"><div class="mark-stack"><img class="mark-icon" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAABccqhmAAB+RUlEQVR42u29d5xlV3EtvKr2Pjd198xolBMiimAyxhgbm/RwwjY2Bj9scOB9BhOMCcbY5ByMsQ0GY4KNMTmaDBIgJESSCBLKAUlII81oRpNnOtxwzq7vj51qn27Zz36gEdOn5nd/03379u3ue0/Vrlq1ahXQWWedddZZZ5111llnnXXWWWedddZZZ5111llnnXXWWWedddZZZ5111llnnXXWWWedddZZZ5111llnnXXWWWedddZZZ5111llnnXXWWWedddZZZ5111llnnXXWWWedddZZZ5111llnnXXWWWedddZZZ5111llnnXXWWWedddZZZ5111llnnXXWWWedddZZZ5111llnnXXWWWedddZZZ5111llnnXXWWWedddZZZ5111llnnXXWWWedddZZZ5111llnnXXWWWfrx6h7CdbJG01U3ABARIqvRxOR4tZZFwA6+0l0eGYwEZqm+R87MhHBGAPnXBcQugDQ2a3d2BgQgKZpivsXNm2kU2572+Htbn+7zbe57W1POvqYY47euGHDpqpfDeHQ1NPp5MDi4uK2bVu3brl2y9ZtN9yw/9prr13Zt3uP089jjIGIwDnXvdhdAOjs1nLaM3Ph9IPREPe+z302PvThD7/fzz7o53791Dvf5SHHHX/cvYbVgOObLup/CjcJt6mbYfuN2y+95IILPnP2WV/95FfPPOviCy+4YLGZzW72Z3bWBYDObmEzxhRO+MAH/fymxzzudx/5v37pl590yh3v8OABWawAWMYYK5PJtHFN3Yg4B0mODxBAAoi/xxKzZWOHvX5vjgboA1huJrjqiitO+/JpX/zXj3/0o18875xvH7i536GzLgB0dguk+i44XX8wwKMe/du3+z9PftJzf/bBv/A0C4sDmOLAZHk6dfXUQdiRWEeChsBOBI4ELtXzlDIAAGAhGCJYkGOHmoVc3/YGG3rzdgEG42aKs790xuv/+S1v/ocvfe4L2xPmQNSVBl0A6OzHne4nRyPg957whDs+83l/+ca73f2ejxxDsHu6bzqpZ1PHZGcstoZDLQ0aCBo4+JNf4CBwcAAoZAIhCAjAIBhiGPhbBYIFwwrX3GA6NFVv82DToAJwzje//q43vv5vX3zapz69LWYDETDsrAsAnf0o031r0dQ1AOChv/yIo1/44he9+v4//4tP2o8x9iwfWJyR2MaIrcVhSg61ODRwmKFGA4EDvPNLDgAuZQA+AHD4zIBgwLDEqMCwQjBk0COLvrBjx3WPDR/Z3zjog3H65z/z2le96MWvvuT8C5a6sqALAJ39SNN9hmu8q55w8on2xa9+9Z8+9g8e/5YpCDtWdi1PqeEJiZ3BoUaDGg4zNPCf+1s6+YPzC4CMA3jXJ4gPAAIwERgMA0JFBhYEC4MKBj0ysDDowaByVPdgcMxg82C2fPDA2974j7/3d69+zRcmyyvSZQNdAOjs/zHdT0g7AU/+s6fd+7kveMEHjzjuxLvcsLJzeYyap0bsVOrg8P42lQZ1yABqSJH2S8wExEEIEHhHp9ADIALYAUQ+MHDIBFgYFbMPALCoyKAnBhUZ9GFhaoxHtuqd2Duid/H3z/+Pl73g+U878wun7+iygS4AdPY/SfeV0/zMz//cxpe8+lWv+YUHP/RpN8oi9qwcWGxYeivU8AQ1puHEr1FjBoeZNGgQnD8AfhLT/9D8c+KDAZFP+pkI3DqoWUIQEgKTLwcsfBCw8I7fp5AJ+MDguMb0mNER80MQ3vu2t//R61/68vftuWmnY2b/O3QgYRcAOvtP0n3mxLjbfPRR/Bd//VeP+uM/e+pHpr2+3bp802LN0ptSwxOpMSHv8NNw8tfB8f3Nn/ROxJ/0MRCE3p+IQPcAiChdDAQAQmD1OYNhyICBFAQqCtkADCpi9FBhAAN2qHuocPLgqMEN1179nde94IX/+1Mf/PAPU2BzTSYhdNYFgM5WE2t+9w+fcKe/fsXL3n/iKXe4/w3jneMDbuJq43pj1FiRGSZoUKNBE1L9ePI7+NQ+1vflTcLJH01C+89nAcHzEzeAQIAgBAL/uSHAwiSA0ISPfQbAPisIZQI3NN482jB/JObwxc9+4lWvfM5fvvK6H1w9jYGuaxneCjLN7iW4daT7ESy7013v3H/ru//1pc943vM/Nt5YnXjD0q4DKzyrlk1tlzDDssywghnGMsOEakzR+BJAmgT4Nf4A9xkAACeAhNPfQdCEzADUYgBQ4AIBEPLO78FCagUVgZB/nphtNKHjUJNgKv5/MmTHs+l072x5eo+fut/DH/P7v/eH0+n06xd877vbXONgTHf5dRnAOj/1Y0+/6vfwFy954a8++elPf7fduPGYG5ZvWpxSY8fcWO/wNSZoUrrfSBMQ/9Wovvgnz9Te4OzeuSUFhlD9p1S/9cuBQBDxDs+6XEAGCH1p4LsFhhhGOGUEQ6rQh0GfKnCD6Ybe3OhYswkXfudbH3jFs57ztO9/85z9HUjYZQDr/tR/8C8/4ui3vf89//Ko//341223K8Pt470rE276izTlRUywhBnGqDFGjYT4S4OaxJ/4ImhIpfYUHJfiaZ6dH/ANv+zMlIIFiJSbI7YCfCYQvuRCkSAxcaAMLkayURPwhppCaQIHMMysqes908WVk297x/v9zu///p8NBoPvXfDd714zHU98NkDosIEuAzj8Qb5Y+x534gnmRa979VMf9YTff/N+1Ni5vHexMU1vjJqXZYYJaoxl5kk9Mb2XJpB44kmeW3ukTmjRaT0ASmBgdnFOdX8eD2pATMRgEYQqogAM81XjkQMO4UQSWEiBSmxhQb5jQAZ9suiLRQ8VrON6zvbt8dWR9vrLL/7S6573/D8+8zOf3dZlA10GcFin+/HUBwFPfPpT7/3mf3/3afd60IOeuGVl53hPvVhPjestyZQWaYolzLCCGhPUmFI48cWhIe34oR4HSqcvPHWNe1WPP36cWwJMERBkQCgGCWqXB3p6MOALFPEBSkGpURyEJgQxMLgW5/ZNF1c2HX/CXR/9e7//Fyff5rbbLzrvvAsW9+93ERDtCERdBnDYpPvxVLvvz/7Mhhe/9jWvecBDHvb0G2Uf9iwfXKytDLyzzzCRkOqHNL+hxqfUoYPvwkktwbVJNfNyFiDq6C/f7nzWS6j+9XAwwRGYwKH/Ly4VDuJ/vuiMITy/E8nVg8TAQgWRyIY2YmwfVqjQh4V1XPdR4fjBsYNd27Ze/raXvPQxn/rXf70kvW7O5bSlsy4D+ImKrkGRxzmH+U0b6XkvffGvv/ptb/72EXe8/c/9cHn74qIbY5nraglTLGOG5fD/BL7Or8mf+tH5E4tPl8oSS3dKtX07VW+Ddxr5J6Jc6wMwBGEiAYhYSBCyhNgx0NJh3vnL3yc0DwLLMJYOOWtpSFDD4wMOQEPgGuA904PL1eaNJzzyNx/ztHvf9750+YUXnbP7ph11LJu6bKDLAH6iXlXD+dT/9d/9nds+9xUvfdcpd777Q6+bbq+Xmum04aaX0H2pMSOP8Ecyj0+fXWLuZVfKpz3HAJBS+TLNF6HWG01lyR/uE2ImEUeSH+MZgoo4FHuCFJiEIc/w3IKcDjBCC7E4YWI2wAl9MMTowfp/ZFGhQs8ZNxRTnzQ8ZuQO7Nv1zte/8X+/5/V/85VmNummDLsM4CcH5ItMvpNud0r1hre/9TnPetnLPjc9anS765Z3LI5palcwM4sYYxm+pz8hX+vHXn6c1Gtizz74rK/78/ntJH9MUMKfrdhenPj6Jv7xnMNIep54pOfAktKA/JwhOMQMhIosIbchIQQhgnPAzDlMRSCBK+A7GR4r8L8SmZ0rB5eXemb+fr/0a0+8zy8++JTrL7n0KzfdcL0nEAVJss66DOBWB/IlJp8hPPEZT7//M174gg8vHHX07a5d2b48wYwn3NglmWIiM0xRY0oucfZrNEGgw5NsaqHizI9Ox+kUzj0+73iSXJjSyZ77d4QyG6DQyhMiZhFHGTnwXw3ZQDzxi7Zi/J0S8Oe/ntWGM0LofHoAW1mwtf70hwWDMYVDUzv0YDHPPfSZYVD5YWQhVzcyXehtnp9fmY2/+o5/f9I7XvXKD+7bdWPTzRV0AeBWC/Ld5wE/s/CC17/m9ff9xYc+5cZmL/ZOFpcb2/TGMsNybOtJDf/PoQkgmoPv6afSPjHxJDkTQ/HzRdX4kk/qVXW6pvcVuQH5PJ8IJAHhI1VSpJ8bnDqc/r4lGBoFYaAIRHBqksA1/u+pKsbA9mFgsbw0xvVX7ceOK/djz7VL2LttGQd2jjFdIZCZgx0uoBoOMViwOPKEBRx1yibc5vYLOPXkXn3ikUN7Ii/Yq2/c8v2/f+YLHnPOR99/dcwG/Jh0lxF0AeAQgXwEeJBvwwZ61ste+Du/99Qn//t0UI1uXN69POParlDNK6gxRY2JzMLQjp/bb1J7LAJmsuZbEg/9mN5zdHgpATmkx+RSQIojWT27AMLMijUQ2cEqi8i1vajvlvaVE/CGxgkaEfSHFSoMsH/fGFd9YzsuP/1abPneVuzZsggsA2ALsAFsH6hGgB0CpgdwDyALoAcMNgIbj8GmE0/AKacu4MQ71eNTHzCYv/MdB7jhU59+2b89969ft+2qyyf+fTAQ13EHugBwS5761qCp/UX3K49+1MnPedXL/+Wku97tl26Y3lQvNdPpTIF8Y3jH9/9c4M1L6JFrtDx37nNzzp/grBJ5JkopfyTspxEeJhCYWeAo9ONT/q6yBABwHukDibgEDgqXgGLE/lSJEPv86cQPqf5g2INBD9dcvBPnfehKXPzFq3Dwmv3ADEDfggZ9UK8PMj0IVYDpQagHMj2ADGAsiPs+MPTmAbsBDTYBdjPQnwM2cn3KXZz7zd+YH91l856tp7/5db/zuTe96dxmNvXZQNcy7ALAjx3kU+o8J55ym+qFr3/Nsx7+u495/U1Ywq7lfYszP7HHnrs/88M6UqcxXaf0+GLtnD0/03KLFD98bgqqbqzDW9t9iGCEs9BvqtopdwskBgCEAACXaMJEKZNYy5cidVjCnEDtHGyPMTIjXH/pPnz5refhwk9fBtk7BUZD8KACYs1OFcADEFcAW4jpMbjvQBYw1mcAXAF2BFRDwPZBNAAN50Gjo0D9OdgBwW6qp8ffqT/62QcYHLH7ex/80iv/6hmXnX3G7lwWdNlAFwB+nCAfAX/0tKfc609f9PwPjY475i5blrcvLqO2tYmDOw1mobVXS+1BPsmyXH4yrzWPr87+lManIzgIdoTHOMlJuShMgCkGEFbZgazi+KefRsQOAAU0rWwnhp/Q4gD7r7MnJwkwN5jDrp0TnPnGc3Hu+y9Ds2cFWOiBqwoCC5HA8ScLmD6IewAbFtMDTB9ALAd6APcBM3QwA8BWAFX+vt4A6G0ADTbAzPfQ2wSYBXHcb6a3v9to/r53dNj+mbc+7qtveOlHFvfuEWIOf3oHEnYB4EcM8t3v5x+48Tmvetnr7vmQhzzlRrcXe1YOLk5N3ZtQzdMgxzULLb146tdKiyf2zLVfGTWPF3vwVFTcXqSTROMCUjxLnurjVeIeotj6uiHowUJJjh7Bw3JxiGb6h8yhAWzPYGCGOOczW/CZl52Bxcu2A5sWwFXP/41kvAOTBciA2EJMP5z+FYvtO+JQChAxmR7EDgAeOLAFTA9EFYR7QDUAVUNIbwE0GIAGgNkomDuaMJh39fAI5jvdrdfbtPfKMy59y8v+5OJPffDaLhvoAsCPAOTzZ6VzDvMbN9CfPf95j3zcs5/+8aWe6W1b3rk85dqOqeGxTBN7rwnCnI1oGW54ao+oAzWk/L6m5+RxqZ+f3C+f5xnU8+ezFNAcA5TPd8bqSQAu0cLQy/fc/TILyVTjEukDaicYDUc4sKfBp1/9TZz/bxf5Q3xk4RoJJ3oVgL4I6sX6vgcx8aTv+8eRBUzlH2vi94XnoL4HB20fZIdAbwSpeqA+gAHBbgJGRwEbjyAMN9TjzScM5085Flg848PP/ubrnv9Pe7b8cBbLoq5l2AWA/9arYowC+R776FOe9YqXvPPEu9ztEddOt9eL9cp0apreclDmmaL20tuSB168BFdm7et6WnzrLUzjlZh7POUZAlDk5KM40Sm6v0h5ysf6PWj8kTrFCwKQ4gUKMnPPBw4p8P+oLdDUAjaEud4Czj9rC/7jeV/EgctuAh+xEWAbSEkMIROct+dP/ZABIIB+MMH5Taj3qfL1v7Eh5Y9ZQ+XBQNP3gcF6TADWAD0C+gCNCNUGYHgEYW4jML+xqftzcCfcZjA6arbzB5e9+eWPPe/db70AELCxcK7pQMIuAPwXIJ8a1z3+5JPsX7zu5U//5d9//Bu34yD2LO9bnHLTG2PGXpHHi3IkOW4R6H+pQ60cVc+8M5XsfGlRaqHaeVGuO2YHImV5Hj82KZuIKr86wMTuAYr7RLH7SHJ2EH/rWd2gP+phOiGc9obz8fU3fQtoHHh+AOc4oPrhpI9OTf4kJ6ogqgSA6YFMH8KVygpy0PAZQ+UxANPLN9v3OIEhoAJQEWhAoAHAc0BvARgsCDZuBkbDZjq3uT865QRG860vveGbr37ui7dfduHYZ3Vdy7ALAP8FyMfW4A/+7Kk//cd//ez3V8cec+rW5Z3LE8y45sauYBqm9XzK7yCYab39sGMvc+cLCr2qsyWw+JSDSpbmJlDR148pPKs03SHTdqV1spOu6xVHQESzBuOPZZCIEgXJjD4ngvnBHH5wxS587FlnYvvZ14E2zwFkvE4QGYANiAce2Y8lQAgAPhhUIGNT6y9nAMbfz1UOALEMMOE+E+4zPX/62/BCVAT0APRCpTAAqgVguIEwtwGYn3euP2ymxx4/mj/aLe669r1v/L1z3/r6M2ZLB6VrGXYB4GZBvnve/37zz/37v/n7uz3oQU+6od7l9k2WlsXKYEVmnsIbdfjS0E5I9UWDcup41id+cDAigFxszWtKLykcQJUE4VQ3KgCoyFV+WuQU4R4qfx+S1Zz/HJz8rWkEvb6B5R6+/J6LcdrLvopmzxS8cQjnOKTrIb3nKqD7VQD1ArLPvrYnrnyGEHEB01NOngMGmR5ge5CIA6ggQMZCjIcYYCklCv5zHzt4SNyfA/rz4nojYH5B3HDYTPvDanCH21Z2+MNLT/vqi575hB9+/ctdy7ALACWTb25hgZ76kr9+1KOe/ifvHQ+r+W3LuxZrauyMGjsJJ/40KPFOkcd0Y49dkDlzogG9cD8rJ6NV9Fwp03Q/ylcM52QNPko/E4mAq4OCmuZTo8JQnIAo860vA0o8f0/lHQ372LO7wX+84Cu49P0XAnMD0KCCNJwc29fqypkpAoAViMLJbkLqTt57yVQ55eeeD2vx+2w87QMuwCobMAwY8c5uQxkQA0JsOPQIZiSwA4LpC3o9caMFYH4BbjBopsceN9pw0mA2vfb9//z4b7zh5R9f2b9HiI3P2NZpy3DdBgC9Z+9XHv2ok/7slS9951F3u8uvXDvZPl1upvXUNL0JZpiKB/lirR/Vb5tWGy437aRE9KEm6oRAJJ6I0z7IUfbqJSH5mbzDYdpPCvKP5+S7OJmHkgrsM4jypC/IRgkHEDQOYDYY9YY478wt+ORzz8DilTvBm+ZCqDHJwZPzR+DOREBPf90GIK+X2oEwHAg/vVQepGwhOr9VAcAYgMnX/gY+CFSUmguw5LnRsdoYUHh6ga3gen1gOA8sLAjmhq4eLjCffHx/MHfD1V8/97UvfPzFn/rwFp8NWLimXn9+sO5APhPGdZ3DSbe/bfXSt77p2X/6ypeetnT08I7XLe04sEK1HXNtl2Xq5bdRYyJh8YZauhFBuJKOT6uiqw4CeqSW9LgtRZouZ4EO5G8kPYarxDlJYQpxIKdAASjBCnlIKDl/nuUVIsxqh/6wwswxPvOG7+Bzf3EWpnvH4I3zcI6Ck0bH7Svn7YWefS/z+ePpbmMJ0MuYQGz5xcDBFrCDUOPHABAzAusd3JJPIAxSICBOoIi/jwGw+MfF1874aqepRWoAYtgKgMXF6ZJsPvZOP/U7j3n28Xc4dfeOiy44f7xvtyOmkDmtH2xg3WQAGuQjJjzhz55y3z9+0XP/o3/00adct7JjeYyaZ+SZfBNkCe5E4ZWc8CtgX4/Ilym9lFJ6lNLsiOqLctWS9gNFA9anOCvEX/f6CSikvnNLjxIGEGf/22+8OE9OGg3ncNWlN+FTf3kmbjxzK+jIkXd6CStDQ61OFBF/Dg7fT6c/sQ31e6V6/uGxbFR20Mv9f9Pq/xuT24KGU4oPDk5v8uf6a7Ec8BCEDxjcFx9r/NyR688Rj4aC+RHcqO/q0UBw4nHD0dy+XVef//oXPep773n7JQkbWCcg4brIANgYSFCTuccDfnrhb97/rjc96ilPfueOwWTT1vHO5Ympe8uY8lI49VeiOk/Q329I1HptrazbCqGrRDR0Wg4YIpYMwQWCT6m46bfvEAMkXLQOaY1wTQVbkNowIGVUXwcfEUFDQF0L+j2Lud4cznjvZfjwn3wWB6/YDT5qwffzoUA67gE8yOk89zOin9D7ePr3c+rPJqTxMXsI/xujUv5eLgFSEGB/+msHLwKBQDhomFr4MsGqJkakRYS/2zHICaF2hLoBOSESZl46OFma9OePvdtv/+bT73iP+2HXZRedu7jTS5FFfKDLAH6CT/24eGMwGuJJL/qrX3vsc57+ieU+925c3rVYc9ObouZxPPXFb9mp1eCOluJyQIti23oBpUz7odp57NdqsVq44fS5n6ftCAzioLWRAT9N6U/Ifi46WGsFxVajkKom8mMbEYxdg8Gwj6XdDT7/kvNw8fsuBg0B6hs4CSd2JPNA1/WxZ29A3IeYUOuzIv5wBbIVhDnQeUMQgXqcCVmF6QFVL7cTjYVwcPwqBLAiAEjABELKXwV8gAQxMYEJ3CNLICsgEoceMfcIxgpsjzDsA8MRMDcEhj1XD2xTn3TCaP6E+uBN3/+nv3vcWW/6mzOb6fiwzwYO2wCgx3V/4Vd/6dhnvPblbzvpXvf4ravHN06X3bSeGdcbywxTzMJqrUDmUQCf+y9euFRG6wAQMKkyhQ8IfpLiJ7gwgZeCgJ7lhybiSOuELzWCsnP7kWFStOLie8gj/+IaGLawPYvzztyCLzz3LBy8fD/4qI1hws/XwZKovD3VzzcqAFQt6m5PObsFGeM/jrW/ziZMbBPagPzHzw3IMMQSYLxDS0ynknMHBWJLkRTEBDghAVUxQyDACsgQyEjEA9Ln3CNUfUGvD/T7wNyAMD8QjKpmvGHBjk49seLlb3/vg6e/+LlPv+6cs/YC8H/PYdgyPOwCgNbkO+Loo/hZf/PKP3nEEx//9h1Yws7FPQdq4wYTrnlFwqhukN/26b0rU/01XihqBYCUnUvW2y8GbsLjLfyET/weVwhwBKYf5UWdmhMgJJ434I/1Yn1ngS8IyjVfIQeOf0/dNBiNRuiB8NnXXeK+/vqv1pAx84aN1okBuB9OfAaRZeGey4QeCyITRnrjzfi2HunWX0z5q/R9/uTXzq/r/XAfmQDwhVv8VgJEZwB+56BfWtAD+3kNODEBAIzZQOgugimpKhET2PisgXsCG3DHwYAw7Avm+oSFkbiBqcfHHT3acKx1uPTdb3/CV171/A/MlvYflgSiwycAEMGo7bqP+qMnnPrHL//rDwxPOfF+1y/vWPYLNpyd0pSnaDBBE/j7LqnwRt0MaeX2aaJWnfjlzH74FcIpzm3pLX9dsnbaxjknqmJn1QUgXU5oaTDkDoBO60kLcKqvSXguF5R6quECbrzyGnzp1W+vr/vqysD2H4JmWkNmB5Zh+j0/rtsPJ7dp3TRpp8oneEL0PTTvT/7Q/w+5OHHPBwa2ALPq7yvQj6LjU3b28GtEhF+YMvofW4IRAwD5mSoLRyyA8Y+V+GKG7yWWMGpAMJX4JKQi9HvAsA+MesCGITDsN/VoQDj52P5ALr/si195yXP/4AdnfP6mBBIeJtnAYQECsmGI86f+He9218Er3vXPL33s85790V0b3QnXL+1cHHNTrfDULtOMVhTCX0tcrgk0EpD0tO/uvwiT6jHxmtSz/Bmnz9WAdlQnWVkrUnBToi/wfAG/cJMl7vdkAkW97qKupxKIpDjg40k9PVthQ38jzv3MGfiPP335eM/l149Gmyc7ZPcFD3VyzG6M7vgwoK5BVQMzZA/Y9Yv0PnL4/ccKGDR9gC3DGAFbP+5reoH+GzIDk52dYgZgbAn4Gd3rR2r1CccTn1Jtn9B/8oQgYvgQSuFFNiQRLCQK1OoIHsZ0iyPdOexRFKBxQC2CqQNcw0xCvH9xumyPO/6uP/17j//LY297h13Xnfut70U6cZcB3BoiWKDxmp7Fk57/lw//3Wc/4wMrGwfH3LC8Y7mhxq5QzcuYYiXN6EtQ44trsrMklz6RW/sv2sV30eePAUBP9q3mBEh5f4vME13aYwVcBIaQbTAIaLw6+CoZTG41HX3KX6M/WkC9NMGX3/Le+jvv+wIP+8MeFpffOb3+xmc24+UVEIGOfOQjsPnXvyioATdZhhn1QMZjAUGqK/XTIhaQqL6G/f3sUooPq1qC+eYBPg6lRMwICLCx3ZdRfzLw1N8I9jESJwDU6gRE4IN9giEWLgUA40uo9DqbFK0BJp+4WIGxBGMExnhMclgR5vuCTXOE4aCp+1bcSccNR+aHV3/9Ky989mMvP/0z2w+HbOAnNgAQc5rxvvcvPHDTc/7+tW+9zU/f//eume6oD86Wpy4w+caYYUX19J1ImrrzirxO+TYX5Bpao7UnawQBf6Dkqb2Ugsf6n4idiCtbdaJkvUIfgCgo+3A5tusBPBa4AB6qcWCilhqwn2YUAIPBRlx98aXutBf+43TnJdfMj44/2uGmfb82/uH1p7umDkes//tp/m5H4YQnfUh6xz0czd4DoMGATI+FPH0XMBA2oc6PJQIDZDik9S5Re1mBfOFj7/xBF4AMJB7JMYWPNbsh7/gsifjjMwD/uVgCp5RLlQUCjlkDWbionEppjFI5vnqjIreAYlPCEqwRVJUvCeYDSDgciutjNj5y89yGY0fAlo/+259+6eUv/tfFHVubn2RsgH6ST30w4ckv/KuHPv6Fz/n8nj4G25Z2HZiaZjDGjCdBkHMW+/lpPRUS2yYv3Grj7Hmmvujvt1qAejEGp2255cY+A2IO6b3EH0lUOH8xhafVf2NrkAKHQMS5oAwUtwPHIoND9tE0Drbfh2GDb77/8/VZf/ee2i2tzFc9+7l6284/rPcd2LNGEeVfGTPPdPKfvwqbfuH5aPaOYQxgB1aEQ4vPgMh4jT8KuTcbBgIYKNb5I9WUVF7iXOuzjbm5d/7U8gsgHlM6+cl4Bw9MQAaJSwBhiM4SdVAMgQgJB4hpE8W2DBVIbQoKqSwwABsKzQhBZYGqIvQrwaBHGFbAgscGpsMKOOWkwYivv/780577zN+48guf2No+lDoM4MfW3rNomgYnn3qH/t9+9P1vesgT//Cfrqx3ut3T/ZOprQdLmNEiphirHXuNIAQAUnP6rWgtOd1OXre6wi55P+oTpnIKT/L4L6WFGRBJE3gFapc39WaecFmGNJJ7BqVaT+4Y1E4wHM5jcc9BfPKlb55++58/NuwNhz0znT5pcvWWv3TL45W1Q34YV5KJYN/XziDIN+moh/0R7EIFzJZhBhYxZTcVQD0GBwSNKoLtR4Tf99mS81etej9kBoZLfn+Y8Iu1FOmPDcW2H4FJYnsPJr7oanehT1IktVTgZy8k/q9pEuljSs+TyRb+NXbO4wONEGYCzBqgdmSEiQ7uHy9h05G3/ZnHPe45g/7c+T88+8wrIA3I/GSRh36iMoAo1vGARzz06Be+++1n4YSj7nbd4tYDUyuDZUx5RaaYaYEO5KUb+g91aKvcFfiZqtVLJZ2be9GISiAwD+gTjJf1ScSf9suf0ncpgcXYGVgtyqnVekP2EoZ45voLuORb38Xpr3zHeP91N873R4MLm607Hj3bsfvq3BaU/4vLQUAb7nMk7viyD2Lh1EfIbPsyUFmw5UQGCh5HMBDLDGP9x2IcFOiHkDH4o1WBfXHBQUL0KTh8SPXj5/HrEQS0kkG8FusvYQW5p+pbqOQDQNh3Hh6LHDw4t3kodQsAZvF6pQaoKp8RDCrBoCduYY6wsXL1qC+4/QnD0c4vf+WNH3/KHz53acfW5idpsOgnIgOIPH7nHB77rKc+4DnvedsVNy24o7ct37Q8q2SwiCktydRv3UGDWarvBU3i8Ps3PO2w13CdQu6llQ3QGqO2RTlASpEXeRceQj0fQea8vYdVsFGU3ULfrzX5o9l8cXAoUlwbBzsaoBbBV972gfpLr/wXuJXJsMf8xskV1zym2Xdw93//BTfAZNsKbvrM+2h4yiJtftgjgUYgXJPpcx4D7sUxYPH9tUpSX9940I+MSWg/Wc5tvcDgi1BCbAFS5flKKSMwqk4PwSOl7XkdUiofKDi2aDpm0FQjVf8nmnTothS8bv+GBgZm7hJEGrhzJI0DHBMbYj6wOFk54h6n/uK9fu03Hrzl62d/ePGmG2s29idixJh+Epw/0nn/9G9f/ujHPPc5H79ivG284sbwU3s1puTFOhqRoMsnaT21E4UAay6dX4Ct+PiSt2hJ3rPnLxCdqqsOgCLfRIVdUvVB5g7koZ50glMW8ySNLgo057cIUpw4f34k2DmHueEG3HjdFnz2ZW8Zb/v6pfPDzQu17Nn3q5Nrt31ZnPu/OPVvFmXNAOFJf/KzuPMrviRs51HvXwTbgYfcKdc/gdqbAD62Xn7LEIgZMOxbeqzR/fAHx4zAZPIPQi8/BYHI92d/Sgvn1D4FgED2SZhOaAFG8I9ITUhyeI85K7DEbAEqS4itREM+obEBKOxXgrkesDAkLIyAnqnHR2wazh853rv1c096wv1+eObnd7C1cHXdBYD/F3IPB+d/2j+85nG/+qynfvCa5a2LU3a9JYx5SeJW3Tpt0vWDLlmIM9b6xs/WJMjLO5txMcCUqbasSa/RE3jx1StIQeEa9RJgefS2yBhEnTKiRUGlqEHKZZ0xWPkQ0DgBWYOBHeL7XzzTfek176pn+1ZGfWu/OL1my/+u9x/c9yO7PIgBaYAN99lA93rHx2TzTz8Ck5uWIeI3fUIAjgQgExzQZGaf9TV2PPmlSOuRT2qSovbPeADyzD/HdEul/oHpR6EsII3NhMdSqYganFzyxwCLD0Au6igmgJBDPGKAybcJOXQK+j1g1COM+oINI8LANNOF+d7o5GE9/vyT/uDOV372I1tu7UHA3KqdP6T9z3jrG574sGc8+b0/WLp+cWaawUGMaUl8i8/P6ksQ64i6fFB0XgHDca6vCZ5Yy+JPVU4kHD1oq1V7hLSk9mpxT+hMnZC1evwIL6Nc3pWGhCRu6WlNFGlprlLDn1A3DnY4h3rc4LS/eef07H/4wMCYXmUnkydNLr/muc3yykqBHv4/m8SSYIKtH3o/+pt34NgH/1ZILSYwfZNpvrHet4rcg5TqS4gLEmGE2LZLpzoy2SfW/Tak/lSm8nHkgRC/nh2ddIqmTn/fMsxZQwi+rPgbFJAXAomQqCGsQlYtpBESh8QIjQOI2YhrpivC9n6Pfcyz911z7Qd3XXL+Hrb2VtsduNVmALHV9+S/f+XvPvLZz/zwZUs/PNBYGS3KGGPxCL8f4vFpf5DITFtt89iuqFNfp9JI/yfyjKCYnlt77AZFGaDpwazjQqj3DSFwAPTqbQoiPQKR3G6Mvy+1W4JEcM5rBI0GG3HdZZe70172T9OdF189P9iw4bpm645HzLbe9IP/O6Dvf0y8SCUBTn78XXG/fzwL/c3HYHlpEdYMEnlH1eY+3S9reWFN71UvJofXTaf7BD/UUzx3GPahsEo1BAaJ96uRTFKtP8nBgWMASSvNKfViE0hILA6rAoovKTi0DK1FaBf6VuHIAvNDYH7g6lGf+OSNtnf6k/7gDj/49AeuubUCg7fKABAn+X7taU+89//5p384/6qlLQdqI4ODNOYVmWAmDSZSSnHHFVqpx07l3H5B0A21v78CBCy5tUaEVch/6tpJJvzQGi8grVEepKAk7c5C2XZa662R0N93tYPpV+iZAb73kdPqs/7xfdaNaztgetv4yi3Pbg4ujW+xy4XIB4INPzVHD/zXd+P4BzxGlsdjIgdhawuyTey7RzafQSbuWBUxoQJH4OrHTEDI1+mxxody2KKtx0r5TNX46Vfm9EM4Zh1tL0iBmwgw4ij+/qJ4BIj0B4I1kd4g6FXAoCKMeoKFIWGuauq5AePEOcGnH//bp9xw9hduujVOFN7qAkBcvnnPh//CUX/1uQ9fv8Xtc1NM7DJNeRkTTKTGTAS1KGbfKsBsdUsvAcDESivHpVKx7Pur6fxWIIG+btvjwMg+XWYS+mDyxw8VNX97kVdWCXBOMBxuwP7du3HG6/51fNVp35rvzQ+Wadf+35hed+NXpHE/vlP/Zq8aC0gN0JDovi/6ddz3Lz+JxrA040VwNch/sKrXWbf6Qorfqs0lpudJCyA2JShPAup4yR4MjRlBEYG51UxJgKXk9ye+NY44VDou7FXNg0RpN3vpNcyZOGRYYA3SQNHQ+oGiUa+ZbpivekfUB2/82K//4qn7r7p4fGsjC92qAkB8cTaffLx95Te/8L3JcQt32zM9UI95ascyCYCfX7TZBE3+OFNLxcmaazVKiL6EaTvOpBuRoI0HpZhTEoColVVngc/VL2SRFRTPV27lkVVLu2gV+i9OQGww7G/CD7/7/fr0V7zN7d+yfTQY9s+e/WDLbzV7D+xFG4u4Zd+s3CU4+VePw//6l6/K/AmnYnl5EWQGRa0UZvRFzeWndUdMBWAnFMYNOKLyKniQrCLyFAGklYFF0JBamUPUYcwCrsQguAIYjLIKCgMo9B9DxmFiEDBAL8wRDCrBqALmR8DI1OOjjh7Nu8su+tQnfvtBv+1WFkViX7EDAVeDfkLAUz/0tjdsvu9P/dbO5V2LE1P3VxCdH2F8N/T3xanUXW/RQ3H2x/57ckCiVp6ec0mGi5ee6J4AWuVBqjg0H0BzAZR6r1/2Wa4A03yBoucP+OGm0QACg2++/SPTL776bf3ZeNIbNO4vp5de8xS3uPwjBvr+h+AgyAN++69cxFWfeieOuttmnHznn0fdTGEEMEyJ7st5jp+YSkHPhAlQEvVAK733w36knJ9Wqa6WXwuEnjjXQer7kRBi30GgHI0ptANXCULcjOCrho4jpuPCW9s0ABm245XJ4sY7nnSvjUffdt+W0z52jmcLdl2AVurvp6r+17Oe9LMPevqf/MvWpW0HGovBskxoghpTgdfn8wMxisUf33zOHrkqNafM7VcXBJRjp149gQTsVPho8QhXXw+lBiCp9Zox5ae1U62AJqcFluJ3FAxHG7D7+h3ucy940+Syj395rj/ob6Htu39+cuWWT0ndyC2e8v+nccD5nH66u8Hl7/88nPkO3eUhfwRbGch0DGNMAu5MZPrFoKDagkH1J7XeosqvYvwRr5Hi65OeoVh/4X/1Uq+l6pJIQLQG70M/jvJhkRsC1GoKUFgQk3cukhAqa6rlpcnybX7uvr+5eP2OT+y96Ds7bi16g7eKEiCm/ifc4y7D533zs9v22pXB2Lf5eBljnohfxFGHmh/FZtw8kUMa9KMSA2AltpGXZVDBrKeEGMkaUwBY3QFAmfOTQuFFJHUcOHQCibLaiCgNPyJG0ziwZQyrOVzylW+6r7zh391k78FBX/D22eXXPrM5uDzBrdl0l+D2jzyeHv3Os2TD8adi37InDmkGnlI7TfP+wYGBANi1mHupq6CSNolMPi7bgMk9y1ku/6oH7v8q6AVqqcsqdFdfTHqFmiTaMEXFIc6EoYgJLPSA0dC5uSFjY7O097OPuPdJkx1bas80PLR4wK0iA4iO8bh/fcOrNt/9Dv9r32TveMJ1bwUTmkqDWVzGIe0xnhL+E137r9LLyVN2muYrrXeb1oqPkofXdK9fKweVNN/k/MxExMR+0ldEVv9MRu0cquEINCOc+Y/vn37tzR8eENjavQd+Y3rx1X/vxtPm0Kf8/42SYM8Vi7j4E++g4++xme5w6oMwq6dgOFhmMi2RTyMJGIzz+km8I2YIbSIPVDBBuTGZNAgbg04O+h59jYGD8mLUVfpvrQBAqiwgnRXoMjIRz0oxiVASktTNbHT0/BHzR55w8IbTPvpN4kO/g+CQX1Ux9b/LIx92/JM/++5tO5Z3LE64HqxIHOd1mDkfALBqGw8K1D4r9DC4Jc1VbMtZ9WeLyirLCQC9wEPjVdABgLD6eUXATLBg5tBfblypCeAHlYDhYANuuuZ6fOk175juvPjqUX9ucKW7cstDZ9t2bfux9vZ/fG8q4BoADPql1/wW/fJffcLNAKysLJO1vSx2mBKxnLqvBfAVj2sFhNaVTEIMK14QhDwlK7ZTxRELBGA/Vpzw0wYeBISsKhVIEciSoKPKPEhdILH9zCZkAhboVYK+Gice9Vx97FH9wdmP+5Vjdn7r9J2HujV4aDOAcGFzv8Lj3vd377PHbTp1ebbcjLkxfvuueJVeCUs401IOWaN9ViLpWWE3ztMLc5wMUcgwhVNDg4G0BtqTKKaSqaZCZYZIrd8j4A5EIDRefCg9YeMcyFpU/TlcdPrXcPor/nm6uHvPqMf0b/V5V/xas/vA/lv/qX9zyYCEI9wBV3/5crnmu++gu/zcL9IxR98W48kiKq605n+s7dNgUEL+c9otCsAjXrsLkMl8QW9E8psjsUhncdKq44gCQdt3AyTRw0mtWSvHSIpSktrvk6xBIYvESBY36Bs+9i73uOM1H3vPR+AOLTnIHNqDwi/suOujf+V2D/rzP/nnvSu7VibG9SZSYyoOtUjW55cw4CNSAG6anklaV4/ybr2ANwUcxyP81AoU+vzX3TVRJwHJ2l03tYE7IP/FhUMOFBRAPUDYNA790QjTlQm+8qb34bvv/kzNo8HQTKfvm51z6RNlZdL8xJ36N1sSGGD3FYv4zkfeRcfftY+73e3hMqvHZGDSEFBM1U2W8Ur1FrcR/laHQGMKQZHFn8xrJLuSm0B6aWpyfp9BEFgksRnjX0OCcloUhSBEgTdQ1hskqMOGgYqJ3Wy6cuRdTr7Xviuv+fDBy8/bdSg1BG4VGMCvveklr5i/3XH3X5ot1RNuzKQ4/UV1ZOTm2zJ6MSZKdV72p3/gbbNrK/TRGkM7/1WNtEbQb/0y8WcTNeJDR1wh3h9uwI2X/RCff807ccM3L3S9YzYRG3PT7Kvff+jh4fytbIANMD0g+O4Hv0xNdYG5z0P/ANaNpXEmtfgKDT+62V5/lAknhQVATfARrwb/1IpmKbI6UQJt8YcGP2+PgSOOBIvuHK2FHrWEWjU/gcg3QIw4ZjILJ97x9tf/x799QJoahyrbO2QBgIKS7wkPuOeGh77szz+8vz5YT7ipJlJjikD2icM96u1cNZ1PCHXYakV+NVQjzCAHdp577yIthSTNk2KVGrDarNXa9nMzQSIJy2S8IbJLGhFw1UO/N8T5nzwDX37ze7Gy/yCqTfMzmR8O3HlXPsht23XjYeX87ZKAAFx5xuV0za6L6L4PeQKO6E1p6pgspTkBtBH91olPxTz/6pYPEa1ZIohq2UXnF4XiUpYOQqRpxkwybWMWUtOctMrly36wQqxIlQFMMIYJ9Wy6+Q4n/tTu8y941/IPLz1Axh6SjsAhCwAcaJwPeuFTfv/4n73vow+M94+n3Ni4pceF1N9Jeb5KuKAoXFCrFXx0n1+p5EpO4IlATLGdHnb1KZH/FrLQ1uVQqV4EBylt5CGhVBfGfnDjBP3hPGYHpjjjLe/HBR/7IrhXgUf9qcz3R7Jz33vdty5522Hp/GuUBLLj3MvkYnMqn3z7++DUTWOZkoHkIaDIAcjJlErpqYUBoATiV6doeUFqkglbtZs9rlrjvKQpdPsTlUAAuNhF0D+CUgsxlSvQHQMqphPZawuQhcwGc1XP9OfH2z//gTNoLcXZwzYAEEGcoLd5Iz/sjc//gBvJ5rHMaIKafO3vUroMfZO85QVtIAZqvbaOumVOEN8gNThOkluRqztBbUCwDTyz6i6kqzMw/ySs/hgNN+KGC6/CF177Ntx48Q9QHTEPYUAMNzQ/rPD1i39D9i0e+IkF/f5bcSA4X737bLlw+Dxy08Y+8LZMMEDd5CEh7eyKSkxUBuVVSxrTVGAE/jSnsx3eVdxXW1bTbKZerybxHFE/lLQQDKV98XHUey22H5FXOa6IrHXiNtzmNvfbevqn31jv3VHjELQF+dCc/v7H3uYhP3PShhNPuMvyZDyekuMZ/GIGF28hjYoKuNLaf6En+NpTdVKcBFkfTgA0IOeEXWT8+UUdmlzkLf7MhEFIXsOdruWidMjyYo1z4F4fVW+A737qdHzmNW/F/l17UB0xD2cI0u/V2DgcYf/SV931N12f+4qHu4UVq0uX7IK54mXy+csG8qYvjdksg46rvNZ/BT8MVMFLh1lAjGQKMa0OyAW9XsqyUVqZSHqnRb+/3mmFxAnBiVJeWoUlRIp32PCS3rqwwUV8tuCXjriwgt15kdHaAdMZsOIIyyuzMW0azh/7iN/5eV8i3PLuyIfyUrjjIx/8ayLipqhdUzi+5FVdxRvn0hsWT18u5kLRcuH8YCnARL9KU6P87UMqBhun237668iDPeInSZKGnBOHwXAey7sX8bnXvxPnvOfT4H4Fu3GExjLQq0BDW/PGecj1O9+CxmWSwbqw8LfuP/PvcNTGcXPJlt7sFZ8BXbUFfNvKb/y1AupTDgJJQCRTiP2cP60i5jsHSNO+ttvFogJrhfwb7VK7MI8zS9geVIixQsVrynucYxBw4rO/sCrABwGCEz8fMGuAaQ2MG7LjZeDIX/jVPwLZQ8IH4EPx3rumAfcrHP/Ae/7uEi2zI1jP9Etrs/xJKy4EBcCHZSph3FWNASWaqfKEsJOjkN0rznspM4u440FPA+liJL5yolp/YeU3aiIMBhvxw+9eik+89I24/rzLYTfOAxVDKgMa9iFzPSejgRXLkB/eeOYax9T6yAJWrlrE8vUfxoaNPSwdrJu//SKaD30bOFpAGyuAndceNVA7A6W1jllWaaiWSkpQFGxdl2s2V8SJJNG4xWV9iezZ0G3DfO3EXW8un/jtxREiAmn8+rGmAeoaqB3b5YOzenine/xWddKdB5k/cRgHgAiWbbzjbYbztz3xgSuTldqR2KTdL5KStJhuRzAwrq8unFFTMrWjSis+CCWh0JwGSsktpLJ1ky5XwmqOuJR/k3MO3OuhMn1888Ofwxf+7l+wcnAZdsOcF7C0BlRZYGCB4cDRhrmBLE0vlu1796yf9F9fCKHeXfre24jmgX6vloUK8onzgb85A9Qsgo6vACtA2D8KK3BJMjwrCuu9f56GLQCHBgyjoPv6pk/esAwXZEQDv4QK2Em1AR2pwyDl+6rMoNhnzqeYtLp7IqkcaEIWMBnPxmbjcH7hPr946qEoA275ABBS3WMfeK872eH8wNWzcez3u4j+iwuntmRMlsuazuk13hLTcEkCIV4XMKfm8aR2kjcCETkmcsykNQNbSSOt4fPpWog7+ByGw41Y2bmIz//9v+L8T54OM+yDe9afKlUFqiyoFzWkjMPcEDi4fDYmMwFh/Vl0rsXzLxCiZdj5AagPOnIj5Ac70bzsK+ArtoJvY0EDv28EFYG8dLgPCEo7MIKFHEeOoVvGopSHtGQ4AIoz5aQ2QFEOBE5WnyaSpYc07pA83hGLY5aGWOLWWaiJzwZoGkFdi5vWQA1gw71//mH+edzhHQDii7j5vnf5Gc/zb8Kor3f8Bi5nApIjawR5IjaQswMkmrBT90vrf6dWgHoegON8XShQSJcCWJX95cwOYSMxMeaGm3D1Od/HJ17xRtxw4eWoNs6FbRIG6FmIDf/3KlDPgirraNQDLa1c2spd11kZAGBy/Qrcnm/ALljiXi1SQeb6kOUlzF5zFty/nwdsBnCEBYwvCVAJqPJ7AuPqcKgBokIKvCXJIlJuBC6aTI447YdP97eWuYoCicLjxMVOQ5wkFfW9WfHZOcA14kuAhtA4Qg3m2RQY3OEeDwFVQS3olrse7C3u/0EOaf5OJ//0BBNMITxznviTnDilY6VmnhdqiMNcntTrCgEttX47RTdR/O1AJ3a5PhQhNCBHZTKH9oShpgYT/PhuNRqAZoSvv/fjuPDzXwX1LOxw4EeWrfFbb42XzI7BAIOwMWdQQZbH28pnX29mADcDJjd8BaNTHyFSO58fT4BKAEuo/+MC8A92w/zZA0HHzwPb69BGXqMV6KBOccmHR4uvJy63AFYBew5MHNDmCPUH0hDl9lDYRkyu2PMmEsVPHOWJg6J8APtP6wZohBhEdjZunD3uxPvShmOM7N/a3JKXwy0bAAIYQqM+jU489t4TmaAmsNf0jyd45Py7kLkZxd7iBCDF7T6xoqdWfq4XdOaejf+ad3gKiryxvSeK0iFh3XeZuESWXy0Og9EGLG7dhbP/7cPYfulVsAujrCxg2Dt8vEX1yL71N2shfQuMZ/uwni1yL6Y3nIv+RkAOOtQesEXDAGpg8wju8m2QF3wJ/KT7Aw84CdjZAFMHMuy1BJrg1B5IaqVvZQ8vzZFFNaD0JdXucRqJoywOIwKRuOpN/BQhk6PwvCCAXNpf4AQCckFhyEHtK/RZQ+N8FjCZzqaDTZtP7p10p42T/Vv3pF0Mh2sb0B6xYO2RC7ebNTPUJJxSeA3RhcjtFEiXu7tSovNpdVPeBJQAPim/Twq8rxwujthClJGWVkfROU8Wmx9uxA3fuRyfetVbsP2Ka2A3LXgSWRKGs8WNBhVo1AMNKki/AvUtqF9BGre8rgNAfPVnu7ahNwfYnl/CZweA6fntQmKBhRFkuoLmDWdD3nM+sJGAIyqf+lcAVeJ3BlqlK7DWIhAUaVyhBpdlhjWfIAQDB4YDS0NcAEFCQAN2Dfl6X7UAYycgtgEVYBWAQL9LYNYA9dTV6BPsCXc87pYuCe0tHvAFsAsjw8Pehrquna7PHVxoxWj0zWcH3O7+kKIFpx58QICFiung2NuNgz8SReBCSSEKCeDwxG2hCNcIqkEfMhV860Ofw0Vf/hqYCHZhzreMTEz544nvswDqW5/69yofCCq/vpZ7PRChEXSGZvEg7ACwIyaatvCYBpAaZAmy0EA+eRHkil0wf/4A0PEbQDtrDwQ2BJohE77qSNTJB8oqJmerwxc/8IS81vxvwvrIZxqtNF1CriBIOyHTerKkZQBdegpqR5g1gGU4IaA6+sTjAFx6SxaEtzAG4P80M+xb1zODppnWToRjr78M0arPh7wEQrSOWwHOZvBFFPfTQY/8omzltCJKEgijFhvQARtGG3Bw+y6c9a6PYMdl18AuzKVywaf5yvktZxCwMpDK+kDQt6BeBYJxNLB+11RnQLM88Wt4hyxx74CEVmEz86y6xtO+cARDfrAdzV9/CeapPwP8wsngnQ0wCadCndY9ZPQ9jpAL2no9/j1sclpA0cmjF0eCmU4LSEH1tLqxASlpAoVSmeSA5FzmBcwaABuOOaHVbzr8QEAAoH5ViWG4GnUDsbHnXzBttOpuAAP1rL8kOXCd07WKdkiaD5X2Zt80XpBbPim4hAc1ztNPB6MFXP3ti3DORz6Dlb2LsBsXAmEE/riwxpN8rA1O78E/WH/6cwQAw43YgvsGSU6G1nkAkNr5rcJ9/14bF96MWr2vNURqX5HPDyHTGerXfw3m6rujeuI90RwEZF+thD498QZNPJl9QIhj4/H9E1ldGqRIweLQBBUhqLYh2ktnEOm/ARwUd7OnuJolCKUANyCuG8DNbTryFvb/WxoEDK+1ZdMwpQDt4pJ7rbbaGtCXttQvrV7Xlt4Y0mRhWrV4N2UT8a2gOEqUf2TTAP3BEFVjce4HP4fLvvg1YNCHmRtCGhc2Q4QNuZa98/ciyKeyAd/39ySgKjzGGPaBoMsAEkDbGwB1pWh05IFAmgFNmApqArDrak8RtoLmIxdjcsVemGfdDzh2HrKjDteDzwbAvjxALVniLZV9pWqwcDjZhViM3ysfx8pFL4ZY1TqI15FzbeIIKfQfTmWyLqyvd4S6BjcAaDDauC4yAGHVu1fiHBIwAKEs1CHFppxW6qameGNdRYqzne+LWYCE9SA3rwBJ8KnZcDSPyU2LOPO9H8W2i6+AGY0ghv3vZk1aiS3MoIj294PT92zGAXoVJGQAPghUPnD0K6Ay1Hm/f6PIVhA7zNe/0ZF9tnpG27F/ozYTmku3wj33AMzT7wt64ImQHQ1oHIaHZnEAMQJ8AjhKp3YSFdGycHHhRMwU0oWbVZ1XgYqIrWkolWg1ySKCuGzUg4IECd2LJgwJia36tzggf6iw31rEd22injpR2ZggSRx7rcyh6zMJSxwYuXAv5QJzXReJGkmvvd3nDyk/M2FutIBrz78C577/E1jZfwB2w7wne1jDfgMugUScxHZfz3hwz/oAQMYkp5fK9/2psoD1G3TJGOZ+DzDUBQDfaROpAJihr9eN83wRI0l+u1Bn9cc6QI1vqi8YyGQF9Wu+AfvYu4H/4O6gAwD21/66miHxR8Sp8oByGim6HaiKen+9RV0X8WQh/3u41FZUZJFCI0DDCMQeZI4ZSMQAhGDhsQCB6d3CFcChCQAAqKbMtCw0tklUl18Pe+e8KrX2dDcgLeDU6i95TbBQ1uGPCG+c4/dbXASmV6GHCud/6su44PSzQQLY4dATkzxH2wkzkzUQJoaBo150bh8EYIznqvc84IfK+IzB9nxLsLJgZldVFabMnfMDPqD2AZlUgPQgduYvjEaCMEiYsEnkDAZRA4mCmq72Gde8oP7QhTBX7oZ59k+DjpsDba+DxFgoCRpAagI5f02AfQ0awT9pwLHQCEtGnR4OIT/sqTJMituF8hpylTDkQ09SyZq6E87vfqzF/2oCbvUhD7MA0KbZugT3SjFZJyQJ+0+VfMEKzH19F9BiUlVdW8hDiu/KmUJ0P2kE/dEcVvYs4hvv/iBuvPhKmA1zqf1Hxtf7XjDGORjLsOSS08d+f0D/xXL4OJQHtgpAIcMYA64YtjJg7kqA5ElDACsEND1PlrfwZBjnfBAwUpz8KWNMMyOhe3BEH80FW+H+4iD6z3kAcM+jQVsbn/qzbxWm3rxPPjLnw+Wl0bprVRCIir5TC9cDCqyAoKnjanGVyzMxEB8EGpd1Jg77EiC11xJZJ87/5889mJp1Gr2Wr6/gY1oY03mXRFxz3aXJRF76Ows5xr3wLuxymxttwO4fbMHX3/0RLO3YBbMw8r8Lh3qfCGICsm8YYslRPNkD008M+88D6i/GBwOKdOCKwcZ/j7UGPWvAjC4A+AyA0AfQE8BZAP10RPhTO7AraQY0daDWzgAx8OohhFRQuwa0cQhZWsH4JV+F+f27w/z2XRn7HLDcuKgW7UI/PzmxCyCg+LFeKjy35fxKkUqoNShUtKf93gBpd5/Ucklx4pzAzRzgHFfrJgBISJXiVF/c96eH8PW+NUjWa9SJs47MLmQL8X4JOnBOsloww4OC8UQYDeZx1TfOw/c+/jk00wZmYR6uaUBswsoqE7JO7+ASkH0fABhi4onvv0bxVhnAWJ89GAM2BmwNuDKwlmGtTaPRnSEw+gjSEOAsyFWANFm406kdXE10oBoQGyF8XwqQnzehnoVUNZp3nwdctRv8tPsDR/ZZdk8dVV5Ixs3ihcNMJE7Yg1KkWnWkrst0aTpisLhMR1EHj2SWqZYdz+PrER/Ij494gO87rIsA4M96B6CGOAQykHZmUo8senyhbcgJpJWg1Ygi5fLplrALVYIHYAiSZvctyBl87yNfwFVnnwPu9WEGfk8BGRuGOsKJzxQGehhc+ek+USd/JP2QuiXAzxrPWWcDriyqnoW1BGsYnf/nGkAYXvmnBjAjCPsAmrq/Dfk2IGv+NxAnOyTO3jgC2EFcGAo40qD51rXOXbeX+Zk/6/jUo4Ab6wDOUTo5ooxX+ty1nb9FD411bDiU9LVbdKHQYvbG/QJZXIRjpSPONesiAMTUPNT43IRMQKn8+ZMbOZqSAlI4fg0adFEa7yFzqMFOi8QLEWrXYDgaYnpgjO+892PYeclVMKNh1nkzJi2QBHM4wTlN9okNyL/J036ows1GGnBA/q0FWwaT5wlYY1AZA2tiAOi6AKHxI+jB8/kN+TFfZ3Mkj1McIkBjQ4swgoF16AbUPo0AgVztJcMEntCxYQDsPOjci88EP/l+kEfcHrLDa05Qbvx5klEtuUsU9f5Yt/rgt7qRXvEu/yl2lzhGcWjQFbrDAIgbn3WYdREAIILGp3YsgkKjhxXTLy18JOXZVNJ1GTECR8Vgn95J3sqYvr9xgsHcCIvX78a3P/hJHNh2E8zCnCf2EAeVmUD8YAYxg3oGwmGvU6z5jQl7nvznbCqGqXw2wOHEN8aRYRi2YMPgyqCyxgcBBipjwQEJWq/DwFBYGw0ACQM9vi9mvAMa5++Q0BaUgJZx6OioJSyeOWj9deA0BE+QYQ+oG8z+8VzwD/eD//BeHrzdP/Pv+1QC0YhATfbmzEsiHY/y/JDOHFpRIK2wk/D7CvIBp8RDYaLGxS1/HhyqEgASpL99/R+m+ETQUNR3oHK/WtyrG8kWkhWBjFrMqDIzxAM2ZozDuXnsuOgqnP/hz2A2mcLODSG18+vJKaTk+uS37Ov6+LHxGx8jwg9rQFwxmdgG9OOpPgCAmY2TgB2YeDMMYwSVtSAih878e2TDAW7h9f8a+LpfKkUPRjj9OTlOsZVFImmolzkCwclIgpTYRoZ8+jK46/bBPPsBwLEjyI4ZqM+eLxCdPuytAKu2VStUR3k6AtoKtiiXiUKNGyttgCBGKg0gt3T/75CWAHHMl4L4YnjBMkGT0tR/1PvLKrxqj3sA+vIItsoO9OSXEAajEa792ndx8afPALGB7fUC2UTpTHM4USpOtTs4BIEqMPsCyYei0AdbSC8EBQOP9lfWERuwIRhLMIbBzDBMYGawQdgZjI4KHPw5qf9GHKARTwWWGB2k1GQj3xEEK8AtgUN1LsIbhLahcrgj+pBLt0P++myYZ94fuMuRkBvrxNTTFHNRIiPJyVUcoLbDa9+XFugvefwjXcVEICdOkpjEesgACNQUYgz5/QLUlH5c+JkIP4Wea8Bk1ujJRrBWCMSM/rCPq77wNVzxxa+DhwMwkx8MYVOAQT6Fp7jGNQB8VvX2jarzCcIVk43cf4CtAVWVYzYgDid+FU599l0IYwiVYVh/KnQZgLoSqQdgKkDtabLURHaHQR6cjjTeloelQY54BYR2IcVTnHxWAPhW4fwAcuAA6ld8Dfb/3At4xO3gtjde0CNeYwyw84dVVBNOQIBTgULK4CSqi1X2BtVym4LoFigPzS2vz3FopgHDG+Uzq3xqi0MCVMLCLpUFlMIeekebnvSLu+ZFAGFGv6pwySfPwJavnxfAvhAYTJYQ969EwAA4nPJMoNjeSxlBoPca3yIUjqO/5NhasLXwzs+e7GMZRp38lQ0tQGb0jYExbDrPD+Gbket/Cz//3wQkXkzJsJNADkJQAIpZBIXSIKXadcAPyJOLYi3PDJEG1O9BXIPmrd8GXbsf9Mf3BA4QcNCBiSA1eV0BE7KLRh30gqz9176+RVqbLEX7P6DW1kNlB+uoDYikkBrBjyjoGV9YAsGE7gDFZZsiSa5LlAaglnZJ9F9jYSuLSz71FWz95vdh5+Z8ayiGdiKP7gaJaRB7dpaNQB7ldN8yyPTY9/nhOGYBxP6UsLndx+RLA2MYHE5+NgRrfQAwRGAiZ40FW2NW5y3rEwREwgDIZ/w28MVTCu7xF+8tVnFqkZVgk/KPupGq350vB+IyEHH+Y9lkIZ+7DLxzCfYZ94cc2YPbWwfgLgysaCygLTmvd0tqDcJ2X7sYOQ6BpA4Kgy7+IeuiBIgILgoZb83cY/IgH4U2C4ukwOAobwIW1TZMuSATjLG4/JNnYet3LoTdOA+pXdgwkbMPMp7hRybsFAwTfghU3sT+qyyEY39f/NeNBRnPH2NjfG1P/nvZGnA49ckQDDNsCAYVMypmWDZ5j+F6dvyAkHM/A4E09SQ/WLWpBwgIoJKIrqPzheDvAvmLJQnAeoQ+BH62SJRhNMGpAwtncx/uvOtRv2KK6nk/A3esnyMgS4mwntJ6Ci1DF0bJtXqwKuSFSs2ZFFACKk2idw1ARbRbFn45VD2ArNlPgKM8ERjFPrXcdyOrdf79i8zFei4HAvf6uPxzX8XW717kJbtEQhsv9usJVGVqbxT10AKeYgzIVqCqAqwFWevZgWx8ICG/6ZatATHYr6X2JQQz+dYfM5gDC5AINgQAS+wHATsIMF8TUeM/lgEc7mP49h/HtWDWv/5sPD5jrL/PGF+SwQBcQbgK71NgEMaPPQLrMz4y6XvhCNjQR3PDLkxe9FXQVbuAYy3EOEhPwg4CKraJJXSPpNWN8MFBC8/olIHgA5OfTASLCUy2Q1ACHJoA4ARNHLkOwiDS0t5PQSAtDMnLQlP7UAXfJuo/DAa46kvnYNv3LoHdNJf0BYQp7Z8n5oToU+zxG8X3t/HiqhimYmLLlL7fs/pg2FMODIMsga3PJJgprIEmGGNgrYU1DGsMDBtYZhg2bH2J47oKAGmChozPAMSoFl/waTH5/fNEq+DgMSCQSZ8TKn9/dHAOgcLY/D3Gen4H5c/hDGhYQQ4uY/aar0G+fYPfThTxiRAEyoWwUAKkglXLJXQGIGpfYFonhlJvfr2UALHh14T9f1Ko8ksY8PEvNkd0VWK2kEu7tMDFOfRH87j2a9/D9d/4HszcIPRxuRzCCCe1pLrfg4USFH6k8pRdj/LDwQbFWXa5C2A8iAhmR8wwZGGsJw6l2j+VASEQGO/8zASGOAMGMXdMQABERGSyk1HltwBJEwpCB5/WcwSKg+JSQuDNqjIbEhiDVAdwsM6eGsaI/fM1uW/MzrelBxaoa7h/+jb44Az0kNAhSFk6xfldtQJMSimBNSodxKnWsLQigYkJV6B10gYUkAtLGF0Ac0QBJHIzmEEKEOLluUPl5xV75wbYfsEVuO7s78DMDbLCQwBvKOZuad+8CVmBAgCNavUZDilflv0KYh6B2x/4/exBP2Lv+GxDvZ9AwNwJMGzgZQQIBgyijgpcgIDhIJeKfNofCUEm1NscHgOCwOR2oE4kRNLaQTTh43hRcaMUheqQgoeC3oWvsYfjyVSQoUPz7+eB905Bj7ozsKtOxT1FJp/eJASNA2ReS/oeDVhLWludh+CadZMBKLwzATUqEMQaSwIdSO1sS9uAXFwK6mCHA+zbsh0//Mo3YYa9zON2IbOIBB+/0yHUl5nv708U8oQfztx/X9MHYNDY5OiF44eAwJxPfGbyDh8DgcIGDBsYMFcAWDoQILV1Q9buIggYCUFGchBQa+L8UW+CTkC5rNPv1Mi6D75laAoE31uT0TpWnYS4m1IEGDHcJy4ErcxAj707sMev+BWrHF5aG4GjFF0E/iBh+o/Kpk/7/T8EBfkhkwRzSsCj3U4R/eJIpn5nhMRz90UAqixWDizh2tO/7u+27B8Ya8gAxVKozYVjJhDedDXnH3EBtLKCONZLPiiwT+vZkQ2nfGz7sS/ifFyhlPIbJt9dDAHFgP2/LgEICZ4Ip8wsAoKBGxCzAgl0XptPVIlBgEN6YEwuIh38fU14kkj4TCpDypxyQC3jE59oo4V88TIfkH7v7qDdDWiiyLtqUaWKAaXEmCCgWJnSvirXdeulBFD6PaI4/FBgYCRtEEpwkDItEMIAOcL1Z3wLk4MrsP3Kt/sofz+CJkBS9Ilcf4Jq+6m03x/9ICZHUdQjpPwc5MA8qm8CvTcGAfaaFYSQ7lOoHDz6bylzAliAgAF03q9OP4GETE2S40cAjqS1sQdICg+ATek/hPPkIBso0alwHUgeFokpP8TPHSC3DCkcFhSWiWKDgZx1hb9ufvfukD0NMA3Za1wUEp571c5CZBGa4hgUFNTjQ5EPHjpFIFGLONJwUBlBI49Cn/4cQrkTAfcHuOnci7C4dSfsqA/ULrO2QnsxrHILg8dx4i/U9brvHzMA+BZfAPmYDDsKiD8xZWEPsK/p2bf0mIV96w9gZufTf88B8F/3eEK8pgMe2UWA6B7ej13MAIjDad8gZ3TRWUxg4bmg79hwbvcRB/qv8jxpMnU3cQFiKh5bunW4yBjEog5udfwsVJAzLvcago+7B2R3EyYWKaH7RLm2LyoTnVUUn5ISwpFmnQSATJV0qq5r0sJGUbp+ue+f4AIRmMEQi1u2Y9clV8IM+37dKsf+jMtCIpzUGlPLT2K7jtnPnhuTugAgAlVB74/ha35jQESOfHsvfCuDGUz+YnUBYght5nj6+6yAiRLU4PfbBCITdylAMgOQJRt7/xHwi6CtJB6AWr3NUcqL4gNyd0AfwS6dOmp2oIU4i/HRxnmAMS8WRBYRdA60sQc560rQhgHokXeC3FinAEBOypJCEdtAa3UFokx5DG5yi6NCh6oLEGp9gXOSg6UWZNSbgHThIACsRbMyxvZvnZ8mAD3LKugIsNr8mGr+UAIYddrHDIAZgjDD24PzpB8GG3ZkQ8mAAOaBHSOCgeRiXU/MjmP/Pzi+oQBus0//DEIwEIIpl5V1fcDg6DDB+fXNJM0+7/QxOzShlnbRgaMOgN4egzQaKnF2gMICwOj4saccCT0uSND56yk0H9VegQ19uM9fBlroAQ88BdhR+46FK4HB4NTqmkc5AAAlLuC3FK0XDCAJf3plFZE0cRUZAYlcRYIGueVHALiqcNO3z8PswCK41/N1f4Bx46af2PYjDvlESv19nS9MzteYoSxQj4k1v58TMN75jU//fdpv0ilOxCDiRP3NQcBTfT0I6O83Yb4hkIC6EKACgDGAYzgJjOqIpor1Thv9O6XUoZND4nEgfwqY7OjxG8Tk7ZKJNCKBAISk+uPl6C2Ewr4BgpcZEwM454MAEUj8KlsaCvDxi0Cb5yC3Owqys/bykXGXQHt5pUL+U1tS04I9CHiLZwCHhgko4rl9aROTwnbCvjYXRqOcFDLicP0+Fq/fgYNXbQH1ewoogCL66FNe/Z9afPAAXxTtZAIqcWTDso8QCPzMvscDPNMvTBEagKPwBxOM8c5vDIW6n1IgoIBBmBCUmMjHFQDEHQYQm3uR3csMR/EFCid+fG9jiQ/dMYilQgjmQqyk3Hx9JhQYfxRYnBFdJHVdsFG/hIWq/zL1OD2X/2WEHdz7zwd2HQRG1vty/L2pXfe3herjtU6BFgx4cXDconygQ3UBkgQGYNwMrMeC0Z4FCFmBI0bTNNh74ZV57NOp3mpK8wNxJ+7oM6ZF8DFF64+Cc8NGwY4gBkKsMoJMCuKI5keHt74LQBRJP0YJgABMXDg+Ay7mEJ0BWRUmHNGB9ZeDenD8yA9p328jldvXW1Q4s+L/GxMChA8CFFsNtMZj/c2F+1wMIPEXE/jlL1haBj50IbjXAP1AV07zSVn7X1aFvLiYVuDpsACiTOwtmAccshOo1hmZbvWFFwZKCUgiNbhXYfHyazG+abd36IYYYpjEt+6Kfn+M7unUNqr+R+L/k4mz/hWYK3/q+1o/DPQQiIV9mh/afuRvJqT6hhlV6PvHzz3yH9qHRHEMGAYRA2AQuuWg8YKn2CZjxdHg3AbMQGAmhgoFXMCCYZCGsYT06R55HWs4egIYOH+96CYQQOwBXqL82Jg9OAKGfeD6PZAvXAHaYBAfVsrZiXqnc/ubXP7b05KL9VACKEWvRJYUkWIISAIDUIJWgBiD2dIYB664xq/iChE26YKIb+4TqTYf5Vsqyygu9YxZg/Ey4MakLoCvzgPwRxSwQsr03hb5p2T9eee3zDAUCD/xUhPy9xF3539xFZL3RxJQTPvV5B3CKU9mDZDQY0gOYZo0AcKso0VO26GDgzFh/iZ0f2Ig4NVpv8R+tMogwF6yTOYtcM41wAU3Ags27DdEa9dgOSREEfFu4BL239zyL/0h2w0YNRIjACiFrk+5WFEcwJXF4iXXoJlM/SruxgFWHBrPqKX4xqeeP+U3nfPJIkn002cJFJV8Y3BgNTMQxT2NZJpvIgWpEiDV/ACThNq/RP5NzAJAMMQc7u8wgNz08f5U1PZhJkAyKQ8uMANT2khJG5KCyEveD5nSBBS1degnS1rbHcpOqjNbl6JgSPgZFDQE0jdwFiUR54eXTr8MuM0RoEEPMnb5WoKUQGCZ/AQAEKplcLiDgJwofuxCep9XhcWySXK3wBrU+w9i8fptQK9KrRMhAEYcjDhYONKpf6DyRpVeNpx5+4aCco8NrEBK/f6YRaTywASBT47z/TET8B2GyPMn7eQU2n2x7Uc6m4hnDoE7HkA6ElOaTZRrew4DQVETwKIEByPhJ9wnRtLoMLiFFkYQoajzw/hwUQ74mxQlQ8wGAtBD4CKjQJCI37cIOuMKYI5zxskogO7VS+6L1vg6kQQjJmJWnZJQFwnS/150IQiCGoulH1wPN56CjUFk+SWmQIzsrDMBSuk+xX2vlAG9xPkP2vIe5Iu3XLv7p7IutfSIEknJa4dyPNVD6g82sXaMz5kwq5ABAB4LIOr2AkQ3oNiKy+99WqMVOPpkJPB1KM0HxGwRJu6QCG1flyngysHSFlB/sUhuQaRTmNRKn9giVOoeLheuQq4cWJvrQS7YCr7b8cBtjwH214nGSmqxiLT/bs0diJnKLZQMHJITKKbbWeTLvwAuyIClmwBiDZqDSxhv3eGBv/wEYYOPIvSYVssvUHwlrfnyYJCwX/2VVXwygGTIS3qZIOsd0/0oG0YsHKECj+rHk58T2k86C6Dk7KlshZAzfmFJBwKmM6HlE6mzIwXqjxZDkBRTMJaAuUPQKgEpk8Ione6awtkC+ZKKEGegMOpGBHIXpfZi+D4G5MwfgFzjs5c4i6J1ABU4WMiMyy2PAhyqFNQRsSJs5T5PBEMltFrIWIy37IBrXEjREXr9SCd2eoG18k8U9YxMPZOXffiln6FxEDoEcbgnLv1kG2f+Q1uQwWSEiQhswFHp16TUHyH9N47IOBOJP6n3TwkUDNSiuA+ts3AG6CDgHSdzPPzlQTkYqP5/VnpSJYJBMfwV273R4YU1MEhJ4g3tciB+L+tAwBl0JPJtx/BL0qACtu+DfH8rMGeSl/kOV+5sJTPgNRWEDu8ugCjUX7cBI5IbZMKMgVuZYbz9Ji/M6aJeQN4bEGcKBAwRyxHNlSC2E1tLYiPxhxQpyHMETHR+E9mAALhhooY5kDoo1PIc5NsM57SfU+kQQe1M9WWJeACFazeXBd1egLUOhuyPKHCBEBCYFBagg0PYJk2tbIGzk0tB/KFMDNInPViNIeaPJZ7yrLgDqVrgsOk5qFb1DOQ71wJLU69yHLKAGODyfgEldONTXl4nAcDrHxb9f3VzoTuAymK6Yxea8ST19ynWWykCR2XWoP3FpKI7khAIgo6f8lKAvfN7cJBidw5M4sW6/LohJnI5EKS5fk7UXwr7BzkGitRQiGvJU1MxZqkefegEQcL14AL/mzg6c6qMKe+R8M4eBDo574yUQBzSHIGUOZicPVAcFlLiA6Jbf7pFSKtBxMAvcDEbIDLl4a0k6WnPMnDBDcDIqDkAfXgp0FvA3hnWDQ9AJJG/4slJVGaEhiHTBivX78hgEPK0YMoUOQhIWk/lTaUF6R1/lV/YoeYD/KksHLI9L+6Z+vbsmCPvXyH9rBiiYQYgKf2E544IfwL8mFMXAMjzALlI7czXYeElMcRpYYuW1aWypY8WIzC1jGPZQGovX6TuUlkSFIxQ1s5PJYcACgMIgYAosA1DJtCqVYA+AxdtBZamoB6nlWCi8AA98RrQa9MCCg7TNmCk/8adoOE+UXppZC3q3Xsx238gROxwEaRhYRXVaa16LrL+rJKBplTXh6wcZBRTJ33NgGGcYeMMW8dsHcM4JuNiy4/UEop88lNaVJpagJ6kllaZ+/sDEahTBFKpsGrTJz8sp/nKkz3fRwobSCPD+vGUAzd0EGDVyjOcW3tqPsA7dFJxcCkbiOvJUxBQOAL5fZKyfwm4dDsw4FbPryyHUyADr58SILG+SY0Dxx0BoW8627ELxURVnK+m7ND5MEVWD4mAH9ukKoSkNgMAwnFgSFAAkS4+b6T9GmKfIARn9oGAHRURXD0FQt9fof4cuwBJOIZgQwjovN8XwCQI+xU0JVhSlyae6On0VyrCMSsQ3Q3gnBHEGjzrQhaAXm4XGs6ikVSe+qvYhBwDgX8MhWstRTAynrF60Q2QlRnEcskFUiKi0qSLaX3sBdAAnkt6CKoXahj1eILp3gOep682r6RyIX5/mhmgBPqkwZ1QXiQdAH9UM9gkUVDP6yBAyFHYO4GENyjWHzMsk5oFyPp/WgGqOOlBJR6lwG0DRuh6diYSs3NHKrXPszdS1PaxbVvIK7GiEaeVb/FAyMrfvn3MJeuTCHDsIORSMEiOTiWwELNONU1IcSlJaC/HTBVVBdm9CPrhLtAwLLRLF4usWop7KIwP0U9NI9zlYtXQEDWMZs9BuMnEt270FmDSEZ7S+vD4RlJq52TkNzP2KLMDmUDsW3Yg9mRQEjA75oARxAChRD/C8uCcyicuAWWEn0E5SCT2H6XvS8pAXQDIlwQXe3VVizZUxtS+Se68qFOfWjyB/DW1XYhagAK3ZwXUfUD5eAQsQQ0W5Q5BOPnjtqp4LV55U04iyvZnbm36z9eJLDgAJ67QSReRoLvi3+HpTXvVOxgmBUi1UARlSiiGAedE7V/PqGvs/ZIXIQuJAIV3hFQbT4QdhZZNOrVJ44rCBLjI9zdREES1A6PDF9yV1v3s6a9dCRDeKmZACI69vBpTEnP1WR5F1l4x2CUFKOilwcK1wfl485cHFSVo0g6Me74o3peu0NxGELQpfEGiKH7SZBEQMiGbbfzpNrCQ7fuA3Uug0RykqUGa/eck0gkBNOuGCJRSeNGYgDifnq1M0RxcCjvbXJkntYQWivlwMSxiuESD1RCQAt8pOWuY4DN5zLc4zeNocLxf8qluEuyQdf5M1PxTU3+s9GtN4gR0vt/GARMGwCjJQLG21zJ9FFe+oez/t7OANjdAn+gFcMytk17RdCkCfu3WoHp8Gjluzx4QMKmBK3f47ceh9peyDRC6g7ReBEEoZTtR+CP+gyG4g0uQ2SxMAgZ4sNX2ye2f8GJa58Di/FIQsJYUlnC0M4SJIyvfZwEmbO/xQcDABIePGQFpEA/smX7x8ygimrIDTt9j4vdx5gJokJATfN1ZOnz9C8Ta+XTHR3RQABTPg8qWYCujT/wB5deknZ5jCk8K1FkdJES3+UCtciGXndT+4dZArtoNjMNsAAoOkHohuFoXbUAoFqBIWBEeVi05AJPdeyHOgURaNVNJ8NE91bQJJr+w7EXdcsvHb58wqW6PraZI7sm6fpq+LSASRGpv0UGCziQi8McZG6AYPCJDNQSfrH3Web/3Bh0J83qMopevgcDYP/HvjVgpNAJojZM/kcZCNiHxUFFtv9jiLUbJ287ewgNyC1BJhbV4A6gscGAFsmsR6BlVlyjp8FVbiw7zEkDgN/42gRPoAkLqpjPU+w5kx+ZcJ6TzIKCzuk+cZrQSSKhkvv33OCBzAZhVWq/nRBIn3ecmUWEsPSWQufykWX56AIhQlqmqZSnQkied8+uyXMLK6LiYo2DM6qgcp0CVb2p6sPo+4VUgfiujoNQZkATwtW8KDEpIdE5J81wLlXTE1NIMOMIN+8PvqXCqzHOKq4PWQwDwAgDOL2BLKqlkGbKyApnUgWCh1FVFy4WJatdmiW8i8ik+awHPqOcnHE+UINbpCsFJ5bxMeTowMf4CHqDFPvLUX7oU8ph6YBVSSkfyYearEwKxoUPeB7o1OL9rXHB6ToCe5NAg4k/6wv84/0+MFjNQCrUvUe1BIV8OkO4msWKPYg1+QKIJq1PChKGQSPtahSOgRKmNAW7YB5k2udulgkDobq0TIpBDXr4ocFEjjNjAHVxOrT5Cbv+t2guFVsQ1BmTzXH/ke6eyknOqX6aREZMogUGrh3ziEhGoHq8fAQl7/ijPAMRMQEQN/rRozora3Bla69vD7BwplEwr6ygmTRrdX1VPl1OD1NIYFM6tN2o7a5FWcAsHSL1/zhdPdCGjniNnnxJ/EWuB/SugvSt5h4Cg2B14+M8CJF8WcWkQLhN5xAHNwRV/ggd5cBHd0tNXDKmsK4/uBkVgR17R1cXjwS/24IDLEEAusc4IedAoofcUtAFYO2xuGRGy3BeJAvqgxT+Q+H6pIykZWCSVEK3rDCDQ/wtiDOVTPzM51amPPHuTrok2SMw5OKRBXD07EEk7hMLZEyB4sxwBTxxblXoUwcO0RA4YqB2w/SBgPUadbr6TCDi3PiTB0k70+DuId2KZzuCWl2OQKHeqh4yLdNvFUJ4TJ4IwOzLGUcjL46xNcDhHYEdkvVIPC8ASfD1nDlHkM8p/ZUJPvB4ooft68Uye/NPXn5RJS3wekEY0OiMqhvhWKea0fSs6d6u7Vzi+Yu+KcvqiRCeUijyJYap5AbS6bSjhYMmjhmUPsk1b1M+/bX/YTpQAoawJeAimww/dNKAf/uEYCsQwmqVlyHiaRQIgRX2cWn6tKa9cHArDCQvUDHkKwBSG9Qgk7HQ3njkKfXiqL6VOgGLxIYt66unEopRMAKCSFlPZT+IHBNK3E9ehgCjL7zITV9p/LR/MU6SZx7OKLYhWQIjAX9QQpKQpqoKIGhJineaXwz7l3HFs/BqVdrR+IYE/+fcuA8sTP6vSLmrXDwiYpdCj/hkTwS0uQRqtEkCpLawq9bxlKWwVzsE78rqF/TonYqZI/WVQ0nhnEKwjsAPIQeCiw0d14szuC6koytVuMRvRp38p+MGgFgmovGQEXROgvBIJKuOOQRuKwx+rpbSFtyzbs7RW1uEvfFEtHiVFFCLW6+SQO0ho0YU1jVivsSa++ciDlhT5yhTYu+xnUyRMkKdUZp2oAuf9bUoZqHGQxWUf2YvCLqeCoqmgqQ1otN6/A5PzKG9G65lIofo63ePUt8+EHlKCFKF40GWAavlpkC9zB2TVQcRrpKrdOHALHUoAoO6iSakKsqrGl/Jx0cmJ1hQELluBVOgKZMkxLolAsasU8YH0BvLqjoHOItDSE4g/vHHA9sW07jzOAbcQyVvMDsksQMDMQhD1Mk9uNkOzPA4bV2J0l1QFiFJRIDEsAgiTI93CIVX3J0YfpwEdkBoIiv9idgB9muuLkNLFQnroCFn4g1aXoDlApHKPUnCj2AaULgeIkTZpZ1ImZ0UgUOJosGRqfjrelZRUdCWxoYSk3F0gJgiB4cRFaX8vwEV5dgDkZ3NdCCARNJAmzf8nirnEAQZpdao0VhCLex35GXLTIqhxcalJur5Eit3mh2EGkDwlDXkHwMVAlieQWUBHAjSaNACVK4U32Z/0hWCEbsEYlzYDa84loez5MynWHhf9W11okJKrpij6EURFc+uP1RQgrx4R5jX2RXaagAofyeo48XWF0k/MLb/Yls2KzpoRmhxUXeFSzIaEj80ahzQjafslgo9mi6mMsOgapGqgNUfQYhMSxXbgBLI49cxUoUNaCh4iWXCVAogXfcDyBNJIsUbZmwvxwBQvPCnaXlLoSXgNg8i4lP6rgYtUu0c5cNIYIqXhHsobfIvan0NrKtX9aegHqXUYKcxa2FIljzoz6GqA+Monh5EW50ORgIiSZk67ZZ/LdcqKwap8IK/p75KwaCQJEQpgWYnNhTVjOoXXMwGrGYNCtLr2b3cXrAEmDWj3il9eq1eer5suAJEC8cIU4NJSAn208+f3QzQAw6uowKqlk8E3cv6w4AQqMXnJP+IwH+jTTGYt9hk3/EQQCqKPbaVWHd1Z1AkmxYRXkfKrciJsBjKd88fAmqEAnbFprYgM3/gmqkBKuTAua/z0JhQleR4tRnt7D8qtvkSx36/D9WrikGhpulLNJE+HFR0BgexcVoByksFaJyAgx92IoRVTN3ArY8SpiCgLUSKtyEM+nMlDmgxCzKlMEJKQketesuNE5Ep7BYQ9aBiIQbGtR5kDoM/vrAakJvx0mSEZPixaV1TiBUX7p7OyQgxRk4o6Kt9X+pOUI+GaDqzOGy/OEQMHWkq9atwYedeEKJLYmnwAddInQe/24EEh8xfxBgJ2LUJmLh90RXA53ANA6oD5N6+ZTiHTqSfXxLVLQEttNaG0DoZdngqE2gZLqy4igWOEPn/8nqzj79d+k1LuUUhD1gSg3L9P2QUpFaD0R0lR+RfdDEUG8rIkAnGu6dw+V3yryJ6ppKM1I0WJzK9uHBV3B6xA0gJZlZ2rMf5WKpAHhtYk91DrGm19XcJOsTgxqNOdA8vA4iR6oEsaBusiADgRkojwM2g8BWqXhoLytqRy3FL0BFfi86s10kmpVaWQShSEiB3BuOSgHgR0DOuYjPObfaHmzDV3n1q04VLWmWKrMsuclApGxXWZOhQdBgAAzm/ITn1+opL9reW/VEpfDP6o0z+Vg1bdB5QCHK1WohYRze87Vkt+tzMB/f5SyUwtS4UMMpNhjwPsG4OYHSLl/RBQQw/5dloiApbH/k0LvIA0HERlWkba+TXrntqwGgEBBAygjYuobtzInd+/qOdPqaYHSrooaS33ou+sZgQQZwJWqwXrGZYIfhowyJgOA1DFkKggKqso9nouIDsvrRrdl3Jk36DYE0A6YCRcSVKQIDXeKbSKmlgulqF2X2ctFgitCgLpefeseG2CtB5L1o8mYCHXvTIJL5xLFwSpU7V9hAoUUUuvlEbu1YfWnkv9fvWGkbAjiaQTx0y+pViy+UOHInUsyr1uWbJOrfoC1uQH6EvEIDNMOz2AAuwHkxS6Co4ktdxJ03jjUSlRM6A9IZp9TjSfQx8grOoEF7ZNBWdM8n/iQWERp6I6+6xB3OqgkH6YqJSDUZCN9Zry3SugmVMBYL2UALFnxwTUDdx4pt4t/WZltEb0OREZgYnfreWWFdknjvdyBvcoP6cjsGMYh5xzhIGd2OLLgFCOM2qNuJRxX2cj+rrU0mKUMo1uFKi4JETHc2rtBdOgnmJpKjQ/SYW3D5k1aPnMKvVHWb4nQFArwrKSGOfWhGDxeavTtWpKSf1N1kAOTiDjhhNp6BDwQg4VCOjlAIiByRSYThNoRqrAixtVpb0+lVrTWpFxr+ScMh4jvsxnYSGX9gdGBy9aTxS1RcjrAaiMQK/+jpOJCUwsBEHVdykpsHaDp1MCKb2fWA9+SVmfp1JL7QNUuECuuyUFD1LTdqtkwhPAl1N/UZiA5vkUICCXxLOkTrVKB7DVXyyIaLGEYGBagw5MA6Pw0Hjjod0OzAwZzyB147Mm55D3wOkSoIWwqzcgT92piwS+DUjR4SkTfHybn5VYpwaF/O8VJ/vaz6kXgqAg9khuHaY5Aa8gTKIyhoSB+qDmmnqddwHCe9rMGnKuNaehHU1KHCZkWgJZQyQ2ZIVaFrxF1Y8KQaTVpdrbiJGXw6iWXiEEovU7RAtJtoVEVq+HCX+3gxycACYoIWG9BAA/DwwQwa2sQJwLzt9Kodppwxo4gmZuxQtIVA0WJ/M4LvlA2j+VdxEiv/larjsu/EBLHq4deHTzsFS3KUhJ/mMhCMg1cBgvLq90/g+45aW6mawcICbrJ6UlnfbUWvbpsZxMAhJN0go6D6Q3CenOQCsbF5X5lUKirggo7QEyavcaqXXCF/qFNzejHL6+Z7kkPB3WASDPTHis1znI0kqO8lBjligbw7mmB0gc59o8vCEsnG5wadYyKPw4ptjqY2dIncrUmsrjdqsodg9QPL7QBlSSYmiBgdwaHBKws8TcwOHgTbv3AOtZECigOvt3z9zB/duoMgzl0FqgV2dppFSaCpC9HCpAsU1KrxGTVeB9SSxCzi6IRAmFouhWpNHh9kVTZBHxFzer+0NMwL4VoG4iKLlONAERNPkbgUxmLSEtoByVp5JTHX9nES5qxvBis9oNGJ7RlYSeFgksUYQz4AdV27Oa7IdoTQJ19qvhH53+F8KPINiYBbDl2WyMA9t27Ski4zrNALCyzzU7b7qUKgIELgdbWQNYI5RBszXsVdxNq692rc0GKYaEvFpvm15Oq1l6xcIQKrZP/ecnf8vdmIGl2t8YXiloPQQA7wQMntV+AIg5y2VHgMa51pCGImwLQSjuZpIIFrq8mss4ao/ciOSorgsK0v17Krb7RocvsKO1kGuk8d4MDqZAJnn+P0CEVc8ODuzas3X/tdsOYl2nAOLp29Jgcs2V5/jNOc4RUYG35ZxQzVmUonKeUi6tWCqK3xfTiVbaXyycQT59tNrQ2k6vJ0hV7b/W9poifrS2n84caP/kkLAAb/kAQGX0a1bGcE2TerlZBDTWXQr15/R9zot+FprBq52TyMVVSxHljSw9tYVG8TOolb1RSzQylgMtyhatzVSNFGNSBCFDBHZwAzPkGy6+4gvjHXtrIsJ6VgaT4J/L3/nalwGALVzaGRU7OtzC08L234QRtIJofL+JNCegVVbSWsBOVhCW4n2XsufPeTt1OfbbUghaJT64hlSMANgzjifMOmECBvCmWVnxmu8tgGDNkwJlZyW3hx0HzX+WIuVm9bwCoYbTDgK02JrqRxILg5y/tboOScBdaK0/SV1LVDL/QlbglVCkZlS4/CvnfBhAoQ23PiOAB3+n5519OQ5Mp6aygyQQoLAgai/piFqBaGfcVEybgkr1YJEWLVjpRsa0n0IrUNpAgZBbfaq3aL/ta4ZvjjqcGYWydxZ2kdrDHAPIsuBUNzWalUmAgd2qMphQoq8STtXoiGGTDBPpEz4tfvUOzD4oJNkxFRLa+/r8z3PsyxBJur1acoYVk19af5ce+9UhqEALiGCrXm/feE992ee/ek54LdZ3AAjdn2brFSsrl176JRpZK5B6VZTmFuBHmfgTD5E4N5DeaRYHDvlVq8O4Jk6g5Zz+kwy2mD1pT/+1Moq1swAuAgAOTIAJDok6xKFTBZ7VkOUV5yWRo0C6awFnrRYME3SHl4gd0m4/vfQjRNa4OYjJSznHbEILdRAnmjAVyD7KGXQVOIoFk2uUAhlLKLEF17hpv5qzF5/5jXfsveiqRWIOIqjr3IwB3BQHPvX+14oluIADrEWn10lie8BH/y+cT5xVibXeH4jV/lvqS2DVZmFBEP8oev9rLBbhYqKpDAjxiZmAsQOWANj1wgQECc1qYDpBIgBEGTBp12pKwScSM9i4KN1ExDBkHME6gQf/8tYYDszevL0Hbf1/rF7uaXzFvqoyp9bUJ9DW/csPjO1JTnuQ/e8zJcdf/6f3vzbuv+ssZwFLp/37t8bX3nQdz1U9QBxRibTmQUGVmYX9ELJGhgBWE5qCgk8gq2T7lRjEWo6f3te2I9PNZAJrPcFa6YRfGEJ7aoBv+fHwQxMADJGbziB1DT38n2ZCVx2r4YUX4XbaJjDOL3b0z+OEnCtOh/bOdVWlK30Af7OOyTrAZwuJPRh0APMasNLx09YqrQ8QFpswCJYYrsF0NNo4+t6Xz/iXa7/wjRuIGa7p5ABS8DcGWNrpFj/w1j+tNloLqadpTj+Ar6TkwqQoDSNBqI0FtE9fgAyhrfEupGjBghKU1VJjbUygACBaJUu8AAX51FgFOiney77ZOpAF17zblXHAf0IPULAq56IInPk2Xp4D02lYZIUV4gzG+VscA4ZK8X0LEsWMfxb21PW61gGImQFrvj+trT6Rvx8g8gSQylRYqSf44ove9Dw46dQA18oCmLH0sTd+cXL+lV+vNg1HcPWU0wKeMt1OWEtL3os0QNha87cmIzCS0DjMoErp/EmoYxUwqGsH3AzIVxKIVov+ZHxD9tfriAcggExqD4G3Uyyl+ihIe9g402+paNkSpFDeoYJ+m8uEvBbcJLmv+HxrLpcM2aBlxxUJZ0YfioUfJLn/r0sCDu0/AUEaGS8MNo9O/4d3/PGucy/d29X+N5MFgIDJftnz6qc+muoGXMERSc2cywFKzh0ov6xKPi7BvaT0rbX/SyiqKDcpgvyKjRgVhMCajH4z2gCyxmGnDhspFIPUYWjI0f4ZsLxeBEGcXwRS6KXp0itN6UXnllUnLLXKhLjVNy7zjC82KTCRwxaiLAwSyT5KNZJWtX4AEIxfHlSk/sUkQNhCnPv+BCIDVzfjDXNHz5971hc/evaL/+k9zNwh/zd7XTQAG9SXfGXnnn/8m9+ujhzOw9RjMgJicaQQ9XYnNr6mhfw6ZX5HnvgjdXiojCCWoUCpGF1Q0lVmqLEAWQvpR94FX5S/YTg9pyWODEOmBEwOd1Xg+FrMmobGdazri/6MngWXoJRATA5sHJgdMbm0SGatTUxxwkttE4pLRuMhk6EGUktHy4ASF3s4sGuInfPbK1iAYvSHWgEj8v0YDFc34/n5I+Yvv+yC73z8D57/BExqkWKysbM1SwFjsPKBl35673s+9KL+MXObQPUYJIARr6BT1PiihFn1USFQaIEC71olQzstjxuoNOmofSasooXSauyqmGuJv9LqeYF0WDkAe1ZW1iopD6MMwL8Ybv/BsRw8OAUahvO5MBWz3KTWQkVF19WgalrooYUegwy4j7OhJDABNw61goPApQ3FWj+g1V9SbcAG5Br43YJCtGoCTLf+QAQ3c+Mj5o+e33LVNZe+79ef+ouTG3ZNiRndPtD/i2vEeRLn8hv+4NUHPvjRF9tj5zaAmzHE1WTFxf2cMeAL1CLYKK63xlauDBGh1AGITimrDxWtRKH3E5TOLmV9m57D5d8p3hd3E6TnjfssCdi5b8/6yAB27htj3+L1MLZHDg4EpaWWEV7SW35TipZHgEWXDLSaeplUYlr0zWIrbOz76quF4qK6jB+UpUGRtIROgV8QIg3V7Gi6YeGY+Yu/fe7n3/Mr/9/9Vq7ZPibDq0eeO/vP8QDUWHzt41+1/23vehZtGm2gETOkmcICZJGVekyo1SPvI3Z3ou9zqR5U7g9AqvtFv7+0aktBnv9fCzMq5sBzF+i/zvYCw1CMw8Et1xzeGUDQAMCBFSfXbf8q9ysHSF1MX6mwK5wd14W3KHaAXQBoXBRZjISfsC1I4lqwdmso7g4IaX7RsYnpGPkV4Zl7kFuFWvMfKUwwSMjRTMbDuQ2D3mjj6Ix3vus573v4//cbK1ffOO5Av//JtRI192aY/PP/96aDL/7zB2Aym5qjh/NAM4U0NYwkSW+w5wQIxTKB4Eq0WKn2IikGF7oBBor3n+cMCsIRl6XiatZf/DIXXaQiq1zdRWCIMPafe+4t/TLf8jNIcaHi0vgi/pUHPAuTyRgEE/i6AogQE5ExQZ9LrXsKs9fE7BsIhkE2/M/sBVsMg40J/+cbsb/PMMMYf2P2X0sfh68R+8f5VV8EZgND+XND7LfBCzsjNDNiZqPRwnDY39S74dIrzvnUU178kAte/97PY9pId/L/P/eMAGa4q8/dOj3zC/8oR9xxc3XnUx8oQ2tlMpuicTVcmAZZq1VPCqvRATwcMIS4AASlFPladOBVXT7Gf9Ljy2li6hRAHSCx7SBT9DYMsHj9hbjqpX8LmR7mASBsA8Z1N+2j446o6YE/9auyNF6Cc3VgxzkiamCZwCTCmZgvhoQMCRkWsiwwnD5mw8KGhA2Hx5CwNUIcPmYSNlYMG7Hx8cz+fvYfW2JhNmLIf2zBYoLKiAUaAzgW1FYw65F1g/5oMNffVPV6o96Oq675/hmvfcvjz3jKq16y/4Kr9qR2Zlfz/4iuGQMc3DZrznrP52YXX/4+2nDi8XTy7e4lG6oKxhiRegonU3GuFhJHRCJBXSgsaxSQeCkqUeMjLOGW2k5CJD4ZZBJK35tv/uukniOKGkJAaEDiPH4srqQukoCpAZEDw0HcBNWwAo7o4aJnPAjLF+4BGZQbhX/s4fVQBPXwY3uGzF897q/oN3/2tQIAkxrkJAE6Eok5HNQ6TdjVbnzKH0/9eJITkz/xw/8mnupB5NNYC8sMy4wq7P9LXyMDywRLBj0iVCBUqQXMsGAYGFTooQLDYYrxjj03Xv+N899z1YdPe9eW0755FQ6MPaBpupT/x3PdsFqgSaA7PfxY/oUn/C7f92FPlhNOvrsMgu/MANTwh2kT7nP+Y2n81+L94tTX63ALj0XjB8rFARS+T1rPlx6f7vO+L0588HdhxkXqfBiIbxELesDy3jEued6Dsf3d3y7/vsM5ALTAU/rpO53AD7v3b8vtT3gwLwxPRlya6btpAFkHYqaKTdAGEPhMwZEBszFgMl6y3ZiQqZOHCXwAIGMMLFPDxLVltszs2AmMYbbETBBXgZxly1VQ7+mx/yXIAc1kuljv2b/l4HU7Ljx4xXUX7r3oB5fv/e4V2+od++r0J1njHb9r8/2Yy0jjOQPR7Camk+6zGbe7753opLveA8eecneZ33xbsgtHC9kKjpiaSPMlIiELR4AjK0KMuvGlhLBFHa9LZjQANU0tDg4NmJw4cSLhMR60qgVoBJCm8Uw+YoIxEAdx4uBc4wMADJwTSDNBMzmI5Zuuxv7vn4mt7/ksVq5YPhTOf2gDwBodFABAFZUebiZziN9TUDZp7b9IWuCMi5kYrfGcktsCsW2ThskFmNWCmVvjV/JZibjO8Q8FNpDahmt9nQae/E+6J89a7DGgv0688+l6Pjx34ZTSurB010KwSrQCotJ5yimHzKTg/R4i5z/0AUADg+TTp1t/FhrHi8WneZ3T3zqCgdKK8E52K39folBoqkGwjgPAf+s3WittWOsb5Uf850m3z/snLSjcupHN7i3qrLPOOuuss84666yzzjrrrLPOOuuss84666yzzjrrrLPOOuuss84666yzzjrrrLPOOuuss84666yzzjrrrLPOOuuss84666yzzjrrrLPOOuuss84666yzzjrrrLPOOuuss84666yzzjrrrLPOOuuss84666yzzjrrrLPOOuuss84666yzzjrrrLPOOuuss84666yzzjrrrLPOOuuss84666yzzjrrrLPOOuuss84666yzzjrrrLPOOuuss84666yzzjrrrLPOOuuss84666yzzjrrrLPOOuuss84666yzH6X9/2yKxnNuqYSWAAAAAElFTkSuQmCC" alt=""><img class="mark-wordmark" src="data:image/png;base64,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" alt="Site Gateway"></div><h1>${title}</h1><p>${message}</p><div class="foot">Host. Proxy. Secure.</div></main></body></html>`;
  await fsp.writeFile(path.join(defaultSiteDir, "index.html"), html);
}


// renderCaddyfile -- builds the full Caddy JSON/Caddyfile config from current state
// (sites, proxies, redirects, streams, access lists, default site settings).
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


// syncCaddy -- applies the generated config to the running Caddy instance and
// records success/failure (gatewayError, lastGatewayReload) for the dashboard.
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


let configDrift = { checkedAt: null, drift: false, detail: null };
function caddyAdminRequest(options, body) {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: "127.0.0.1", port: 2019, timeout: 5000, ...options }, response => {
      let data = "";
      response.on("data", chunk => { data += chunk; });
      response.on("end", () => resolve({ status: response.statusCode, body: data }));
    });
    request.on("error", reject);
    request.on("timeout", () => request.destroy(new Error("Caddy admin API request timed out.")));
    if (body) request.write(body);
    request.end();
  });
}
async function checkConfigDrift() {
  try {
    const caddyfileContent = await fsp.readFile(caddyfilePath, "utf8").catch(() => null);
    if (!caddyfileContent) return;
    const [adapted, live] = await Promise.all([
      caddyAdminRequest({ method: "POST", path: "/adapt", headers: { "Content-Type": "text/caddyfile" } }, caddyfileContent),
      caddyAdminRequest({ method: "GET", path: "/config/" })
    ]);
    if (adapted.status !== 200 || live.status !== 200) return;
    const adaptedParsed = JSON.parse(adapted.body);
    const adaptedConfig = adaptedParsed && adaptedParsed.config !== undefined ? adaptedParsed.config : adaptedParsed;
    const liveConfig = JSON.parse(live.body);
    const drift = JSON.stringify(adaptedConfig) !== JSON.stringify(liveConfig);
    configDrift = { checkedAt: new Date().toISOString(), drift, detail: drift ? "Caddy\u2019s live configuration no longer matches the saved configuration." : null };
  } catch (error) {
    // Caddy admin API unreachable, or transient error: don\u2019t flag drift on a check we couldn\u2019t complete.
    configDrift = { ...configDrift, checkedAt: new Date().toISOString() };
  }
}

// --- Status helpers & public (client-facing, secret-stripped) view builders ------------------
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


// --- Certificate inventory & domain readiness diagnostics --------------------------------------
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


// --- Upstream (proxy target) health checks ------------------------------------------------------
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


// --- Access log ingestion (tailing Caddy's access log into SQLite) ------------------------------
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


// --- Raw TCP probing, used for streaming-host health checks --------------------------------------
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


// --- Icon catalog (searchable dashboard-icons list) & icon caching -------------------------------
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


// --- Dashboard snapshot: aggregates health/status across every subsystem for the
//     Overview page and the /api/dashboard endpoint --------------------------------------------
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
  if (configDrift.drift) attention.push({ kind: "drift", name: "Configuration drift", message: "Caddy\u2019s live configuration no longer matches the saved configuration.", target: "administration" });
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


// --- Hosted site process/lifecycle control --------------------------------------------------------
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

// --- Streaming host process/lifecycle control -------------------------------------------------------
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


// --- Upload handling (hosted site ZIP install) ------------------------------------------------------
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


// --- Backups: create / open / list / restore, including encryption -----------------------------------
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

// ============================================================================================
// HTTP layer: Express app setup, auth middleware, and every /api/* route.
// Routes below are grouped by area; see the section comments for each group.
// ============================================================================================
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


// --- Session / login / MFA login / logout ------------------------------------------------------------
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

// --- Public access-check endpoint used by Caddy's forward_auth for Access Lists -----------------------
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

// --- Themed login page served for Access-List-protected routes ------------------------------------------
app.get("/_site-gateway/login", (req, res) => {
  const listId = String(req.query.list || ""), list = accessLists.find(item => item.id === listId && item.enabled !== false);
  if (!list) return res.status(404).send("Access policy not found."); const safeReturn = String(req.query.return || "/").startsWith("/") ? String(req.query.return || "/") : "/";
  res.type("html").send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>Sign in · Site Gateway</title><style>:root{color-scheme:dark;--bg:#08101d;--panel:#101a2b;--line:#25344c;--text:#eef4ff;--muted:#95a4ba;--green:#62e6a7}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:22px;background:radial-gradient(circle 220px at 50% 0,#17372b 0,transparent 100%),var(--bg);color:var(--text);font-family:Inter,system-ui,sans-serif}.card{width:min(430px,100%);padding:34px;border:1px solid var(--line);border-radius:20px;background:var(--panel);box-shadow:0 24px 70px #0007}.mark{width:48px;height:48px;display:grid;place-items:center;border-radius:14px;background:#18362b;color:var(--green);font-weight:900}.eyebrow{margin:25px 0 7px;color:var(--green);font-size:11px;font-weight:850;letter-spacing:.13em;text-transform:uppercase}h1{margin:0;font-size:34px;letter-spacing:-.045em}p{color:var(--muted);line-height:1.55}label{display:block;margin-top:17px;font-size:13px;font-weight:700}input{display:block;width:100%;height:46px;margin-top:7px;padding:0 12px;border:1px solid var(--line);border-radius:10px;background:#0a1423;color:var(--text);font:inherit}button{width:100%;height:46px;margin-top:22px;border:0;border-radius:10px;background:var(--green);color:#05251a;font-weight:850;cursor:pointer}.error{color:#ff7185;font-size:13px}</style></head><body><form class="card" method="post" action="/_site-gateway/login"><div class="mark">SG</div><div class="eyebrow">Protected by Site Gateway</div><h1>Sign in to continue</h1><p>This service uses the <strong>${String(list.name).replace(/[<>]/g, "")}</strong> access policy.</p>${req.query.error ? '<p class="error">That username or password was not accepted.</p>' : ""}<input type="hidden" name="list" value="${listId}"><input type="hidden" name="return" value="${safeReturn.replaceAll('"', '&quot;')}"><label>Username<input name="username" autocomplete="username" required></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button>Sign in</button></form></body></html>`);
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

// --- First-run admin setup ---------------------------------------------------------------------------------
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

// --- Everything below requires an authenticated session (auth middleware applied above) --------------------
app.use("/api", (req, res, next) => { currentAuditActor = req.user?.id || null; return req.user.setupRequired ? res.status(428).json({ error: "Complete the initial administrator setup before continuing." }) : next(); });
app.use("/api", (req, res, next) => { if (req.path.startsWith("/account/")) return next(); if (req.method === "GET" || req.user.role === "administrator") return next(); const operational = /^\/(sites|proxies|redirects|streams|access-lists)(\/|$)/.test(req.path); if (req.user.role === "standard" && operational) return next(); return res.status(403).json({ error: "Administrator access is required for this action." }); });

// --- Account: password change & MFA setup/confirm/disable/recovery-codes -----------------------------------
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

// --- Config, Users, Audit log, Groups, Access List <-> Group assignment --------------------------------------
app.get("/api/config", (req, res) => res.json({ version: appVersion, minPort, maxPort, adminPort, storage: { engine: "sqlite", databasePath: storage.databasePath, instanceId: LOCAL_INSTANCE_ID, backupsPath: backupsDir, certificatesPath: certificatesRoot }, gateway: { enabled: true, error: gatewayError }, backup: { encryptionAvailable: Boolean(scheduledBackupPassword) } }));
app.post("/api/gateway/resync", async (req, res, next) => {
  if (req.user.role !== "administrator") return res.status(403).json({ error: "Administrator access is required." });
  try {
    await syncCaddy();
    configDrift = { checkedAt: new Date().toISOString(), drift: false, detail: null };
    recordActivity(`Gateway configuration re-synced by \u201c${req.user.username}\u201d.`);
    res.json({ ok: true });
  } catch (error) { next(error); }
});
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
app.post("/api/users/:id/mfa/disable", async (req, res, next) => {
  try {
    if (req.user.role !== "administrator") return res.status(403).json({ error: "Administrator access is required." });
    const user = users.find(item => item.id === req.params.id);
    if (!user) return res.status(404).json({ error: "User not found." });
    if (!user.mfaEnabled) return res.status(400).json({ error: "Two-factor authentication isn\u2019t enabled for this user." });
    user.mfaEnabled = false; user.mfaSecret = null; user.mfaPendingSecret = null; user.mfaRecoveryCodes = [];
    user.updatedAt = new Date().toISOString();
    await saveUsers();
    recordActivity(`Administrator “${req.user.username}” disabled two-factor authentication for “${user.username}”.`, "warning");
    res.json({ ok: true });
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

// --- Settings, dashboard, certificates, health checks, domain readiness ---------------------------------------
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

// GET /api/support-report -- generates the downloadable diagnostics report (gateway
// health, storage integrity, every route's config, certificate status, domain
// readiness, and recent activity) used for troubleshooting.
app.get("/api/support-report", async (req, res, next) => {
  try {
    if (req.user.role !== "administrator") return res.status(403).json({ error: "Administrator access is required." });
    const certificateReport = await certificateInventory();
    certificateReport.latestError = certificateReport.latestError ? { present:true, at:certificateReport.latestError.at } : null;
    const report = { product: "Site Gateway", generatedAt: new Date().toISOString(), version: appVersion, caddyVersion, nodeVersion: process.version, storage: { engine: "SQLite", integrity: storage.integrity() }, gateway: { healthy: !gatewayError, lastReload: lastGatewayReload }, routes: { hosted: sites.map(({ id,name,domain,tls,enabled,port }) => ({ id,name,domain,tls,enabled,port })), proxies: proxies.map(({ id,name,domain,tls,enabled,target,healthEnabled,healthExpected }) => ({ id,name,domain,tls,enabled,target,healthEnabled,healthExpected })), redirects: redirects.map(({ id,name,domain,tls,enabled,code }) => ({ id,name,domain,tls,enabled,code })) }, certificates: certificateReport, readiness: await domainReadiness(), recentEvents: recentActivity.slice(0,20).map(item => ({ at:item.at, status:item.status, message:item.status === "error" ? "Operational error recorded; review the protected in-app event log for details." : item.message })) };
    res.setHeader("Content-Disposition", `attachment; filename="site-gateway-support-${new Date().toISOString().slice(0,10)}.json"`); res.type("json").send(JSON.stringify(report, null, 2));
  } catch (error) { next(error); }
});

// --- Upstream health, Logs, and Performance (request throughput/trend) endpoints --------------------------------
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

// --- Icon search and per-entity icon upload/URL/removal -----------------------------------------------------------
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

// --- Hosted Sites: create / toggle / replace files / delete / edit --------------------------------------------------
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
    if (req.body.name !== undefined) {
      const name = String(req.body.name).trim();
      if (!name) return res.status(400).json({ error: "Site name is required." });
      site.name = name;
    }
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

// --- Proxy Hosts: create / edit / custom certificate upload / toggle / delete ---------------------------------------
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


// --- Access Lists: create / edit / assignments / delete ------------------------------------------------------------
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


// --- Redirect Hosts: create / edit / delete -------------------------------------------------------------------------
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


// --- Streaming Hosts: list / create / edit / toggle / delete -----------------------------------------------------------
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


// --- Settings (general), log retention/pruning, log download, factory reset ---------------------------------------------
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
app.post("/api/settings/reset-defaults", async (req, res, next) => { try { if (req.user.role !== "administrator") return res.status(403).json({ error:"Administrator access is required." }); if (String(req.body.confirmation || "") !== "RESTORE DEFAULT") return res.status(400).json({ error:"Type RESTORE DEFAULT exactly to continue." }); if (String(req.body.username || "").trim().toLowerCase() !== String(req.user.username || "").toLowerCase() || !await passwordMatches(String(req.body.password || ""), req.user.password)) return res.status(401).json({ error:"Administrator credentials were not accepted." }); settings.defaultSite = { mode:"themed404", redirectUrl:"", redirectCode:302, preservePath:true, title:"Route not found", message:"The gateway is responding, but this address has not been configured.", customHtml:"" }; settings.backups = { enabled:false, frequency:"daily", hour:2, retention:7, type:"complete", includeLogs:false, encrypt:false, lastRunAt:null, lastStatus:null }; settings.certificateHealth = { warningDays:30, criticalDays:7, staleMinutes:10 }; await saveSettings(); recordActivity("Gateway preferences restored to defaults."); res.json({ ...settings, backupDirectory:backupsDir }); } catch (error) { next(error); } });
app.post("/api/factory-reset", async (req, res, next) => { try { if (String(req.body.confirmation || "") !== "FACTORY RESET") return res.status(400).json({ error:"Type FACTORY RESET exactly to continue." }); if (String(req.body.username || "").toLowerCase() !== String(req.user.username || "").toLowerCase() || !await passwordMatches(String(req.body.password || ""), req.user.password)) return res.status(401).json({ error:"Administrator credentials were not accepted." }); await Promise.all([...activeServers.keys()].map(stopSite)); await Promise.all([...activeStreams.keys()].map(stopStream)); storage.close(); for (const directory of [sitesDir, uploadDir, caddyDir, iconsDir, logsDir, backupsDir, defaultSiteDir, certificatesRoot, path.join(dataDir,"database")]) await clearDirectoryContents(directory); storage = await openStorage(dataDir, backupsDir); sites = []; proxies = []; users = []; redirects = []; streams = []; accessLists = []; groups = []; settings = {}; recentActivity.splice(0); await loadSites(); await syncCaddy(); res.setHeader("Set-Cookie", "webserver_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"); res.status(202).json({ ok:true }); } catch (error) { next(error); } });

// --- Backups: list / create / import / download / restore / delete -----------------------------------------------------
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

// --- Error handling middleware & server startup -------------------------------------------------------------------------
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
setTimeout(() => checkConfigDrift().catch(error => console.warn("Config drift check failed:", error.message)), 10000).unref();
setInterval(() => checkConfigDrift().catch(error => console.warn("Config drift check failed:", error.message)), 10 * 60000).unref();


// --- Scheduled jobs: automatic backups, log pruning, public IP checks, graceful shutdown ---------------------------------
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
