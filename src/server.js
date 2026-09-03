import crypto from "node:crypto";
import dns from "node:dns/promises";
import { execFile } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import AdmZip from "adm-zip";
import express from "express";
import multer from "multer";
import { LOCAL_INSTANCE_ID, openStorage } from "./storage.js";

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
let sites = [];
let proxies = [];
let users = [];
let redirects = [];
let accessLists = [];
let settings = {};
let gatewayError = null;
let lastGatewayReload = null;
let caddyVersion = "Unknown";
const recentActivity = [];
const upstreamHealth = new Map();
const loginAttempts = new Map();
const probeFailures = { gateway: 0, http: 0, https: 0 };
let iconCatalog = null;
let storage;

function recordActivity(message, status = "ok") {
  const entry = { message, status, at: new Date().toISOString() };
  recentActivity.unshift(entry);
  recentActivity.splice(20);
  fsp.appendFile(activityLogPath, `${JSON.stringify(entry)}\n`).catch(() => {});
  try { storage?.recordAudit(message, status); } catch (error) { console.warn("Could not record SQLite audit event:", error.message); }
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
  const { password, sessionVersion, ...safe } = user;
  return safe;
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
const saveRedirects = async () => storage.saveCollection("redirects", redirects);
const saveAccessLists = async () => storage.saveCollection("access_lists", accessLists);
const saveSettings = async () => storage.saveSettings(settings);

async function loadSites() {
  await Promise.all([fsp.mkdir(sitesDir, { recursive: true }), fsp.mkdir(uploadDir, { recursive: true }), fsp.mkdir(caddyDir, { recursive: true }), fsp.mkdir(iconsDir, { recursive: true }), fsp.mkdir(logsDir, { recursive: true }), fsp.mkdir(backupsDir, { recursive: true }), fsp.mkdir(defaultSiteDir, { recursive: true }), fsp.mkdir(customCertificatesDir, { recursive: true }), fsp.mkdir(managedCertificatesDir, { recursive: true }), fsp.mkdir(certificateExportsDir, { recursive: true })]);
  if (!storage) storage = await openStorage(dataDir, backupsDir);
  if (storage.snapshot) { recordActivity(`Legacy JSON migrated to SQLite. Safety backup: ${storage.snapshot.filename}.`); storage.snapshot = null; }
  sites = storage.loadCollection("sites");
  proxies = storage.loadCollection("proxies");
  try {
    const lines = (await fsp.readFile(activityLogPath, "utf8")).trim().split("\n").slice(-20).reverse();
    recentActivity.push(...lines.map(line => JSON.parse(line)));
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
  }
  if (usersChanged) await saveUsers();
  redirects = storage.loadCollection("redirects");
  accessLists = storage.loadCollection("access_lists");
  const defaultSettings = {
    defaultSite: { mode: "themed404", redirectUrl: "", redirectCode: 302, preservePath: true, title: "Route not found", message: "The gateway is responding, but this address has not been configured.", customHtml: "" },
    backups: { enabled: false, frequency: "daily", hour: 2, retention: 7, type: "configuration", includeLogs: false, encrypt: false, lastRunAt: null, lastStatus: null },
    certificateHealth: { warningDays: 30, criticalDays: 7, staleMinutes: 10 }
  };
  const storedSettings = storage.loadSettings() || defaultSettings;
  settings = { ...defaultSettings, ...storedSettings, defaultSite: { ...defaultSettings.defaultSite, ...(storedSettings.defaultSite || {}) }, backups: { ...defaultSettings.backups, ...(storedSettings.backups || {}) }, certificateHealth: { ...defaultSettings.certificateHealth, ...(storedSettings.certificateHealth || {}) } };
  await saveSettings();
}

function normalizeDomain(value) {
  return String(value || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, "");
}

function validateDomain(domain, exceptId) {
  if (!domain) return null;
  if (domain.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) return "Enter a valid public domain such as app.example.com.";
  if ([...sites, ...proxies, ...redirects].some(item => item.domain === domain && item.id !== exceptId)) return "That domain is already assigned.";
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
  if (body.accessListId !== undefined) item.accessListId = String(body.accessListId || "");
  if (body.compression !== undefined) item.compression = ["off", "gzip", "automatic"].includes(body.compression) ? body.compression : "automatic";
  if (body.hstsSubdomains !== undefined) item.hstsSubdomains = Boolean(body.hstsSubdomains);
  if (body.requestHeaders !== undefined) item.requestHeaders = cleanHeaders(body.requestHeaders);
  if (body.responseHeaders !== undefined) item.responseHeaders = cleanHeaders(body.responseHeaders);
  if (body.upstreamTlsServerName !== undefined) item.upstreamTlsServerName = String(body.upstreamTlsServerName || "").trim().slice(0, 253);
  if (body.upstreamTlsInsecure !== undefined) item.upstreamTlsInsecure = Boolean(body.upstreamTlsInsecure);
  if (body.healthEnabled !== undefined) item.healthEnabled = Boolean(body.healthEnabled);
  if (body.healthPath !== undefined) item.healthPath = /^\//.test(body.healthPath || "") ? String(body.healthPath).slice(0, 500) : "/";
  if (body.healthMethod !== undefined) item.healthMethod = ["GET", "HEAD"].includes(body.healthMethod) ? body.healthMethod : "GET";
  if (body.healthExpected !== undefined) {
    const expected = String(body.healthExpected || "200-499").trim().slice(0, 80);
    if (!/^\d{3}(?:\s*-\s*\d{3})?(?:\s*,\s*\d{3}(?:\s*-\s*\d{3})?)*$/.test(expected)) throw Object.assign(new Error("Expected status must contain HTTP codes or ranges, such as 200,204 or 200-399."), { status: 400 });
    item.healthExpected = expected;
  }
  if (body.healthTimeoutSeconds !== undefined) item.healthTimeoutSeconds = Math.min(Math.max(Number(body.healthTimeoutSeconds) || 4, 1), 60);
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
  return item.tls === "http" ? `http://${item.domain}` : item.domain;
}

function caddyQuote(value) {
  return `"${String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("\n", " ")}"`;
}

function accessDirectives(accessListId) {
  const list = accessLists.find(item => item.id === accessListId && item.enabled !== false);
  if (!list) return [];
  const output = [];
  if (list.deniedNetworks?.length) output.push(`  @blocked-${list.id} remote_ip ${list.deniedNetworks.join(" ")}`, `  abort @blocked-${list.id}`);
  if (list.networks?.length) {
    output.push(`  @outside-${list.id} not remote_ip ${list.networks.join(" ")}`, `  abort @outside-${list.id}`);
  }
  if (list.credentials?.length) {
    output.push(`  @protected-${list.id} not path /_site-gateway/*`, `  forward_auth @protected-${list.id} 127.0.0.1:${adminPort} {`, `    uri /api/access-check?list=${list.id}`, "  }", `  handle /_site-gateway/* {`, `    reverse_proxy 127.0.0.1:${adminPort}`, "  }");
  }
  return output;
}

function commonHostDirectives(item) {
  const output = [...accessDirectives(item.accessListId)];
  if (item.compression !== "off") output.push(item.compression === "gzip" ? "  encode gzip" : "  encode zstd gzip");
  for (const header of item.responseHeaders || []) output.push(`  header ${header.name} ${caddyQuote(header.value)}`);
  if (item.hsts && item.tls !== "http") output.push(`  header Strict-Transport-Security ${caddyQuote(`max-age=31536000${item.hstsSubdomains ? "; includeSubDomains" : ""}`)}`);
  if (item.tls === "internal") output.push("  tls internal");
  if (item.tls === "custom" && item.certificatePath && item.keyPath) output.push(`  tls ${caddyQuote(item.certificatePath)} ${caddyQuote(item.keyPath)}`);
  return output;
}

function proxyBlock(target, item, indent = "  ") {
  const output = [`${indent}reverse_proxy ${target} {`];
  const timeout = Math.min(Math.max(Number(item.healthTimeoutSeconds) || 4, 1), 60);
  if (item.upstreamTlsServerName) output.push(`${indent}  transport http {`, `${indent}    tls_server_name ${item.upstreamTlsServerName}`, ...(item.upstreamTlsInsecure ? [`${indent}    tls_insecure_skip_verify`] : []), `${indent}    response_header_timeout ${timeout}s`, `${indent}  }`);
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
    : `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark light"><title>${title}</title><style>:root{color-scheme:dark light;--bg:#08101d;--card:#101a2b;--line:#25344c;--text:#eef4ff;--muted:#95a4ba;--green:#62e6a7}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 50% 0,#163829 0,transparent 42%),var(--bg);color:var(--text);font-family:Inter,system-ui,sans-serif}.card{width:min(620px,100%);padding:44px;border:1px solid var(--line);border-radius:22px;background:color-mix(in srgb,var(--card) 94%,transparent);box-shadow:0 28px 80px #0006}.mark{width:54px;height:54px;border-radius:15px;display:grid;place-items:center;background:#17352a;color:var(--green);font-weight:900}.eyebrow{margin:28px 0 10px;color:var(--green);font-size:12px;font-weight:800;letter-spacing:.14em;text-transform:uppercase}h1{margin:0;font-size:clamp(34px,7vw,56px);letter-spacing:-.05em;line-height:1.02}p{color:var(--muted);font-size:17px;line-height:1.65;margin:20px 0 0}.foot{padding-top:28px;margin-top:30px;border-top:1px solid var(--line);font-size:13px;color:var(--muted)}@media(prefers-color-scheme:light){:root{--bg:#f3f6fa;--card:#fff;--line:#d6dfeb;--text:#132033;--muted:#637188;--green:#138a5b}}</style></head><body><main class="card"><div class="mark">SG</div><div class="eyebrow">Site Gateway</div><h1>${title}</h1><p>${message}</p><div class="foot">Host. Proxy. Secure.</div></main></body></html>`;
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
  for (const site of sites.filter(item => item.enabled && item.domain)) {
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
      sites = storage.loadCollection("sites"); proxies = storage.loadCollection("proxies"); redirects = storage.loadCollection("redirects"); accessLists = storage.loadCollection("access_lists"); settings = storage.loadSettings() || settings;
    } catch { /* Startup may not have completed database initialization yet. */ }
    gatewayError = rollbackSucceeded ? null : rejectedReason;
    throw Object.assign(new Error(`Gateway configuration was rejected: ${rejectedReason}${rollbackSucceeded ? " The previous working configuration remains active." : ""}`), { status: 400 });
  }
}

function siteStatus(site) {
  if (!site.enabled) return "disabled";
  if (site.domain && gatewayError) return "error";
  return activeServers.has(site.id) ? "running" : "error";
}

function publicSite(site) {
  return { ...site, status: siteStatus(site), url: `http://${site.host || "localhost"}:${site.port}` };
}

function publicProxy(proxy, includeAdvanced = false) {
  const { certificatePath, keyPath, ...safe } = proxy;
  if (!includeAdvanced) { delete safe.customConfig; delete safe.requestHeaders; }
  return { ...safe, certificatePath: certificatePath ? "installed" : null, hasCustomCertificate: Boolean(certificatePath && keyPath), status: proxy.enabled ? (gatewayError ? "error" : "running") : "disabled", upstream: upstreamHealth.get(proxy.id) || null };
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
  const configured = [...sites.map(item => ({ ...item, kind: "Hosted site" })), ...proxies.map(item => ({ ...item, kind: "Proxy host" }))]
    .filter(item => item.enabled && item.domain && item.tls !== "http");
  const parsed = [];
  const certificateFiles = [...await walkFiles(certificateDir), ...await walkFiles(customCertificatesDir)];
  for (const filename of certificateFiles.filter(file => /\.(?:crt|pem)$/i.test(file))) {
    try {
      const certificate = new crypto.X509Certificate(await fsp.readFile(filename));
      const stat = await fsp.stat(filename);
      parsed.push({ certificate, names: certificateNames(certificate), updatedAt: stat.mtime.toISOString(), filename, source: filename.startsWith(customCertificatesDir) ? "Custom upload" : "Caddy / ACME" });
    } catch { /* Ignore non-certificate PEM files and unreadable entries. */ }
  }
  const certificates = configured.map(item => {
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
  const latestError = recentActivity.find(item => item.status === "error" && /cert|tls|acme|caddy|gateway/i.test(item.message)) || null;
  return { checkedAt: new Date().toISOString(), thresholds: settings.certificateHealth, latestError, summary: { total: certificates.length, healthy: certificates.filter(item => item.status === "healthy").length, within30Days: certificates.filter(item => item.daysRemaining != null && item.daysRemaining <= 30 && item.daysRemaining > 0).length, within7Days: certificates.filter(item => item.daysRemaining != null && item.daysRemaining <= 7 && item.daysRemaining > 0).length, warning: certificates.filter(item => item.status === "warning").length, critical: certificates.filter(item => item.status === "critical").length, expired: certificates.filter(item => item.status === "expired").length, pending: certificates.filter(item => item.status === "pending").length, mismatch: certificates.filter(item => item.status === "mismatch").length }, certificates };
}

async function domainReadiness() {
  const routes = [...sites.map(item => ({ ...item, kind: "Hosted site" })), ...proxies.map(item => ({ ...item, kind: "Proxy host" })), ...redirects.map(item => ({ ...item, kind: "Redirect host" }))].filter(item => item.enabled && item.domain);
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
  if (!proxy.enabled) return { status: "disabled", checkedAt: new Date().toISOString(), history: [] };
  if (proxy.healthEnabled === false) return { status: "unmonitored", checkedAt: null, history: [] };
  const started = performance.now();
  let result;
  try {
    const target = new URL(proxy.healthPath || "/", `${proxy.target}/`).toString();
    const response = await fetch(target, { method: proxy.healthMethod || "GET", redirect: "manual", signal: AbortSignal.timeout((proxy.healthTimeoutSeconds || 4) * 1000), headers: { "user-agent": "Site-Gateway-Health/1.0" } });
    await response.body?.cancel();
    const responseMs = Math.round(performance.now() - started);
    const accepted = expectedStatusMatches(response.status, proxy.healthExpected);
    result = { status: accepted ? "healthy" : "unhealthy", httpStatus: response.status, responseMs, checkedAt: new Date().toISOString(), error: accepted ? null : `Expected ${proxy.healthExpected || "200-499"}; received HTTP ${response.status}` };
  } catch (error) {
    result = { status: "unhealthy", httpStatus: null, responseMs: Math.round(performance.now() - started), checkedAt: new Date().toISOString(), error: error.name === "TimeoutError" ? `Timed out after ${proxy.healthTimeoutSeconds || 4} seconds` : error.message };
  }
  const previous = upstreamHealth.get(proxy.id);
  result.history = [{ status: result.status, responseMs: result.responseMs, httpStatus: result.httpStatus, checkedAt: result.checkedAt }, ...(previous?.history || [])].slice(0, 20);
  upstreamHealth.set(proxy.id, result);
  return result;
}

async function checkAllProxies() {
  await Promise.all(proxies.map(checkProxy));
  return proxies.map(publicProxy);
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
        entries.push({ at: raw.ts ? new Date(raw.ts * 1000).toISOString() : null, host: requestHost, method: request.method, uri: request.uri, status: raw.status, size: raw.size, durationMs: Number.isFinite(raw.duration) ? Math.round(raw.duration * 1000) : null, remoteIp: request.remote_ip || null });
        if (entries.length >= limit) return entries;
      } catch { /* Skip incomplete lines while Caddy writes. */ }
    }
  }
  return entries;
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
      databaseBytes: (await fsp.stat(storage.databasePath).catch(() => null))?.size || 0
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

const portableCollections = { "sites.json": () => sites, "proxies.json": () => proxies, "redirects.json": () => redirects, "access-lists.json": () => accessLists, "users.json": () => users, "settings.json": () => settings };

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
      storage.saveCollection("sites", []); storage.saveCollection("proxies", []); storage.saveCollection("redirects", []);
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
    await Promise.all([...activeServers.keys()].map(stopSite)); sites = []; proxies = []; users = []; redirects = []; accessLists = []; settings = {}; recentActivity.splice(0); await loadSites();
    for (const site of sites.filter(item => item.enabled)) await startSite(site);
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
app.disable("x-powered-by");
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(publicDir));
app.use("/site-icons", express.static(iconsDir, { immutable: true, maxAge: "30d", setHeaders: res => res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'") }));

app.get("/api/session", (req, res) => {
  const user = sessionUser(req);
  res.json({ authenticated: Boolean(user), setupRequired: Boolean(user?.setupRequired), installationSetupPending: users.some(item => item.setupRequired), user: user ? publicUser(user) : null, username: user?.username || null });
});
app.post("/api/login", async (req, res, next) => {
  try {
    const key = req.ip || req.socket.remoteAddress || "unknown";
    const attempt = loginAttempts.get(key) || { count: 0, resetAt: Date.now() + 15 * 60 * 1000 };
    if (attempt.resetAt <= Date.now()) { attempt.count = 0; attempt.resetAt = Date.now() + 15 * 60 * 1000; }
    if (attempt.count >= 8) return res.status(429).json({ error: "Too many sign-in attempts. Try again in 15 minutes." });
    const username = String(req.body.username || "").trim().toLowerCase();
    const user = users.find(item => item.username === username);
    if (!user || user.status !== "active" || !await passwordMatches(req.body.password || "", user.password)) {
      attempt.count += 1; loginAttempts.set(key, attempt);
      return res.status(401).json({ error: "Incorrect username or password." });
    }
    loginAttempts.delete(key);
    user.lastLoginAt = new Date().toISOString(); user.updatedAt = user.lastLoginAt; await saveUsers();
    if (!user.sessionVersion) user.sessionVersion = crypto.randomBytes(16).toString("hex");
    const expires = String(Date.now() + 12 * 60 * 60 * 1000);
    const value = `${user.id}.${expires}.${user.sessionVersion}`;
    res.setHeader("Set-Cookie", `webserver_session=${value}.${sign(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200`);
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
app.get("/api/access-check", (req, res) => {
  const listId = String(req.query.list || ""), list = accessLists.find(item => item.id === listId && item.enabled !== false);
  if (!list || !list.credentials?.length) return res.status(204).end();
  const username = accessSession(req, listId); if (username) { res.setHeader("X-Site-Gateway-User", username); return res.status(204).end(); }
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
    const listId = String(req.body.list || ""), list = accessLists.find(item => item.id === listId && item.enabled !== false), username = String(req.body.username || "").trim(); const credential = list?.credentials?.find(item => item.username === username);
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
app.use("/api", (req, res, next) => req.user.setupRequired ? res.status(428).json({ error: "Complete the initial administrator setup before continuing." }) : next());
app.use("/api", (req, res, next) => req.user.role === "administrator" || req.method === "GET" ? next() : res.status(403).json({ error: "Administrator access is required to make changes." }));
app.get("/api/config", (req, res) => res.json({ version: appVersion, minPort, maxPort, adminPort, storage: { engine: "sqlite", databasePath: storage.databasePath, instanceId: LOCAL_INSTANCE_ID, backupsPath: backupsDir, certificatesPath: certificatesRoot }, gateway: { enabled: true, error: gatewayError } }));
app.get("/api/users", (req, res) => req.user.role === "administrator" ? res.json(users.map(publicUser)) : res.status(403).json({ error: "Administrator access is required." }));
app.post("/api/users", async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const displayName = String(req.body.displayName || "").trim();
    const password = String(req.body.password || "");
    const role = req.body.role === "administrator" ? "administrator" : "standard";
    if (!/^[a-z0-9][a-z0-9._-]{2,63}$/.test(username)) return res.status(400).json({ error: "Username must be 3–64 characters using letters, numbers, periods, hyphens, or underscores." });
    if (users.some(user => user.username === username)) return res.status(409).json({ error: "That username already exists." });
    if (!displayName || displayName.length > 80) return res.status(400).json({ error: "Display name is required and must be 80 characters or fewer." });
    if (password.length < 8) return res.status(400).json({ error: "Password must contain at least 8 characters." });
    const now = new Date().toISOString();
    const user = { id: crypto.randomUUID(), username, displayName, role, status: "active", password: await passwordRecord(password), source: "local", createdAt: now, updatedAt: now, lastLoginAt: null };
    users.push(user); await saveUsers(); recordActivity(`User “${user.username}” created as ${role === "administrator" ? "Administrator" : "Standard User"}.`);
    res.status(201).json(publicUser(user));
  } catch (error) { next(error); }
});
app.patch("/api/users/:id", async (req, res, next) => {
  try {
    const user = users.find(item => item.id === req.params.id);
    if (!user) return res.status(404).json({ error: "User not found." });
    const nextRole = req.body.role === undefined ? user.role : req.body.role === "administrator" ? "administrator" : "standard";
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
    user.updatedAt = new Date().toISOString(); await saveUsers(); recordActivity(`User “${user.username}” updated · ${user.role === "administrator" ? "Administrator" : "Standard User"} · ${user.status}.`);
    res.json(publicUser(user));
  } catch (error) { next(error); }
});
app.get("/api/sites", (req, res) => res.json(sites.map(publicSite)));
app.get("/api/proxies", (req, res) => res.json(proxies.map(proxy => publicProxy(proxy, req.user.role === "administrator"))));
app.get("/api/redirects", (req, res) => res.json(redirects));
app.get("/api/access-lists", (req, res) => res.json(accessLists.map(({ credentials, ...item }) => ({ ...item, credentials: (credentials || []).map(({ username }) => ({ username })) }))));
app.get("/api/settings", (req, res) => req.user.role === "administrator" ? res.json({ ...settings, backupDirectory: backupsDir }) : res.status(403).json({ error: "Administrator access is required." }));
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
    res.json({ entries: await readAccessLogs(limit, host), hosts: [...new Set([...sites, ...proxies].map(item => item.domain).filter(Boolean))].sort(), activity: recentActivity });
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
app.put("/api/:kind/:id/icon", async (req, res, next) => {
  try {
    const collection = req.params.kind === "sites" ? sites : req.params.kind === "proxies" ? proxies : null;
    if (!collection) return res.status(404).json({ error: "Entry type not found." });
    const item = collection.find(entry => entry.id === req.params.id);
    if (!item) return res.status(404).json({ error: "Entry not found." });
    const slug = String(req.body.slug || "").trim();
    const icon = slug ? await cacheIcon(slug) : null;
    item.iconSlug = slug || null;
    item.icon = icon;
    if (collection === sites) await saveSites(); else await saveProxies();
    recordActivity(`${slug ? "Icon updated" : "Icon reset"} for “${item.name}”.`);
    res.json(collection === sites ? publicSite(item) : publicProxy(item));
  } catch (error) { next(error); }
});
app.post("/api/sites", upload.single("files"), async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const port = Number.parseInt(req.body.port, 10);
    const domain = normalizeDomain(req.body.domain);
    const tls = ["http", "automatic", "internal"].includes(req.body.tls) ? req.body.tls : "automatic";
    const hsts = req.body.hsts === "true";
    const id = `${slugify(name) || "site"}-${crypto.randomBytes(3).toString("hex")}`;
    if (!name) throw Object.assign(new Error("Site name is required."), { status: 400 });
    const portError = validatePort(port);
    if (portError) throw Object.assign(new Error(portError), { status: 400 });
    const domainError = validateDomain(domain);
    if (domainError) throw Object.assign(new Error(domainError), { status: 400 });
    if (!req.file) throw Object.assign(new Error("Choose a ZIP file or index.html."), { status: 400 });
    const site = { id, name, port, domain, tls, hsts, enabled: true, createdAt: new Date().toISOString() };
    await installUpload(site, req.file);
    sites.push(site);
    try { await startSite(site); } catch (error) { console.error(error); }
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
    await saveSites();
    recordActivity(`Hosted site “${site.name}” deleted.`);
    res.status(204).end();
  } catch (error) { next(error); }
});
app.patch("/api/sites/:id", async (req, res, next) => {
  try {
    const site = sites.find(item => item.id === req.params.id);
    if (!site) return res.status(404).json({ error: "Site not found." });
    const domain = normalizeDomain(req.body.domain);
    const domainError = validateDomain(domain, site.id);
    if (domainError) return res.status(400).json({ error: domainError });
    site.domain = domain;
    site.tls = ["http", "automatic", "internal"].includes(req.body.tls) ? req.body.tls : "automatic";
    site.hsts = req.body.hsts === true;
    await syncCaddy();
    await saveSites();
    recordActivity(`Gateway settings updated for “${site.name}”.`);
    res.json(publicSite(site));
  } catch (error) { next(error); }
});
app.post("/api/proxies", async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const domain = normalizeDomain(req.body.domain);
    if (!name) return res.status(400).json({ error: "Proxy name is required." });
    const domainError = validateDomain(domain);
    if (domainError || !domain) return res.status(400).json({ error: domainError || "Domain is required." });
    const proxy = {
      id: `${slugify(name) || "proxy"}-${crypto.randomBytes(3).toString("hex")}`,
      name,
      domain,
      target: validateTarget(req.body.target),
      tls: ["http", "automatic", "internal"].includes(req.body.tls) ? req.body.tls : "automatic",
      hsts: req.body.hsts === true,
      enabled: true,
      createdAt: new Date().toISOString()
    };
    applyAdvancedSettings(proxy, req.body);
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
    if (req.body.domain !== undefined) {
      const domain = normalizeDomain(req.body.domain);
      const domainError = validateDomain(domain, proxy.id);
      if (domainError || !domain) return res.status(400).json({ error: domainError || "Domain is required." });
      proxy.domain = domain;
    }
    if (req.body.name !== undefined) {
      const name = String(req.body.name).trim();
      if (!name) return res.status(400).json({ error: "Proxy name is required." });
      proxy.name = name;
    }
    if (req.body.target !== undefined) proxy.target = validateTarget(req.body.target);
    if (req.body.tls !== undefined) proxy.tls = req.body.tls === "custom" && proxy.certificatePath && proxy.keyPath ? "custom" : ["http", "automatic", "internal"].includes(req.body.tls) ? req.body.tls : proxy.tls;
    if (req.body.hsts !== undefined) proxy.hsts = req.body.hsts === true;
    applyAdvancedSettings(proxy, req.body);
    await syncCaddy();
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
    if (!certificate.checkHost(proxy.domain)) return res.status(400).json({ error: `The certificate does not cover ${proxy.domain}.` });
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
    const item = { id: `access-${crypto.randomBytes(4).toString("hex")}`, name, networks, deniedNetworks, credentials, enabled: true, createdAt: new Date().toISOString() };
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
    if (Array.isArray(req.body.credentials) && req.body.credentials.length) {
      const credentials = [];
      for (const entry of req.body.credentials.slice(0, 25)) { const username = String(entry.username || "").trim(), password = String(entry.password || ""); if (!/^[A-Za-z0-9._-]{1,64}$/.test(username) || password.length < 8) return res.status(400).json({ error: "Access usernames must be valid and passwords must contain at least 8 characters." }); const { stdout } = await execFileAsync("caddy", ["hash-password", "--plaintext", password]); credentials.push({ username, hash: stdout.trim(), password: await passwordRecord(password) }); }
      item.credentials = credentials;
    }
    if (!(item.networks || []).length && !(item.deniedNetworks || []).length && !(item.credentials || []).length) return res.status(400).json({ error: "Keep at least one network rule or login." });
    await syncCaddy(); await saveAccessLists(); recordActivity(`Access List “${item.name}” updated.`); res.json({ ...item, credentials: (item.credentials || []).map(({ username }) => ({ username })) });
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
    const name = String(req.body.name || "").trim(); const domain = normalizeDomain(req.body.domain); const target = String(req.body.target || "").trim().replace(/\/$/, "");
    const domainError = validateDomain(domain); if (!name || domainError || !domain) return res.status(400).json({ error: domainError || "Name and source domain are required." });
    try { const parsed = new URL(target); if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error(); } catch { return res.status(400).json({ error: "Destination must be a complete HTTP or HTTPS URL." }); }
    const item = { id: `redirect-${crypto.randomBytes(4).toString("hex")}`, name, domain, target, code: [301,302,307,308].includes(Number(req.body.code)) ? Number(req.body.code) : 302, preservePath: req.body.preservePath !== false, tls: ["http","automatic","internal"].includes(req.body.tls) ? req.body.tls : "automatic", hsts: Boolean(req.body.hsts), accessListId: String(req.body.accessListId || ""), enabled: true, createdAt: new Date().toISOString() };
    redirects.push(item); await syncCaddy(); await saveRedirects(); recordActivity(`Redirect Host “${name}” created.`); res.status(201).json(item);
  } catch (error) { next(error); }
});
app.patch("/api/redirects/:id", async (req, res, next) => {
  try {
    const item = redirects.find(value => value.id === req.params.id); if (!item) return res.status(404).json({ error: "Redirect Host not found." });
    if (req.body.domain !== undefined) { const domain = normalizeDomain(req.body.domain); const error = validateDomain(domain, item.id); if (error || !domain) return res.status(400).json({ error: error || "Source domain is required." }); item.domain = domain; }
    if (req.body.enabled !== undefined) item.enabled = Boolean(req.body.enabled);
    for (const key of ["name","target","accessListId"]) if (req.body[key] !== undefined) item[key] = String(req.body[key]).trim();
    if (req.body.target !== undefined) { try { const parsed = new URL(item.target); if (!['http:','https:'].includes(parsed.protocol)) throw new Error(); } catch { return res.status(400).json({ error: "Destination must be a complete HTTP or HTTPS URL." }); } }
    if (req.body.code !== undefined && [301,302,307,308].includes(Number(req.body.code))) item.code = Number(req.body.code);
    if (req.body.preservePath !== undefined) item.preservePath = Boolean(req.body.preservePath);
    if (req.body.tls !== undefined) item.tls = ["http","automatic","internal"].includes(req.body.tls) ? req.body.tls : item.tls;
    if (req.body.hsts !== undefined) item.hsts = Boolean(req.body.hsts);
    await syncCaddy(); await saveRedirects(); recordActivity(`Redirect Host “${item.name}” updated.`); res.json(item);
  } catch (error) { next(error); }
});
app.delete("/api/redirects/:id", async (req, res, next) => {
  try { const index = redirects.findIndex(item => item.id === req.params.id); if (index < 0) return res.status(404).json({ error: "Redirect Host not found." }); const [item] = redirects.splice(index, 1); await syncCaddy(); await saveRedirects(); recordActivity(`Redirect Host “${item.name}” deleted.`); res.status(204).end(); } catch (error) { next(error); }
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
    await syncCaddy(); await saveSettings(); recordActivity("Administration settings updated."); res.json({ ...settings, backupDirectory: backupsDir });
  } catch (error) { next(error); }
});
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
app.use((error, req, res, next) => {
  console.error(error);
  recordActivity(`${req.method} ${req.path}: ${error.message || "Unexpected gateway error"}`, "error");
  res.status(error.status || 500).json({ error: error.message || "Something went wrong." });
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

async function shutdown() {
  await Promise.all([...activeServers.keys()].map(stopSite));
  try { storage?.close(); } catch { /* Database may already be closed during restore. */ }
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
