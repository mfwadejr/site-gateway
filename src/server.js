import crypto from "node:crypto";
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

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageMetadata = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
const appVersion = process.env.APP_VERSION || packageMetadata.version;
const publicDir = path.join(__dirname, "public");
const dataDir = path.resolve(process.env.DATA_DIR || "/data");
const sitesDir = path.join(dataDir, "sites");
const configPath = path.join(dataDir, "sites.json");
const proxiesPath = path.join(dataDir, "proxies.json");
const usersPath = path.join(dataDir, "users.json");
const uploadDir = path.join(dataDir, ".uploads");
const caddyDir = path.join(dataDir, "caddy");
const iconsDir = path.join(dataDir, "icons");
const logsDir = path.join(dataDir, "logs");
const accessLogPath = path.join(logsDir, "access.json");
const activityLogPath = path.join(logsDir, "activity.jsonl");
const certificateDir = path.join(caddyDir, "data", "caddy", "certificates");
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
const activeServers = new Map();
let sites = [];
let proxies = [];
let users = [];
let gatewayError = null;
let lastGatewayReload = null;
let caddyVersion = "Unknown";
const recentActivity = [];
const upstreamHealth = new Map();
const loginAttempts = new Map();
const probeFailures = { gateway: 0, http: 0, https: 0 };
let iconCatalog = null;

function recordActivity(message, status = "ok") {
  const entry = { message, status, at: new Date().toISOString() };
  recentActivity.unshift(entry);
  recentActivity.splice(20);
  fsp.appendFile(activityLogPath, `${JSON.stringify(entry)}\n`).catch(() => {});
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
  const { password, ...safe } = user;
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
  const [userId, expires, signature] = token.split(".");
  if (!userId || Number(expires) <= Date.now() || !safeEqual(signature || "", sign(`${userId}.${expires}`))) return null;
  return users.find(user => user.id === userId && user.status === "active") || null;
}

async function saveSites() {
  await fsp.writeFile(configPath, JSON.stringify(sites, null, 2));
}

async function saveProxies() {
  await fsp.writeFile(proxiesPath, JSON.stringify(proxies, null, 2));
}

async function saveUsers() {
  const nextPath = `${usersPath}.next`;
  await fsp.writeFile(nextPath, JSON.stringify(users, null, 2), { mode: 0o600 });
  await fsp.rename(nextPath, usersPath);
}

async function loadSites() {
  await Promise.all([fsp.mkdir(sitesDir, { recursive: true }), fsp.mkdir(uploadDir, { recursive: true }), fsp.mkdir(caddyDir, { recursive: true }), fsp.mkdir(iconsDir, { recursive: true }), fsp.mkdir(logsDir, { recursive: true })]);
  try {
    sites = JSON.parse(await fsp.readFile(configPath, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") console.error("Could not read sites.json; starting empty:", error.message);
    sites = [];
    await saveSites();
  }
  try {
    proxies = JSON.parse(await fsp.readFile(proxiesPath, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") console.error("Could not read proxies.json; starting empty:", error.message);
    proxies = [];
    await saveProxies();
  }
  try {
    const lines = (await fsp.readFile(activityLogPath, "utf8")).trim().split("\n").slice(-20).reverse();
    recentActivity.push(...lines.map(line => JSON.parse(line)));
  } catch { /* Activity history starts empty on a new installation. */ }
  try {
    users = JSON.parse(await fsp.readFile(usersPath, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    const now = new Date().toISOString();
    users = [{ id: crypto.randomUUID(), username: adminUser.toLowerCase(), displayName: "Administrator", role: "administrator", status: "active", password: await passwordRecord(adminPassword), source: "bootstrap", createdAt: now, updatedAt: now, lastLoginAt: null }];
    await saveUsers();
  }
}

function normalizeDomain(value) {
  return String(value || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, "");
}

function validateDomain(domain, exceptId) {
  if (!domain) return null;
  if (domain.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) return "Enter a valid public domain such as app.example.com.";
  if ([...sites, ...proxies].some(item => item.domain === domain && item.id !== exceptId)) return "That domain is already assigned.";
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

function caddySiteAddress(item) {
  return item.tls === "http" ? `http://${item.domain}` : item.domain;
}

function renderCaddyfile() {
  const email = String(process.env.ACME_EMAIL || "").trim();
  const lines = ["{", "  admin localhost:2019", "  persist_config off"];
  if (email) lines.push(`  email ${email}`);
  const logging = ["  log {", `    output file ${accessLogPath} {`, "      roll_size 10mb", "      roll_keep 5", "      roll_keep_for 168h", "      roll_uncompressed", "    }", "    format json", "  }"];
  lines.push("}", "", ":80 {", ...logging, "  respond \"Site Gateway is ready.\" 404", "}");
  for (const site of sites.filter(item => item.enabled && item.domain)) {
    lines.push("", `${caddySiteAddress(site)} {`, ...logging, `  root * ${path.join(sitesDir, site.id)}`, "  encode zstd gzip", "  file_server");
    if (site.hsts && site.tls !== "http") lines.push('  header Strict-Transport-Security "max-age=31536000; includeSubDomains"');
    lines.push("}");
  }
  for (const proxy of proxies.filter(item => item.enabled && item.domain)) {
    lines.push("", `${caddySiteAddress(proxy)} {`, ...logging, `  reverse_proxy ${proxy.target}`);
    if (proxy.hsts && proxy.tls !== "http") lines.push('  header Strict-Transport-Security "max-age=31536000; includeSubDomains"');
    lines.push("}");
  }
  return `${lines.join("\n")}\n`;
}

async function syncCaddy() {
  const nextPath = `${caddyfilePath}.next`;
  await fsp.writeFile(nextPath, renderCaddyfile());
  try {
    await execFileAsync("caddy", ["fmt", "--overwrite", nextPath]);
    await execFileAsync("caddy", ["validate", "--config", nextPath, "--adapter", "caddyfile"]);
    await fsp.rename(nextPath, caddyfilePath);
    await execFileAsync("caddy", ["reload", "--config", caddyfilePath, "--adapter", "caddyfile"]);
    gatewayError = null;
    lastGatewayReload = new Date().toISOString();
  } catch (error) {
    await fsp.rm(nextPath, { force: true });
    gatewayError = error.stderr || error.message;
    throw Object.assign(new Error(`Gateway configuration was rejected: ${gatewayError}`), { status: 400 });
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

function publicProxy(proxy) {
  return { ...proxy, status: proxy.enabled ? (gatewayError ? "error" : "running") : "disabled", upstream: upstreamHealth.get(proxy.id) || null };
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
  for (const filename of (await walkFiles(certificateDir)).filter(file => /\.(?:crt|pem)$/i.test(file))) {
    try {
      const certificate = new crypto.X509Certificate(await fsp.readFile(filename));
      const stat = await fsp.stat(filename);
      parsed.push({ certificate, names: certificateNames(certificate), updatedAt: stat.mtime.toISOString() });
    } catch { /* Ignore non-certificate PEM files and unreadable entries. */ }
  }
  const certificates = configured.map(item => {
    const found = parsed.find(entry => entry.names.some(name => name === item.domain || (name.startsWith("*.") && item.domain.endsWith(name.slice(1)))));
    if (!found) return { domain: item.domain, name: item.name, kind: item.kind, status: "pending", daysRemaining: null, expiresAt: null, issuer: null, updatedAt: null };
    const expiresAt = new Date(found.certificate.validTo);
    const daysRemaining = Math.ceil((expiresAt.getTime() - Date.now()) / 86400000);
    const status = daysRemaining <= 0 ? "expired" : daysRemaining <= 7 ? "critical" : daysRemaining <= 30 ? "warning" : "healthy";
    return { domain: item.domain, name: item.name, kind: item.kind, status, daysRemaining, expiresAt: expiresAt.toISOString(), issuer: found.certificate.issuer, updatedAt: found.updatedAt, fingerprint: found.certificate.fingerprint256 };
  });
  return { summary: { total: certificates.length, healthy: certificates.filter(item => item.status === "healthy").length, warning: certificates.filter(item => item.status === "warning").length, critical: certificates.filter(item => item.status === "critical").length, expired: certificates.filter(item => item.status === "expired").length, pending: certificates.filter(item => item.status === "pending").length }, certificates };
}

async function checkProxy(proxy) {
  if (!proxy.enabled) return { status: "disabled", checkedAt: new Date().toISOString(), history: [] };
  const started = performance.now();
  let result;
  try {
    const response = await fetch(proxy.target, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(4000), headers: { "user-agent": "Site-Gateway-Health/1.0" } });
    await response.body?.cancel();
    const responseMs = Math.round(performance.now() - started);
    result = { status: response.status < 500 ? "healthy" : "unhealthy", httpStatus: response.status, responseMs, checkedAt: new Date().toISOString(), error: response.status >= 500 ? `HTTP ${response.status}` : null };
  } catch (error) {
    result = { status: "unhealthy", httpStatus: null, responseMs: Math.round(performance.now() - started), checkedAt: new Date().toISOString(), error: error.name === "TimeoutError" ? "Timed out after 4 seconds" : error.message };
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
  for (const certificate of certificates.certificates.filter(item => ["warning", "critical", "expired"].includes(item.status))) attention.push({ kind: "certificate", name: certificate.domain, message: certificate.status === "expired" ? "Certificate has expired." : `Certificate expires in ${certificate.daysRemaining} day${certificate.daysRemaining === 1 ? "" : "s"}.` });
  const disk = await fsp.statfs(dataDir).catch(() => null);
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
      nodeVersion: process.version
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
app.disable("x-powered-by");
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(publicDir));
app.use("/site-icons", express.static(iconsDir, { immutable: true, maxAge: "30d", setHeaders: res => res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'") }));

app.get("/api/session", (req, res) => {
  const user = sessionUser(req);
  res.json({ authenticated: Boolean(user), user: user ? publicUser(user) : null, username: user?.username || null });
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
    const expires = String(Date.now() + 12 * 60 * 60 * 1000);
    const value = `${user.id}.${expires}`;
    res.setHeader("Set-Cookie", `webserver_session=${value}.${sign(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200`);
    res.json({ ok: true, user: publicUser(user) });
  } catch (error) { next(error); }
});
app.post("/api/logout", (req, res) => {
  res.setHeader("Set-Cookie", "webserver_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
  res.json({ ok: true });
});
app.use("/api", (req, res, next) => {
  const user = sessionUser(req);
  if (!user) return res.status(401).json({ error: "Please sign in." });
  req.user = user;
  next();
});
app.use("/api", (req, res, next) => req.user.role === "administrator" || req.method === "GET" ? next() : res.status(403).json({ error: "Administrator access is required to make changes." }));
app.get("/api/config", (req, res) => res.json({ version: appVersion, minPort, maxPort, adminPort, gateway: { enabled: true, error: gatewayError } }));
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
    if (password.length < 12) return res.status(400).json({ error: "Password must contain at least 12 characters." });
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
      if (password.length < 12) return res.status(400).json({ error: "Password must contain at least 12 characters." });
      user.password = await passwordRecord(password);
    }
    user.updatedAt = new Date().toISOString(); await saveUsers(); recordActivity(`User “${user.username}” updated · ${user.role === "administrator" ? "Administrator" : "Standard User"} · ${user.status}.`);
    res.json(publicUser(user));
  } catch (error) { next(error); }
});
app.get("/api/sites", (req, res) => res.json(sites.map(publicSite)));
app.get("/api/proxies", (req, res) => res.json(proxies.map(publicProxy)));
app.get("/api/dashboard", async (req, res, next) => {
  try { res.json(await dashboardSnapshot()); }
  catch (error) { next(error); }
});
app.get("/api/certificates", async (req, res, next) => {
  try { res.json(await certificateInventory()); }
  catch (error) { next(error); }
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
    const tls = req.body.tls === "http" ? "http" : "automatic";
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
    site.tls = req.body.tls === "http" ? "http" : "automatic";
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
      tls: req.body.tls === "http" ? "http" : "automatic",
      hsts: req.body.hsts === true,
      enabled: true,
      createdAt: new Date().toISOString()
    };
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
    const domain = normalizeDomain(req.body.domain);
    const domainError = validateDomain(domain, proxy.id);
    if (domainError || !domain) return res.status(400).json({ error: domainError || "Domain is required." });
    proxy.name = String(req.body.name || proxy.name).trim();
    proxy.domain = domain;
    proxy.target = validateTarget(req.body.target);
    proxy.tls = req.body.tls === "http" ? "http" : "automatic";
    proxy.hsts = req.body.hsts === true;
    await syncCaddy();
    await saveProxies();
    recordActivity(`Proxy host “${proxy.name}” updated.`);
    res.json(publicProxy(proxy));
  } catch (error) { next(error); }
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

async function shutdown() {
  await Promise.all([...activeServers.keys()].map(stopSite));
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
