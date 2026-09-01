import crypto from "node:crypto";
import { execFile } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import AdmZip from "adm-zip";
import express from "express";
import multer from "multer";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, "public");
const dataDir = path.resolve(process.env.DATA_DIR || "/data");
const sitesDir = path.join(dataDir, "sites");
const configPath = path.join(dataDir, "sites.json");
const proxiesPath = path.join(dataDir, "proxies.json");
const uploadDir = path.join(dataDir, ".uploads");
const caddyDir = path.join(dataDir, "caddy");
const caddyfilePath = path.join(caddyDir, "Caddyfile");
const execFileAsync = promisify(execFile);
const adminPort = numberEnv("ADMIN_PORT", 8080);
const minPort = numberEnv("SITE_PORT_MIN", 9000);
const maxPort = numberEnv("SITE_PORT_MAX", 9099);
const adminUser = process.env.ADMIN_USERNAME || "admin";
const adminPassword = process.env.ADMIN_PASSWORD || "change-this-password";
const sessionSecret = process.env.SESSION_SECRET || crypto.createHash("sha256").update(`${adminUser}:${adminPassword}`).digest("hex");
const activeServers = new Map();
let sites = [];
let proxies = [];
let gatewayError = null;

function numberEnv(name, fallback) {
  const value = Number.parseInt(process.env[name] || "", 10);
  return Number.isInteger(value) ? value : fallback;
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
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

function authenticated(req) {
  const token = cookieMap(req.headers.cookie).webserver_session;
  if (!token) return false;
  const [expires, signature] = token.split(".");
  return Number(expires) > Date.now() && safeEqual(signature || "", sign(expires));
}

async function saveSites() {
  await fsp.writeFile(configPath, JSON.stringify(sites, null, 2));
}

async function saveProxies() {
  await fsp.writeFile(proxiesPath, JSON.stringify(proxies, null, 2));
}

async function loadSites() {
  await Promise.all([fsp.mkdir(sitesDir, { recursive: true }), fsp.mkdir(uploadDir, { recursive: true }), fsp.mkdir(caddyDir, { recursive: true })]);
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
  lines.push("}", "", ":80 {", "  respond \"Web Server gateway is ready.\" 404", "}");
  for (const site of sites.filter(item => item.enabled && item.domain)) {
    lines.push("", `${caddySiteAddress(site)} {`, `  root * ${path.join(sitesDir, site.id)}`, "  encode zstd gzip", "  file_server");
    if (site.hsts && site.tls !== "http") lines.push('  header Strict-Transport-Security "max-age=31536000; includeSubDomains"');
    lines.push("}");
  }
  for (const proxy of proxies.filter(item => item.enabled && item.domain)) {
    lines.push("", `${caddySiteAddress(proxy)} {`, `  reverse_proxy ${proxy.target}`);
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
  return { ...proxy, status: proxy.enabled ? (gatewayError ? "error" : "running") : "disabled" };
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

app.get("/api/session", (req, res) => res.json({ authenticated: authenticated(req), username: authenticated(req) ? adminUser : null }));
app.post("/api/login", (req, res) => {
  if (!safeEqual(req.body.username || "", adminUser) || !safeEqual(req.body.password || "", adminPassword)) return res.status(401).json({ error: "Incorrect username or password." });
  const expires = String(Date.now() + 12 * 60 * 60 * 1000);
  res.setHeader("Set-Cookie", `webserver_session=${expires}.${sign(expires)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200`);
  res.json({ ok: true });
});
app.post("/api/logout", (req, res) => {
  res.setHeader("Set-Cookie", "webserver_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
  res.json({ ok: true });
});
app.use("/api", (req, res, next) => authenticated(req) ? next() : res.status(401).json({ error: "Please sign in." }));
app.get("/api/config", (req, res) => res.json({ minPort, maxPort, adminPort, gateway: { enabled: true, error: gatewayError } }));
app.get("/api/sites", (req, res) => res.json(sites.map(publicSite)));
app.get("/api/proxies", (req, res) => res.json(proxies.map(publicProxy)));
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
    res.json(publicProxy(proxy));
  } catch (error) { next(error); }
});
app.delete("/api/proxies/:id", async (req, res, next) => {
  try {
    const index = proxies.findIndex(item => item.id === req.params.id);
    if (index < 0) return res.status(404).json({ error: "Proxy host not found." });
    proxies.splice(index, 1);
    await syncCaddy();
    await saveProxies();
    res.status(204).end();
  } catch (error) { next(error); }
});
app.use((error, req, res, next) => {
  console.error(error);
  res.status(error.status || 500).json({ error: error.message || "Something went wrong." });
});

app.listen(adminPort, "0.0.0.0", () => {
  console.log(`Web Server dashboard listening on port ${adminPort}`);
  if (adminPassword === "change-this-password") console.warn("WARNING: Change ADMIN_PASSWORD before exposing the dashboard.");
});

async function shutdown() {
  await Promise.all([...activeServers.keys()].map(stopSite));
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
