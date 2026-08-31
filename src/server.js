import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import AdmZip from "adm-zip";
import express from "express";
import multer from "multer";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, "public");
const dataDir = path.resolve(process.env.DATA_DIR || "/data");
const sitesDir = path.join(dataDir, "sites");
const configPath = path.join(dataDir, "sites.json");
const uploadDir = path.join(dataDir, ".uploads");
const adminPort = numberEnv("ADMIN_PORT", 8080);
const minPort = numberEnv("SITE_PORT_MIN", 9000);
const maxPort = numberEnv("SITE_PORT_MAX", 9099);
const adminUser = process.env.ADMIN_USERNAME || "admin";
const adminPassword = process.env.ADMIN_PASSWORD || "change-this-password";
const sessionSecret = process.env.SESSION_SECRET || crypto.createHash("sha256").update(`${adminUser}:${adminPassword}`).digest("hex");
const activeServers = new Map();
let sites = [];

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

async function loadSites() {
  await Promise.all([fsp.mkdir(sitesDir, { recursive: true }), fsp.mkdir(uploadDir, { recursive: true })]);
  try {
    sites = JSON.parse(await fsp.readFile(configPath, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") console.error("Could not read sites.json; starting empty:", error.message);
    sites = [];
    await saveSites();
  }
}

function siteStatus(site) {
  return activeServers.has(site.id) ? "running" : site.enabled ? "error" : "disabled";
}

function publicSite(site) {
  return { ...site, status: siteStatus(site), url: `http://${site.host || "localhost"}:${site.port}` };
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
app.get("/api/config", (req, res) => res.json({ minPort, maxPort, adminPort }));
app.get("/api/sites", (req, res) => res.json(sites.map(publicSite)));
app.post("/api/sites", upload.single("files"), async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const port = Number.parseInt(req.body.port, 10);
    const id = `${slugify(name) || "site"}-${crypto.randomBytes(3).toString("hex")}`;
    if (!name) throw Object.assign(new Error("Site name is required."), { status: 400 });
    const portError = validatePort(port);
    if (portError) throw Object.assign(new Error(portError), { status: 400 });
    if (!req.file) throw Object.assign(new Error("Choose a ZIP file or index.html."), { status: 400 });
    const site = { id, name, port, enabled: true, createdAt: new Date().toISOString() };
    await installUpload(site, req.file);
    sites.push(site);
    await saveSites();
    try { await startSite(site); } catch (error) { console.error(error); }
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
    res.json(publicSite(site));
  } catch (error) { next(error); }
});
app.delete("/api/sites/:id", async (req, res, next) => {
  try {
    const index = sites.findIndex(item => item.id === req.params.id);
    if (index < 0) return res.status(404).json({ error: "Site not found." });
    const [site] = sites.splice(index, 1);
    await stopSite(site.id);
    await fsp.rm(path.join(sitesDir, site.id), { recursive: true, force: true });
    await saveSites();
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
