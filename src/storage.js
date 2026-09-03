import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import AdmZip from "adm-zip";

export const LOCAL_INSTANCE_ID = "local";
export const ENTITY_KINDS = ["sites", "proxies", "redirects", "access_lists", "users"];
const legacyFiles = { sites: "sites.json", proxies: "proxies.json", redirects: "redirects.json", access_lists: "access-lists.json", users: "users.json" };
const entityTables = { sites: "hosted_sites", proxies: "proxy_hosts", redirects: "redirect_hosts", access_lists: "access_lists", users: "users" };

function now() { return new Date().toISOString(); }

async function migrationSnapshot(dataDir, backupsDir, migrationsDir) {
  const present = Object.values(legacyFiles).filter(name => fs.existsSync(path.join(dataDir, name)));
  if (!present.length) return null;
  const stamp = now().replace(/[:.]/g, "-");
  const snapshotDir = path.join(migrationsDir, `json-backup-${stamp}`);
  await fsp.mkdir(snapshotDir, { recursive: true });
  const zip = new AdmZip();
  const manifest = { format: 1, product: "Site Gateway", purpose: "pre-sqlite-migration", type: "complete", includeLogs: false, createdAt: now(), files: [], checksums: {} };
  for (const name of [...present, "settings.json"].filter(name => fs.existsSync(path.join(dataDir, name)))) {
    const value = await fsp.readFile(path.join(dataDir, name));
    await fsp.writeFile(path.join(snapshotDir, name), value, { mode: name === "users.json" ? 0o600 : 0o640 });
    zip.addFile(`legacy-json/${name}`, value); manifest.files.push(`legacy-json/${name}`); manifest.checksums[`legacy-json/${name}`] = crypto.createHash("sha256").update(value).digest("hex");
  }
  for (const [directory, archive] of [["sites", "sites"], ["icons", "icons"], ["default-site", "default-site"], ["certificates", "certificates"]]) {
    const source = path.join(dataDir, directory); if (fs.existsSync(source)) zip.addLocalFolder(source, archive);
  }
  manifest.files = zip.getEntries().filter(entry => !entry.isDirectory).map(entry => entry.entryName);
  manifest.checksums = Object.fromEntries(zip.getEntries().filter(entry => !entry.isDirectory).map(entry => [entry.entryName, crypto.createHash("sha256").update(entry.getData()).digest("hex")]));
  zip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2)));
  const filename = `pre-sqlite-migration-${stamp}.sgbackup`;
  await fsp.writeFile(path.join(backupsDir, filename), zip.toBuffer(), { mode: 0o600 });
  return { filename, snapshotDir };
}

export async function openStorage(dataDir, backupsDir) {
  const databaseDir = path.join(dataDir, "database"), migrationsDir = path.join(dataDir, "migrations"), databasePath = path.join(databaseDir, "site-gateway.sqlite");
  await Promise.all([fsp.mkdir(databaseDir, { recursive: true }), fsp.mkdir(migrationsDir, { recursive: true }), fsp.mkdir(backupsDir, { recursive: true })]);
  const isNew = !fs.existsSync(databasePath);
  const snapshot = isNew ? await migrationSnapshot(dataDir, backupsDir, migrationsDir) : null;
  const db = new DatabaseSync(databasePath);
  await fsp.chmod(databasePath, 0o600);
  db.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS instances (id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS hosted_sites (id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE, payload TEXT NOT NULL CHECK(json_valid(payload)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS proxy_hosts (id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE, payload TEXT NOT NULL CHECK(json_valid(payload)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS redirect_hosts (id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE, payload TEXT NOT NULL CHECK(json_valid(payload)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS access_lists (id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE, payload TEXT NOT NULL CHECK(json_valid(payload)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE, payload TEXT NOT NULL CHECK(json_valid(payload)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS hosted_sites_instance ON hosted_sites(instance_id);
    CREATE INDEX IF NOT EXISTS proxy_hosts_instance ON proxy_hosts(instance_id);
    CREATE INDEX IF NOT EXISTS redirect_hosts_instance ON redirect_hosts(instance_id);
    CREATE INDEX IF NOT EXISTS access_lists_instance ON access_lists(instance_id);
    CREATE INDEX IF NOT EXISTS users_instance ON users(instance_id);
    CREATE TABLE IF NOT EXISTS access_assignments (instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE, route_kind TEXT NOT NULL, route_id TEXT NOT NULL, access_list_id TEXT NOT NULL REFERENCES access_lists(id) ON DELETE RESTRICT, created_at TEXT NOT NULL, PRIMARY KEY(route_kind,route_id));
    CREATE TABLE IF NOT EXISTS settings (instance_id TEXT PRIMARY KEY REFERENCES instances(id) ON DELETE CASCADE, payload TEXT NOT NULL CHECK(json_valid(payload)), updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id TEXT REFERENCES instances(id), actor_id TEXT, action TEXT NOT NULL, status TEXT NOT NULL, details TEXT, created_at TEXT NOT NULL);
  `);
  const timestamp = now();
  db.prepare("INSERT OR IGNORE INTO instances(id,name,kind,status,created_at,updated_at) VALUES(?,?,?,?,?,?)").run(LOCAL_INSTANCE_ID, "Local Gateway", "local", "active", timestamp, timestamp);
  db.prepare("INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,?)").run(timestamp);

  function transaction(work) { db.exec("BEGIN IMMEDIATE"); try { const result = work(); db.exec("COMMIT"); return result; } catch (error) { db.exec("ROLLBACK"); throw error; } }
  function loadCollection(kind, instanceId = LOCAL_INSTANCE_ID) { const table = entityTables[kind]; if (!table) throw new Error(`Unsupported collection ${kind}`); return db.prepare(`SELECT payload FROM ${table} WHERE instance_id=? ORDER BY created_at,id`).all(instanceId).map(row => JSON.parse(row.payload)); }
  function refreshAssignments(instanceId = LOCAL_INSTANCE_ID) {
    db.prepare("DELETE FROM access_assignments WHERE instance_id=?").run(instanceId);
    const insert = db.prepare("INSERT INTO access_assignments(instance_id,route_kind,route_id,access_list_id,created_at) VALUES(?,?,?,?,?)");
    for (const [kind, table] of [["hosted", "hosted_sites"], ["proxy", "proxy_hosts"], ["redirect", "redirect_hosts"]]) for (const row of db.prepare(`SELECT id,payload FROM ${table} WHERE instance_id=?`).all(instanceId)) { const value = JSON.parse(row.payload); if (value.accessListId) insert.run(instanceId, kind, row.id, value.accessListId, now()); }
  }
  function saveCollection(kind, values, instanceId = LOCAL_INSTANCE_ID) {
    const table = entityTables[kind]; if (!table) throw new Error(`Unsupported collection ${kind}`);
    transaction(() => {
      if (["sites","proxies","redirects"].includes(kind)) db.prepare("DELETE FROM access_assignments WHERE instance_id=? AND route_kind=?").run(instanceId, kind === "sites" ? "hosted" : kind === "proxies" ? "proxy" : "redirect");
      if (kind !== "access_lists") db.prepare(`DELETE FROM ${table} WHERE instance_id=?`).run(instanceId);
      const insert = db.prepare(`INSERT INTO ${table}(id,instance_id,payload,created_at,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at`);
      for (const value of values) {
        const created = value.createdAt || now(), stored = { ...value, instanceId };
        if (kind === "proxies") for (const key of ["certificatePath", "keyPath"]) if (stored[key]) stored[key] = String(stored[key]).replace(path.join(dataDir, "custom-certificates"), path.join(dataDir, "certificates", "custom"));
        insert.run(value.id, instanceId, JSON.stringify(stored), created, now());
      }
      if (kind === "access_lists") {
        const keep = new Set(values.map(value => value.id));
        for (const row of db.prepare("SELECT id FROM access_lists WHERE instance_id=?").all(instanceId)) if (!keep.has(row.id)) db.prepare("DELETE FROM access_lists WHERE id=?").run(row.id);
      }
      if (["sites","proxies","redirects"].includes(kind)) refreshAssignments(instanceId);
    });
  }
  function loadSettings(instanceId = LOCAL_INSTANCE_ID) { const row = db.prepare("SELECT payload FROM settings WHERE instance_id=?").get(instanceId); return row ? JSON.parse(row.payload) : null; }
  function saveSettings(value, instanceId = LOCAL_INSTANCE_ID) { db.prepare("INSERT INTO settings(instance_id,payload,updated_at) VALUES(?,?,?) ON CONFLICT(instance_id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at").run(instanceId, JSON.stringify(value), now()); }
  function integrity() { return db.prepare("PRAGMA integrity_check").all().map(row => Object.values(row)[0]); }
  function recordAudit(action, status = "ok", details = null, actorId = null, instanceId = LOCAL_INSTANCE_ID) { db.prepare("INSERT INTO audit_events(instance_id,actor_id,action,status,details,created_at) VALUES(?,?,?,?,?,?)").run(instanceId, actorId, action, status, details ? JSON.stringify(details) : null, now()); }
  function backupTo(filename) { try { fs.rmSync(filename, { force: true }); db.exec(`VACUUM INTO '${String(filename).replaceAll("'", "''")}'`); } catch (error) { throw new Error(`Could not create a consistent SQLite backup: ${error.message}`); } }

  if (isNew) {
    try { transaction(() => {
      for (const [kind, filename] of Object.entries(legacyFiles)) {
        const source = path.join(dataDir, filename); if (!fs.existsSync(source)) continue;
        const values = JSON.parse(fs.readFileSync(source, "utf8"));
        const table = entityTables[kind], insert = db.prepare(`INSERT INTO ${table}(id,instance_id,payload,created_at,updated_at) VALUES(?,?,?,?,?)`);
        for (const value of values) {
          const migrated = { ...value, instanceId: LOCAL_INSTANCE_ID };
          if (kind === "proxies") for (const key of ["certificatePath", "keyPath"]) if (migrated[key]) migrated[key] = String(migrated[key]).replace(path.join(dataDir, "custom-certificates"), path.join(dataDir, "certificates", "custom"));
          insert.run(value.id, LOCAL_INSTANCE_ID, JSON.stringify(migrated), value.createdAt || timestamp, timestamp);
        }
      }
      const settingsFile = path.join(dataDir, "settings.json");
      if (fs.existsSync(settingsFile)) db.prepare("INSERT OR REPLACE INTO settings(instance_id,payload,updated_at) VALUES(?,?,?)").run(LOCAL_INSTANCE_ID, fs.readFileSync(settingsFile, "utf8"), timestamp);
      refreshAssignments(LOCAL_INSTANCE_ID);
    }); } catch (error) {
      db.close();
      await Promise.all([fsp.rm(databasePath, { force: true }), fsp.rm(`${databasePath}-wal`, { force: true }), fsp.rm(`${databasePath}-shm`, { force: true })]);
      throw new Error(`Legacy JSON migration failed and was rolled back: ${error.message}`);
    }
  }
  const result = integrity(); if (result.length !== 1 || result[0] !== "ok") { db.close(); throw new Error(`SQLite integrity check failed: ${result.join(", ")}`); }
  return { db, databasePath, isNew, snapshot, loadCollection, saveCollection, loadSettings, saveSettings, integrity, recordAudit, backupTo, close: () => db.close() };
}
