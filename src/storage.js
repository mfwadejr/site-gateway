// ============================================================================
// storage.js -- SQLite persistence layer for Site Gateway.
// Owns the on-disk database, one-time legacy JSON migration, and every
// read/write function server.js uses to load and save app data (sites,
// proxies, redirects, streams, access lists, users, groups, settings,
// activity/audit logs, and request performance data).
// ============================================================================

import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import AdmZip from "adm-zip";


// Legacy pre-SQLite storage: each entity kind used to live in its own JSON
// file under the data directory. entityTables maps the same kinds to their
// current SQLite table names.
export const LOCAL_INSTANCE_ID = "local";
export const ENTITY_KINDS = ["sites", "proxies", "redirects", "streams", "access_lists", "users", "groups"];
const legacyFiles = { sites: "sites.json", proxies: "proxies.json", redirects: "redirects.json", streams: "streams.json", access_lists: "access-lists.json", users: "users.json", groups: "groups.json" };
const entityTables = { sites: "hosted_sites", proxies: "proxy_hosts", redirects: "redirect_hosts", streams: "stream_hosts", access_lists: "access_lists", users: "users", groups: "groups" };

function now() { return new Date().toISOString(); }

// One-time safety snapshot taken before migrating legacy JSON files into
// SQLite: zips up the JSON files plus related data directories (sites,
// icons, default-site, certificates) into a timestamped .sgbackup archive
// so the pre-migration state is always recoverable.

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

// openStorage -- the single entry point server.js calls at boot. Ensures the
// data directories and SQLite database exist, runs schema setup and the
// legacy JSON migration (if needed), and returns the full set of
// read/write functions used throughout the app.
  const filename = `pre-sqlite-migration-${stamp}.sgbackup`;
  await fsp.writeFile(path.join(backupsDir, filename), zip.toBuffer(), { mode: 0o600 });
  return { filename, snapshotDir };
}

export async function openStorage(dataDir, backupsDir) {
  const databaseDir = path.join(dataDir, "database"), migrationsDir = path.join(dataDir, "migrations"), databasePath = path.join(databaseDir, "site-gateway.sqlite");
  await Promise.all([fsp.mkdir(databaseDir, { recursive: true }), fsp.mkdir(migrationsDir, { recursive: true }), fsp.mkdir(backupsDir, { recursive: true })]);

  // --- Schema setup -----------------------------------------------------
  // Core entity tables (hosted sites, proxy hosts, redirect hosts, stream
  // hosts, access lists, users, groups) each store their record as a JSON
  // payload column, plus supporting tables for access-list assignments,
  // settings, audit/activity logs, and raw request (access) events used
  // for performance reporting.
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
    CREATE TABLE IF NOT EXISTS stream_hosts (id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE, payload TEXT NOT NULL CHECK(json_valid(payload)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS access_lists (id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE, payload TEXT NOT NULL CHECK(json_valid(payload)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE, payload TEXT NOT NULL CHECK(json_valid(payload)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS groups (id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE, payload TEXT NOT NULL CHECK(json_valid(payload)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS hosted_sites_instance ON hosted_sites(instance_id);
    CREATE INDEX IF NOT EXISTS proxy_hosts_instance ON proxy_hosts(instance_id);
    CREATE INDEX IF NOT EXISTS redirect_hosts_instance ON redirect_hosts(instance_id);
    CREATE INDEX IF NOT EXISTS stream_hosts_instance ON stream_hosts(instance_id);
    CREATE INDEX IF NOT EXISTS access_lists_instance ON access_lists(instance_id);
    CREATE INDEX IF NOT EXISTS users_instance ON users(instance_id);
    CREATE INDEX IF NOT EXISTS groups_instance ON groups(instance_id);
  // Forward-compatible column add for databases created before "category"
  // existed on activity_events; a no-op once the column is already there.
    CREATE TABLE IF NOT EXISTS access_assignments (instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE, route_kind TEXT NOT NULL, route_id TEXT NOT NULL, access_list_id TEXT NOT NULL REFERENCES access_lists(id) ON DELETE RESTRICT, created_at TEXT NOT NULL, PRIMARY KEY(route_kind,route_id));
    CREATE TABLE IF NOT EXISTS settings (instance_id TEXT PRIMARY KEY REFERENCES instances(id) ON DELETE CASCADE, payload TEXT NOT NULL CHECK(json_valid(payload)), updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id TEXT REFERENCES instances(id), actor_id TEXT, action TEXT NOT NULL, status TEXT NOT NULL, details TEXT, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS activity_events (id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id TEXT REFERENCES instances(id), message TEXT NOT NULL, status TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'activity', created_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS activity_events_instance_created ON activity_events(instance_id,created_at DESC);

  // --- Core entity read/write --------------------------------------------
  // transaction() wraps a block of statements in BEGIN IMMEDIATE/COMMIT,
  // rolling back on any thrown error.
    CREATE TABLE IF NOT EXISTS access_events (id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id TEXT REFERENCES instances(id), at TEXT, host TEXT, method TEXT, uri TEXT, status INTEGER, size INTEGER, duration_ms INTEGER, remote_ip TEXT, source TEXT, UNIQUE(instance_id,source));
  // loadCollection -- reads every record of one entity kind (sites, proxies,
  // redirects, streams, access_lists, users, groups) for an instance.
    CREATE INDEX IF NOT EXISTS access_events_instance_at ON access_events(instance_id,at DESC);
  // refreshAssignments -- rebuilds the access_assignments table (which route
  // is protected by which Access List) from the current hosted/proxy/
  // redirect payloads. Called after any save that could change accessListId.
  `);
  try { db.exec("ALTER TABLE activity_events ADD COLUMN category TEXT NOT NULL DEFAULT 'activity'"); } catch { /* Column already exists. */ }
  const timestamp = now();
  db.prepare("INSERT OR IGNORE INTO instances(id,name,kind,status,created_at,updated_at) VALUES(?,?,?,?,?,?)").run(LOCAL_INSTANCE_ID, "Local Gateway", "local", "active", timestamp, timestamp);
  db.prepare("INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,?)").run(timestamp);
  // saveCollection -- replaces (or, for access_lists, upserts/prunes) all
  // records of one entity kind for an instance, inside a single transaction.

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

  // --- Settings -----------------------------------------------------------
      }
      if (kind === "access_lists") {
        const keep = new Set(values.map(value => value.id));

  // --- Database health ------------------------------------------------------
        for (const row of db.prepare("SELECT id FROM access_lists WHERE instance_id=?").all(instanceId)) if (!keep.has(row.id)) db.prepare("DELETE FROM access_lists WHERE id=?").run(row.id);
      }

  // --- Audit & activity logs -----------------------------------------------
  // recordAudit -- administrative/security audit trail (who did what).
      if (["sites","proxies","redirects"].includes(kind)) refreshAssignments(instanceId);
  // recordActivity -- user-facing activity feed (what happened), auto-
  // categorized into certificate/security/activity based on the message text.
    });
  }

  // --- Access (request) events, powering Logs and Performance ---------------
  // recordAccessEvents -- bulk-inserts raw request log lines tailed from
  // Caddy's access log; ON IGNORE + UNIQUE(instance_id,source) makes re-
  // ingesting the same log line idempotent.
  function loadSettings(instanceId = LOCAL_INSTANCE_ID) { const row = db.prepare("SELECT payload FROM settings WHERE instance_id=?").get(instanceId); return row ? JSON.parse(row.payload) : null; }
  function saveSettings(value, instanceId = LOCAL_INSTANCE_ID) { db.prepare("INSERT INTO settings(instance_id,payload,updated_at) VALUES(?,?,?) ON CONFLICT(instance_id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at").run(instanceId, JSON.stringify(value), now()); }
  // performanceLiveCount -- request count within the last windowSeconds,
  // used for the "live requests" figure on the dashboard.
  function integrity() { return db.prepare("PRAGMA integrity_check").all().map(row => Object.values(row)[0]); }
  // performanceRoutes -- per-domain request/error/avg-response-time totals
  // for the last hour and last 24 hours; backs the "Throughput by domain"
  // table on the Performance page. A domain only appears here if it has
  // at least one request within the last 24 hours (the dayCutoff filter).
  function recordAudit(action, status = "ok", details = null, actorId = null, instanceId = LOCAL_INSTANCE_ID) { db.prepare("INSERT INTO audit_events(instance_id,actor_id,action,status,details,created_at) VALUES(?,?,?,?,?,?)").run(instanceId, actorId, action, status, details ? JSON.stringify(details) : null, now()); }
  function recordActivity(message, status = "ok", instanceId = LOCAL_INSTANCE_ID) { const text = String(message); const category = /cert|tls|acme|certificate/i.test(text) ? "certificate" : /login|password|security|access list|credential/i.test(text) ? "security" : "activity"; db.prepare("INSERT INTO activity_events(instance_id,message,status,category,created_at) VALUES(?,?,?,?,?)").run(instanceId, text, status, category, now()); }
  function listActivity(limit = 100, instanceId = LOCAL_INSTANCE_ID) { return db.prepare("SELECT message,status,category,created_at AS at FROM activity_events WHERE instance_id=? ORDER BY id DESC LIMIT ?").all(instanceId, Math.max(1, Math.min(Number(limit) || 100, 500))); }
  function recordAccessEvents(events, instanceId = LOCAL_INSTANCE_ID) { const insert = db.prepare("INSERT OR IGNORE INTO access_events(instance_id,at,host,method,uri,status,size,duration_ms,remote_ip,source) VALUES(?,?,?,?,?,?,?,?,?,?)"); transaction(() => { for (const event of events) insert.run(instanceId, event.at || null, event.host || null, event.method || null, event.uri || null, event.status ?? null, event.size ?? null, event.durationMs ?? null, event.remoteIp || null, event.source); }); }
  function listAccessEvents(limit = 100, host = "", instanceId = LOCAL_INSTANCE_ID) { const rows = db.prepare("SELECT at,host,method,uri,status,size,duration_ms AS durationMs,remote_ip AS remoteIp FROM access_events WHERE instance_id=? AND (?='' OR host=?) ORDER BY id DESC LIMIT ?").all(instanceId, host, host, Math.max(1, Math.min(Number(limit) || 100, 500))); return rows; }
  function performanceLiveCount(windowSeconds = 60, instanceId = LOCAL_INSTANCE_ID) { const cutoff = new Date(Date.now() - Math.max(5, Number(windowSeconds) || 60) * 1000).toISOString(); return db.prepare("SELECT COUNT(*) AS count FROM access_events WHERE instance_id=? AND at>=?").get(instanceId, cutoff).count; }
  function performanceRoutes(instanceId = LOCAL_INSTANCE_ID) {
    const hourCutoff = new Date(Date.now() - 3600000).toISOString(), dayCutoff = new Date(Date.now() - 86400000).toISOString();
    return db.prepare(`
      SELECT host,
        SUM(CASE WHEN at>=? THEN 1 ELSE 0 END) AS hourRequests,
        SUM(CASE WHEN at>=? AND status>=400 THEN 1 ELSE 0 END) AS hourErrors,
        AVG(CASE WHEN at>=? THEN duration_ms END) AS hourAvgMs,
  // performanceErrorBreakdown -- per-domain, per-status-code error counts
  // over the last 24 hours; feeds the error-breakdown detail shown per row
  // in the Performance table (top statuses per host).
        COUNT(*) AS dayRequests,
        SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END) AS dayErrors,
        AVG(duration_ms) AS dayAvgMs
      FROM access_events WHERE instance_id=? AND at>=? AND host IS NOT NULL AND host!=''
      GROUP BY host ORDER BY dayRequests DESC
    `).all(hourCutoff, hourCutoff, hourCutoff, instanceId, dayCutoff);
  }
  function performanceErrorBreakdown(instanceId = LOCAL_INSTANCE_ID) {
  // performanceTrend -- bucketed request counts over a configurable window
  // (default 6 hours, 15-minute buckets), optionally filtered to one host;
  // backs the "Requests" trend chart on the Performance page.
    const dayCutoff = new Date(Date.now() - 86400000).toISOString();
    return db.prepare(`
      SELECT host, status, COUNT(*) AS count
      FROM access_events WHERE instance_id=? AND at>=? AND status>=400 AND host IS NOT NULL AND host!=''
      GROUP BY host, status ORDER BY count DESC
    `).all(instanceId, dayCutoff);
  }
  function performanceTrend(host = "", hours = 6, bucketMinutes = 15, instanceId = LOCAL_INSTANCE_ID) {
    const bucketMs = Math.max(1, Number(bucketMinutes) || 15) * 60000;
    const windowMs = Math.max(1, Number(hours) || 6) * 3600000;
    const cutoff = new Date(Date.now() - windowMs).toISOString();
    const rows = db.prepare(`SELECT at FROM access_events WHERE instance_id=? AND at>=? AND (?='' OR host=?)`).all(instanceId, cutoff, host, host);
    const buckets = new Map();

  // --- Log retention / pruning ----------------------------------------------
  // pruneEvents -- deletes access/activity/audit rows older than the
  // configured retention policy (per category: access, activity, certificate,
  // security, audit), returning how many rows were removed per category.
  // Used by both the manual "prune now" action and the scheduled job.
    for (const row of rows) { const t = new Date(row.at).getTime(); if (Number.isNaN(t)) continue; const bucketStart = Math.floor(t / bucketMs) * bucketMs; buckets.set(bucketStart, (buckets.get(bucketStart) || 0) + 1); }
  // previewPruneEvents -- same policy/cutoffs as pruneEvents but read-only;
  // used to show "this will remove N records" before the user confirms.
    const startBucket = Math.floor((Date.now() - windowMs) / bucketMs) * bucketMs, endBucket = Math.floor(Date.now() / bucketMs) * bucketMs;
    const points = [];

  // --- Backups ---------------------------------------------------------------
  // backupTo -- writes a consistent point-in-time copy of the SQLite database
  // to `filename` using VACUUM INTO (safe to run against a live database).
    for (let bucket = startBucket; bucket <= endBucket; bucket += bucketMs) points.push({ at: new Date(bucket).toISOString(), count: buckets.get(bucket) || 0 });
    return points;

  // --- One-time legacy JSON -> SQLite migration --------------------------------
  // Runs only when the database file didn't exist yet (isNew). Reads any
  // legacy *.json files found in the data directory, inserts their records
  // into the new SQLite tables inside a transaction, and rolls the whole
  // database file back if anything fails partway through.
  }
  function pruneEvents(policy = {}, instanceId = LOCAL_INSTANCE_ID) { const cutoff = days => new Date(Date.now() - Math.max(7, Number(days) || 30) * 86400000).toISOString(); return transaction(() => { const counts = {}; const jobs = [["access", "access_events", "at", policy.accessDays, ""], ["activity", "activity_events", "created_at", policy.activityDays, "category='activity'"], ["certificate", "activity_events", "created_at", policy.certificateDays, "category='certificate'"], ["security", "activity_events", "created_at", policy.securityDays, "category='security'"], ["audit", "audit_events", "created_at", policy.auditDays, ""]]; for (const [name, table, column, days, filter] of jobs) { const result = db.prepare(`DELETE FROM ${table} WHERE instance_id=? AND ${column} < ?${filter ? ` AND ${filter}` : ""}`).run(instanceId, cutoff(days)); counts[name] = Number(result.changes || 0); } return counts; }); }
  function previewPruneEvents(policy = {}, instanceId = LOCAL_INSTANCE_ID) { const cutoff = days => new Date(Date.now() - Math.max(7, Number(days) || 30) * 86400000).toISOString(); const counts = {}; const jobs = [["access", "access_events", "at", policy.accessDays, ""], ["activity", "activity_events", "created_at", policy.activityDays, "category='activity'"], ["certificate", "activity_events", "created_at", policy.certificateDays, "category='certificate'"], ["security", "activity_events", "created_at", policy.securityDays, "category='security'"], ["audit", "audit_events", "created_at", policy.auditDays, ""]]; for (const [name, table, column, days, filter] of jobs) counts[name] = Number(db.prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE instance_id=? AND ${column} < ?${filter ? ` AND ${filter}` : ""}`).get(instanceId, cutoff(days)).count || 0); return counts; }
  function listAudit(filters = {}, instanceId = LOCAL_INSTANCE_ID) { const rows = db.prepare("SELECT id,actor_id,action,status,details,created_at FROM audit_events WHERE instance_id=? ORDER BY id DESC LIMIT 500").all(instanceId); return rows.filter(row => (!filters.user || row.actor_id === filters.user) && (!filters.action || row.action.toLowerCase().includes(filters.action.toLowerCase())) && (!filters.status || row.status === filters.status)).map(row => ({ ...row, details: row.details ? JSON.parse(row.details) : null })); }
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

  // --- One-off cleanup of a previously confusing error message ---------------
  // humanizeGatewayErrors -- rewrites a specific raw Caddy error string that
  // used to appear verbatim in the activity/audit logs into a plain-language
  // explanation. Runs at boot so existing log rows get the friendlier text too.
      if (fs.existsSync(settingsFile)) db.prepare("INSERT OR REPLACE INTO settings(instance_id,payload,updated_at) VALUES(?,?,?)").run(LOCAL_INSTANCE_ID, fs.readFileSync(settingsFile, "utf8"), timestamp);
      refreshAssignments(LOCAL_INSTANCE_ID);
    }); } catch (error) {
      db.close();
      await Promise.all([fsp.rm(databasePath, { force: true }), fsp.rm(`${databasePath}-wal`, { force: true }), fsp.rm(`${databasePath}-shm`, { force: true })]);
      throw new Error(`Legacy JSON migration failed and was rolled back: ${error.message}`);
    }
  }
  function humanizeGatewayErrors(instanceId = LOCAL_INSTANCE_ID) { const friendly = "Gateway configuration rejected: HTTP upstream cannot use HTTPS transport. Disable upstream TLS verification or change the upstream URL to HTTPS."; const activity = db.prepare("SELECT id FROM activity_events WHERE instance_id=? AND message LIKE '%upstream address scheme is HTTP but transport is configured for HTTP+TLS%'").all(instanceId); const updateActivity = db.prepare("UPDATE activity_events SET message=? WHERE id=?"); for (const row of activity) updateActivity.run(friendly, row.id); const audit = db.prepare("SELECT id FROM audit_events WHERE instance_id=? AND action LIKE '%upstream address scheme is HTTP but transport is configured for HTTP+TLS%'").all(instanceId); const updateAudit = db.prepare("UPDATE audit_events SET action=? WHERE id=?"); for (const row of audit) updateAudit.run(friendly, row.id); return activity.length + audit.length; }
  const result = integrity(); if (result.length !== 1 || result[0] !== "ok") { db.close(); throw new Error(`SQLite integrity check failed: ${result.join(", ")}`); }
  return { db, databasePath, isNew, snapshot, loadCollection, saveCollection, loadSettings, saveSettings, integrity, recordAudit, listAudit, recordActivity, listActivity, humanizeGatewayErrors, recordAccessEvents, listAccessEvents, pruneEvents, previewPruneEvents, backupTo, performanceLiveCount, performanceRoutes, performanceErrorBreakdown, performanceTrend, close: () => db.close() };
}
