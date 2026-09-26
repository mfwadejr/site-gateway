import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import AdmZip from "adm-zip";

export const LOCAL_INSTANCE_ID = "local";
export const ENTITY_KINDS = ["sites", "proxies", "redirects", "streams", "access_lists", "users", "groups"];
const legacyFiles = { sites: "sites.json", proxies: "proxies.json", redirects: "redirects.json", streams: "streams.json", access_lists: "access-lists.json", users: "users.json", groups: "groups.json" };
const entityTables = { sites: "hosted_sites", proxies: "proxy_hosts", redirects: "redirect_hosts", streams: "stream_hosts", access_lists: "access_lists", users: "users", groups: "groups" };

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
    CREATE TABLE IF NOT EXISTS access_assignments (instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE, route_kind TEXT NOT NULL, route_id TEXT NOT NULL, access_list_id TEXT NOT NULL REFERENCES access_lists(id) ON DELETE RESTRICT, created_at TEXT NOT NULL, PRIMARY KEY(route_kind,route_id));
    CREATE TABLE IF NOT EXISTS settings (instance_id TEXT PRIMARY KEY REFERENCES instances(id) ON DELETE CASCADE, payload TEXT NOT NULL CHECK(json_valid(payload)), updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id TEXT REFERENCES instances(id), actor_id TEXT, action TEXT NOT NULL, status TEXT NOT NULL, details TEXT, created_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS audit_events_instance_created ON audit_events(instance_id,created_at DESC);
    CREATE TABLE IF NOT EXISTS activity_events (id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id TEXT REFERENCES instances(id), message TEXT NOT NULL, status TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'activity', created_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS activity_events_instance_created ON activity_events(instance_id,created_at DESC);
    CREATE TABLE IF NOT EXISTS icon_mirror (instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE, source TEXT NOT NULL, slug TEXT NOT NULL, format TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'mirrored', content_hash TEXT NOT NULL, last_synced_at TEXT NOT NULL, upstream_removed_at TEXT, PRIMARY KEY(instance_id,source,slug));
    CREATE TABLE IF NOT EXISTS access_events (id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id TEXT REFERENCES instances(id), at TEXT, host TEXT, method TEXT, uri TEXT, status INTEGER, size INTEGER, duration_ms INTEGER, remote_ip TEXT, source TEXT, UNIQUE(instance_id,source));
    CREATE INDEX IF NOT EXISTS access_events_instance_at ON access_events(instance_id,at DESC);
    CREATE TABLE IF NOT EXISTS api_tokens (id TEXT PRIMARY KEY, instance_id TEXT REFERENCES instances(id) ON DELETE CASCADE, name TEXT NOT NULL, token_hash TEXT NOT NULL, prefix TEXT NOT NULL, owner_user_id TEXT NOT NULL, scope TEXT NOT NULL DEFAULT 'full', session_version TEXT, created_at TEXT NOT NULL, last_used_at TEXT, expires_at TEXT, revoked_at TEXT);
    CREATE INDEX IF NOT EXISTS api_tokens_hash ON api_tokens(token_hash);
    CREATE INDEX IF NOT EXISTS api_tokens_instance ON api_tokens(instance_id);
    CREATE TABLE IF NOT EXISTS backup_events (id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id TEXT REFERENCES instances(id) ON DELETE CASCADE, type TEXT NOT NULL, filename TEXT, backup_type TEXT, size_bytes INTEGER, actor_user_id TEXT, created_at TEXT NOT NULL, safety_backup_filename TEXT, status TEXT NOT NULL DEFAULT 'success', error_message TEXT);
    CREATE INDEX IF NOT EXISTS backup_events_instance_created ON backup_events(instance_id,created_at DESC);
  `);
  try { db.exec("ALTER TABLE activity_events ADD COLUMN category TEXT NOT NULL DEFAULT 'activity'"); } catch { /* Column already exists. */ }
  try { db.exec("ALTER TABLE api_tokens ADD COLUMN icon TEXT"); } catch { /* Column already exists. */ }
  try { db.exec("ALTER TABLE api_tokens ADD COLUMN icon_slug TEXT"); } catch { /* Column already exists. */ }
  try { db.exec("ALTER TABLE icon_mirror ADD COLUMN label TEXT"); } catch { /* Column already exists. */ }
  try { db.exec("ALTER TABLE icon_mirror ADD COLUMN search_text TEXT"); } catch { /* Column already exists. */ }
  const timestamp = now();
  db.prepare("INSERT OR IGNORE INTO instances(id,name,kind,status,created_at,updated_at) VALUES(?,?,?,?,?,?)").run(LOCAL_INSTANCE_ID, "Local Gateway", "local", "active", timestamp, timestamp);
  db.prepare("INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,?)").run(timestamp);
  // Migration 2: Gateway Events used to classify each row into one of only three categories
  // (activity/certificate/security) at write time, purely for retention pruning. The UI's own
  // filter dropdown separately re-derived a richer six-way category from the same message text
  // client-side, on every render, using a different regex -- the two could disagree. Now that
  // classifyActivity() (above) is the single source of truth computed once at write time,
  // every pre-existing row still carries its old 3-way category and needs recomputing under the
  // new 6-way scheme so historical and new events filter consistently. Guarded by its own
  // schema_migrations row so this bulk UPDATE runs exactly once, not on every boot.
  if (!db.prepare("SELECT 1 FROM schema_migrations WHERE version=2").get()) {
    const legacyRows = db.prepare("SELECT id,message FROM activity_events").all();
    if (legacyRows.length) {
      const updateCategory = db.prepare("UPDATE activity_events SET category=? WHERE id=?");
      transaction(() => { for (const row of legacyRows) updateCategory.run(classifyActivity(row.message), row.id); });
    }
    db.prepare("INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(2,?)").run(timestamp);
  }

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
  // The single source of truth for a Gateway Event's category. Previously this coarse 3-way
  // split (activity/certificate/security, used only for retention pruning) and a separate,
  // richer 6-way split computed independently client-side by categoryOf() in app.js (used only
  // for the UI's filter dropdown) classified the same message text with two different regexes
  // that could disagree. classifyActivity() is now the one place this decision is made, at
  // write time, and both the UI filter and retention pruning read the stored result instead of
  // re-deriving it. See mapActivityCategoryToRetentionBucket() below for how these six values
  // map back onto the three retention buckets the Logs & Retention policy still tracks.
  function classifyActivity(text) { return /cert|tls|https|acme/i.test(text) ? "certificate" : /health|upstream|response|fetch/i.test(text) ? "health" : /login|user|password|access|credential|security/i.test(text) ? "authentication" : /backup|restore/i.test(text) ? "backup" : /config|route|host|gateway|reload/i.test(text) ? "configuration" : "system"; }
  function recordActivity(message, status = "ok", instanceId = LOCAL_INSTANCE_ID) { const text = String(message); const category = classifyActivity(text); const result = db.prepare("INSERT INTO activity_events(instance_id,message,status,category,created_at) VALUES(?,?,?,?,?)").run(instanceId, text, status, category, now()); return result.lastInsertRowid; }
  function listActivity(limit = 100, instanceId = LOCAL_INSTANCE_ID) { return db.prepare("SELECT id,message,status,category,created_at AS at FROM activity_events WHERE instance_id=? ORDER BY id DESC LIMIT ?").all(instanceId, Math.max(1, Math.min(Number(limit) || 100, 500))); }
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
        SUM(CASE WHEN at>=? THEN COALESCE(size,0) ELSE 0 END) AS hourBytes,
        COUNT(DISTINCT CASE WHEN at>=? THEN remote_ip END) AS hourVisitors,
        COUNT(*) AS dayRequests,
        SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END) AS dayErrors,
        AVG(duration_ms) AS dayAvgMs,
        SUM(COALESCE(size,0)) AS dayBytes,
        COUNT(DISTINCT remote_ip) AS dayVisitors
      FROM access_events WHERE instance_id=? AND at>=? AND host IS NOT NULL AND host!=''
      GROUP BY host ORDER BY dayRequests DESC
    `).all(hourCutoff, hourCutoff, hourCutoff, hourCutoff, hourCutoff, instanceId, dayCutoff);
  }
  function performanceErrorBreakdown(instanceId = LOCAL_INSTANCE_ID) {
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
    const rows = db.prepare(`SELECT at,status FROM access_events WHERE instance_id=? AND at>=? AND (?='' OR host=?)`).all(instanceId, cutoff, host, host);
    const buckets = new Map();
    for (const row of rows) { const t = new Date(row.at).getTime(); if (Number.isNaN(t)) continue; const bucketStart = Math.floor(t / bucketMs) * bucketMs; const entry = buckets.get(bucketStart) || { count: 0, errors: 0 }; entry.count += 1; if (Number(row.status) >= 400) entry.errors += 1; buckets.set(bucketStart, entry); }
    const startBucket = Math.floor((Date.now() - windowMs) / bucketMs) * bucketMs, endBucket = Math.floor(Date.now() / bucketMs) * bucketMs;
    const points = [];
    for (let bucket = startBucket; bucket <= endBucket; bucket += bucketMs) { const entry = buckets.get(bucket); points.push({ at: new Date(bucket).toISOString(), count: entry?.count || 0, errors: entry?.errors || 0 }); }
    return points;
  }
  // Retention still tracks three buckets for Gateway Events (activity/certificate/security),
  // matching the Logs & Retention policy's own three day-count fields -- but the stored
  // category column now holds one of six values (see classifyActivity above), so each bucket
  // maps onto a set of those six rather than a single exact match: "certificate" is unchanged,
  // "security" now matches the "authentication" category (closest equivalent to the old
  // security bucket), and "activity" is everything else (health/backup/configuration/system).
  const ACTIVITY_RETENTION_FILTERS = { activity: "category NOT IN ('certificate','authentication')", certificate: "category='certificate'", security: "category='authentication'" };
  function pruneEvents(policy = {}, instanceId = LOCAL_INSTANCE_ID) { const cutoff = days => new Date(Date.now() - Math.max(7, Number(days) || 30) * 86400000).toISOString(); return transaction(() => { const counts = {}; const jobs = [["access", "access_events", "at", policy.accessDays, ""], ["activity", "activity_events", "created_at", policy.activityDays, ACTIVITY_RETENTION_FILTERS.activity], ["certificate", "activity_events", "created_at", policy.certificateDays, ACTIVITY_RETENTION_FILTERS.certificate], ["security", "activity_events", "created_at", policy.securityDays, ACTIVITY_RETENTION_FILTERS.security], ["audit", "audit_events", "created_at", policy.auditDays, ""]]; for (const [name, table, column, days, filter] of jobs) { const result = db.prepare(`DELETE FROM ${table} WHERE instance_id=? AND ${column} < ?${filter ? ` AND ${filter}` : ""}`).run(instanceId, cutoff(days)); counts[name] = Number(result.changes || 0); } return counts; }); }
  function previewPruneEvents(policy = {}, instanceId = LOCAL_INSTANCE_ID) { const cutoff = days => new Date(Date.now() - Math.max(7, Number(days) || 30) * 86400000).toISOString(); const counts = {}; const jobs = [["access", "access_events", "at", policy.accessDays, ""], ["activity", "activity_events", "created_at", policy.activityDays, ACTIVITY_RETENTION_FILTERS.activity], ["certificate", "activity_events", "created_at", policy.certificateDays, ACTIVITY_RETENTION_FILTERS.certificate], ["security", "activity_events", "created_at", policy.securityDays, ACTIVITY_RETENTION_FILTERS.security], ["audit", "audit_events", "created_at", policy.auditDays, ""]]; for (const [name, table, column, days, filter] of jobs) counts[name] = Number(db.prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE instance_id=? AND ${column} < ?${filter ? ` AND ${filter}` : ""}`).get(instanceId, cutoff(days)).count || 0); return counts; }
  function listAudit(filters = {}, instanceId = LOCAL_INSTANCE_ID) { const rows = db.prepare("SELECT id,actor_id,action,status,details,created_at FROM audit_events WHERE instance_id=? ORDER BY id DESC LIMIT 500").all(instanceId); return rows.filter(row => (!filters.user || row.actor_id === filters.user) && (!filters.action || row.action.toLowerCase().includes(filters.action.toLowerCase())) && (!filters.status || row.status === filters.status)).map(row => ({ ...row, details: row.details ? JSON.parse(row.details) : null })); }
  // 95th-percentile latency per host. SQLite has no percentile aggregate, so the
  // durations come back pre-sorted per host and the index is picked in JavaScript.
  function performancePercentiles(percentile = 0.95, instanceId = LOCAL_INSTANCE_ID) {
    const hourCutoff = new Date(Date.now() - 3600000).toISOString(), dayCutoff = new Date(Date.now() - 86400000).toISOString();
    const rows = db.prepare("SELECT host,at,duration_ms AS durationMs FROM access_events WHERE instance_id=? AND at>=? AND duration_ms IS NOT NULL AND host IS NOT NULL AND host!='' ORDER BY host, duration_ms").all(instanceId, dayCutoff);
    const pick = values => { if (!values.length) return null; const index = Math.min(values.length - 1, Math.max(0, Math.ceil(percentile * values.length) - 1)); return Math.round(values[index]); };
    const byHost = new Map();
    for (const row of rows) { if (!byHost.has(row.host)) byHost.set(row.host, { day: [], hour: [] }); const entry = byHost.get(row.host); entry.day.push(row.durationMs); if (row.at >= hourCutoff) entry.hour.push(row.durationMs); }
    return Object.fromEntries([...byHost].map(([host, entry]) => [host, { hourP95: pick(entry.hour), dayP95: pick(entry.day) }]));
  }
  function performanceTopPaths(limit = 10, instanceId = LOCAL_INSTANCE_ID) {
    const dayCutoff = new Date(Date.now() - 86400000).toISOString();
    const cap = Math.max(1, Math.min(Number(limit) || 10, 50));
    const rows = db.prepare("SELECT host,uri,COUNT(*) AS count FROM access_events WHERE instance_id=? AND at>=? AND host IS NOT NULL AND host!='' GROUP BY host,uri ORDER BY host, count DESC").all(instanceId, dayCutoff);
    const byHost = new Map();
    for (const row of rows) { const list = byHost.get(row.host) || []; if (list.length < cap) list.push({ uri: row.uri || "/", count: row.count }); byHost.set(row.host, list); }
    return Object.fromEntries(byHost);
  }
  function performanceSlowest(host = "", hours = 6, limit = 20, instanceId = LOCAL_INSTANCE_ID) {
    const cutoff = new Date(Date.now() - Math.max(1, Number(hours) || 6) * 3600000).toISOString();
    return db.prepare("SELECT host,uri,method,status,duration_ms AS durationMs,at FROM access_events WHERE instance_id=? AND at>=? AND (?='' OR host=?) AND duration_ms IS NOT NULL ORDER BY duration_ms DESC LIMIT ?").all(instanceId, cutoff, host, host, Math.max(1, Math.min(Number(limit) || 20, 50)));
  }
  // --- API tokens. Dedicated table (not the generic JSON-collection pattern) because
  // every authenticated API request looks a token up by its SHA-256 hash.
  function listApiTokens(instanceId = LOCAL_INSTANCE_ID) { return db.prepare("SELECT id,name,prefix,owner_user_id AS ownerUserId,scope,icon,icon_slug AS iconSlug,created_at AS createdAt,last_used_at AS lastUsedAt,expires_at AS expiresAt,revoked_at AS revokedAt FROM api_tokens WHERE instance_id=? ORDER BY created_at DESC").all(instanceId); }
  function createApiToken(row, instanceId = LOCAL_INSTANCE_ID) { db.prepare("INSERT INTO api_tokens(id,instance_id,name,token_hash,prefix,owner_user_id,scope,session_version,created_at,last_used_at,expires_at,revoked_at) VALUES(?,?,?,?,?,?,?,?,?,NULL,?,NULL)").run(row.id, instanceId, String(row.name), String(row.tokenHash), String(row.prefix), String(row.ownerUserId), row.scope === "read-only" ? "read-only" : "full", row.sessionVersion || null, now(), row.expiresAt || null); return listApiTokens(instanceId).find(item => item.id === row.id) || null; }
  function findApiTokenByHash(tokenHash, instanceId = LOCAL_INSTANCE_ID) { return db.prepare("SELECT id,name,prefix,owner_user_id AS ownerUserId,scope,session_version AS sessionVersion,created_at AS createdAt,last_used_at AS lastUsedAt,expires_at AS expiresAt,revoked_at AS revokedAt FROM api_tokens WHERE instance_id=? AND token_hash=?").get(instanceId, String(tokenHash)) || null; }
  function revokeApiToken(id, instanceId = LOCAL_INSTANCE_ID) { return Number(db.prepare("UPDATE api_tokens SET revoked_at=? WHERE instance_id=? AND id=? AND revoked_at IS NULL").run(now(), instanceId, id).changes || 0) > 0; }
  function touchApiToken(id, instanceId = LOCAL_INSTANCE_ID) { db.prepare("UPDATE api_tokens SET last_used_at=? WHERE instance_id=? AND id=?").run(now(), instanceId, id); }
  function setApiTokenIcon(id, { icon, iconSlug }, instanceId = LOCAL_INSTANCE_ID) { const changes = db.prepare("UPDATE api_tokens SET icon=?, icon_slug=? WHERE instance_id=? AND id=?").run(icon || null, iconSlug || null, instanceId, id).changes; return changes > 0 ? listApiTokens(instanceId).find(item => item.id === id) || null : null; }

  function upsertIconMirror({ source, slug, format, contentHash, label, searchText }, instanceId = LOCAL_INSTANCE_ID) { db.prepare("INSERT INTO icon_mirror(instance_id,source,slug,format,status,content_hash,last_synced_at,upstream_removed_at,label,search_text) VALUES(?,?,?,?,'mirrored',?,?,NULL,?,?) ON CONFLICT(instance_id,source,slug) DO UPDATE SET format=excluded.format, status='mirrored', content_hash=excluded.content_hash, last_synced_at=excluded.last_synced_at, upstream_removed_at=NULL, label=excluded.label, search_text=excluded.search_text").run(instanceId, source, slug, format, contentHash, now(), label || slug, searchText || slug); }
  function markIconMirrorRemoved(source, slugsStillPresent, instanceId = LOCAL_INSTANCE_ID) { const rows = db.prepare("SELECT slug FROM icon_mirror WHERE instance_id=? AND source=? AND status='mirrored'").all(instanceId, source); const present = new Set(slugsStillPresent); const update = db.prepare("UPDATE icon_mirror SET status='removed', upstream_removed_at=? WHERE instance_id=? AND source=? AND slug=?"); let removed = 0; for (const row of rows) if (!present.has(row.slug)) { update.run(now(), instanceId, source, row.slug); removed += 1; } return removed; }
  function iconMirrorStats(instanceId = LOCAL_INSTANCE_ID) { return db.prepare("SELECT source, status, COUNT(*) AS count, MAX(last_synced_at) AS last_synced_at FROM icon_mirror WHERE instance_id=? GROUP BY source, status").all(instanceId); }
  function findIconMirror(source, slug, instanceId = LOCAL_INSTANCE_ID) { return db.prepare("SELECT * FROM icon_mirror WHERE instance_id=? AND source=? AND slug=?").get(instanceId, source, slug) || null; }
  function searchIconMirror(query, limit = 30, instanceId = LOCAL_INSTANCE_ID) {
    const needle = `%${String(query).toLowerCase()}%`;
    const rows = db.prepare(
      "SELECT source, slug, format, label, search_text AS searchText, content_hash AS contentHash FROM icon_mirror " +
      "WHERE instance_id=? AND status='mirrored' AND (search_text LIKE ? OR slug LIKE ?) " +
      "ORDER BY CASE source WHEN 'dashboard-icons' THEN 0 WHEN 'selfhst' THEN 1 ELSE 2 END, slug"
    ).all(instanceId, needle, needle);
    // One source-priority pass to dedupe by slug (dashboard-icons already sorted first above),
    // then a relevance sort matching the existing search-tier convention (exact/startsWith/contains).
    const seen = new Set();
    const deduped = [];
    for (const row of rows) { if (seen.has(row.slug)) continue; seen.add(row.slug); deduped.push(row); }
    const lowerQuery = String(query).toLowerCase();
    // dashboard-icons/selfhst commonly ship a "-light"/"-dark" background-context variant
    // alongside a brand's base icon (plex, plex-dark, plex-light, plex-dash-dark, ...) -- real,
    // distinct files, not duplicates, but this app is dark-only and showing every variant in a
    // single unified results grid buries the one icon most searches actually want. Hide them from
    // a broad search (lucide is unaffected -- it has no such convention), but never hide the exact
    // slug someone actually typed, so a specific variant stays reachable on request.
    const filtered = deduped.filter(row => row.source === "lucide" || row.slug === lowerQuery || !/-(?:light|dark)$/i.test(row.slug));
    const scored = filtered.map(row => ({
      ...row,
      score: row.slug === lowerQuery ? 0 : row.slug.startsWith(lowerQuery) ? 1 : (row.label || "").toLowerCase().startsWith(lowerQuery) ? 2 : 3,
    }));
    scored.sort((left, right) => left.score - right.score || left.slug.localeCompare(right.slug));
    return scored.slice(0, Math.max(1, Math.min(Number(limit) || 30, 100)));
  }
  // --- Backup history. Independent of what is on disk, so deleted backups and failed
  // attempts stay visible in the timeline.
  function recordBackupEvent(event, instanceId = LOCAL_INSTANCE_ID) { db.prepare("INSERT INTO backup_events(instance_id,type,filename,backup_type,size_bytes,actor_user_id,created_at,safety_backup_filename,status,error_message) VALUES(?,?,?,?,?,?,?,?,?,?)").run(instanceId, String(event.type), event.filename || null, event.backupType || null, event.sizeBytes ?? null, event.actorUserId || null, event.createdAt || now(), event.safetyBackupFilename || null, event.status === "failed" ? "failed" : "success", event.errorMessage ? String(event.errorMessage).slice(0, 500) : null); }
  function listBackupEvents(limit = 500, instanceId = LOCAL_INSTANCE_ID) { return db.prepare("SELECT id,type,filename,backup_type AS backupType,size_bytes AS sizeBytes,actor_user_id AS actorUserId,created_at AS createdAt,safety_backup_filename AS safetyBackupFilename,status,error_message AS errorMessage FROM backup_events WHERE instance_id=? ORDER BY id DESC LIMIT ?").all(instanceId, Math.max(1, Math.min(Number(limit) || 500, 500))); }
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
  function humanizeGatewayErrors(instanceId = LOCAL_INSTANCE_ID) { const friendly = "Gateway configuration rejected: HTTP upstream cannot use HTTPS transport. Disable upstream TLS verification or change the upstream URL to HTTPS."; const activity = db.prepare("SELECT id FROM activity_events WHERE instance_id=? AND message LIKE '%upstream address scheme is HTTP but transport is configured for HTTP+TLS%'").all(instanceId); const updateActivity = db.prepare("UPDATE activity_events SET message=? WHERE id=?"); for (const row of activity) updateActivity.run(friendly, row.id); const audit = db.prepare("SELECT id FROM audit_events WHERE instance_id=? AND action LIKE '%upstream address scheme is HTTP but transport is configured for HTTP+TLS%'").all(instanceId); const updateAudit = db.prepare("UPDATE audit_events SET action=? WHERE id=?"); for (const row of audit) updateAudit.run(friendly, row.id); return activity.length + audit.length; }
  const result = integrity(); if (result.length !== 1 || result[0] !== "ok") { db.close(); throw new Error(`SQLite integrity check failed: ${result.join(", ")}`); }
  return { db, databasePath, isNew, snapshot, loadCollection, saveCollection, loadSettings, saveSettings, integrity, recordAudit, listAudit, recordActivity, listActivity, humanizeGatewayErrors, recordAccessEvents, listAccessEvents, pruneEvents, previewPruneEvents, backupTo, performanceLiveCount, performanceRoutes, performanceErrorBreakdown, performanceTrend, performancePercentiles, performanceTopPaths, performanceSlowest, listApiTokens, createApiToken, findApiTokenByHash, revokeApiToken, touchApiToken, setApiTokenIcon, upsertIconMirror, markIconMirrorRemoved, iconMirrorStats, findIconMirror, searchIconMirror, recordBackupEvent, listBackupEvents, close: () => db.close() };
}
