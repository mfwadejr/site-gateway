const $ = selector => document.querySelector(selector);
const state = { sites: [], proxies: [], redirects: [], streams: [], accessLists: [], groups: [], backups: [], settings: null, dashboard: null, certificates: null, readiness: null, logs: null, users: [], user: null, config: null, view: "overview", loaded: false, pendingDelete: null, pendingReplace: null, editing: null, iconTarget: null, passwordTarget: null, healthTimer: null };
document.querySelector("#create-form [name=domain]")?.closest("label")?.childNodes[0] && (document.querySelector("#create-form [name=domain]").closest("label").childNodes[0].textContent = "Primary domain ");
if (!document.querySelector("#create-form [name=accessListId]")) { const anchor = document.querySelector("#create-form [name=tls]")?.closest("label"); if (anchor) { const label = document.createElement("label"); label.innerHTML = '<span>Access List <span class="optional">Optional</span></span><select name="accessListId"><option value="">Public — no Access List</option></select><small>Protect this hosted site and all of its domains.</small>'; anchor.before(label); } }
if (!document.querySelector("#settings-access-list")) { const anchor = document.querySelector("#settings-form [name=domain]")?.closest("label"); if (anchor) { const label = document.createElement("label"); label.innerHTML = '<span>Access List <span class="optional">Optional</span></span><select id="settings-access-list" name="accessListId"><option value="">Public — no Access List</option></select><small>Protect this route and all of its domains.</small>'; anchor.after(label); } }
const proxyAccessLabel = document.querySelector("#proxy-form [name=accessListId]")?.closest("label"); const proxyTlsLabel = document.querySelector("#proxy-form [name=tls]")?.closest("label"); if (proxyAccessLabel && proxyTlsLabel) proxyTlsLabel.before(proxyAccessLabel);
const settingsAccessLabel = document.querySelector("#settings-access-list")?.closest("label"); const settingsTlsLabel = document.querySelector("#settings-form [name=tls]")?.closest("label"); if (settingsAccessLabel && settingsTlsLabel) settingsTlsLabel.before(settingsAccessLabel);
document.querySelector("#settings-advanced [name=accessListId]")?.closest("label")?.remove();
const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");

function applyTheme(preference) {
  const effective = preference === "system" ? (systemTheme.matches ? "dark" : "light") : preference;
  document.documentElement.dataset.theme = effective;
  document.querySelector('meta[name="theme-color"]').content = effective === "dark" ? "#08101d" : "#f3f6fa";
}
const savedTheme = localStorage.getItem("webserver-theme") || "system";
$("#theme-select").value = savedTheme; applyTheme(savedTheme);
$("#theme-select").addEventListener("change", event => { localStorage.setItem("webserver-theme", event.target.value); applyTheme(event.target.value); });
systemTheme.addEventListener("change", () => { if ($("#theme-select").value === "system") applyTheme("system"); });

async function api(url, options = {}) {
  const response = await fetch(url, options);
  if (response.status === 401) { showLogin(); throw new Error("Please sign in again."); }
  if (!response.ok) { const body = await response.json().catch(() => ({})); throw new Error(body.error || "Request failed."); }
  return response.status === 204 ? null : response.json();
}
function showLogin(message = "") { state.user = null; state.users = []; state.view = "overview"; const form = $("#login-form"); form.reset(); form.elements.username.value = ""; form.elements.password.value = ""; $("#login").classList.remove("hidden"); $("#dashboard").classList.add("hidden"); $("#login-error").textContent = message; $("#mfa-login-form").reset(); $("#mfa-login-form").classList.add("hidden"); $("#login-form").classList.remove("hidden"); $("#mfa-login-error").textContent = ""; setTimeout(() => form.elements.username.focus(), 0); }
function showDashboard() { $("#login").classList.add("hidden"); $("#dashboard").classList.remove("hidden"); }
function toast(message) { const el = $("#toast"); el.textContent = message; el.classList.add("show"); setTimeout(() => el.classList.remove("show"), 2800); }
function escapeHtml(value) { const el = document.createElement("div"); el.textContent = value ?? ""; return el.innerHTML; }
function publicUrl(item) { return item.domain ? `${item.tls === "http" ? "http" : "https"}://${item.domain}` : `${location.protocol}//${location.hostname}:${item.port}`; }
function formatBytes(value) {
  if (!Number.isFinite(value)) return "Unavailable";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"]; let size = value / 1024, unit = units[0];
  for (let index = 1; size >= 1024 && index < units.length; index++) { size /= 1024; unit = units[index]; }
  return `${size >= 10 ? size.toFixed(0) : size.toFixed(1)} ${unit}`;
}
function formatDuration(seconds) {
  if (!Number.isFinite(seconds)) return "Unavailable";
  const days = Math.floor(seconds / 86400), hours = Math.floor(seconds % 86400 / 3600), minutes = Math.floor(seconds % 3600 / 60);
  if (days) return `${days}d ${hours}h`; if (hours) return `${hours}h ${minutes}m`; return `${minutes}m`;
}
function formatTime(value) {
  if (!value) return "Just now";
  const date = new Date(value); return Number.isNaN(date.getTime()) ? "Recently" : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}
function formatRelativeTime(value) {
  if (!value) return "Just now";
  const date = new Date(value); if (Number.isNaN(date.getTime())) return "Recently";
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 45) return "Just now";
  if (seconds < 90) return "1 minute ago";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} minutes ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.round(hours / 24);
  if (days < 7) return `${days} day${days === 1 ? "" : "s"} ago`;
  return formatTime(value);
}
function certificateStatusLabel(status) { return ({ healthy:"Healthy", warning:"Renewal due soon", critical:"Renewal required urgently", expired:"Expired", pending:"Awaiting Caddy / ACME certificate", mismatch:"Certificate does not cover this domain" }[status] || String(status || "Unknown")).replaceAll("-", " "); }
function parseHeaderLines(value) { return String(value || "").split("\n").map(line => { const index = line.indexOf(":"); return index > 0 ? { name:line.slice(0,index).trim(), value:line.slice(index+1).trim() } : null; }).filter(Boolean); }
function monitoringChecked(form, kind) { const scope = kind === "proxy" ? "#settings-advanced" : "#settings-hosted-advanced"; return Boolean(form.querySelector(`${scope} [name="healthEnabled"]`)?.checked); }
// event.submitter is null on implicit form submission (e.g. pressing Enter in a field instead of
// clicking the button), which previously crashed every save handler below on `button.disabled = true`
// and silently dropped the whole save. Fall back to the form's actual submit button.
function resolveSubmitter(event) { return event.submitter || event.target.querySelector('button:not([type="button"])'); }
function scopedValue(form, scope, name, fallback = "") { return form.querySelector(`${scope} [name="${name}"]`)?.value || fallback; }
// #settings-form reuses field names (healthEnabled, healthPath, accessListId, compression, etc.) between the
// hidden site-scoped (#settings-hosted-advanced) and proxy-scoped (#settings-advanced) sections. form.elements.NAME
// resolves to a RadioNodeList when a name is duplicated, and assigning .value/.checked to a RadioNodeList of
// non-radio inputs silently does nothing — so every one of these fields must be read/written through its scope.
function setScoped(form, scope, name, value) { const el = form.querySelector(`${scope} [name="${name}"]`); if (!el) return; if (el.type === "checkbox") el.checked = Boolean(value); else el.value = value; }
function advancedFormBody(form, body, scoped) {
  // scoped = { scope, formEl } — pass this when `form` came from a shared form (like #settings-form) where
  // field names collide with another section, so every ambiguous field is read from its own scope instead of
  // trusting the unscoped FormData value (which can silently pick up the other section's field).
  const read = (name, fallback = "") => scoped ? scopedValue(scoped.formEl, scoped.scope, name, fallback) : (form.get(name) || fallback);
  const checked = (name) => scoped ? Boolean(scoped.formEl.querySelector(`${scoped.scope} [name="${name}"]`)?.checked) : form.has(name);
  body.domains = String(form.get("domainsText") || "").split(/[\n,]+/).map(value => value.trim()).filter(Boolean);
  body.hsts = form.has("hsts"); body.hstsSubdomains = checked("hstsSubdomains"); body.healthEnabled = checked("healthEnabled"); body.upstreamTlsInsecure = checked("upstreamTlsInsecure"); body.blockCommonExploits = checked("blockCommonExploits");
  body.accessListId = read("accessListId", body.accessListId || "");
  body.requestHeaders = parseHeaderLines(read("requestHeadersText")); body.responseHeaders = parseHeaderLines(read("responseHeadersText")); body.compression = read("compression", "automatic"); body.customConfig = read("customConfig");
  body.locations = String(form.get("customLocationsText") || "").split("\n").map(line => { const [path, target, behavior] = line.split("|").map(value => value.trim()); return path && target ? { path, target, stripPrefix:behavior.toLowerCase() === "strip" } : null; }).filter(Boolean);
  body.upstreams = String(form.get("upstreamsText") || "").split("\n").map(value => value.trim()).filter(Boolean);
  body.healthPath = read("healthPath", "/"); body.healthMethod = read("healthMethod", "GET"); body.healthExpected = read("healthExpected", "200-499"); body.healthTimeoutSeconds = Number(read("healthTimeoutSeconds", "4")); body.healthRetries = Number(read("healthRetries", "0"));
  delete body.requestHeadersText; delete body.responseHeadersText; delete body.customLocationsText;
  return body;
}
// Single capture-path for monitoring settings: unchecked checkboxes must be sent as false.
document.addEventListener("submit", async event => {
  if (event.target?.id !== "settings-form" || !state.editing) return;
  event.preventDefault(); event.stopImmediatePropagation();
  const form = new FormData(event.target), button = resolveSubmitter(event);
  const certificate = form.get("certificateFile"), privateKey = form.get("privateKeyFile");
  let body = Object.fromEntries(form); delete body.certificateFile; delete body.privateKeyFile;
  if (state.editing.kind === "proxy") body = advancedFormBody(form, body, { scope: "#settings-advanced", formEl: event.target });
  else { const scope = "#settings-hosted-advanced"; body = { domain: body.domain, domains: String(form.get("domainsText") || "").split(/[\n,]+/).map(value => value.trim()).filter(Boolean), tls: body.tls, hsts: form.has("hsts"), accessListId: scopedValue(event.target, scope, "accessListId"), healthEnabled: monitoringChecked(event.target, "site"), healthPath: scopedValue(event.target, scope, "healthPath", "/"), healthMethod: scopedValue(event.target, scope, "healthMethod", "GET"), healthExpected: scopedValue(event.target, scope, "healthExpected", "200-499"), healthTimeoutSeconds: Number(scopedValue(event.target, scope, "healthTimeoutSeconds", "4")), healthRetries: Number(scopedValue(event.target, scope, "healthRetries", "0")), compression: scopedValue(event.target, scope, "compression", "automatic"), requestHeaders: parseHeaderLines(scopedValue(event.target, scope, "requestHeadersText")), responseHeaders: parseHeaderLines(scopedValue(event.target, scope, "responseHeadersText")), hstsSubdomains: event.target.querySelector(`${scope} [name="hstsSubdomains"]`)?.checked === true, customConfig: scopedValue(event.target, scope, "customConfig") }; }
  const uploadCustom = state.editing.kind === "proxy" && body.tls === "custom" && certificate?.size && privateKey?.size;
  if (state.editing.kind === "proxy" && body.tls === "custom" && !uploadCustom) {
    const existing = state.proxies.find(item => item.id === state.editing.id);
    if (!existing?.certificatePath) { $("#settings-error").textContent = "Choose both the certificate and private key for Custom HTTPS."; return; }
  }
  button.disabled = true;
  try {
    await api(`/api/${state.editing.kind === "proxy" ? "proxies" : "sites"}/${state.editing.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (uploadCustom) { const files = new FormData(); files.append("certificate", certificate); files.append("privateKey", privateKey); await api(`/api/proxies/${state.editing.id}/certificate`, { method: "POST", body: files }); }
    $("#settings-dialog").close(); await refresh(); toast("Gateway settings applied.");
  }
  catch (error) { $("#settings-error").textContent = error.message; }
  finally { button.disabled = false; }
}, true);

function healthCopy(group, label) {
  if (!group.total) return "Nothing configured";
  if (group.errors) return `${group.errors} ${group.errors === 1 ? label.replace(/s$/, "") : label} need attention`;
  if (group.running) return `${group.running} running${group.disabled ? ` · ${group.disabled} disabled` : ""}`;
  return `${group.disabled} disabled`;
}

function probeClass(service) { return service.status === "ready" ? "running" : service.status === "error" ? "error" : service.status === "checking" ? "idle" : "inactive"; }
function probeCopy(service, ready, error, unconfigured = "Not configured") {
  if (service.status === "checking") return "Checking again before reporting a problem";
  if (service.status === "unconfigured") return unconfigured;
  return service.status === "ready" ? ready : error;
}

function renderDashboardJobs(system) { const columns = document.querySelector("#dashboard-view .dashboard-columns"), health = columns?.firstElementChild; if (!columns) return; let panel = document.querySelector("#dashboard-jobs"); if (!panel) { panel = document.createElement("section"); panel.id = "dashboard-jobs"; panel.className = "dashboard-panel dashboard-jobs-panel"; columns.insertBefore(panel, columns.children[1] || null); } if (health && health.parentElement === columns) columns.parentElement.insertBefore(health, columns); panel.innerHTML = `<div class="panel-heading"><div><p class="eyebrow">Operations</p><h2>Scheduled jobs</h2></div></div><div class="dashboard-jobs-list">${(system.jobs || []).map(job => `<div class="dashboard-list-item"><span class="status-dot ${job.enabled ? "running" : "idle"}"></span><span><strong>${escapeHtml(job.name)}</strong><small>${job.enabled ? `Active · ${escapeHtml(job.schedule)}` : "Disabled"}</small></span></div>`).join("")}</div>`; }
function updateDashboardUptime(seconds) { const started = window.__dashboardStartedAt || (window.__dashboardStartedAt = Date.now() - Number(seconds || 0) * 1000); const target = document.querySelector("#system-uptime"); if (!target) return; const elapsed = Math.max(0, Math.floor((Date.now() - started) / 1000)); target.textContent = formatDuration(elapsed); }
function renderDashboard() {
  const data = state.dashboard; if (!data) return;
  if (data.system) renderDashboardJobsSafe(data.system);
  $("#dash-hosted-total").textContent = data.hosted.total;
  $("#dash-hosted-detail").textContent = healthCopy(data.hosted, "sites");
  $("#dash-proxy-total").textContent = data.proxies.total;
  $("#dash-proxy-detail").textContent = healthCopy(data.proxies, "routes");
  $("#dash-tls-total").textContent = data.tlsDomains;
  $("#dash-tls-detail").textContent = data.certificates.total ? `${data.certificates.healthy} healthy · ${data.certificates.pending} not detected` : "No TLS domains";
  $("#dash-redirect-total").textContent = state.redirects?.length || 0;
  $("#dash-stream-total").textContent = state.streams?.length || 0;
  $("#dash-attention-total").textContent = data.attention.length;
  $("#dash-attention-detail").textContent = data.attention.length ? `${data.attention.length} item${data.attention.length === 1 ? "" : "s"} to review` : "No current issues";
  $("#dash-attention-chip").classList.toggle("accent-warning", data.attention.length > 0);
  $("#dash-attention-chip").classList.toggle("accent-green", data.attention.length === 0);
  $("#dash-attention-icon").textContent = data.attention.length > 0 ? "!" : "✓";
  $("#dash-throughput-total").textContent = data.throughput?.liveRequests ?? 0;
  const hasErrors = data.attention.length > 0, isChecking = [data.gateway, data.services.http, data.services.https].some(service => service.status === "checking"), hasNothingRunning = !data.hosted.running && !data.proxies.running;
  const overall = $("#overall-health");
  overall.className = `health-badge ${hasErrors ? "error" : isChecking || hasNothingRunning ? "warning" : "healthy"}`;
  overall.textContent = hasErrors ? "Needs attention" : isChecking ? "Checking" : hasNothingRunning ? "Idle" : "Healthy";
  $("#health-panel").className = `dashboard-panel health-panel ${hasErrors ? "status-error" : isChecking || hasNothingRunning ? "status-warning" : "status-healthy"}`;
  $("#gateway-health-dot").className = `status-dot ${probeClass(data.gateway)}`;
  $("#gateway-health-copy").textContent = probeCopy(data.gateway, data.gateway.lastReload ? `Ready · reloaded ${formatTime(data.gateway.lastReload)}` : "Ready and responding", "Caddy is not responding");
  $("#http-health-dot").className = `status-dot ${probeClass(data.services.http)}`;
  $("#http-health-copy").textContent = probeCopy(data.services.http, "Ready and responding", "Not responding");
  $("#https-health-dot").className = `status-dot ${probeClass(data.services.https)}`;
  $("#https-health-copy").textContent = probeCopy(data.services.https, `Ready and responding · ${data.services.https.activeDomains} TLS domain${data.services.https.activeDomains === 1 ? "" : "s"}`, "Not responding", "Not configured · no TLS domains enabled");
  $("#storage-health-dot").className = `status-dot ${data.services.storage.healthy ? "running" : "error"}`;
  $("#storage-health-copy").textContent = data.services.storage.healthy ? "Ready · /data is readable and writable" : "Permission error · check /data";
  const streaming = data.streamingPorts || { total: 0, listening: 0 };
  $("#streaming-health-dot").className = `status-dot ${!streaming.total ? "inactive" : streaming.listening === streaming.total ? "running" : "error"}`;
  $("#streaming-health-copy").textContent = !streaming.total ? "No streaming hosts configured" : `${streaming.listening} of ${streaming.total} port${streaming.total === 1 ? "" : "s"} listening`;
  const upstreams = data.upstreams || { total: 0, healthy: 0, unhealthy: 0 };
  $("#upstream-health-dot").className = `status-dot ${!upstreams.total ? "inactive" : upstreams.unhealthy > 0 ? "error" : "running"}`;
  $("#upstream-health-copy").textContent = !upstreams.total ? "No proxy hosts configured" : `${upstreams.healthy} of ${upstreams.total} healthy`;
  $("#health-checked").innerHTML = `<span class="live-dot" id="health-live-dot"></span>Last checked ${formatTime(data.checkedAt)}`;
  updateDashboardUptime(data.system.uptimeSeconds);
  $("#system-memory").textContent = formatBytes(data.system.memoryBytes);
  $("#system-data").textContent = formatBytes(data.system.dataBytes);
  $("#system-disk").textContent = formatBytes(data.system.diskFreeBytes);
  $("#system-disk").title = `${formatBytes(data.system.diskFreeBytes)} available of ${formatBytes(data.system.diskTotalBytes)} on the /data volume`;
  $("#system-app-version").textContent = `v${data.system.appVersion}`;
  $("#system-caddy-version").textContent = data.system.caddyVersion;
  $("#system-database").textContent = `${data.system.databaseEngine} · ${data.system.databaseStatus}`;
  $("#system-database-detail").textContent = `${formatBytes(data.system.databaseBytes)} configuration database`;
  $("#system-public-ip").textContent = data.system.publicIp || (data.system.publicIpError ? "Unavailable" : "Checking…");
  $("#system-public-ip-detail").textContent = data.system.publicIpError ? `Check failed · ${data.system.publicIpError}` : data.system.publicIpCheckedAt ? `Checked ${formatTime(data.system.publicIpCheckedAt)}` : "Not yet checked";
  $("#attention-panel").classList.toggle("is-clear", data.attention.length === 0);
  $("#dashboard-lower-columns").classList.toggle("attention-clear", data.attention.length === 0);
  $("#attention-list").innerHTML = data.attention.length ? data.attention.map(item => `<${item.target ? "button" : "div"} class="attention-tile ${item.target ? "issue-link" : ""}" ${item.target ? `data-issue-target="${escapeHtml(item.target)}"` : ""}><span class="status-dot error"></span><span class="attention-copy"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.message)}</small></span></${item.target ? "button" : "div"}>`).join("") : '<div class="all-clear"><span class="status-dot running"></span><span>Everything looks good — no issues to review.</span></div>';
  $("#activity-list").innerHTML = data.activity.length ? data.activity.slice(0, 5).map(item => `<div class="activity-tile"><span class="activity-mark ${item.status === "error" ? "bad" : item.status === "warning" ? "warn" : ""}">${item.status === "error" || item.status === "warning" ? "!" : "✓"}</span><span class="activity-copy"><strong>${escapeHtml(item.message)}</strong><small title="${escapeHtml(formatTime(item.at))}">${escapeHtml(formatRelativeTime(item.at))}</small></span></div>`).join("") : '<p class="quiet-state">No recent activity.</p>';
}
setInterval(() => { if (!document.querySelector("#dashboard-view.hidden")) updateDashboardUptime(); }, 1000);

function initials(name) {
  const words = String(name || "").trim().split(/\s+/).map(word => word.replace(/[^a-z0-9]/gi, "")).filter(Boolean);
  if (!words.length) return "??";
  return (words.length > 1 ? words[0][0] + words[1][0] : words[0].slice(0, 2).padEnd(2, words[0][0])).toUpperCase();
}
function iconMarkup(item) { return item.icon ? `<img src="${escapeHtml(item.icon)}" alt="">` : escapeHtml(initials(item.name)); }
document.addEventListener('error', event => { const image = event.target; if (!(image instanceof HTMLImageElement) || !image.closest('.site-icon') || image.dataset.fallback) return; image.dataset.fallback = 'true'; const fallback = document.createElement('span'); fallback.textContent = initials(image.closest('[data-id]')?.querySelector('h2')?.textContent || '?'); image.replaceWith(fallback); }, true);
function canManage() { return ["administrator", "standard"].includes(state.user?.role); }
function canAdmin() { return state.user?.role === "administrator"; }

function hostedCard(site) {
  const status = site.status === "running" ? "running" : site.status === "error" ? "error" : "disabled";
  const upstream = !site.enabled || site.upstream?.status === "unmonitored" ? "Monitoring paused" : !site.upstream || site.upstream.status === "pending" ? "Upstream check pending" : site.upstream.status === "healthy" ? `Upstream ${site.upstream.httpStatus} · ${site.upstream.responseMs} ms` : `Upstream unavailable · ${escapeHtml(site.upstream.error || "check failed")}`;
  const menu = canManage() ? `<div class="menu-wrap"><button class="icon-button menu-button" aria-label="Site options" aria-expanded="false">•••</button><div class="menu"><button data-action="settings">Domain & TLS</button><button data-action="icon">Change icon</button><button data-action="replace">Replace files</button><button data-action="delete" class="danger-text">Delete site</button></div></div>` : "";
  const toggle = canManage() ? `<button class="toggle ${site.enabled ? "on" : ""}" data-action="toggle" aria-label="${site.enabled ? "Disable" : "Enable"} ${escapeHtml(site.name)}"><span></span></button>` : "";
  return `<article class="site-card" data-id="${site.id}" data-kind="hosted"><div class="card-top"><div class="site-icon">${iconMarkup(site)}</div>${menu}</div><h2>${escapeHtml(site.name)}</h2><p class="address">${escapeHtml(site.domain || `Port ${site.port}`)}</p>${site.domain ? `<p class="gateway-address ${site.tls !== "http" ? "secure" : ""}">${escapeHtml(publicUrl(site))}</p>` : ""}<p class="upstream-copy ${site.upstream?.status === "unhealthy" ? "bad" : ""}">${upstream}</p><div class="card-footer"><span class="status-pill"><span class="status-dot ${status}"></span>${status === "error" ? "Needs attention" : status[0].toUpperCase() + status.slice(1)}</span><div class="card-actions">${toggle}<a class="launch" href="${publicUrl(site)}" target="_blank" rel="noopener" aria-label="Open ${escapeHtml(site.name)}">↗</a></div></div></article>`;
}
function proxyCard(proxy) {
  const status = proxy.status === "running" ? "running" : proxy.status === "error" ? "error" : "disabled";
  const upstream = !proxy.enabled || proxy.upstream?.status === "unmonitored" ? "Monitoring paused" : !proxy.upstream || proxy.upstream.status === "pending" ? "Upstream check pending" : proxy.upstream.status === "healthy" ? `Upstream ${proxy.upstream.httpStatus} · ${proxy.upstream.responseMs} ms` : `Upstream unavailable · ${escapeHtml(proxy.upstream.error || "check failed")}`;
  const menu = canManage() ? `<div class="menu-wrap"><button class="icon-button menu-button" aria-label="Proxy options" aria-expanded="false">•••</button><div class="menu"><button data-action="settings">Edit proxy</button><button data-action="icon">Change icon</button><button data-action="delete" class="danger-text">Delete proxy</button></div></div>` : "";
  const toggle = canManage() ? `<button class="toggle ${proxy.enabled ? "on" : ""}" data-action="toggle" aria-label="${proxy.enabled ? "Disable" : "Enable"} ${escapeHtml(proxy.name)}"><span></span></button>` : "";
  const access = proxy.accessListId ? (state.accessLists.find(item => item.id === proxy.accessListId)?.name || "Access List") : "Public · no Access List";
  return `<article class="site-card proxy" data-id="${proxy.id}" data-kind="proxy"><div class="card-top"><div class="site-icon">${iconMarkup(proxy)}</div>${menu}</div><h2>${escapeHtml(proxy.name)}</h2><p class="address">${escapeHtml(proxy.target)}</p><p class="gateway-address ${proxy.tls !== "http" ? "secure" : ""}">${escapeHtml(publicUrl(proxy))}</p><p class="upstream-copy ${proxy.upstream?.status === "unhealthy" ? "bad" : ""}">${upstream}</p><p class="access-summary">${escapeHtml(access)}</p><div class="card-footer"><span class="status-pill"><span class="status-dot ${status}"></span>${status === "error" ? "Needs attention" : status[0].toUpperCase() + status.slice(1)}</span><div class="card-actions">${toggle}<a class="launch" href="${publicUrl(proxy)}" target="_blank" rel="noopener" aria-label="Open ${escapeHtml(proxy.name)}">↗</a></div></div></article>`;
}

function renderCertificates() {
  const data = state.certificates; if (!data) return;
  $("#certificate-count").textContent = data.summary.total;
  $("#cert-healthy").textContent = data.summary.healthy; $("#cert-30").textContent = data.summary.within30Days; $("#cert-7").textContent = data.summary.within7Days; $("#cert-warning").textContent = data.summary.warning + data.summary.critical + data.summary.expired + data.summary.mismatch; $("#cert-pending").textContent = data.summary.pending;
  const ageMinutes = (Date.now() - new Date(data.checkedAt).getTime()) / 60000, stale = ageMinutes > (data.thresholds?.staleMinutes || 10);
  $("#cert-last-checked").textContent = `Last checked ${formatTime(data.checkedAt)} · ${stale ? "data may be stale" : "current"}`;
  $("#certificate-list").innerHTML = data.certificates.length ? data.certificates.map(cert => `<details class="certificate-row"><summary><span class="status-dot ${cert.status === "healthy" ? "running" : cert.status === "pending" ? "idle" : "error"}"></span><span><strong>${escapeHtml(cert.domain)}</strong><small>${escapeHtml(cert.kind)} · ${escapeHtml(cert.name)} · ${escapeHtml(cert.source)}</small></span><span><strong>${cert.expiresAt ? `${cert.daysRemaining} days remaining` : cert.status === "mismatch" ? "Domain mismatch" : "Not detected"}</strong><small>${cert.expiresAt ? `Expires ${formatTime(cert.expiresAt)}` : cert.mismatch ? `Covers: ${(cert.coveredNames || []).map(escapeHtml).join(", ") || "no DNS names"}` : "No stored certificate was found"}</small></span></summary><dl class="certificate-details"><div><dt>Status</dt><dd>${escapeHtml(cert.status)}</dd></div><div><dt>Valid from</dt><dd>${cert.validFrom ? escapeHtml(formatTime(cert.validFrom)) : "—"}</dd></div><div><dt>Issuer</dt><dd>${escapeHtml(cert.issuer || "—")}</dd></div><div><dt>Covered domains</dt><dd>${escapeHtml((cert.coveredNames || []).join(", ") || "—")}</dd></div><div><dt>Serial number</dt><dd>${escapeHtml(cert.serialNumber || "—")}</dd></div><div><dt>SHA-256 fingerprint</dt><dd>${escapeHtml(cert.fingerprint || "—")}</dd></div><div><dt>Last detected update</dt><dd>${cert.updatedAt ? escapeHtml(formatTime(cert.updatedAt)) : "—"}</dd></div></dl></details>`).join("") : '<p class="quiet-state padded">No HTTPS domains are configured.</p>';
  renderReadiness();
}

function renderReadiness() {
  const routes = state.readiness?.routes || [];
  $("#readiness-list").innerHTML = routes.length ? routes.map(item => {
    const dnsOk = item.dns.healthy, portsOk = item.ports.http && item.ports.https !== false;
    const tlsOk = ["healthy", "warning", "critical", "not-configured"].includes(item.tls.status);
    const upstreamOk = !item.upstream || item.upstream.status === "healthy";
    const check = item.upstream;
    const message = !dnsOk ? `DNS failed${item.dns.error ? ` · ${item.dns.error}` : ""}` : !item.ports.http ? "HTTP port 80 is not responding inside the container" : item.ports.https === false ? "HTTPS port 443 is not responding inside the container" : !tlsOk ? `TLS ${item.tls.status.replaceAll("-", " ")}` : !upstreamOk ? `Upstream ${check?.error || "unavailable"}` : `Ready · DNS ${item.dns.addresses.join(", ")}${check ? ` · upstream ${check.httpStatus || "responding"}` : ""}`;
    const upstreamDetail = check ? `<div><dt>Upstream</dt><dd>Expected ${escapeHtml(item.upstreamExpected || "200-499")} · received ${check.httpStatus ?? "no response"}${check.responseMs != null ? ` · ${check.responseMs} ms` : ""} · ${check.attempts || 1} attempt${(check.attempts || 1) === 1 ? "" : "s"}</dd></div><div><dt>Last checked</dt><dd>${escapeHtml(formatTime(check.checkedAt))}</dd></div>${check.error ? `<div><dt>Failure detail</dt><dd class="danger-text">${escapeHtml(check.error)}</dd></div>` : ""}` : "<div><dt>Upstream</dt><dd>No upstream health check configured.</dd></div>";
    return `<details class="certificate-row readiness-row"><summary><span class="status-dot ${dnsOk && portsOk && tlsOk && upstreamOk ? "running" : "error"}"></span><span><strong>${escapeHtml(item.domain)}</strong><small>${escapeHtml(message)}</small></span></summary><dl class="certificate-details"><div><dt>DNS</dt><dd>${item.dns.healthy ? `Resolved${item.dns.addresses.length ? ` · ${escapeHtml(item.dns.addresses.join(", "))}` : ""}` : `Failed${item.dns.error ? ` · ${escapeHtml(item.dns.error)}` : ""}`}</dd></div><div><dt>Gateway ports</dt><dd>HTTP 80 ${item.ports.http ? "responding" : "not responding"} · HTTPS 443 ${item.ports.https === false ? "not responding" : "responding"}</dd></div><div><dt>TLS</dt><dd>${escapeHtml(item.tls.status.replaceAll("-", " "))}</dd></div>${upstreamDetail}</dl></details>`;
  }).join("") : '<p class="quiet-state">No configured domains to check.</p>';
}

function renderLogs() {
  const data = state.logs; if (!data) return;
  const selected = $("#log-host").value; $("#log-host").innerHTML = '<option value="">All domains</option>' + data.hosts.map(host => `<option value="${escapeHtml(host)}">${escapeHtml(host)}</option>`).join(""); $("#log-host").value = selected;
  const statusClass = $("#log-status").value, entries = statusClass ? data.entries.filter(entry => String(entry.status || "").startsWith(statusClass)) : data.entries;
  const errors = entries.filter(entry => entry.status >= 400).length, measured = entries.filter(entry => entry.durationMs != null), average = measured.length ? Math.round(measured.reduce((sum,entry) => sum + entry.durationMs,0) / measured.length) : null;
  $("#log-summary").innerHTML = `${entries.length} request${entries.length === 1 ? "" : "s"} · ${errors} error response${errors === 1 ? "" : "s"} · ${average == null ? "no latency data" : `${average} ms average`} · <span id="log-last-checked">Checked ${escapeHtml(formatTime(new Date().toISOString()))}</span>`;
  $("#log-rows").innerHTML = entries.length ? entries.map(entry => `<tr><td>${escapeHtml(formatTime(entry.at))}</td><td>${escapeHtml(entry.host || "—")}</td><td><code>${escapeHtml(entry.method || "")} ${escapeHtml(entry.uri || "")}</code></td><td><span class="http-status ${entry.status >= 500 ? "bad" : ""}">${entry.status ?? "—"}</span></td><td>${entry.durationMs == null ? "—" : `${entry.durationMs} ms`}</td></tr>`).join("") : '<tr><td colspan="5" class="quiet-state">No matching requests have been logged yet.</td></tr>';
  const categoryOf = message => /cert|tls|https/i.test(message) ? "certificate" : /health|upstream|response|fetch/i.test(message) ? "health" : /login|user|password|access/i.test(message) ? "authentication" : /backup|restore/i.test(message) ? "backup" : /config|route|host|gateway|reload/i.test(message) ? "configuration" : "system";
  const severity = $("#event-severity").value, category = $("#event-category").value;
  const activity = data.activity.filter(item => (!severity || item.status === severity) && (!category || categoryOf(item.message) === category));
  $("#gateway-log-list").innerHTML = activity.length ? activity.map(item => { const eventCategory = categoryOf(item.message); const indicatorClass = item.status === "error" ? "disabled" : item.status === "warning" ? "error" : "running"; return `<div class="event-row"><span class="status-dot ${indicatorClass}" aria-label="${escapeHtml(item.status || "ok")}"></span><span><strong>${escapeHtml(item.message)}</strong><small>${escapeHtml(eventCategory)} · ${escapeHtml(formatTime(item.at))}</small></span></div>`; }).join("") : '<div class="gateway-empty-state"><span class="status-dot"></span><strong>No matching gateway events</strong><small>Try a different severity or category filter.</small></div>';
}

function renderPerformance() {
  const data = state.performance; if (!data) return;
  const selected = $("#performance-host").value;
  $("#performance-host").innerHTML = '<option value="">All domains</option>' + data.hosts.map(host => `<option value="${escapeHtml(host)}">${escapeHtml(host)}</option>`).join("");
  $("#performance-host").value = selected;
  const label = selected ? escapeHtml(selected) : "all domains";
  $("#performance-summary").innerHTML = `${data.liveRequests} request${data.liveRequests === 1 ? "" : "s"} in the last minute across ${label} · <span id="performance-last-checked">Checked ${escapeHtml(formatTime(data.checkedAt))}</span>`;
  const rangeLabel = $("#performance-range").selectedOptions[0]?.textContent || "Last 6 hours";
  $("#performance-trend-title").textContent = `Requests · ${rangeLabel.toLowerCase()}${selected ? ` · ${selected}` : ""}`;
  const points = data.trend || [];
  const max = Math.max(1, ...points.map(point => point.count));
  const left = 34, right = 8, top = 10, bottom = 20, width = 600, height = 140;
  const plotWidth = width - left - right, plotHeight = height - top - bottom;
  const xAt = index => left + (points.length > 1 ? (index / (points.length - 1)) * plotWidth : plotWidth);
  const yAt = count => top + plotHeight - (count / max) * plotHeight;
  const gridFractions = [0, 0.5, 1];
  const gridLines = gridFractions.map(fraction => {
    const y = (top + plotHeight * (1 - fraction)).toFixed(1);
    return `<line x1="${left}" y1="${y}" x2="${width - right}" y2="${y}" stroke="var(--line)" stroke-width="1" />`;
  }).join("");
  const leftPct = (left / width) * 100, topPct = 0, plotHeightPct = (plotHeight / height) * 100, topInsetPct = (top / height) * 100;
  const axisLabels = gridFractions.map(fraction => {
    const value = Math.round(max * fraction);
    const yPct = topInsetPct + plotHeightPct * (1 - fraction);
    return `<span class="axis-label" style="left:0;width:${(leftPct - 2).toFixed(2)}%;top:${yPct.toFixed(2)}%;text-align:right">${value}</span>`;
  }).join("");
  const firstPoint = points[0], lastPoint = points[points.length - 1];
  const timeLabels = points.length ? `<span class="time-label" style="left:${leftPct.toFixed(2)}%">${escapeHtml(formatTime(firstPoint.at))}</span><span class="time-label time-label-end" style="left:${(100 - (right / width) * 100).toFixed(2)}%">${escapeHtml(formatTime(lastPoint.at))}</span>` : "";
  $("#performance-sparkline-labels").innerHTML = points.length ? `${axisLabels}${timeLabels}` : "";
  const coords = points.map((point, index) => [xAt(index), yAt(point.count)]);
  const smoothLine = coords.length < 2 ? "" : coords.reduce((d, point, index) => {
    if (index === 0) return `M${point[0].toFixed(1)},${point[1].toFixed(1)}`;
    const p0 = coords[index - 2 >= 0 ? index - 2 : index - 1];
    const p1 = coords[index - 1];
    const p2 = point;
    const p3 = coords[index + 1] || point;
    const cp1x = p1[0] + (p2[0] - p0[0]) / 6, cp1y = p1[1] + (p2[1] - p0[1]) / 6;
    const cp2x = p2[0] - (p3[0] - p1[0]) / 6, cp2y = p2[1] - (p3[1] - p1[1]) / 6;
    return `${d} C${cp1x.toFixed(1)},${cp1y.toFixed(1)} ${cp2x.toFixed(1)},${cp2y.toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
  }, "");
  const baseline = (top + plotHeight).toFixed(1);
  const areaPath = coords.length ? `${smoothLine} L${coords[coords.length - 1][0].toFixed(1)},${baseline} L${coords[0][0].toFixed(1)},${baseline} Z` : "";
  $("#performance-sparkline").setAttribute("viewBox", `0 0 ${width} ${height}`);
  $("#performance-sparkline").innerHTML = points.length ? `${gridLines}<path d="${areaPath}" fill="var(--green)" opacity="0.12" stroke="none" /><path d="${smoothLine}" fill="none" stroke="var(--green)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />` : "";
  if (!points.length) $("#performance-sparkline-labels").innerHTML = '<span class="axis-label" style="left:0;width:100%;top:45%;text-align:center">No request data for this window yet.</span>';
  const routes = data.routes || [];
  const countCell = (count, errors, breakdown) => { const title = breakdown?.length ? ` title="${escapeHtml(breakdown.map(item => `${item.status}: ${item.count.toLocaleString()}`).join(" · "))}"` : ""; return `${count.toLocaleString()}${errors ? ` <span class="count-divider">·</span> <span class="http-status bad"${title}>${errors.toLocaleString()}</span>` : ""}`; };
  $("#performance-rows").innerHTML = routes.length ? routes.map(route => `<tr class="${selected && route.host === selected ? "row-highlight" : ""}"><td title="${escapeHtml(route.host)}">${escapeHtml(route.host)}</td><td>${countCell(route.hourRequests, route.hourErrors)}</td><td>${countCell(route.dayRequests, route.dayErrors, route.errorBreakdown)}</td><td>${route.dayAvgMs == null ? "—" : `${route.dayAvgMs} ms`}</td></tr>`).join("") : '<tr><td colspan="4" class="quiet-state">No requests have been logged yet.</td></tr>';
  if (selected) $(`#performance-rows tr.row-highlight`)?.scrollIntoView({ block: "nearest" });
}

function renderUsers() {
  const counts = { administrator: 0, standard: 0, viewer: 0, disabled: 0, archived: 0 };
  state.users.forEach(user => { if (user.status === "active") counts[user.role] = (counts[user.role] || 0) + 1; else if (counts[user.status] !== undefined) counts[user.status] += 1; });
  const summary = $("#user-summary");
  if (summary) summary.innerHTML = [["Administrators", counts.administrator, "#62e6a7"], ["Standard Users", counts.standard, "#6ea8ff"], ["Viewers", counts.viewer, "#b58cff"], ["Disabled", counts.disabled, "#ff7185"], ["Archived", counts.archived, "#e6a04f"]].map(([label, count, color]) => `<div><span class="status-dot" style="${count ? `background:${color}` : ""}"></span><strong>${count}</strong><span>${label}</span></div>`).join("");
  $("#user-list").innerHTML = state.users.length ? state.users.map(user => {
    const isSelf = user.id === state.user?.id;
    const statusClass = user.status === "active" ? "running" : user.status === "disabled" ? "disabled" : "inactive";
    const roleAction = user.role === "administrator" ? "standard" : user.role === "standard" ? "viewer" : "administrator";
    const roleLabel = user.role === "administrator" ? "Administrator" : user.role === "viewer" ? "Viewer" : "Standard User";
    const lifecycle = user.status === "archived" ? `<button class="button secondary" data-user-action="status" data-value="active">Restore</button>` : `<button class="button secondary danger-text" data-user-action="status" data-value="archived">Archive</button>`;
    const statusToggle = user.status === "archived" ? "" : `<button class="toggle ${user.status === "active" ? "on" : ""}" data-user-action="status" data-value="${user.status === "active" ? "disabled" : "active"}" aria-label="${user.status === "active" ? "Disable" : "Enable"} ${escapeHtml(user.username)}"><span></span></button>`;
    const menu = `<div class="menu-wrap"><button class="icon-button menu-button" type="button" aria-label="User options" aria-expanded="false">•••</button><div class="menu"><button data-user-action="icon">Change icon</button>${!isSelf ? `<button data-user-action="delete" class="danger-text">Delete</button>` : ""}</div></div>`;
    return `<article class="user-card" data-user-id="${user.id}"><div class="user-card-head"><div class="user-avatar">${escapeHtml(initials(user.displayName))}</div><div class="user-head-actions"><span class="status-pill"><span class="status-dot ${statusClass}"></span>${escapeHtml(user.status)}</span>${menu}</div></div><h2>${escapeHtml(user.displayName)}${isSelf ? ' <small>You</small>' : ""}</h2><p class="address">${escapeHtml(user.username)}</p><div class="user-meta"><span>${roleLabel}</span><span>${user.lastLoginAt ? `Last login ${escapeHtml(formatTime(user.lastLoginAt))}` : "Never signed in"}</span></div><div class="user-actions"><button class="button secondary" data-user-action="role" data-value="${roleAction}">Make ${roleAction === "administrator" ? "Administrator" : roleAction === "viewer" ? "Viewer" : "Standard"}</button><button class="button secondary" data-user-action="password">Reset password</button>${lifecycle}</div><div class="card-footer">${statusToggle}</div></article>`;
  }).join("") : '<p class="quiet-state">No users found.</p>';
  document.querySelectorAll("#user-list .user-card").forEach(card => { card.style.position = "relative"; card.style.minHeight = "250px"; card.style.paddingBottom = "64px"; const head = card.querySelector(".user-card-head"), status = head?.querySelector(".status-pill"), footer = card.querySelector(".card-footer"); if (!head || !footer) return; if (status) footer.prepend(status); });
  document.querySelectorAll("#user-list .user-card").forEach(card => { const user = state.users.find(item => item.id === card.dataset.userId); const old = card.querySelector('[data-user-action="role"]'); if (!user || !old) return; const select = document.createElement("select"); select.className = "user-role-select"; select.setAttribute("aria-label", `Role for ${user.username}`); select.innerHTML = '<option value="administrator">Administrator</option><option value="standard">Standard User</option><option value="viewer">Viewer</option>'; select.value = user.role; select.addEventListener("change", async () => { try { await api(`/api/users/${user.id}`, { method:"PATCH", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ role:select.value }) }); await loadFeatureView(); toast("User role updated."); } catch (error) { select.value = user.role; toast(error.message); } }); old.replaceWith(select); });
}

function renderAccount() {
  if (!state.user) return;
  $("#account-display-name").textContent = state.user.displayName || "—";
  $("#account-username").textContent = state.user.username || "—";
  $("#account-role").textContent = state.user.role === "administrator" ? "Administrator" : state.user.role === "viewer" ? "Viewer" : "Standard User";
  const enabled = Boolean(state.user.mfaEnabled);
  const pill = $("#account-mfa-status");
  pill.innerHTML = `<span class="status-dot ${enabled ? "running" : "inactive"}"></span>${enabled ? "On" : "Off"}`;
  $("#account-mfa-enable").classList.toggle("hidden", enabled);
  $("#account-mfa-disable").classList.toggle("hidden", !enabled);
  $("#account-mfa-recovery").classList.toggle("hidden", !enabled);
}

async function loadFeatureView() {
  if (state.view === "certificates") { [state.certificates, state.readiness] = await Promise.all([api("/api/certificates"), api("/api/readiness")]); renderCertificates(); }
  if (state.view === "logs") { state.logs = await api(`/api/logs?host=${encodeURIComponent($("#log-host").value)}`); renderLogs(); }
  if (state.view === "performance") { state.performance = await api(`/api/performance?host=${encodeURIComponent($("#performance-host").value)}&hours=${encodeURIComponent($("#performance-range").value || "6")}`); renderPerformance(); }
  if (state.view === "administration") { [state.users, state.settings, state.backups] = await Promise.all([api("/api/users"), api("/api/settings"), api("/api/backups")]); renderUsers(); window.renderExtendedViews?.(); }
  if (["redirects","access","documentation"].includes(state.view)) window.renderExtendedViews?.();
  restoreAdminTab();
}
function render() {
  const viewHash = state.view === "administration" ? `administration/${state.adminTab || "users"}` : state.view;
  if (location.hash !== `#${viewHash}`) history.pushState(null, "", `${location.pathname}${location.search}#${viewHash}`);
  $("#hosted-count").textContent = state.sites.length; $("#proxy-count").textContent = state.proxies.length; $("#streaming-count").textContent = state.streams.length; $("#redirect-count").textContent = state.redirects.length; $("#access-count").textContent = state.accessLists.length; $("#certificate-count").textContent = state.certificates?.summary.total || 0;
  document.querySelectorAll("nav [data-view], .aside-utilities [data-view]").forEach(button => button.classList.toggle("nav-active", button.dataset.view === state.view));
  const overview = state.view === "overview";
  $("#dashboard-view").classList.toggle("hidden", !overview);
  const management = state.view === "hosted" || state.view === "proxies";
  $("#management-view").classList.toggle("hidden", !management); $("#management-summary").classList.toggle("hidden", !(management || state.view === "streaming" || state.view === "redirects" || state.view === "access"));
  $("#certificates-view").classList.toggle("hidden", state.view !== "certificates"); $("#logs-view").classList.toggle("hidden", state.view !== "logs"); $("#performance-view").classList.toggle("hidden", state.view !== "performance"); $("#users-view").classList.toggle("hidden", state.view !== "administration"); $("#account-view").classList.toggle("hidden", state.view !== "account");
  if (state.view === "administration") { const adminTab = state.adminTab || "users"; document.querySelectorAll("[data-admin-tab]").forEach(item => item.classList.toggle("tab-active", item.dataset.adminTab === adminTab)); document.querySelectorAll("[data-admin-panel]").forEach(panel => panel.classList.toggle("hidden", panel.dataset.adminPanel !== adminTab)); }
  $("#streaming-view").classList.toggle("hidden", state.view !== "streaming"); $("#redirects-view").classList.toggle("hidden", state.view !== "redirects"); $("#access-view").classList.toggle("hidden", state.view !== "access"); $("#documentation-view").classList.toggle("hidden", state.view !== "documentation");
  const adminUsersActive = state.view === "administration" && document.querySelector("[data-admin-tab].tab-active")?.dataset.adminTab === "users";
  $("#open-create").classList.toggle("hidden", !(management || adminUsersActive || ["streaming","redirects","access"].includes(state.view)) || !canManage()); $("#check-health").classList.toggle("hidden", state.view !== "certificates"); $("#refresh-logs").classList.toggle("hidden", state.view !== "logs");
  if (overview) {
    $("#page-title").textContent = "Dashboard";
    $("#page-subtitle").textContent = "Health, activity, and system status at a glance.";
    renderDashboard();
    return;
  }
  if (!management) {
    const headings = { certificates:["Certificates","Expiration, issuer, and certificate-detection status for automatic HTTPS."], logs:["Access Logs & Gateway Events","Recent requests, upstream responses, and gateway health events served through Caddy."], performance:["Performance","Live and historical request throughput across your gateway."], administration:["Administration","Users, gateway defaults, backups, security, and updates."], streaming:["Streaming hosts","Forward raw TCP/UDP traffic on a specific port straight to another host and port."], redirects:["Redirect hosts","Send domains to a new destination with clear, predictable rules."], access:["Access Lists","Create reusable network and login protection for your hosts."], documentation:["Documentation","Plain-language guidance and real-world Site Gateway examples."], account:["My Account","Manage your profile, password, and two-factor authentication."] };
    const heading = headings[state.view] || ["Site Gateway",""]; $("#page-title").textContent = heading[0]; $("#page-subtitle").textContent = heading[1];
    $("#open-create").textContent = state.view === "administration" ? "＋ Create user" : state.view === "streaming" ? "＋ New streaming host" : state.view === "redirects" ? "＋ New redirect host" : state.view === "access" ? "＋ New Access List" : $("#open-create").textContent;
    if (state.view === "streaming") $("#stream-empty").classList.toggle("hidden", !state.loaded || state.streams.length > 0);
    if (state.view === "streaming") { const items = state.streams; const running = items.filter(item => item.status === "running").length, disabled = items.filter(item => item.status === "disabled").length, errors = items.filter(item => item.status === "error").length; $("#running-count").textContent = running; $("#disabled-count").textContent = disabled; $("#error-count").textContent = errors; $("#running-label").textContent = running ? "Running" : "None running"; $("#disabled-label").textContent = disabled ? "Disabled" : "None disabled"; $("#error-label").textContent = errors ? "Needs attention" : "No issues"; $("#running-dot").className = `status-dot ${running ? "running" : "inactive"}`; $("#disabled-dot").className = `status-dot ${disabled ? "disabled" : "inactive"}`; $("#error-dot").className = `status-dot ${errors ? "error" : "inactive"}`; $(".port-note").classList.add("hidden"); }
    if (state.view === "redirects") $("#redirect-empty .create-trigger").textContent = "Create a redirect host";
    if (state.view === "redirects") $("#redirect-empty").classList.toggle("hidden", !state.loaded || state.redirects.length > 0);
    if (state.view === "redirects") { const items = state.redirects; const running = items.filter(item => item.enabled !== false).length, disabled = items.length - running; $("#running-count").textContent = running; $("#disabled-count").textContent = disabled; $("#error-count").textContent = 0; $("#running-label").textContent = running ? "Running" : "None running"; $("#disabled-label").textContent = disabled ? "Disabled" : "None disabled"; $("#error-label").textContent = "No issues"; $("#running-dot").className = `status-dot ${running ? "running" : "inactive"}`; $("#disabled-dot").className = `status-dot ${disabled ? "disabled" : "inactive"}`; $("#error-dot").className = "status-dot inactive"; $(".port-note").classList.add("hidden"); }
    if (state.view === "certificates") renderCertificates(); else if (state.view === "administration") renderUsers(); else if (state.view === "logs") renderLogs(); else if (state.view === "performance") renderPerformance(); else if (state.view === "account") renderAccount();
    return;
  }
  const items = state.view === "hosted" ? state.sites : state.proxies;
  $("#site-grid").innerHTML = items.map(state.view === "hosted" ? hostedCard : proxyCard).join("");
  $("#empty").classList.toggle("hidden", !state.loaded || items.length > 0);
  $("#empty h2").textContent = state.view === "hosted" ? "Publish your first site" : "Create your first proxy host";
  $("#empty p").textContent = state.view === "hosted" ? "Upload a ZIP and optionally connect a domain with automatic HTTPS." : "Connect a domain to another container, application, or LAN service.";
  $("#page-title").textContent = state.view === "hosted" ? "Hosted sites" : "Proxy hosts";
  $("#page-subtitle").textContent = state.view === "hosted" ? "Upload and publish websites on a port or domain." : "Route domains securely to applications and containers.";
  $("#open-create").textContent = state.view === "hosted" ? "＋ New hosted site" : "＋ New proxy host";
  $("#open-create").classList.toggle("hidden", !canManage());
  $("#empty .create-trigger").textContent = state.view === "hosted" ? "Create a hosted site" : "Create a proxy host";
  $("#empty .create-trigger").disabled = false;
  $(".port-note").classList.toggle("hidden", state.view === "proxies");
  const running = items.filter(item => item.status === "running").length, disabled = items.filter(item => item.status === "disabled").length, errors = items.filter(item => item.status === "error").length;
  $("#running-count").textContent = running; $("#disabled-count").textContent = disabled; $("#error-count").textContent = errors;
  $("#running-label").textContent = running ? "Running" : "None running"; $("#disabled-label").textContent = disabled ? "Disabled" : "None disabled"; $("#error-label").textContent = errors ? "Needs attention" : "No issues";
  $("#running-dot").className = `status-dot ${running ? "running" : "inactive"}`; $("#disabled-dot").className = `status-dot ${disabled ? "disabled" : "inactive"}`; $("#error-dot").className = `status-dot ${errors ? "error" : "inactive"}`;
}
async function refresh() { const requests = [api("/api/sites"), api("/api/proxies"), api("/api/redirects"), api("/api/streams"), api("/api/access-lists"), canAdmin() ? api("/api/groups") : Promise.resolve([]), api("/api/dashboard"), api("/api/certificates")]; const results = await Promise.allSettled(requests); results.forEach((result, index) => { if (result.status !== "fulfilled") return; const keys = ["sites", "proxies", "redirects", "streams", "accessLists", "groups", "dashboard", "certificates"]; state[keys[index]] = result.value; }); state.loaded = true; render(); window.renderExtendedViews?.(); const pending = state.proxies.filter(proxy => proxy.enabled !== false && !proxy.upstream).map(proxy => proxy.id); if (pending.length && !state.pendingProxyRefresh) { state.pendingProxyRefresh = true; refreshPendingProxies(pending).finally(() => { state.pendingProxyRefresh = false; }); } }
async function refreshPendingProxies(ids = []) {
  const pending = new Set(ids.map(String));
  for (const delay of [1000, 2000, 3000]) {
    if (!pending.size) return;
    await new Promise(resolve => setTimeout(resolve, delay));
    await refresh();
    for (const proxy of state.proxies) if (pending.has(String(proxy.id)) && proxy.upstream) pending.delete(String(proxy.id));
  }
}
async function refreshDashboard() {
  const button = $("#refresh-health"); button.disabled = true; button.classList.add("spinning"); $("#health-checked").innerHTML = '<span class="live-dot checking"></span>Checking services…';
  try { state.dashboard = await api("/api/dashboard"); renderDashboard(); }
  finally { button.disabled = false; button.classList.remove("spinning"); }
}
function restoreAdminTab() { if (state.view === "administration") document.querySelector(`[data-admin-tab="${state.adminTab || "users"}"]`)?.click(); }
async function boot() {
  const requestedHash = location.hash.slice(1); state.adminTab = requestedHash.startsWith("administration/") ? requestedHash.split("/")[1] || "users" : "users"; if (requestedHash.startsWith("administration/")) history.replaceState(null, "", `${location.pathname}${location.search}#administration`);
  const session = await fetch("/api/session").then(response => response.json());
  $("#login-title").textContent = session.installationSetupPending ? "Welcome to Site Gateway" : "Welcome back";
  $("#login-copy").textContent = session.installationSetupPending ? "Sign in using the administrator credentials you configured during installation." : "Sign in to manage your sites.";
  if (!session.authenticated) return showLogin();
  if (session.setupRequired) { $("#login").classList.add("hidden"); $("#dashboard").classList.add("hidden"); $("#setup-form [name=username]").value = session.user.username; if (!$("#setup-dialog").open) $("#setup-dialog").showModal(); return; }
  state.view = location.hash.slice(1) || "overview"; state.users = []; showDashboard(); state.user = session.user; $("#user-label").textContent = session.user?.displayName || session.username; document.querySelectorAll(".admin-only").forEach(element => element.classList.toggle("hidden", !canAdmin())); render(); state.config = await api("/api/config");
  $("#version-label").textContent = `v${state.config.version || "unknown"}`;
  $("#port-range").textContent = `${state.config.minPort}–${state.config.maxPort}`; $("#port-help").textContent = `Direct LAN access range: ${state.config.minPort}–${state.config.maxPort}`;
  $("#create-form [name=port]").min = state.config.minPort; $("#create-form [name=port]").max = state.config.maxPort; await refresh(); if (state.view !== "overview") await loadFeatureView();
  if (!state.healthTimer) state.healthTimer = setInterval(() => { if (state.view === "overview" && !$("#dashboard").classList.contains("hidden")) refreshDashboard().catch(error => toast(error.message)); }, 30000);
}

$("#login-form").addEventListener("submit", async event => { event.preventDefault(); $("#login-error").textContent = ""; try { const result = await api("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(event.target))) }); if (result?.mfaRequired) { $("#login-form").classList.add("hidden"); $("#mfa-login-form").classList.remove("hidden"); $("#mfa-login-form [name=code]").focus(); return; } event.target.reset(); await boot(); } catch (error) { $("#login-error").textContent = error.message; } });
$("#mfa-login-form").addEventListener("submit", async event => { event.preventDefault(); $("#mfa-login-error").textContent = ""; try { const response = await fetch("/api/login/mfa", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(event.target))) }); const body = await response.json().catch(() => ({})); if (!response.ok) throw new Error(body.error || "That code didn't match. Try again."); event.target.reset(); await boot(); } catch (error) { $("#mfa-login-error").textContent = error.message; } });
$("#mfa-login-cancel").addEventListener("click", () => { $("#mfa-login-form").reset(); $("#mfa-login-error").textContent = ""; $("#mfa-login-form").classList.add("hidden"); $("#login-form").classList.remove("hidden"); });
$("#setup-form").addEventListener("submit", async event => { event.preventDefault(); $("#setup-error").textContent = ""; try { await api("/api/setup/admin", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(event.target))) }); $("#setup-dialog").close(); event.target.reset(); await boot(); showLogin("Administrator account saved. Sign in with your finalized credentials."); } catch (error) { $("#setup-error").textContent = error.message; } });
$("#setup-dialog").addEventListener("cancel", event => event.preventDefault());
$("#logout").addEventListener("click", async () => { await fetch("/api/logout", { method: "POST" }); showLogin(); });
$("#check-health").addEventListener("click", async event => { const button = event.currentTarget; button.disabled = true; button.textContent = "Checking…"; try { const result = await api("/api/health/check", { method:"POST" }); state.dashboard = result.dashboard; state.certificates = result.certificates; state.readiness = { routes:result.readiness }; renderCertificates(); toast("Certificate and domain checks completed."); } catch (error) { toast(error.message); } finally { button.disabled = false; button.textContent = "Run certificate check"; } });
$("#download-support").addEventListener("click", () => { location.href = "/api/support-report"; });
$("#attention-list").addEventListener("click", event => { const target = event.target.closest("[data-issue-target]")?.dataset.issueTarget; if (target) { state.view = target; render(); loadFeatureView().catch(error => toast(error.message)); } });
function closeMenus() { document.querySelectorAll(".menu-open").forEach(card => { card.classList.remove("menu-open"); card.querySelector(".menu-button")?.setAttribute("aria-expanded", "false"); }); }
document.querySelectorAll("nav, .aside-utilities, .brand").forEach(nav => nav.addEventListener("click", event => { const button = event.target.closest("[data-view]"); if (button) { closeMenus(); state.view = button.dataset.view; render(); loadFeatureView().catch(error => toast(error.message)); } }));
$("#dashboard-view").addEventListener("click", event => { const target = event.target.closest("[data-target], [data-view]"); if (!target) return; state.view = target.dataset.target || target.dataset.view; render(); loadFeatureView().catch(error => toast(error.message)); });
$("#refresh-logs").addEventListener("click", () => loadFeatureView().catch(error => toast(error.message)));
$("#log-host").addEventListener("change", () => loadFeatureView().catch(error => toast(error.message)));
$("#performance-host").addEventListener("change", () => loadFeatureView().catch(error => toast(error.message)));
$("#performance-range").addEventListener("change", () => loadFeatureView().catch(error => toast(error.message)));
$("#log-status").addEventListener("change", renderLogs);
$("#event-severity").addEventListener("change", renderLogs);
$("#event-category").addEventListener("change", renderLogs);
function openCreate() {
  if (state.view === "administration") { $("#user-form").reset(); $("#user-error").textContent = ""; return $("#user-dialog").showModal(); }
  if (state.view === "streaming") { $("#stream-form").reset(); delete $("#stream-form").dataset.editing; $("#stream-title").textContent = "Create a streaming host"; $("#stream-form .button.primary").textContent = "Create streaming host"; $("#stream-error").textContent = ""; return $("#stream-dialog").showModal(); }
  if (state.view === "redirects") { $("#redirect-form").reset(); delete $("#redirect-form").dataset.editing; $("#redirect-error").textContent = ""; return $("#redirect-dialog").showModal(); }
  if (state.view === "access") { $("#access-form").reset(); delete $("#access-form").dataset.editing; $("#access-error").textContent = ""; $("#access-form .access-create-guidance")?.remove(); const assignmentSummary = $("#access-assignment-summary"); assignmentSummary?.classList.add("hidden"); if (assignmentSummary) assignmentSummary.innerHTML = ""; window.renderCredentialEditor?.([]); return $("#access-dialog").showModal(); }
  if (state.view === "proxies") { $("#proxy-form").reset(); $("#custom-certificate-fields").classList.remove("custom-certificate-visible"); $("#proxy-error").textContent = ""; return $("#proxy-dialog").showModal(); }
  $("#create-form").reset(); $("#create-error").textContent = ""; const used = new Set(state.sites.map(site => site.port)); let port = state.config.minPort; while (used.has(port)) port++; $("#create-form [name=port]").value = port; $("#create-dialog").showModal();
}
$("#open-create").addEventListener("click", openCreate);
document.addEventListener("click", event => { if (event.target.closest(".create-trigger")) openCreate(); if (event.target.closest(".close-dialog")) event.target.closest("dialog").close(); if (!event.target.closest(".menu-wrap")) closeMenus(); });
document.addEventListener("keydown", event => { if (event.key === "Escape") closeMenus(); });
document.querySelectorAll("dialog").forEach(dialog => dialog.addEventListener("close", () => { closeMenus(); dialog.querySelectorAll('input[type="password"]').forEach(input => input.value = ""); }));
$("#refresh-health").addEventListener("click", () => refreshDashboard().catch(error => toast(error.message)));
$("#create-form").addEventListener("submit", async event => { event.preventDefault(); const button = resolveSubmitter(event); button.disabled = true; button.textContent = "Publishing…"; $("#create-error").textContent = ""; try { await api("/api/sites", { method: "POST", body: new FormData(event.target) }); $("#create-dialog").close(); await refresh(); toast("Hosted site created and gateway applied."); } catch (error) { $("#create-error").textContent = error.message; } finally { button.disabled = false; button.textContent = "Create & publish"; } });
$("#proxy-form").addEventListener("submit", async event => { event.preventDefault(); const button = resolveSubmitter(event); button.disabled = true; button.textContent = "Publishing…"; $("#proxy-error").textContent = ""; const form = new FormData(event.target), certificate = form.get("certificateFile"), privateKey = form.get("privateKeyFile"), wantsCustom = form.get("tls") === "custom"; if (wantsCustom && (!certificate?.size || !privateKey?.size)) { $("#proxy-error").textContent = "Choose both the certificate and private key for Custom HTTPS."; button.disabled = false; button.textContent = "Create & publish"; return; } const body = advancedFormBody(form, Object.fromEntries(form)); delete body.certificateFile; delete body.privateKeyFile; if (wantsCustom) body.tls = "http"; try { const created = await api("/api/proxies", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); if (wantsCustom) { const files = new FormData(); files.append("certificate", certificate); files.append("privateKey", privateKey); await api(`/api/proxies/${created.id}/certificate`, { method:"POST", body:files }); } $("#proxy-dialog").close(); await refresh(); toast(wantsCustom ? "Proxy host created with its custom certificate." : "Proxy host created. Certificate provisioning runs automatically."); } catch (error) { $("#proxy-error").textContent = error.message; } finally { button.disabled = false; button.textContent = "Create & publish"; } });

function ensureHostedHealthFields() { [document.querySelector("#create-form details"), document.querySelector("#settings-hosted-advanced")].forEach(details => { if (!details || details.querySelector("[name=healthEnabled]")) return; const access = details.querySelector("[name=accessListId]")?.closest("label"); if (!access) return; access.insertAdjacentHTML("afterend", '<label>Health-check path<input name="healthPath" value="/"></label><label>Health-check method<select name="healthMethod"><option value="GET">GET — retrieve a response</option><option value="HEAD">HEAD — headers only</option></select></label><label>Expected status<input name="healthExpected" value="200-499"><small>Examples: 200, 200,204, or 200-399.</small></label><label>Timeout in seconds<input name="healthTimeoutSeconds" type="number" min="1" max="60" value="4"></label><label>Retries<input name="healthRetries" type="number" min="0" max="3" value="0"></label><label class="check-control"><input name="healthEnabled" type="checkbox" checked><span>Monitor this site</span></label>'); }); }
setInterval(ensureHostedHealthFields, 300);
function openSettings(kind, id) {
  if (kind === "hosted") kind = "site";
  const item = (kind === "proxy" ? state.proxies : state.sites).find(value => value.id === id); if (!item) return; state.editing = { kind, id }; const form = $("#settings-form"); form.reset();
  $("#settings-title").textContent = kind === "proxy" ? "Edit proxy host" : "Domain & TLS"; $("#settings-name-wrap").classList.toggle("hidden", kind !== "proxy"); $("#settings-target-wrap").classList.toggle("hidden", kind !== "proxy"); $("#settings-advanced").classList.toggle("hidden", kind !== "proxy"); $("#settings-hosted-advanced").classList.toggle("hidden", kind !== "site");
  form.elements.name.value = item.name || ""; form.elements.domain.value = item.domain || ""; form.elements.target.value = item.target || ""; form.elements.tls.value = item.tls || "automatic"; form.elements.hsts.checked = Boolean(item.hsts); if (form.elements.settingsAccessListId) form.elements.settingsAccessListId.value = item.accessListId || "";
  if (kind === "proxy") {
    const scope = "#settings-advanced";
    setScoped(form, scope, "accessListId", item.accessListId || ""); setScoped(form, scope, "healthPath", item.healthPath || "/"); setScoped(form, scope, "healthMethod", item.healthMethod || "GET"); setScoped(form, scope, "healthExpected", item.healthExpected || "200-499"); setScoped(form, scope, "healthTimeoutSeconds", item.healthTimeoutSeconds || 4); setScoped(form, scope, "healthEnabled", item.healthEnabled !== false); setScoped(form, scope, "compression", item.compression || "automatic"); setScoped(form, scope, "blockCommonExploits", Boolean(item.blockCommonExploits));
    form.elements.customLocationsText.value = (item.locations || []).map(location => `${location.path} | ${location.target} | ${location.stripPrefix ? "strip" : "preserve"}`).join("\n");
    setScoped(form, scope, "requestHeadersText", (item.requestHeaders || []).map(header => `${header.name}: ${header.value}`).join("\n")); setScoped(form, scope, "responseHeadersText", (item.responseHeaders || []).map(header => `${header.name}: ${header.value}`).join("\n"));
    form.elements.upstreamTlsServerName.value = item.upstreamTlsServerName || ""; setScoped(form, scope, "upstreamTlsInsecure", Boolean(item.upstreamTlsInsecure)); setScoped(form, scope, "hstsSubdomains", Boolean(item.hstsSubdomains)); setScoped(form, scope, "customConfig", item.customConfig || "");
  }
  if (kind === "site") {
    const scope = "#settings-hosted-advanced";
    setScoped(form, scope, "healthPath", item.healthPath || "/"); setScoped(form, scope, "healthMethod", item.healthMethod || "GET"); setScoped(form, scope, "healthExpected", item.healthExpected || "200-499"); setScoped(form, scope, "healthTimeoutSeconds", item.healthTimeoutSeconds || 4); setScoped(form, scope, "healthRetries", item.healthRetries || 0); setScoped(form, scope, "healthEnabled", item.healthEnabled !== false); setScoped(form, scope, "accessListId", item.accessListId || ""); setScoped(form, scope, "compression", item.compression || "automatic"); setScoped(form, scope, "requestHeadersText", (item.requestHeaders || []).map(header => `${header.name}: ${header.value}`).join("\n")); setScoped(form, scope, "responseHeadersText", (item.responseHeaders || []).map(header => `${header.name}: ${header.value}`).join("\n")); setScoped(form, scope, "hstsSubdomains", Boolean(item.hstsSubdomains)); setScoped(form, scope, "customConfig", item.customConfig || "");
  }
  $("#settings-error").textContent = ""; if (form.elements.domainsText) form.elements.domainsText.value = (item.domains || []).filter(domain => domain !== item.domain).join("\n"); $("#settings-dialog").showModal();
  document.querySelector("#settings-form .custom-certificate-fields")?.classList.toggle("custom-certificate-visible", kind === "proxy" && form.elements.tls.value === "custom");
}

$("#site-grid").addEventListener("click", async event => {
  const card = event.target.closest(".site-card"); if (!card) return; const action = event.target.closest("[data-action]")?.dataset.action, kind = card.dataset.kind;
  if (event.target.closest(".menu-button")) { const opening = !card.classList.contains("menu-open"); closeMenus(); card.classList.toggle("menu-open", opening); card.querySelector(".menu-button").setAttribute("aria-expanded", String(opening)); return; } if (!action) return;
  closeMenus();
  if (action === "toggle") { const toggleButton = event.target.closest(".toggle"), wasOn = toggleButton.classList.contains("on"); toggleButton.classList.toggle("on", !wasOn); toggleButton.disabled = true; const base = kind === "proxy" ? "proxies" : "sites"; try { await api(`/api/${base}/${card.dataset.id}/toggle`, { method: "POST" }); await refresh(); toast("Status and gateway configuration updated."); } catch (error) { toggleButton.classList.toggle("on", wasOn); toggleButton.disabled = false; toast(error.message || "Could not update status."); } }
  if (action === "settings") openSettings(kind, card.dataset.id);
  if (action === "delete") { state.pendingDelete = { kind, id: card.dataset.id }; $("#confirm-title").textContent = kind === "proxy" ? "Delete this proxy host?" : "Delete this hosted site?"; $("#confirm-copy").textContent = kind === "proxy" ? "Its domain route will be removed from the gateway." : "Its route and uploaded files will be permanently removed."; $("#confirm-dialog").showModal(); }
  if (action === "replace") { state.pendingReplace = card.dataset.id; $("#replace-files").click(); }
  if (action === "icon") openIconPicker(kind, card.dataset.id);
});
document.querySelector("#redirect-list")?.addEventListener("click", event => {
  const card = event.target.closest(".redirect-card"); if (!card) return;
  if (event.target.closest(".menu-button")) { const opening = !card.classList.contains("menu-open"); closeMenus(); card.classList.toggle("menu-open", opening); card.querySelector(".menu-button")?.setAttribute("aria-expanded", String(opening)); return; }
  const action = event.target.closest("[data-redirect-action]")?.dataset.redirectAction; if (action === "icon") { closeMenus(); openIconPicker("redirect", card.dataset.redirectId); }
});
$("#confirm-dialog").addEventListener("close", async () => { if ($("#confirm-dialog").returnValue === "confirm" && state.pendingDelete) { const base = state.pendingDelete.kind === "proxy" ? "proxies" : "sites"; await api(`/api/${base}/${state.pendingDelete.id}`, { method: "DELETE" }); await refresh(); toast("Entry deleted and gateway updated."); } state.pendingDelete = null; });
$("#replace-files").addEventListener("change", async event => { if (!event.target.files[0] || !state.pendingReplace) return; const data = new FormData(); data.append("files", event.target.files[0]); try { await api(`/api/sites/${state.pendingReplace}/files`, { method: "POST", body: data }); toast("Site files updated."); } catch (error) { toast(error.message); } event.target.value = ""; state.pendingReplace = null; });

function openIconPicker(kind, id) {
  state.iconTarget = { kind, id }; $("#icon-search").value = ""; $("#icon-url").value = ""; $("#icon-upload").value = ""; $("#icon-error").textContent = ""; $("#icon-results").innerHTML = '<p class="quiet-state">Enter at least two characters to search.</p>'; $("#icon-dialog").showModal(); setTimeout(() => $("#icon-search").focus(), 0);
}
let iconSearchTimer;
$("#icon-search").addEventListener("input", event => {
  clearTimeout(iconSearchTimer); const query = event.target.value.trim(); $("#icon-error").textContent = "";
  if (query.length < 2) { $("#icon-results").innerHTML = '<p class="quiet-state">Enter at least two characters to search.</p>'; return; }
  $("#icon-results").innerHTML = '<p class="quiet-state">Searching…</p>';
  iconSearchTimer = setTimeout(async () => {
    try {
      const results = await api(`/api/icons/search?q=${encodeURIComponent(query)}`);
      $("#icon-results").innerHTML = results.length ? results.map(icon => `<button type="button" class="icon-choice" data-slug="${escapeHtml(icon.slug)}"><img src="${escapeHtml(icon.preview)}" alt=""><span>${escapeHtml(icon.label)}</span></button>`).join("") : '<p class="quiet-state">No matching icons found.</p>';
    } catch (error) { $("#icon-results").innerHTML = ""; $("#icon-error").textContent = error.message; }
  }, 280);
});
async function saveIcon(slug) {
  if (!state.iconTarget) return; const base = state.iconTarget.kind === "proxy" ? "proxies" : state.iconTarget.kind === "redirect" ? "redirects" : state.iconTarget.kind === "streams" ? "streams" : state.iconTarget.kind === "access" ? "access-lists" : state.iconTarget.kind === "users" ? "users" : "sites";
  $("#icon-error").textContent = "";
  try {
    await api(`/api/${base}/${state.iconTarget.id}/icon`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ slug }) });
    $("#icon-dialog").close(); await refresh(); toast(slug ? "Icon saved locally." : "Two-letter fallback restored.");
  } catch (error) { $("#icon-error").textContent = error.message; }
}
$("#icon-results").addEventListener("click", event => { const choice = event.target.closest("[data-slug]"); if (choice) saveIcon(choice.dataset.slug); });
$("#reset-icon").addEventListener("click", event => { event.preventDefault(); saveIcon(""); });
$("#icon-upload").addEventListener("change", async event => {
  const file = event.target.files[0]; if (!file || !state.iconTarget) return;
  const data = new FormData(); data.append("icon", file); $("#icon-error").textContent = "";
  try { const base = state.iconTarget.kind === "proxy" ? "proxies" : state.iconTarget.kind === "redirect" ? "redirects" : state.iconTarget.kind === "streams" ? "streams" : state.iconTarget.kind === "access" ? "access-lists" : state.iconTarget.kind === "users" ? "users" : "sites"; await api(`/api/${base}/${state.iconTarget.id}/icon`, { method: "POST", body: data }); $("#icon-dialog").close(); await refresh(); toast("Custom icon saved locally."); }
  catch (error) { $("#icon-error").textContent = error.message; }
});
$("#save-icon-url").addEventListener("click", async () => {
  const value = $("#icon-url").value.trim(); if (!/^https:\/\//i.test(value)) { $("#icon-error").textContent = "Enter a trusted HTTPS image URL."; return; }
  if (!state.iconTarget) return; const base = state.iconTarget.kind === "proxy" ? "proxies" : state.iconTarget.kind === "redirect" ? "redirects" : state.iconTarget.kind === "streams" ? "streams" : state.iconTarget.kind === "access" ? "access-lists" : state.iconTarget.kind === "users" ? "users" : "sites";
  try { await api(`/api/${base}/${state.iconTarget.id}/icon`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: value }) }); $("#icon-dialog").close(); await refresh(); toast("Icon URL saved."); }
  catch (error) { $("#icon-error").textContent = error.message; }
});
$("#user-form").addEventListener("submit", async event => {
  event.preventDefault(); const button = resolveSubmitter(event); button.disabled = true; $("#user-error").textContent = "";
  try {
    await api("/api/users", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(event.target))) });
    $("#user-dialog").close(); await loadFeatureView(); toast("User created.");
  } catch (error) { $("#user-error").textContent = error.message; }
  finally { button.disabled = false; }
});
function themedUserConfirm(message, title = "Confirm action") { let dialog = document.querySelector("#user-confirm-dialog"); if (!dialog) { dialog = document.createElement("dialog"); dialog.id = "user-confirm-dialog"; document.body.append(dialog); } dialog.innerHTML = `<form method="dialog" class="dialog-card compact"><div class="dialog-heading"><div><p class="eyebrow">Administration</p><h2>${escapeHtml(title)}</h2></div></div><p class="muted">${escapeHtml(message)}</p><div class="dialog-actions"><button value="cancel" class="button secondary">Cancel</button><button value="confirm" class="button danger">Confirm</button></div></form>`; dialog.showModal(); return new Promise(resolve => dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), { once: true })); }
$("#user-list").addEventListener("click", async event => {
  const menuCard = event.target.closest(".user-card");
  if (menuCard && event.target.closest(".menu-button")) { const opening = !menuCard.classList.contains("menu-open"); closeMenus(); menuCard.classList.toggle("menu-open", opening); menuCard.querySelector(".menu-button")?.setAttribute("aria-expanded", String(opening)); return; }
  const button = event.target.closest("[data-user-action]"); if (!button) return;
  const card = button.closest("[data-user-id]"); const user = state.users.find(item => item.id === card?.dataset.userId); if (!user) return;
  if (button.dataset.userAction === "icon") { closeMenus(); openIconPicker("users", user.id); return; }
  if (button.dataset.userAction === "password") {
    closeMenus();
    state.passwordTarget = user.id; $("#password-form").reset(); $("#password-error").textContent = ""; $("#password-title").textContent = `Reset ${user.username} password`; $("#password-dialog").showModal(); return;
  }
  if (button.dataset.userAction === "delete") {
    closeMenus();
    if (!await themedUserConfirm(`Permanently delete user “${user.username}”? This cannot be undone.`, "Delete user")) return;
    button.disabled = true;
    try { await api(`/api/users/${user.id}`, { method: "DELETE" }); await loadFeatureView(); toast("User deleted."); } catch (error) { toast(error.message); } finally { button.disabled = false; }
    return;
  }
  button.disabled = true;
  try {
    const body = button.dataset.userAction === "role" ? { role: button.dataset.value } : { status: button.dataset.value };
    await api(`/api/users/${user.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    await loadFeatureView(); toast("User updated.");
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; }
});
$("#password-form").addEventListener("submit", async event => {
  event.preventDefault(); const button = resolveSubmitter(event); button.disabled = true; $("#password-error").textContent = "";
  try {
    await api(`/api/users/${state.passwordTarget}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: new FormData(event.target).get("password") }) });
    $("#password-dialog").close(); state.passwordTarget = null; await loadFeatureView(); toast("Password reset.");
  } catch (error) { $("#password-error").textContent = error.message; }
  finally { button.disabled = false; }
});
window.addEventListener("hashchange", () => {
  if (!state.user) return; // Not logged in yet; boot() handles initial routing.
  const requestedHash = location.hash.slice(1);
  state.adminTab = requestedHash.startsWith("administration/") ? requestedHash.split("/")[1] || "users" : "users";
  if (requestedHash.startsWith("administration/")) history.replaceState(null, "", `${location.pathname}${location.search}#administration`);
  state.view = location.hash.slice(1) || "overview";
  render();
  loadFeatureView().catch(error => toast(error.message));
});
boot().catch(error => toast(error.message));

function syncUpstreamTlsControls(form) {
  if (!form || !form.elements.target) return;
  const targets = [form.elements.target.value, form.elements.upstreamsText?.value || ""].join("\n").split(/\n+/).map(value => value.trim()).filter(Boolean);
  const https = targets.length > 0 && targets.every(value => /^https:\/\//i.test(value));
  const tlsName = form.elements.upstreamTlsServerName, tlsSkip = form.elements.upstreamTlsInsecure;
  [tlsName, tlsSkip].forEach(input => { if (!input) return; input.disabled = !https; input.closest("label")?.classList.toggle("control-disabled", !https); });
  if (tlsSkip && !https) tlsSkip.checked = false;
  const help = tlsSkip?.closest("label")?.querySelector("small");
  if (help) help.textContent = https ? "Use only for a trusted internal HTTPS service with a self-signed or hostname-mismatched certificate." : "Available only when the upstream uses HTTPS.";
}
document.addEventListener("input", event => { if (event.target.matches('#proxy-form [name="target"],#proxy-form [name="upstreamsText"],#settings-form [name="target"],#settings-form [name="upstreamsText"]')) syncUpstreamTlsControls(event.target.form); });
document.addEventListener("change", event => { if (event.target.matches('#proxy-form [name="target"],#proxy-form [name="upstreamsText"],#settings-form [name="target"],#settings-form [name="upstreamsText"]')) syncUpstreamTlsControls(event.target.form); });
document.querySelectorAll("#proxy-form,#settings-form").forEach(form => syncUpstreamTlsControls(form));
document.addEventListener("click", event => { if (event.target.closest(".create-trigger,[data-action=edit],[data-card-action=edit]")) setTimeout(() => { syncUpstreamTlsControls(document.querySelector("#proxy-form")); syncUpstreamTlsControls(document.querySelector("#settings-form")); }, 0); });
document.addEventListener("click", event => { const trigger = event.target.closest("[data-action=settings],[data-card-action=settings]"); if (!trigger) return; setTimeout(() => { const item = (state.editing?.kind === "proxy" ? state.proxies : state.sites).find(value => value.id === state.editing?.id); if (!item) return; const scope = state.editing.kind === "proxy" ? "#settings-advanced" : "#settings-hosted-advanced"; const checkbox = document.querySelector(`${scope} [name="healthEnabled"]`); if (checkbox) checkbox.checked = !(item.healthEnabled === false || String(item.healthEnabled).toLowerCase() === "false"); }, 0); });
setInterval(() => { if (state.view !== 'access') return; const items = state.accessLists || []; const enabled = items.filter(item => item.enabled !== false).length; const disabled = items.length - enabled; $('#running-count').textContent = enabled; $('#disabled-count').textContent = disabled; $('#error-count').textContent = 0; $('#running-label').textContent = enabled ? 'Enabled' : 'None enabled'; $('#disabled-label').textContent = disabled ? 'Disabled' : 'None disabled'; $('#error-label').textContent = 'No issues'; $('#running-dot').className = `status-dot ${enabled ? 'running' : 'inactive'}`; $('#disabled-dot').className = `status-dot ${disabled ? 'disabled' : 'inactive'}`; $('#error-dot').className = 'status-dot inactive'; $('.port-note').classList.add('hidden'); }, 500);
function renderDashboardJobsSafe(system) { const slot = document.querySelector("#dashboard-jobs-slot"); if (!slot) return; let panel = document.querySelector("#dashboard-jobs"); if (!panel) { panel = document.createElement("section"); panel.id = "dashboard-jobs"; panel.className = "dashboard-panel dashboard-jobs-panel"; slot.appendChild(panel); } panel.innerHTML = `<div class="panel-heading"><div><p class="eyebrow">Operations</p><h2>Scheduled jobs</h2></div></div><div class="health-grid">${(system.jobs || []).map(job => `<div class="health-tile"><span class="status-dot ${job.enabled ? "running" : "idle"}"></span><span class="health-tile-copy"><strong>${escapeHtml(job.name)}</strong><small>${job.enabled ? `Active · ${escapeHtml(job.schedule)}` : "Disabled"}</small></span></div>`).join("")}</div>`; }

$("#account-password-form").addEventListener("submit", async event => {
  event.preventDefault();
  $("#account-password-error").textContent = "";
  const form = event.target;
  const body = Object.fromEntries(new FormData(form));
  if (String(body.newPassword) !== String(body.confirmPassword)) { $("#account-password-error").textContent = "The new passwords do not match."; return; }
  try {
    await api("/api/account/password", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ currentPassword: body.currentPassword, newPassword: body.newPassword }) });
    form.reset(); toast("Password changed.");
  } catch (error) { $("#account-password-error").textContent = error.message; }
});

let mfaPasswordResolve = null;
function requestMfaPassword(title, heading) {
  $("#mfa-password-title").textContent = title;
  $("#mfa-password-heading").textContent = heading;
  $("#mfa-password-error").textContent = "";
  $("#mfa-password-form").reset();
  $("#mfa-password-dialog").showModal();
  return new Promise(resolve => { mfaPasswordResolve = resolve; });
}
$("#mfa-password-form").addEventListener("submit", event => {
  event.preventDefault();
  const password = new FormData(event.target).get("password");
  $("#mfa-password-dialog").close();
  mfaPasswordResolve?.(password);
  mfaPasswordResolve = null;
});
$("#mfa-password-cancel").addEventListener("click", () => { $("#mfa-password-dialog").close(); mfaPasswordResolve?.(null); mfaPasswordResolve = null; });

$("#account-mfa-enable").addEventListener("click", async () => {
  try {
    const result = await api("/api/account/mfa/setup", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    $("#mfa-setup-qr").innerHTML = result.qrSvg;
    $("#mfa-setup-secret").textContent = result.secret;
    $("#mfa-setup-error").textContent = "";
    $("#mfa-setup-confirm-form").reset();
    $("#mfa-setup-dialog").showModal();
  } catch (error) { toast(error.message); }
});
$("#mfa-setup-cancel").addEventListener("click", () => { $("#mfa-setup-dialog").close(); });
$("#mfa-setup-confirm-form").addEventListener("submit", async event => {
  event.preventDefault();
  $("#mfa-setup-error").textContent = "";
  try {
    const code = new FormData(event.target).get("code");
    const result = await api("/api/account/mfa/confirm", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code }) });
    $("#mfa-setup-dialog").close();
    state.user.mfaEnabled = true;
    renderAccount();
    $("#mfa-recovery-codes").textContent = result.recoveryCodes.join("\n");
    $("#mfa-recovery-dialog").showModal();
    toast("Two-factor authentication enabled.");
  } catch (error) { $("#mfa-setup-error").textContent = error.message; }
});
$("#mfa-recovery-done").addEventListener("click", () => { $("#mfa-recovery-dialog").close(); });

$("#account-mfa-disable").addEventListener("click", async () => {
  const password = await requestMfaPassword("Disable two-factor authentication", "Confirm your password to continue");
  if (!password) return;
  try {
    await api("/api/account/mfa/disable", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password }) });
    state.user.mfaEnabled = false;
    renderAccount();
    toast("Two-factor authentication disabled.");
  } catch (error) { toast(error.message); }
});
$("#account-mfa-recovery").addEventListener("click", async () => {
  const password = await requestMfaPassword("Regenerate recovery codes", "Confirm your password to continue");
  if (!password) return;
  try {
    const result = await api("/api/account/mfa/recovery-codes", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password }) });
    $("#mfa-recovery-codes").textContent = result.recoveryCodes.join("\n");
    $("#mfa-recovery-dialog").showModal();
    toast("Recovery codes regenerated. Your old codes no longer work.");
  } catch (error) { toast(error.message); }
});
