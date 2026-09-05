const $ = selector => document.querySelector(selector);
const summaryBar = document.querySelector("#management-summary");
const redirectView = document.querySelector("#redirects-view");
if (summaryBar && redirectView) redirectView.parentElement.insertBefore(summaryBar, redirectView);
const state = { sites: [], proxies: [], redirects: [], accessLists: [], backups: [], settings: null, dashboard: null, certificates: null, readiness: null, logs: null, users: [], user: null, config: null, view: "overview", pendingDelete: null, pendingReplace: null, editing: null, iconTarget: null, passwordTarget: null, healthTimer: null };
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
function showLogin(message = "") { state.user = null; state.users = []; state.view = "overview"; const form = $("#login-form"); form.reset(); form.elements.username.value = ""; form.elements.password.value = ""; $("#login").classList.remove("hidden"); $("#dashboard").classList.add("hidden"); $("#login-error").textContent = message; }
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
function certificateStatusLabel(status) { return ({ healthy:"Healthy", warning:"Renewal due soon", critical:"Renewal required urgently", expired:"Expired", pending:"Awaiting Caddy / ACME certificate", mismatch:"Certificate does not cover this domain" }[status] || String(status || "Unknown")).replaceAll("-", " "); }
function parseHeaderLines(value) { return String(value || "").split("\n").map(line => { const index = line.indexOf(":"); return index > 0 ? { name:line.slice(0,index).trim(), value:line.slice(index+1).trim() } : null; }).filter(Boolean); }
function advancedFormBody(form, body) {
  body.hsts = form.has("hsts"); body.hstsSubdomains = form.has("hstsSubdomains"); body.healthEnabled = form.has("healthEnabled"); body.upstreamTlsInsecure = form.has("upstreamTlsInsecure");
  body.requestHeaders = parseHeaderLines(form.get("requestHeadersText")); body.responseHeaders = parseHeaderLines(form.get("responseHeadersText"));
  body.locations = String(form.get("customLocationsText") || "").split("\n").map(line => { const [path, target, behavior] = line.split("|").map(value => value.trim()); return path && target ? { path, target, stripPrefix:behavior.toLowerCase() === "strip" } : null; }).filter(Boolean);
  body.upstreams = String(form.get("upstreamsText") || "").split("\n").map(value => value.trim()).filter(Boolean);
  delete body.requestHeadersText; delete body.responseHeadersText; delete body.customLocationsText;
  return body;
}

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

function renderDashboard() {
  const data = state.dashboard; if (!data) return;
  $("#dash-hosted-total").textContent = data.hosted.total;
  $("#dash-hosted-detail").textContent = healthCopy(data.hosted, "sites");
  $("#dash-proxy-total").textContent = data.proxies.total;
  $("#dash-proxy-detail").textContent = healthCopy(data.proxies, "routes");
  $("#dash-tls-total").textContent = data.tlsDomains;
  $("#dash-tls-detail").textContent = data.certificates.total ? `${data.certificates.healthy} healthy · ${data.certificates.pending} not detected` : "No TLS domains";
  $("#dash-attention-total").textContent = data.attention.length;
  $("#dash-attention-detail").textContent = data.attention.length ? `${data.attention.length} item${data.attention.length === 1 ? "" : "s"} to review` : "No current issues";
  const hasErrors = data.attention.length > 0, isChecking = [data.gateway, data.services.http, data.services.https].some(service => service.status === "checking"), hasNothingRunning = !data.hosted.running && !data.proxies.running;
  const overall = $("#overall-health");
  overall.className = `health-badge ${hasErrors ? "error" : isChecking || hasNothingRunning ? "warning" : "healthy"}`;
  overall.textContent = hasErrors ? "Needs attention" : isChecking ? "Checking" : hasNothingRunning ? "Idle" : "Healthy";
  $("#gateway-health-dot").className = `status-dot ${probeClass(data.gateway)}`;
  $("#gateway-health-copy").textContent = probeCopy(data.gateway, data.gateway.lastReload ? `Ready · reloaded ${formatTime(data.gateway.lastReload)}` : "Ready and responding", "Caddy is not responding");
  $("#http-health-dot").className = `status-dot ${probeClass(data.services.http)}`;
  $("#http-health-copy").textContent = probeCopy(data.services.http, "Ready and responding", "Not responding");
  $("#https-health-dot").className = `status-dot ${probeClass(data.services.https)}`;
  $("#https-health-copy").textContent = probeCopy(data.services.https, `Ready and responding · ${data.services.https.activeDomains} TLS domain${data.services.https.activeDomains === 1 ? "" : "s"}`, "Not responding", "Not configured · no TLS domains enabled");
  $("#storage-health-dot").className = `status-dot ${data.services.storage.healthy ? "running" : "error"}`;
  $("#storage-health-copy").textContent = data.services.storage.healthy ? "Ready · /data is readable and writable" : "Permission error · check /data";
  $("#health-checked").textContent = `Last checked ${formatTime(data.checkedAt)}`;
  $("#system-uptime").textContent = formatDuration(data.system.uptimeSeconds);
  $("#system-memory").textContent = formatBytes(data.system.memoryBytes);
  $("#system-data").textContent = formatBytes(data.system.dataBytes);
  $("#system-disk").textContent = formatBytes(data.system.diskFreeBytes);
  $("#system-disk").title = `${formatBytes(data.system.diskFreeBytes)} available of ${formatBytes(data.system.diskTotalBytes)} on the /data volume`;
  $("#system-app-version").textContent = `v${data.system.appVersion}`;
  $("#system-caddy-version").textContent = data.system.caddyVersion;
  $("#system-database").textContent = `${data.system.databaseEngine} · ${data.system.databaseStatus}`;
  $("#system-database-detail").textContent = `${formatBytes(data.system.databaseBytes)} configuration database`;
  $("#attention-list").innerHTML = data.attention.length ? data.attention.map(item => `<${item.target ? "button" : "div"} class="dashboard-list-item issue ${item.target ? "issue-link" : ""}" ${item.target ? `data-issue-target="${escapeHtml(item.target)}"` : ""}><span class="status-dot error"></span><span><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.message)}</small></span></${item.target ? "button" : "div"}>`).join("") : '<p class="quiet-state">Everything looks good.</p>';
  $("#activity-list").innerHTML = data.activity.length ? data.activity.map(item => `<div class="dashboard-list-item"><span class="activity-mark ${item.status === "error" ? "bad" : ""}">${item.status === "error" ? "!" : "✓"}</span><span><strong>${escapeHtml(item.message)}</strong><small>${escapeHtml(formatTime(item.at))}</small></span></div>`).join("") : '<p class="quiet-state">No changes recorded yet.</p>';
}

function initials(name) {
  const words = String(name || "").trim().split(/\s+/).map(word => word.replace(/[^a-z0-9]/gi, "")).filter(Boolean);
  if (!words.length) return "??";
  return (words.length > 1 ? words[0][0] + words[1][0] : words[0].slice(0, 2).padEnd(2, words[0][0])).toUpperCase();
}
function iconMarkup(item) { return item.icon ? `<img src="${escapeHtml(item.icon)}" alt="">` : escapeHtml(initials(item.name)); }
function canManage() { return state.user?.role === "administrator"; }

function hostedCard(site) {
  const status = site.status === "running" ? "running" : site.status === "error" ? "error" : "disabled";
  const menu = canManage() ? `<div class="menu-wrap"><button class="icon-button menu-button" aria-label="Site options" aria-expanded="false">•••</button><div class="menu"><button data-action="settings">Domain & TLS</button><button data-action="icon">Change icon</button><button data-action="replace">Replace files</button><button data-action="delete" class="danger-text">Delete site</button></div></div>` : "";
  const toggle = canManage() ? `<button class="toggle ${site.enabled ? "on" : ""}" data-action="toggle" aria-label="${site.enabled ? "Disable" : "Enable"} ${escapeHtml(site.name)}"><span></span></button>` : "";
  return `<article class="site-card" data-id="${site.id}" data-kind="hosted"><div class="card-top"><div class="site-icon">${iconMarkup(site)}</div>${menu}</div><h2>${escapeHtml(site.name)}</h2><p class="address">${escapeHtml(site.domain || `Port ${site.port}`)}</p>${site.domain ? `<p class="gateway-address ${site.tls !== "http" ? "secure" : ""}">${escapeHtml(publicUrl(site))}</p>` : ""}<div class="card-footer"><span class="status-pill"><span class="status-dot ${status}"></span>${status === "error" ? "Needs attention" : status[0].toUpperCase() + status.slice(1)}</span><div class="card-actions">${toggle}<a class="launch" href="${publicUrl(site)}" target="_blank" rel="noopener" aria-label="Open ${escapeHtml(site.name)}">↗</a></div></div></article>`;
}
function proxyCard(proxy) {
  const status = proxy.status === "running" ? "running" : proxy.status === "error" ? "error" : "disabled";
  const upstream = !proxy.enabled ? "Monitoring paused" : !proxy.upstream ? "Upstream check pending" : proxy.upstream.status === "healthy" ? `Upstream ${proxy.upstream.httpStatus} · ${proxy.upstream.responseMs} ms` : `Upstream unavailable · ${escapeHtml(proxy.upstream.error || "check failed")}`;
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
  $("#cert-event").innerHTML = data.latestError ? `<strong>Latest relevant error</strong><span>${escapeHtml(data.latestError.message)} · ${escapeHtml(formatTime(data.latestError.at))}</span>` : '<strong>Certificate activity</strong><span>No recent certificate or TLS errors have been recorded by Site Gateway.</span>';
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
    return `<div class="dashboard-list-item readiness-row" role="button" tabindex="0" data-readiness-id="${escapeHtml(item.id)}" aria-label="View diagnostics for ${escapeHtml(item.domain)}"><span class="status-dot ${dnsOk && portsOk && tlsOk && upstreamOk ? "running" : "error"}"></span><span><strong>${escapeHtml(item.domain)}</strong><small>${escapeHtml(message)}</small><span class="readiness-hint">Click to view diagnostics</span></span></div>`;
  }).join("") : '<p class="quiet-state">No configured domains to check.</p>';
}

function showReadinessDetails(item) {
  const check = item.upstream;
  const upstream = check ? `<div><dt>Upstream</dt><dd>Expected ${escapeHtml(item.upstreamExpected || "200-499")} · received ${check.httpStatus ?? "no response"}${check.responseMs != null ? ` · ${check.responseMs} ms` : ""} · ${check.attempts || 1} attempt${(check.attempts || 1) === 1 ? "" : "s"}</dd></div><div><dt>Last checked</dt><dd>${escapeHtml(formatTime(check.checkedAt))}</dd></div>${check.error ? `<div><dt>Failure detail</dt><dd class="danger-text">${escapeHtml(check.error)}</dd></div>` : ""}` : "<div><dt>Upstream</dt><dd>No upstream health check configured.</dd></div>";
  $("#readiness-title").textContent = item.domain;
  $("#readiness-detail-content").innerHTML = `<dl class="readiness-detail-grid"><div><dt>DNS</dt><dd>${item.dns.healthy ? `Resolved${item.dns.addresses.length ? ` · ${escapeHtml(item.dns.addresses.join(", "))}` : ""}` : `Failed${item.dns.error ? ` · ${escapeHtml(item.dns.error)}` : ""}`}</dd></div><div><dt>Gateway ports</dt><dd>HTTP 80 ${item.ports.http ? "responding" : "not responding"} · HTTPS 443 ${item.ports.https === false ? "not responding" : "responding"}</dd></div><div><dt>TLS</dt><dd>${escapeHtml(item.tls.status.replaceAll("-", " "))}</dd></div>${upstream}</dl>`;
  $("#readiness-dialog").showModal();
}

$("#readiness-list").addEventListener("click", event => { const row = event.target.closest("[data-readiness-id]"); const item = state.readiness?.routes?.find(route => route.id === row?.dataset.readinessId); if (item) showReadinessDetails(item); });
$("#readiness-list").addEventListener("keydown", event => { if (event.key !== "Enter" && event.key !== " ") return; const row = event.target.closest("[data-readiness-id]"); if (row) { event.preventDefault(); row.click(); } });

function renderLogs() {
  const data = state.logs; if (!data) return;
  const selected = $("#log-host").value; $("#log-host").innerHTML = '<option value="">All domains</option>' + data.hosts.map(host => `<option value="${escapeHtml(host)}">${escapeHtml(host)}</option>`).join(""); $("#log-host").value = selected;
  const statusClass = $("#log-status").value, entries = statusClass ? data.entries.filter(entry => String(entry.status || "").startsWith(statusClass)) : data.entries;
  const errors = entries.filter(entry => entry.status >= 400).length, measured = entries.filter(entry => entry.durationMs != null), average = measured.length ? Math.round(measured.reduce((sum,entry) => sum + entry.durationMs,0) / measured.length) : null;
  $("#log-summary").innerHTML = `${entries.length} request${entries.length === 1 ? "" : "s"} · ${errors} error response${errors === 1 ? "" : "s"} · ${average == null ? "no latency data" : `${average} ms average`} <span id="log-last-checked">Checked ${escapeHtml(formatTime(new Date().toISOString()))}</span>`;
  $("#log-rows").innerHTML = entries.length ? entries.map(entry => `<tr><td>${escapeHtml(formatTime(entry.at))}</td><td>${escapeHtml(entry.host || "—")}</td><td><code>${escapeHtml(entry.method || "")} ${escapeHtml(entry.uri || "")}</code></td><td><span class="http-status ${entry.status >= 500 ? "bad" : ""}">${entry.status ?? "—"}</span></td><td>${entry.durationMs == null ? "—" : `${entry.durationMs} ms`}</td></tr>`).join("") : '<tr><td colspan="5" class="quiet-state">No matching requests have been logged yet.</td></tr>';
  const categoryOf = message => /cert|tls|https/i.test(message) ? "certificate" : /health|upstream|response|fetch/i.test(message) ? "health" : /login|user|password|access/i.test(message) ? "authentication" : /backup|restore/i.test(message) ? "backup" : /config|route|host|gateway|reload/i.test(message) ? "configuration" : "system";
  const severity = $("#event-severity").value, category = $("#event-category").value;
  const activity = data.activity.filter(item => (!severity || item.status === severity) && (!category || categoryOf(item.message) === category));
  $("#gateway-log-list").innerHTML = activity.length ? activity.map(item => { const eventCategory = categoryOf(item.message); return `<div class="event-row"><span class="activity-mark ${item.status === "error" ? "bad" : item.status === "warning" ? "warn" : ""}">${item.status === "error" ? "!" : item.status === "warning" ? "!" : "✓"}</span><span><strong>${escapeHtml(item.message)}</strong><small>${escapeHtml(eventCategory)} · ${escapeHtml(formatTime(item.at))}</small></span></div>`; }).join("") : '<p class="quiet-state">No gateway events match these filters.</p>';
}

function renderUsers() {
  $("#user-count").textContent = state.users.length;
  $("#user-list").innerHTML = state.users.length ? state.users.map(user => {
    const isSelf = user.id === state.user?.id;
    const statusClass = user.status === "active" ? "running" : user.status === "disabled" ? "disabled" : "inactive";
    const roleAction = user.role === "administrator" ? "standard" : "administrator";
    const lifecycle = user.status === "archived" ? `<button class="button secondary" data-user-action="status" data-value="disabled">Restore</button>` : user.status === "active" ? `<button class="button secondary" data-user-action="status" data-value="disabled">Disable</button><button class="button secondary danger-text" data-user-action="status" data-value="archived">Archive</button>` : `<button class="button secondary" data-user-action="status" data-value="active">Enable</button><button class="button secondary danger-text" data-user-action="status" data-value="archived">Archive</button>`;
    return `<article class="user-card" data-user-id="${user.id}"><div class="user-card-head"><div class="user-avatar">${escapeHtml(initials(user.displayName))}</div><span class="status-pill"><span class="status-dot ${statusClass}"></span>${escapeHtml(user.status)}</span></div><h2>${escapeHtml(user.displayName)}${isSelf ? ' <small>You</small>' : ""}</h2><p class="address">${escapeHtml(user.username)}</p><div class="user-meta"><span>${user.role === "administrator" ? "Administrator" : "Standard User"}</span><span>${user.lastLoginAt ? `Last login ${escapeHtml(formatTime(user.lastLoginAt))}` : "Never signed in"}</span></div><div class="user-actions"><button class="button secondary" data-user-action="role" data-value="${roleAction}">Make ${roleAction === "administrator" ? "Administrator" : "Standard"}</button><button class="button secondary" data-user-action="password">Reset password</button>${lifecycle}</div></article>`;
  }).join("") : '<p class="quiet-state">No users found.</p>';
}

async function loadFeatureView() {
  if (state.view === "certificates") { [state.certificates, state.readiness] = await Promise.all([api("/api/certificates"), api("/api/readiness")]); renderCertificates(); }
  if (state.view === "logs") { state.logs = await api(`/api/logs?host=${encodeURIComponent($("#log-host").value)}`); renderLogs(); }
  if (state.view === "administration") { [state.users, state.settings, state.backups] = await Promise.all([api("/api/users"), api("/api/settings"), api("/api/backups")]); renderUsers(); window.renderExtendedViews?.(); }
  if (["redirects","access","documentation"].includes(state.view)) window.renderExtendedViews?.();
}
function render() {
  $("#hosted-count").textContent = state.sites.length; $("#proxy-count").textContent = state.proxies.length; $("#redirect-count").textContent = state.redirects.length; $("#access-count").textContent = state.accessLists.length; $("#certificate-count").textContent = state.certificates?.summary.total || 0;
  document.querySelectorAll("nav [data-view], .aside-utilities [data-view]").forEach(button => button.classList.toggle("nav-active", button.dataset.view === state.view));
  const overview = state.view === "overview";
  $("#dashboard-view").classList.toggle("hidden", !overview);
  const management = state.view === "hosted" || state.view === "proxies";
  $("#management-view").classList.toggle("hidden", !management); $("#management-summary").classList.toggle("hidden", !(management || state.view === "redirects"));
  $("#certificates-view").classList.toggle("hidden", state.view !== "certificates"); $("#logs-view").classList.toggle("hidden", state.view !== "logs"); $("#users-view").classList.toggle("hidden", state.view !== "administration");
  $("#redirects-view").classList.toggle("hidden", state.view !== "redirects"); $("#access-view").classList.toggle("hidden", state.view !== "access"); $("#documentation-view").classList.toggle("hidden", state.view !== "documentation");
  const adminUsersActive = state.view === "administration" && document.querySelector("[data-admin-tab].tab-active")?.dataset.adminTab === "users";
  $("#open-create").classList.toggle("hidden", !(management || adminUsersActive || ["redirects","access"].includes(state.view)) || !canManage());
  if (overview) {
    $("#page-title").textContent = "Dashboard";
    $("#page-subtitle").textContent = "Health, activity, and system status at a glance.";
    renderDashboard();
    return;
  }
  if (!management) {
    const headings = { certificates:["Certificates","Expiration, issuer, and certificate-detection status for automatic HTTPS."], logs:["Access logs","Recent requests served through the Caddy gateway."], administration:["Administration","Users, gateway defaults, backups, security, and updates."], redirects:["Redirect hosts","Send domains to a new destination with clear, predictable rules."], access:["Access Lists","Create reusable network and login protection for your hosts."], documentation:["Documentation","Plain-language guidance and real-world Site Gateway examples."] };
    const heading = headings[state.view] || ["Site Gateway",""]; $("#page-title").textContent = heading[0]; $("#page-subtitle").textContent = heading[1];
    $("#open-create").textContent = state.view === "administration" ? "＋ Create user" : state.view === "redirects" ? "＋ New redirect host" : state.view === "access" ? "＋ New Access List" : $("#open-create").textContent;
    if (state.view === "redirects") $("#redirect-empty .create-trigger").textContent = "Create a redirect host";
    if (state.view === "redirects") { const items = state.redirects; const running = items.filter(item => item.enabled !== false).length, disabled = items.length - running; $("#running-count").textContent = running; $("#disabled-count").textContent = disabled; $("#error-count").textContent = 0; $("#running-label").textContent = running ? "Running" : "None running"; $("#disabled-label").textContent = disabled ? "Disabled" : "None disabled"; $("#error-label").textContent = "No issues"; $("#running-dot").className = `status-dot ${running ? "running" : "inactive"}`; $("#disabled-dot").className = `status-dot ${disabled ? "disabled" : "inactive"}`; $("#error-dot").className = "status-dot inactive"; $(".port-note").classList.add("hidden"); }
    if (state.view === "certificates") renderCertificates(); else if (state.view === "administration") renderUsers(); else if (state.view === "logs") renderLogs();
    return;
  }
  const items = state.view === "hosted" ? state.sites : state.proxies;
  $("#site-grid").innerHTML = items.map(state.view === "hosted" ? hostedCard : proxyCard).join("");
  $("#empty").classList.toggle("hidden", items.length > 0);
  $("#empty h2").textContent = state.view === "hosted" ? "Publish your first site" : "Create your first proxy host";
  $("#empty p").textContent = state.view === "hosted" ? "Upload a ZIP and optionally connect a domain with automatic HTTPS." : "Connect a domain to another container, application, or LAN service.";
  $("#page-title").textContent = state.view === "hosted" ? "Hosted sites" : "Proxy hosts";
  $("#page-subtitle").textContent = state.view === "hosted" ? "Upload and publish websites on a port or domain." : "Route domains securely to applications and containers.";
  $("#open-create").textContent = state.view === "hosted" ? "＋ New hosted site" : "＋ New proxy host";
  $("#empty .create-trigger").textContent = state.view === "hosted" ? "Create a hosted site" : "Create a proxy host";
  $(".port-note").classList.toggle("hidden", state.view === "proxies");
  const running = items.filter(item => item.status === "running").length, disabled = items.filter(item => item.status === "disabled").length, errors = items.filter(item => item.status === "error").length;
  $("#running-count").textContent = running; $("#disabled-count").textContent = disabled; $("#error-count").textContent = errors;
  $("#running-label").textContent = running ? "Running" : "None running"; $("#disabled-label").textContent = disabled ? "Disabled" : "None disabled"; $("#error-label").textContent = errors ? "Needs attention" : "No issues";
  $("#running-dot").className = `status-dot ${running ? "running" : "inactive"}`; $("#disabled-dot").className = `status-dot ${disabled ? "disabled" : "inactive"}`; $("#error-dot").className = `status-dot ${errors ? "error" : "inactive"}`;
}
async function refresh() { [state.sites, state.proxies, state.redirects, state.accessLists, state.dashboard, state.certificates] = await Promise.all([api("/api/sites"), api("/api/proxies"), api("/api/redirects"), api("/api/access-lists"), api("/api/dashboard"), api("/api/certificates")]); render(); window.renderExtendedViews?.(); }
async function refreshDashboard() {
  const button = $("#refresh-health"); button.disabled = true; button.classList.add("spinning"); $("#health-checked").textContent = "Checking services…";
  try { state.dashboard = await api("/api/dashboard"); renderDashboard(); }
  finally { button.disabled = false; button.classList.remove("spinning"); }
}
async function boot() {
  const session = await fetch("/api/session").then(response => response.json());
  $("#login-title").textContent = session.installationSetupPending ? "Welcome to Site Gateway" : "Welcome back";
  $("#login-copy").textContent = session.installationSetupPending ? "Sign in using the administrator credentials you configured during installation." : "Sign in to manage your sites.";
  if (!session.authenticated) return showLogin();
  if (session.setupRequired) { $("#login").classList.add("hidden"); $("#dashboard").classList.add("hidden"); $("#setup-form [name=username]").value = session.user.username; if (!$("#setup-dialog").open) $("#setup-dialog").showModal(); return; }
  state.view = "overview"; state.users = []; showDashboard(); state.user = session.user; $("#user-label").textContent = session.user?.displayName || session.username; document.querySelectorAll(".admin-only").forEach(element => element.classList.toggle("hidden", !canManage())); state.config = await api("/api/config");
  $("#version-label").textContent = `v${state.config.version || "unknown"}`;
  $("#port-range").textContent = `${state.config.minPort}–${state.config.maxPort}`; $("#port-help").textContent = `Direct LAN access range: ${state.config.minPort}–${state.config.maxPort}`;
  $("#create-form [name=port]").min = state.config.minPort; $("#create-form [name=port]").max = state.config.maxPort; await refresh();
  if (!state.healthTimer) state.healthTimer = setInterval(() => { if (state.view === "overview" && !$("#dashboard").classList.contains("hidden")) refreshDashboard().catch(error => toast(error.message)); }, 30000);
}

$("#login-form").addEventListener("submit", async event => { event.preventDefault(); $("#login-error").textContent = ""; try { await api("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(event.target))) }); event.target.reset(); await boot(); } catch (error) { $("#login-error").textContent = error.message; } });
$("#setup-form").addEventListener("submit", async event => { event.preventDefault(); $("#setup-error").textContent = ""; try { await api("/api/setup/admin", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(event.target))) }); $("#setup-dialog").close(); event.target.reset(); await boot(); showLogin("Administrator account saved. Sign in with your finalized credentials."); } catch (error) { $("#setup-error").textContent = error.message; } });
$("#setup-dialog").addEventListener("cancel", event => event.preventDefault());
$("#logout").addEventListener("click", async () => { await fetch("/api/logout", { method: "POST" }); showLogin(); });
$("#check-health").addEventListener("click", async event => { const button = event.currentTarget; button.disabled = true; button.textContent = "Checking…"; try { const result = await api("/api/health/check", { method:"POST" }); state.dashboard = result.dashboard; state.certificates = result.certificates; state.readiness = { routes:result.readiness }; renderCertificates(); toast("Health checks completed."); } catch (error) { toast(error.message); } finally { button.disabled = false; button.textContent = "Check now"; } });
$("#download-support").addEventListener("click", () => { location.href = "/api/support-report"; });
$("#attention-list").addEventListener("click", event => { const target = event.target.closest("[data-issue-target]")?.dataset.issueTarget; if (target) { state.view = target; render(); loadFeatureView().catch(error => toast(error.message)); } });
function closeMenus() { document.querySelectorAll(".menu-open").forEach(card => { card.classList.remove("menu-open"); card.querySelector(".menu-button")?.setAttribute("aria-expanded", "false"); }); }
document.querySelectorAll("nav, .aside-utilities").forEach(nav => nav.addEventListener("click", event => { const button = event.target.closest("[data-view]"); if (button) { closeMenus(); state.view = button.dataset.view; render(); loadFeatureView().catch(error => toast(error.message)); } }));
$("#dashboard-view").addEventListener("click", event => { const card = event.target.closest("[data-target]"); if (card) { state.view = card.dataset.target; render(); loadFeatureView().catch(error => toast(error.message)); } });
$("#refresh-logs").addEventListener("click", () => loadFeatureView().catch(error => toast(error.message)));
$("#log-host").addEventListener("change", () => loadFeatureView().catch(error => toast(error.message)));
$("#log-status").addEventListener("change", renderLogs);
$("#event-severity").addEventListener("change", renderLogs);
$("#event-category").addEventListener("change", renderLogs);
function openCreate() {
  if (state.view === "administration") { $("#user-form").reset(); $("#user-error").textContent = ""; return $("#user-dialog").showModal(); }
  if (state.view === "redirects") { $("#redirect-form").reset(); delete $("#redirect-form").dataset.editing; $("#redirect-error").textContent = ""; return $("#redirect-dialog").showModal(); }
  if (state.view === "access") { $("#access-form").reset(); delete $("#access-form").dataset.editing; $("#access-error").textContent = ""; window.renderCredentialEditor?.([]); return $("#access-dialog").showModal(); }
  if (state.view === "proxies") { $("#proxy-form").reset(); $("#custom-certificate-fields").classList.remove("custom-certificate-visible"); $("#proxy-error").textContent = ""; return $("#proxy-dialog").showModal(); }
  $("#create-form").reset(); $("#create-error").textContent = ""; const used = new Set(state.sites.map(site => site.port)); let port = state.config.minPort; while (used.has(port)) port++; $("#create-form [name=port]").value = port; $("#create-dialog").showModal();
}
$("#open-create").addEventListener("click", openCreate);
document.addEventListener("click", event => { if (event.target.closest(".create-trigger")) openCreate(); if (event.target.closest(".close-dialog")) event.target.closest("dialog").close(); if (!event.target.closest(".menu-wrap")) closeMenus(); });
document.addEventListener("keydown", event => { if (event.key === "Escape") closeMenus(); });
document.querySelectorAll("dialog").forEach(dialog => dialog.addEventListener("close", () => { closeMenus(); dialog.querySelectorAll('input[type="password"]').forEach(input => input.value = ""); }));
$("#refresh-health").addEventListener("click", () => refreshDashboard().catch(error => toast(error.message)));
$("#create-form").addEventListener("submit", async event => { event.preventDefault(); const button = event.submitter; button.disabled = true; button.textContent = "Publishing…"; $("#create-error").textContent = ""; try { await api("/api/sites", { method: "POST", body: new FormData(event.target) }); $("#create-dialog").close(); await refresh(); toast("Hosted site created and gateway applied."); } catch (error) { $("#create-error").textContent = error.message; } finally { button.disabled = false; button.textContent = "Create & publish"; } });
$("#proxy-form").addEventListener("submit", async event => { event.preventDefault(); const button = event.submitter; button.disabled = true; button.textContent = "Publishing…"; $("#proxy-error").textContent = ""; const form = new FormData(event.target), certificate = form.get("certificateFile"), privateKey = form.get("privateKeyFile"), wantsCustom = form.get("tls") === "custom"; if (wantsCustom && (!certificate?.size || !privateKey?.size)) { $("#proxy-error").textContent = "Choose both the certificate and private key for Custom HTTPS."; button.disabled = false; button.textContent = "Create & publish"; return; } const body = advancedFormBody(form, Object.fromEntries(form)); delete body.certificateFile; delete body.privateKeyFile; if (wantsCustom) body.tls = "http"; try { const created = await api("/api/proxies", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); if (wantsCustom) { const files = new FormData(); files.append("certificate", certificate); files.append("privateKey", privateKey); await api(`/api/proxies/${created.id}/certificate`, { method:"POST", body:files }); } $("#proxy-dialog").close(); await refresh(); toast(wantsCustom ? "Proxy host created with its custom certificate." : "Proxy host created. Certificate provisioning runs automatically."); } catch (error) { $("#proxy-error").textContent = error.message; } finally { button.disabled = false; button.textContent = "Create & publish"; } });

function openSettings(kind, id) {
  const item = (kind === "proxy" ? state.proxies : state.sites).find(value => value.id === id); if (!item) return; state.editing = { kind, id }; const form = $("#settings-form"); form.reset();
  $("#settings-title").textContent = kind === "proxy" ? "Edit proxy host" : "Domain & TLS"; $("#settings-name-wrap").classList.toggle("hidden", kind !== "proxy"); $("#settings-target-wrap").classList.toggle("hidden", kind !== "proxy"); $("#settings-advanced").classList.toggle("hidden", kind !== "proxy");
  form.elements.name.value = item.name || ""; form.elements.domain.value = item.domain || ""; form.elements.target.value = item.target || ""; form.elements.tls.value = item.tls || "automatic"; form.elements.hsts.checked = Boolean(item.hsts);
  if (kind === "proxy") { form.elements.accessListId.value = item.accessListId || ""; form.elements.healthPath.value = item.healthPath || "/"; form.elements.healthExpected.value = item.healthExpected || "200-499"; form.elements.healthTimeoutSeconds.value = item.healthTimeoutSeconds || 4; form.elements.healthEnabled.checked = item.healthEnabled !== false; form.elements.compression.value = item.compression || "automatic"; form.elements.customLocationsText.value = (item.locations || []).map(location => `${location.path} | ${location.target} | ${location.stripPrefix ? "strip" : "preserve"}`).join("\n"); form.elements.requestHeadersText.value = (item.requestHeaders || []).map(header => `${header.name}: ${header.value}`).join("\n"); form.elements.responseHeadersText.value = (item.responseHeaders || []).map(header => `${header.name}: ${header.value}`).join("\n"); form.elements.upstreamTlsServerName.value = item.upstreamTlsServerName || ""; form.elements.upstreamTlsInsecure.checked = Boolean(item.upstreamTlsInsecure); form.elements.hstsSubdomains.checked = Boolean(item.hstsSubdomains); form.elements.customConfig.value = item.customConfig || ""; }
  if (kind === "proxy") form.elements.healthMethod.value = item.healthMethod || "GET";
  $("#settings-error").textContent = ""; $("#settings-dialog").showModal();
  document.querySelector("#settings-form .custom-certificate-fields")?.classList.toggle("custom-certificate-visible", kind === "proxy" && form.elements.tls.value === "custom");
}
$("#settings-form").addEventListener("submit", async event => { event.preventDefault(); const button = event.submitter; button.disabled = true; button.textContent = "Applying…"; $("#settings-error").textContent = ""; const form = new FormData(event.target), certificate = form.get("certificateFile"), privateKey = form.get("privateKeyFile"); let body = Object.fromEntries(form); delete body.certificateFile; delete body.privateKeyFile; body = state.editing.kind === "proxy" ? advancedFormBody(form, body) : { domain:body.domain, tls:body.tls, hsts:form.has("hsts") }; const uploadCustom = state.editing.kind === "proxy" && body.tls === "custom" && certificate?.size && privateKey?.size; if (state.editing.kind === "proxy" && body.tls === "custom" && !uploadCustom) { const existing = state.proxies.find(item => item.id === state.editing.id); if (!existing?.certificatePath) { $("#settings-error").textContent = "Choose both the certificate and private key for Custom HTTPS."; button.disabled = false; button.textContent = "Save & apply"; return; } } try { const base = state.editing.kind === "proxy" ? "proxies" : "sites"; await api(`/api/${base}/${state.editing.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); if (uploadCustom) { const files = new FormData(); files.append("certificate", certificate); files.append("privateKey", privateKey); await api(`/api/proxies/${state.editing.id}/certificate`, { method:"POST", body:files }); } $("#settings-dialog").close(); await refresh(); toast("Gateway settings applied."); } catch (error) { $("#settings-error").textContent = error.message; } finally { button.disabled = false; button.textContent = "Save & apply"; } });

$("#site-grid").addEventListener("click", async event => {
  const card = event.target.closest(".site-card"); if (!card) return; const action = event.target.closest("[data-action]")?.dataset.action, kind = card.dataset.kind;
  if (event.target.closest(".menu-button")) { const opening = !card.classList.contains("menu-open"); closeMenus(); card.classList.toggle("menu-open", opening); card.querySelector(".menu-button").setAttribute("aria-expanded", String(opening)); return; } if (!action) return;
  closeMenus();
  if (action === "toggle") { const base = kind === "proxy" ? "proxies" : "sites"; await api(`/api/${base}/${card.dataset.id}/toggle`, { method: "POST" }); await refresh(); toast("Status and gateway configuration updated."); }
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
  if (!state.iconTarget) return; const base = state.iconTarget.kind === "proxy" ? "proxies" : state.iconTarget.kind === "redirect" ? "redirects" : state.iconTarget.kind === "access" ? "access-lists" : "sites";
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
  try { const base = state.iconTarget.kind === "proxy" ? "proxies" : state.iconTarget.kind === "redirect" ? "redirects" : state.iconTarget.kind === "access" ? "access-lists" : "sites"; await api(`/api/${base}/${state.iconTarget.id}/icon`, { method: "POST", body: data }); $("#icon-dialog").close(); await refresh(); toast("Custom icon saved locally."); }
  catch (error) { $("#icon-error").textContent = error.message; }
});
$("#save-icon-url").addEventListener("click", async () => {
  const value = $("#icon-url").value.trim(); if (!/^https:\/\//i.test(value)) { $("#icon-error").textContent = "Enter a trusted HTTPS image URL."; return; }
  if (!state.iconTarget) return; const base = state.iconTarget.kind === "proxy" ? "proxies" : state.iconTarget.kind === "redirect" ? "redirects" : state.iconTarget.kind === "access" ? "access-lists" : "sites";
  try { await api(`/api/${base}/${state.iconTarget.id}/icon`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: value }) }); $("#icon-dialog").close(); await refresh(); toast("Icon URL saved."); }
  catch (error) { $("#icon-error").textContent = error.message; }
});
$("#user-form").addEventListener("submit", async event => {
  event.preventDefault(); const button = event.submitter; button.disabled = true; $("#user-error").textContent = "";
  try {
    await api("/api/users", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(event.target))) });
    $("#user-dialog").close(); await loadFeatureView(); toast("User created.");
  } catch (error) { $("#user-error").textContent = error.message; }
  finally { button.disabled = false; }
});
$("#user-list").addEventListener("click", async event => {
  const button = event.target.closest("[data-user-action]"); if (!button) return;
  const card = button.closest("[data-user-id]"); const user = state.users.find(item => item.id === card?.dataset.userId); if (!user) return;
  if (button.dataset.userAction === "password") {
    state.passwordTarget = user.id; $("#password-form").reset(); $("#password-error").textContent = ""; $("#password-title").textContent = `Reset ${user.username} password`; $("#password-dialog").showModal(); return;
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
  event.preventDefault(); const button = event.submitter; button.disabled = true; $("#password-error").textContent = "";
  try {
    await api(`/api/users/${state.passwordTarget}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: new FormData(event.target).get("password") }) });
    $("#password-dialog").close(); state.passwordTarget = null; await loadFeatureView(); toast("Password reset.");
  } catch (error) { $("#password-error").textContent = error.message; }
  finally { button.disabled = false; }
});
boot().catch(error => toast(error.message));
