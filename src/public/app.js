const $ = selector => document.querySelector(selector);
const state = { sites: [], proxies: [], dashboard: null, config: null, view: "overview", pendingDelete: null, pendingReplace: null, editing: null };
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
function showLogin() { $("#login").classList.remove("hidden"); $("#dashboard").classList.add("hidden"); }
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

function healthCopy(group, label) {
  if (!group.total) return "Nothing configured";
  if (group.errors) return `${group.errors} ${label} need attention`;
  if (group.running) return `${group.running} running${group.disabled ? ` · ${group.disabled} disabled` : ""}`;
  return `${group.disabled} disabled`;
}

function renderDashboard() {
  const data = state.dashboard; if (!data) return;
  $("#dash-hosted-total").textContent = data.hosted.total;
  $("#dash-hosted-detail").textContent = healthCopy(data.hosted, "sites");
  $("#dash-proxy-total").textContent = data.proxies.total;
  $("#dash-proxy-detail").textContent = healthCopy(data.proxies, "routes");
  $("#dash-tls-total").textContent = data.tlsDomains;
  $("#dash-attention-total").textContent = data.attention.length;
  $("#dash-attention-detail").textContent = data.attention.length ? `${data.attention.length} item${data.attention.length === 1 ? "" : "s"} to review` : "No current issues";
  const hasErrors = data.attention.length > 0, hasNothingRunning = !data.hosted.running && !data.proxies.running;
  const overall = $("#overall-health");
  overall.className = `health-badge ${hasErrors ? "error" : hasNothingRunning ? "warning" : "healthy"}`;
  overall.textContent = hasErrors ? "Needs attention" : hasNothingRunning ? "Idle" : "Healthy";
  $("#gateway-health-dot").className = `status-dot ${data.gateway.healthy ? "running" : "error"}`;
  $("#gateway-health-copy").textContent = data.gateway.healthy ? (data.gateway.lastReload ? `Reloaded ${formatTime(data.gateway.lastReload)}` : "Configuration valid") : "Configuration rejected";
  $("#http-health-dot").className = `status-dot ${data.services.http.healthy ? "running" : "error"}`;
  $("#http-health-copy").textContent = data.services.http.healthy ? `Port ${data.services.http.port} ready` : "Entry point unavailable";
  const httpsActive = data.services.https.healthy && data.services.https.activeDomains > 0;
  $("#https-health-dot").className = `status-dot ${data.services.https.healthy ? (httpsActive ? "running" : "inactive") : "error"}`;
  $("#https-health-copy").textContent = !data.services.https.healthy ? "Automation unavailable" : httpsActive ? `${data.services.https.activeDomains} TLS domain${data.services.https.activeDomains === 1 ? "" : "s"} active` : "Waiting for a TLS domain";
  $("#storage-health-dot").className = `status-dot ${data.services.storage.healthy ? "running" : "error"}`;
  $("#storage-health-copy").textContent = data.services.storage.healthy ? "Data directory readable and writable" : "Check data-directory permissions";
  $("#system-uptime").textContent = formatDuration(data.system.uptimeSeconds);
  $("#system-memory").textContent = formatBytes(data.system.memoryBytes);
  $("#system-data").textContent = formatBytes(data.system.dataBytes);
  $("#system-disk").textContent = formatBytes(data.system.diskFreeBytes);
  $("#system-app-version").textContent = `v${data.system.appVersion}`;
  $("#system-caddy-version").textContent = data.system.caddyVersion;
  $("#attention-list").innerHTML = data.attention.length ? data.attention.map(item => `<div class="dashboard-list-item issue"><span class="status-dot error"></span><span><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.message)}</small></span></div>`).join("") : '<p class="quiet-state">Everything looks good.</p>';
  $("#activity-list").innerHTML = data.activity.length ? data.activity.map(item => `<div class="dashboard-list-item"><span class="activity-mark">✓</span><span><strong>${escapeHtml(item.message)}</strong><small>${escapeHtml(formatTime(item.at))}</small></span></div>`).join("") : '<p class="quiet-state">No changes recorded since this container started.</p>';
}

function hostedCard(site) {
  const status = site.status === "running" ? "running" : site.status === "error" ? "error" : "disabled";
  return `<article class="site-card" data-id="${site.id}" data-kind="hosted"><div class="card-top"><div class="site-icon">${escapeHtml(site.name.slice(0, 2).toUpperCase())}</div><div class="menu-wrap"><button class="icon-button menu-button" aria-label="Site options">•••</button><div class="menu"><button data-action="settings">Domain & TLS</button><button data-action="replace">Replace files</button><button data-action="delete" class="danger-text">Delete site</button></div></div></div><h2>${escapeHtml(site.name)}</h2><p class="address">${escapeHtml(site.domain || `Port ${site.port}`)}</p>${site.domain ? `<p class="gateway-address ${site.tls !== "http" ? "secure" : ""}">${escapeHtml(publicUrl(site))}</p>` : ""}<div class="card-footer"><span class="status-pill"><span class="status-dot ${status}"></span>${status === "error" ? "Needs attention" : status[0].toUpperCase() + status.slice(1)}</span><div class="card-actions"><button class="toggle ${site.enabled ? "on" : ""}" data-action="toggle" aria-label="${site.enabled ? "Disable" : "Enable"} ${escapeHtml(site.name)}"><span></span></button><a class="launch" href="${publicUrl(site)}" target="_blank" rel="noopener" aria-label="Open ${escapeHtml(site.name)}">↗</a></div></div></article>`;
}
function proxyCard(proxy) {
  const status = proxy.status === "running" ? "running" : proxy.status === "error" ? "error" : "disabled";
  return `<article class="site-card proxy" data-id="${proxy.id}" data-kind="proxy"><div class="card-top"><div class="site-icon">PX</div><div class="menu-wrap"><button class="icon-button menu-button" aria-label="Proxy options">•••</button><div class="menu"><button data-action="settings">Edit proxy</button><button data-action="delete" class="danger-text">Delete proxy</button></div></div></div><h2>${escapeHtml(proxy.name)}</h2><p class="address">${escapeHtml(proxy.target)}</p><p class="gateway-address ${proxy.tls !== "http" ? "secure" : ""}">${escapeHtml(publicUrl(proxy))}</p><div class="card-footer"><span class="status-pill"><span class="status-dot ${status}"></span>${status === "error" ? "Needs attention" : status[0].toUpperCase() + status.slice(1)}</span><div class="card-actions"><button class="toggle ${proxy.enabled ? "on" : ""}" data-action="toggle" aria-label="${proxy.enabled ? "Disable" : "Enable"} ${escapeHtml(proxy.name)}"><span></span></button><a class="launch" href="${publicUrl(proxy)}" target="_blank" rel="noopener" aria-label="Open ${escapeHtml(proxy.name)}">↗</a></div></div></article>`;
}
function render() {
  $("#hosted-count").textContent = state.sites.length; $("#proxy-count").textContent = state.proxies.length;
  document.querySelectorAll("nav [data-view]").forEach(button => button.classList.toggle("nav-active", button.dataset.view === state.view));
  const overview = state.view === "overview";
  $("#dashboard-view").classList.toggle("hidden", !overview);
  $("#management-view").classList.toggle("hidden", overview);
  $("#management-summary").classList.toggle("hidden", overview);
  $("#open-create").classList.toggle("hidden", overview);
  if (overview) {
    $("#page-title").textContent = "Dashboard";
    $("#page-subtitle").textContent = "Health, activity, and system status at a glance.";
    renderDashboard();
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
  $(".create-trigger").textContent = state.view === "hosted" ? "Create a hosted site" : "Create a proxy host";
  $(".port-note").classList.toggle("hidden", state.view === "proxies");
  const running = items.filter(item => item.status === "running").length, disabled = items.filter(item => item.status === "disabled").length, errors = items.filter(item => item.status === "error").length;
  $("#running-count").textContent = running; $("#disabled-count").textContent = disabled; $("#error-count").textContent = errors;
  $("#running-label").textContent = running ? "Running" : "None running"; $("#disabled-label").textContent = disabled ? "Disabled" : "None disabled"; $("#error-label").textContent = errors ? "Needs attention" : "No issues";
  $("#running-dot").className = `status-dot ${running ? "running" : "inactive"}`; $("#disabled-dot").className = `status-dot ${disabled ? "disabled" : "inactive"}`; $("#error-dot").className = `status-dot ${errors ? "error" : "inactive"}`;
}
async function refresh() { [state.sites, state.proxies, state.dashboard] = await Promise.all([api("/api/sites"), api("/api/proxies"), api("/api/dashboard")]); render(); }
async function boot() {
  const session = await fetch("/api/session").then(response => response.json()); if (!session.authenticated) return showLogin();
  showDashboard(); $("#user-label").textContent = session.username; state.config = await api("/api/config");
  $("#version-label").textContent = `v${state.config.version || "unknown"}`;
  $("#port-range").textContent = `${state.config.minPort}–${state.config.maxPort}`; $("#port-help").textContent = `Direct LAN access range: ${state.config.minPort}–${state.config.maxPort}`;
  $("#create-form [name=port]").min = state.config.minPort; $("#create-form [name=port]").max = state.config.maxPort; await refresh();
}

$("#login-form").addEventListener("submit", async event => { event.preventDefault(); $("#login-error").textContent = ""; try { await api("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(event.target))) }); await boot(); } catch (error) { $("#login-error").textContent = error.message; } });
$("#logout").addEventListener("click", async () => { await fetch("/api/logout", { method: "POST" }); showLogin(); });
document.querySelectorAll("nav").forEach(nav => nav.addEventListener("click", event => { const button = event.target.closest("[data-view]"); if (button) { state.view = button.dataset.view; render(); } }));
$("#dashboard-view").addEventListener("click", event => { const card = event.target.closest("[data-target]"); if (card) { state.view = card.dataset.target; render(); } });
function openCreate() {
  if (state.view === "proxies") { $("#proxy-form").reset(); $("#proxy-error").textContent = ""; return $("#proxy-dialog").showModal(); }
  $("#create-form").reset(); $("#create-error").textContent = ""; const used = new Set(state.sites.map(site => site.port)); let port = state.config.minPort; while (used.has(port)) port++; $("#create-form [name=port]").value = port; $("#create-dialog").showModal();
}
$("#open-create").addEventListener("click", openCreate);
document.addEventListener("click", event => { if (event.target.closest(".create-trigger")) openCreate(); if (event.target.closest(".close-dialog")) event.target.closest("dialog").close(); });
$("#create-form").addEventListener("submit", async event => { event.preventDefault(); const button = event.submitter; button.disabled = true; button.textContent = "Publishing…"; $("#create-error").textContent = ""; try { await api("/api/sites", { method: "POST", body: new FormData(event.target) }); $("#create-dialog").close(); await refresh(); toast("Hosted site created and gateway applied."); } catch (error) { $("#create-error").textContent = error.message; } finally { button.disabled = false; button.textContent = "Create & publish"; } });
$("#proxy-form").addEventListener("submit", async event => { event.preventDefault(); const button = event.submitter; button.disabled = true; button.textContent = "Publishing…"; $("#proxy-error").textContent = ""; const form = new FormData(event.target), body = Object.fromEntries(form); body.hsts = form.has("hsts"); try { await api("/api/proxies", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); $("#proxy-dialog").close(); await refresh(); toast("Proxy host created. Certificate provisioning runs automatically."); } catch (error) { $("#proxy-error").textContent = error.message; } finally { button.disabled = false; button.textContent = "Create & publish"; } });

function openSettings(kind, id) {
  const item = (kind === "proxy" ? state.proxies : state.sites).find(value => value.id === id); if (!item) return; state.editing = { kind, id }; const form = $("#settings-form"); form.reset();
  $("#settings-title").textContent = kind === "proxy" ? "Edit proxy host" : "Domain & TLS"; $("#settings-name-wrap").classList.toggle("hidden", kind !== "proxy"); $("#settings-target-wrap").classList.toggle("hidden", kind !== "proxy");
  form.elements.name.value = item.name || ""; form.elements.domain.value = item.domain || ""; form.elements.target.value = item.target || ""; form.elements.tls.value = item.tls || "automatic"; form.elements.hsts.checked = Boolean(item.hsts); $("#settings-error").textContent = ""; $("#settings-dialog").showModal();
}
$("#settings-form").addEventListener("submit", async event => { event.preventDefault(); const button = event.submitter; button.disabled = true; button.textContent = "Applying…"; $("#settings-error").textContent = ""; const form = new FormData(event.target), body = Object.fromEntries(form); body.hsts = form.has("hsts"); try { const base = state.editing.kind === "proxy" ? "proxies" : "sites"; await api(`/api/${base}/${state.editing.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); $("#settings-dialog").close(); await refresh(); toast("Gateway settings applied."); } catch (error) { $("#settings-error").textContent = error.message; } finally { button.disabled = false; button.textContent = "Save & apply"; } });

$("#site-grid").addEventListener("click", async event => {
  const card = event.target.closest(".site-card"); if (!card) return; const action = event.target.closest("[data-action]")?.dataset.action, kind = card.dataset.kind;
  if (event.target.closest(".menu-button")) return card.classList.toggle("menu-open"); if (!action) return;
  if (action === "toggle") { const base = kind === "proxy" ? "proxies" : "sites"; await api(`/api/${base}/${card.dataset.id}/toggle`, { method: "POST" }); await refresh(); toast("Status and gateway configuration updated."); }
  if (action === "settings") openSettings(kind, card.dataset.id);
  if (action === "delete") { state.pendingDelete = { kind, id: card.dataset.id }; $("#confirm-title").textContent = kind === "proxy" ? "Delete this proxy host?" : "Delete this hosted site?"; $("#confirm-copy").textContent = kind === "proxy" ? "Its domain route will be removed from the gateway." : "Its route and uploaded files will be permanently removed."; $("#confirm-dialog").showModal(); }
  if (action === "replace") { state.pendingReplace = card.dataset.id; $("#replace-files").click(); }
});
$("#confirm-dialog").addEventListener("close", async () => { if ($("#confirm-dialog").returnValue === "confirm" && state.pendingDelete) { const base = state.pendingDelete.kind === "proxy" ? "proxies" : "sites"; await api(`/api/${base}/${state.pendingDelete.id}`, { method: "DELETE" }); await refresh(); toast("Entry deleted and gateway updated."); } state.pendingDelete = null; });
$("#replace-files").addEventListener("change", async event => { if (!event.target.files[0] || !state.pendingReplace) return; const data = new FormData(); data.append("files", event.target.files[0]); try { await api(`/api/sites/${state.pendingReplace}/files`, { method: "POST", body: data }); toast("Site files updated."); } catch (error) { toast(error.message); } event.target.value = ""; state.pendingReplace = null; });
boot().catch(error => toast(error.message));
