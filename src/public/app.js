const $ = selector => document.querySelector(selector);
const state = { sites: [], config: null, pendingDelete: null, pendingReplace: null };
const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");

function applyTheme(preference) {
  const effective = preference === "system" ? (systemTheme.matches ? "dark" : "light") : preference;
  document.documentElement.dataset.theme = effective;
  document.querySelector('meta[name="theme-color"]').content = effective === "dark" ? "#08101d" : "#f3f6fa";
}

const savedTheme = localStorage.getItem("webserver-theme") || "system";
$("#theme-select").value = savedTheme;
applyTheme(savedTheme);
$("#theme-select").addEventListener("change", event => {
  localStorage.setItem("webserver-theme", event.target.value);
  applyTheme(event.target.value);
});
systemTheme.addEventListener("change", () => {
  if ($("#theme-select").value === "system") applyTheme("system");
});

async function api(url, options = {}) {
  const response = await fetch(url, options);
  if (response.status === 401) { showLogin(); throw new Error("Please sign in again."); }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || "Request failed.");
  }
  return response.status === 204 ? null : response.json();
}

function showLogin() { $("#login").classList.remove("hidden"); $("#dashboard").classList.add("hidden"); }
function showDashboard() { $("#login").classList.add("hidden"); $("#dashboard").classList.remove("hidden"); }
function toast(message) { const el = $("#toast"); el.textContent = message; el.classList.add("show"); setTimeout(() => el.classList.remove("show"), 2600); }
function escapeHtml(value) { const el = document.createElement("div"); el.textContent = value; return el.innerHTML; }

function siteCard(site) {
  const status = site.status === "running" ? "running" : site.status === "error" ? "error" : "disabled";
  const label = status[0].toUpperCase() + status.slice(1);
  const siteUrl = `${location.protocol}//${location.hostname}:${site.port}`;
  return `<article class="site-card" data-id="${site.id}">
    <div class="card-top"><div class="site-icon">${escapeHtml(site.name.slice(0, 2).toUpperCase())}</div><div class="menu-wrap"><button class="icon-button menu-button" aria-label="Site options">•••</button><div class="menu"><button data-action="replace">Replace files</button><button data-action="delete" class="danger-text">Delete site</button></div></div></div>
    <h2>${escapeHtml(site.name)}</h2><p class="address">Port ${site.port}</p>
    <div class="card-footer"><span class="status-pill ${status}"><span class="status-dot ${status}"></span>${label}</span>
      <div class="card-actions"><button class="toggle ${site.enabled ? "on" : ""}" data-action="toggle" aria-label="${site.enabled ? "Disable" : "Enable"} ${escapeHtml(site.name)}"><span></span></button>
      <a class="launch" href="${siteUrl}" target="_blank" rel="noopener" aria-label="Open ${escapeHtml(site.name)}">↗</a></div></div>
  </article>`;
}

function render() {
  $("#site-grid").innerHTML = state.sites.map(siteCard).join("");
  $("#empty").classList.toggle("hidden", state.sites.length > 0);
  $("#hosted-count").textContent = state.sites.length;
  $("#proxy-count").textContent = "0";
  const running = state.sites.filter(s => s.status === "running").length;
  const disabled = state.sites.filter(s => s.status === "disabled").length;
  const errors = state.sites.filter(s => s.status === "error").length;
  $("#running-count").textContent = running;
  $("#disabled-count").textContent = disabled;
  $("#error-count").textContent = errors;
  $("#running-label").textContent = running ? "Running" : "No sites running";
  $("#disabled-label").textContent = disabled ? "Disabled" : "No disabled sites";
  $("#error-label").textContent = errors ? "Needs attention" : "No issues";
  $("#running-dot").className = `status-dot ${running ? "running" : "inactive"}`;
  $("#disabled-dot").className = `status-dot ${disabled ? "disabled" : "inactive"}`;
  $("#error-dot").className = `status-dot ${errors ? "error" : "inactive"}`;
}

async function refresh() { state.sites = await api("/api/sites"); render(); }
async function boot() {
  const session = await fetch("/api/session").then(r => r.json());
  if (!session.authenticated) return showLogin();
  showDashboard(); $("#user-label").textContent = session.username;
  state.config = await api("/api/config");
  $("#port-range").textContent = `${state.config.minPort}–${state.config.maxPort}`;
  $("#port-help").textContent = `Available range: ${state.config.minPort}–${state.config.maxPort}`;
  $("#create-form [name=port]").min = state.config.minPort; $("#create-form [name=port]").max = state.config.maxPort;
  await refresh();
}

$("#login-form").addEventListener("submit", async event => {
  event.preventDefault(); $("#login-error").textContent = "";
  try { await api("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(event.target))) }); await boot(); }
  catch (error) { $("#login-error").textContent = error.message; }
});
$("#logout").addEventListener("click", async () => { await fetch("/api/logout", { method: "POST" }); showLogin(); });
function openCreate() {
  $("#create-form").reset(); $("#create-error").textContent = "";
  const used = new Set(state.sites.map(site => site.port)); let port = state.config.minPort; while (used.has(port)) port++;
  $("#create-form [name=port]").value = port; $("#create-dialog").showModal();
}
$("#open-create").addEventListener("click", openCreate);
document.addEventListener("click", event => { if (event.target.closest(".create-trigger")) openCreate(); if (event.target.closest(".close-dialog")) event.target.closest("dialog").close(); });
$("#create-form").addEventListener("submit", async event => {
  event.preventDefault(); const button = event.submitter; button.disabled = true; button.textContent = "Publishing…"; $("#create-error").textContent = "";
  try { await api("/api/sites", { method: "POST", body: new FormData(event.target) }); $("#create-dialog").close(); await refresh(); toast("Site created and running."); }
  catch (error) { $("#create-error").textContent = error.message; }
  finally { button.disabled = false; button.textContent = "Create & publish"; }
});
$("#site-grid").addEventListener("click", async event => {
  const card = event.target.closest(".site-card"); if (!card) return;
  const action = event.target.closest("[data-action]")?.dataset.action;
  if (event.target.closest(".menu-button")) return card.classList.toggle("menu-open");
  if (!action) return;
  if (action === "toggle") { await api(`/api/sites/${card.dataset.id}/toggle`, { method: "POST" }); await refresh(); toast("Site status updated."); }
  if (action === "delete") { state.pendingDelete = card.dataset.id; $("#confirm-dialog").showModal(); }
  if (action === "replace") { state.pendingReplace = card.dataset.id; $("#replace-files").click(); }
});
$("#confirm-dialog").addEventListener("close", async () => {
  if ($("#confirm-dialog").returnValue === "confirm" && state.pendingDelete) { await api(`/api/sites/${state.pendingDelete}`, { method: "DELETE" }); await refresh(); toast("Site deleted."); }
  state.pendingDelete = null;
});
$("#replace-files").addEventListener("change", async event => {
  if (!event.target.files[0] || !state.pendingReplace) return;
  const data = new FormData(); data.append("files", event.target.files[0]);
  try { await api(`/api/sites/${state.pendingReplace}/files`, { method: "POST", body: data }); toast("Site files updated."); }
  catch (error) { toast(error.message); }
  event.target.value = ""; state.pendingReplace = null;
});
boot().catch(error => toast(error.message));
