function extendedEscape(value) { return escapeHtml(value); }
function featureIcon(item, fallback) { return item.icon ? `<img src="${extendedEscape(item.icon)}" alt="">` : fallback; }

function renderRedirects() {
  const list = document.querySelector("#redirect-list"), empty = document.querySelector("#redirect-empty");
  empty.classList.toggle("hidden", state.redirects.length > 0);
  list.innerHTML = state.redirects.map(item => `<article class="site-card redirect-card" data-redirect-id="${item.id}"><div class="card-top"><div class="site-icon">RD</div><span class="status-pill"><span class="status-dot ${item.enabled ? "running" : "disabled"}"></span>${item.enabled ? "Running" : "Disabled"}</span></div><h2>${extendedEscape(item.name)}</h2><p class="address">${extendedEscape(item.domain)}</p><p class="gateway-address">→ ${extendedEscape(item.target)}${item.preservePath ? " · preserves path" : ""}</p><div class="card-footer"><span class="chip">HTTP ${item.code}</span><div class="card-actions"><button class="button secondary" data-redirect-action="edit">Edit</button><button class="button secondary" data-redirect-action="toggle">${item.enabled ? "Disable" : "Enable"}</button><button class="button secondary danger-text" data-redirect-action="delete">Delete</button></div></div></article>`).join("");
}

function renderAccessLists() {
  const list = document.querySelector("#access-list");
  list.innerHTML = state.accessLists.length ? state.accessLists.map(item => { const assigned = [...state.proxies, ...state.sites, ...state.redirects].filter(host => host.accessListId === item.id); return `<article class="data-row" data-access-id="${item.id}"><span class="status-dot ${item.enabled === false ? "disabled" : "running"}"></span><div><strong>${extendedEscape(item.name)}</strong><small>${item.enabled === false ? "Disabled" : "Available to assign"}</small></div><div><strong>${item.networks?.length || 0}</strong><small>Allowed network${item.networks?.length === 1 ? "" : "s"}</small></div><div><strong>${item.credentials?.length || 0}</strong><small>Login${item.credentials?.length === 1 ? "" : "s"}</small></div><div><strong>${assigned.length}</strong><small>Assigned host${assigned.length === 1 ? "" : "s"}</small></div><div class="row-actions"><button class="button secondary" data-access-action="edit">Edit</button><button class="button secondary" data-access-action="toggle">${item.enabled === false ? "Enable" : "Disable"}</button><button class="button secondary danger-text" data-access-action="delete">Delete</button></div></article>`; }).join("") : '<p class="quiet-state padded">No Access Lists yet. Create one to protect a proxy host.</p>';
  const options = '<option value="">Public — no Access List</option>' + state.accessLists.filter(item => item.enabled !== false).map(item => `<option value="${item.id}">${extendedEscape(item.name)}</option>`).join("");
  document.querySelectorAll('select[name="accessListId"]').forEach(select => { const value = select.value; select.innerHTML = options; select.value = value; });
}

function renderBackups() {
  if (!state.settings) return;
  const form = document.querySelector("#backup-settings-form"), defaults = state.settings.backups || {};
  for (const key of ["type","frequency","hour","retention"]) if (form.elements[key] && defaults[key] !== undefined) form.elements[key].value = defaults[key];
  form.elements.enabled.checked = Boolean(defaults.enabled); form.elements.includeLogs.checked = Boolean(defaults.includeLogs); form.elements.encrypt.checked = Boolean(defaults.encrypt);
  document.querySelector("#backup-path").textContent = `Backups are stored in ${state.settings.backupDirectory}. Separate storage can be mounted directly at /data/backups for disk-failure protection.`;
  document.querySelector("#backup-list").innerHTML = state.backups.length ? state.backups.map(item => `<article class="data-row backup-row" data-backup="${extendedEscape(item.filename)}"><span class="status-dot ${item.valid ? "running" : "error"}"></span><div><strong>${extendedEscape(item.filename)}</strong><small>${formatTime(item.createdAt)}</small></div><div><strong>${extendedEscape(item.type)}</strong><small>Site Gateway ${extendedEscape(item.appVersion)}</small></div><div><strong>${formatBytes(item.size)}</strong><small>${item.valid ? "Verified manifest" : "Unreadable manifest"}</small></div><div class="row-actions"><a class="button secondary" href="/api/backups/${encodeURIComponent(item.filename)}/download">Download</a><button class="button secondary" data-backup-action="restore">Restore</button><button class="button secondary danger-text" data-backup-action="delete">Delete</button></div></article>`).join("") : '<p class="quiet-state padded">No stored backups yet.</p>';
}

function renderDefaultSettings() {
  if (!state.settings) return; const form = document.querySelector("#default-site-form"), value = state.settings.defaultSite || {};
  for (const key of ["mode","title","message","redirectUrl","redirectCode","customHtml"]) if (form.elements[key] && value[key] !== undefined) form.elements[key].value = value[key];
  form.elements.preservePath.checked = value.preservePath !== false;
}

function renderHealthSettings() {
  if (!state.settings) return; const form = document.querySelector("#health-settings-form"), value = state.settings.certificateHealth || {};
  for (const key of ["warningDays","criticalDays","staleMinutes"]) if (value[key] !== undefined) form.elements[key].value = value[key];
}

window.renderExtendedViews = function () { renderRedirects(); renderAccessLists(); renderBackups(); renderDefaultSettings(); renderHealthSettings(); };

for (let hour = 0; hour < 24; hour++) document.querySelector('#backup-settings-form [name="hour"]').insertAdjacentHTML("beforeend", `<option value="${hour}">${String(hour).padStart(2,"0")}:00</option>`);

document.querySelector("#redirect-form").addEventListener("submit", async event => {
  event.preventDefault(); const form = new FormData(event.target), body = Object.fromEntries(form); body.preservePath = form.has("preservePath"); document.querySelector("#redirect-error").textContent = "";
  try { const id = event.target.dataset.editing; await api(id ? `/api/redirects/${id}` : "/api/redirects", { method:id ? "PATCH" : "POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) }); delete event.target.dataset.editing; document.querySelector("#redirect-dialog").close(); await refresh(); toast(`Redirect Host ${id ? "updated" : "created"} and applied.`); } catch (error) { document.querySelector("#redirect-error").textContent = error.message; }
});

document.querySelector("#access-form").addEventListener("submit", async event => {
  event.preventDefault(); const form = new FormData(event.target), body = { name:form.get("name"), networks:form.get("networks"), deniedNetworks:form.get("deniedNetworks") }; if (form.get("accessUsername") || form.get("accessPassword")) body.credentials = [{ username:form.get("accessUsername"), password:form.get("accessPassword") }]; else if (!event.target.dataset.editing) body.credentials = []; document.querySelector("#access-error").textContent = "";
  try { const id = event.target.dataset.editing; await api(id ? `/api/access-lists/${id}` : "/api/access-lists", { method:id ? "PATCH" : "POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) }); delete event.target.dataset.editing; document.querySelector("#access-dialog").close(); await refresh(); toast(`Access List ${id ? "updated" : "created"}.`); } catch (error) { document.querySelector("#access-error").textContent = error.message; }
});

document.querySelector("#redirect-list").addEventListener("click", async event => {
  const button = event.target.closest("[data-redirect-action]"), card = button?.closest("[data-redirect-id]"); if (!button || !card) return; const item = state.redirects.find(value => value.id === card.dataset.redirectId); if (!item) return;
  try { if (button.dataset.redirectAction === "edit") { const form = document.querySelector("#redirect-form"); form.reset(); form.dataset.editing = item.id; for (const key of ["name","domain","target","code","tls"]) form.elements[key].value = item[key] || ""; form.elements.preservePath.checked = item.preservePath !== false; document.querySelector("#redirect-dialog").showModal(); return; } if (button.dataset.redirectAction === "delete") { if (!confirm(`Delete redirect “${item.name}”?`)) return; await api(`/api/redirects/${item.id}`, { method:"DELETE" }); } else await api(`/api/redirects/${item.id}`, { method:"PATCH", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ enabled:!item.enabled }) }); await refresh(); toast("Redirect Host updated."); } catch (error) { toast(error.message); }
});

document.querySelector("#access-list").addEventListener("click", async event => {
  const button = event.target.closest("[data-access-action]"), row = button?.closest("[data-access-id]"); if (!button || !row) return; const item = state.accessLists.find(value => value.id === row.dataset.accessId); if (!item) return;
  try { if (button.dataset.accessAction === "edit") { const form = document.querySelector("#access-form"); form.reset(); form.dataset.editing = item.id; form.elements.name.value = item.name; form.elements.networks.value = (item.networks || []).join("\n"); form.elements.deniedNetworks.value = (item.deniedNetworks || []).join("\n"); document.querySelector("#access-dialog").showModal(); return; } if (button.dataset.accessAction === "delete") { if (!confirm(`Delete Access List “${item.name}”?`)) return; await api(`/api/access-lists/${item.id}`, { method:"DELETE" }); } else await api(`/api/access-lists/${item.id}`, { method:"PATCH", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ enabled:item.enabled === false }) }); await refresh(); toast("Access List updated."); } catch (error) { toast(error.message); }
});

document.querySelector(".admin-tabs").addEventListener("click", event => { const button = event.target.closest("[data-admin-tab]"); if (!button) return; document.querySelectorAll("[data-admin-tab]").forEach(item => item.classList.toggle("tab-active", item === button)); document.querySelectorAll("[data-admin-panel]").forEach(panel => panel.classList.toggle("hidden", panel.dataset.adminPanel !== button.dataset.adminTab)); document.querySelector("#open-create").classList.toggle("hidden", button.dataset.adminTab !== "users"); });

document.querySelector("#default-site-form").addEventListener("submit", async event => { event.preventDefault(); const form = new FormData(event.target), value = Object.fromEntries(form); value.preservePath = form.has("preservePath"); try { state.settings = await api("/api/settings", { method:"PATCH", headers:{"Content-Type":"application/json"}, body:JSON.stringify({defaultSite:value}) }); toast("Default Site validated and applied."); } catch (error) { document.querySelector("#default-error").textContent = error.message; } });

document.querySelector("#backup-settings-form").addEventListener("submit", async event => { event.preventDefault(); const form = new FormData(event.target), backups = Object.fromEntries(form); delete backups.backupPassword; backups.enabled = form.has("enabled"); backups.includeLogs = form.has("includeLogs"); backups.encrypt = form.has("encrypt"); try { state.settings = await api("/api/settings", { method:"PATCH", headers:{"Content-Type":"application/json"}, body:JSON.stringify({backups}) }); toast("Backup schedule saved."); } catch (error) { toast(error.message); } });
document.querySelector("#health-settings-form").addEventListener("submit", async event => { event.preventDefault(); const certificateHealth = Object.fromEntries(new FormData(event.target)); try { state.settings = await api("/api/settings", { method:"PATCH", headers:{"Content-Type":"application/json"}, body:JSON.stringify({certificateHealth}) }); renderHealthSettings(); toast("Certificate health thresholds saved."); } catch (error) { toast(error.message); } });

document.querySelector("#create-backup").addEventListener("click", async () => { const form = new FormData(document.querySelector("#backup-settings-form")); try { const result = await api("/api/backups", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({type:form.get("type"),includeLogs:form.has("includeLogs"),password:form.get("backupPassword")}) }); state.backups = await api("/api/backups"); renderBackups(); location.href = `/api/backups/${encodeURIComponent(result.filename)}/download`; toast("Backup created. Download starting."); } catch (error) { toast(error.message); } });
document.querySelector("#import-backup").addEventListener("click", () => document.querySelector("#backup-upload").click());
document.querySelector("#backup-upload").addEventListener("change", async event => { const file = event.target.files[0]; if (!file) return; const data = new FormData(), password = document.querySelector('#backup-settings-form [name="backupPassword"]').value; data.append("backup", file); data.append("password", password); try { await api("/api/backups/import", { method:"POST", body:data }); state.backups = await api("/api/backups"); renderBackups(); toast("Backup imported. Review it before restoring."); } catch (error) { toast(error.message); } finally { event.target.value = ""; } });

document.querySelector("#backup-list").addEventListener("click", async event => { const button = event.target.closest("[data-backup-action]"), row = button?.closest("[data-backup]"); if (!button || !row) return; const filename = row.dataset.backup; try { if (button.dataset.backupAction === "delete") { if (!confirm(`Delete backup ${filename}?`)) return; await api(`/api/backups/${encodeURIComponent(filename)}`, {method:"DELETE"}); } else { if (!confirm("Restore this backup? Current data will be replaced after a safety backup is created.")) return; const password = document.querySelector('#backup-settings-form [name="backupPassword"]').value; await api(`/api/backups/${encodeURIComponent(filename)}/restore`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password})}); await refresh(); } state.backups = await api("/api/backups"); renderBackups(); toast(button.dataset.backupAction === "delete" ? "Backup deleted." : "Backup restored."); } catch (error) { toast(error.message); } });

document.querySelector("#doc-search").addEventListener("input", event => { const query = event.target.value.trim().toLowerCase(), articles = [...document.querySelectorAll("#docs-content article")]; let visible = 0; for (const article of articles) { const match = !query || `${article.dataset.doc} ${article.textContent}`.toLowerCase().includes(query); article.classList.toggle("hidden", !match); if (match) visible++; } document.querySelector("#doc-empty").classList.toggle("hidden", visible > 0); });

document.querySelector("#proxy-dialog").addEventListener("close", () => document.querySelector("#proxy-dialog details")?.removeAttribute("open"));
document.querySelectorAll("#proxy-form, #settings-form").forEach(form => form.elements.tls.addEventListener("change", () => { const fields = form.querySelector("#custom-certificate-fields, .custom-certificate-fields"); fields?.classList.toggle("custom-certificate-visible", form.elements.tls.value === "custom"); }));
