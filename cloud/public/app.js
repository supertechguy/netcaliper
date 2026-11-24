// SPDX-License-Identifier: GPL-3.0-only
// netcaliper dashboard. No framework, no build. Everything coming from devices is rendered with
// textContent (SSIDs, hostnames, messages are attacker-controllable); only the generated icon
// constants are inserted as markup.
import { ICONS, WORDMARK } from "./icons.js";

const $ = (s) => document.querySelector(s);
const main = $("#main");

/** h("tag.cls", {attr}, ...children) — children: string | Node | null | array. */
function h(spec, attrs, ...kids) {
  const [tag, ...cls] = spec.split(".");
  const el = document.createElement(tag || "div");
  if (cls.length) el.className = cls.join(" ");
  if (attrs && (typeof attrs !== "object" || attrs instanceof Node || Array.isArray(attrs))) {
    kids.unshift(attrs);
    attrs = null;
  }
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "style") el.style.cssText = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  const add = (c) => {
    if (c == null || c === false) return;
    if (Array.isArray(c)) c.forEach(add);
    else el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  };
  kids.forEach(add);
  return el;
}

function icon(name) {
  const t = document.createElement("template");
  t.innerHTML = ICONS[name] || ""; // generated constants only
  return t.content.firstChild || document.createTextNode("");
}

function toast(msg, err = false) {
  const el = h("div" + (err ? ".err" : ""), msg);
  $("#toast").append(el);
  setTimeout(() => el.remove(), err ? 8000 : 4000);
}

async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: {} };
  if (opts.json !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(opts.json);
  }
  const r = await fetch("/api/v1/admin" + path, init);
  const body = r.headers.get("content-type")?.includes("json") ? await r.json() : {};
  if (!r.ok) throw new Error(body.error || `${r.status} ${r.statusText}`);
  return body;
}

// ---- formatting

const status = (s) => h("span.st.st-" + (s || "skipped"), s || "?");
const sev = (s) => h("span.sev-" + s, s);
function ago(iso) {
  if (!iso) return "never";
  const s = (Date.now() - Date.parse(iso)) / 1000;
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 129600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}
const when = (iso) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" }) : "");
const short = (id) => (id || "").slice(-8);
function fmt(v) {
  if (v == null) return "—";
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toFixed(2);
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

/** Generic table of objects (used for e.g. wifi.scan BSS lists and client lists in result details). */
function objTable(rows, maxCols = 10) {
  const cols = [];
  for (const r of rows.slice(0, 50)) for (const k of Object.keys(r)) if (!cols.includes(k) && cols.length < maxCols) cols.push(k);
  return h(
    "table",
    h("thead", h("tr", cols.map((c) => h("th", c)))),
    h("tbody", rows.slice(0, 500).map((r) => h("tr", cols.map((c) => h("td", fmt(r[c])))))),
  );
}

const devName = new Map();
async function loadDevices() {
  const ov = await api("/overview");
  for (const d of ov.devices) devName.set(d.id, d.name);
  return ov;
}

// ---- views

const VIEWS = {};

VIEWS[""] = async () => {
  const ov = await loadDevices();
  const today = ov.usage.at(-1) || { rows_written: 0, requests: 0 };
  const isToday = today.day === new Date().toISOString().slice(0, 10);
  const used = isToday ? today.rows_written : 0;
  const pct = Math.min(100, (100 * used) / ov.budget);
  const maxDay = Math.max(1, ...ov.usage.map((u) => u.rows_written));
  return [
    h("h1", icon("results"), "Overview"),
    h(
      "div.cards",
      h("div.card", h("div.dim.small", "devices"), h("div.big", String(ov.devices.filter((d) => !d.revoked_at).length))),
      h(
        "div.card",
        h("div.dim.small", "D1 rows written today (free-tier budget)"),
        h("div.big", `${used.toLocaleString()} / ${ov.budget.toLocaleString()}`),
        h("div.meter" + (pct > 90 ? ".fail" : pct > 70 ? ".warn" : ""), h("i", { style: `width:${pct.toFixed(1)}%` })),
      ),
      h(
        "div.card",
        h("div.dim.small", "last 14 days"),
        h("div.spark", ov.usage.map((u) => h("i", { title: `${u.day}: ${u.rows_written} rows, ${u.requests} requests`, style: `height:${(100 * u.rows_written) / maxDay}%` }))),
      ),
    ),
    h("h2", "Devices"),
    ov.devices.length
      ? h(
          "table",
          h("thead", h("tr", ["Name", "Site", "Version", "Enrolled", "Last seen", ""].map((c) => h("th", c)))),
          h(
            "tbody",
            ov.devices.map((d) =>
              h(
                "tr",
                h("td", h("a", { href: `#/runs?device=${d.id}` }, d.name), d.revoked_at ? h("span.fail.small", " revoked") : null),
                h("td", d.site || h("span.dim", "—")),
                h("td.dim", d.info?.version || ""),
                h("td.dim", when(d.created_at)),
                h("td", ago(d.last_seen_at)),
                h(
                  "td",
                  h("a.small", { href: `#/audit?device=${d.id}` }, "audit"),
                  " ",
                  d.revoked_at
                    ? null
                    : h(
                        "button.btn.danger.small",
                        {
                          onclick: async () => {
                            if (!confirm(`Revoke ${d.name}? It will stop syncing immediately and must be re-enrolled.`)) return;
                            await api(`/devices/${d.id}/revoke`, { method: "POST", json: {} });
                            toast(`${d.name} revoked`);
                            route();
                          },
                        },
                        "revoke",
                      ),
                ),
              ),
            ),
          ),
        )
      : h("p.dim", "No devices yet. ", h("a", { href: "#/enroll" }, "Enroll one.")),
    h("h2", "Recent runs"),
    runsTable(ov.recent),
  ];
};

function runsTable(runs) {
  if (!runs.length) return h("p.dim", "No runs synced yet.");
  return h(
    "table",
    h("thead", h("tr", ["Started", "Device", "Profile", "Status", "Steps"].map((c) => h("th", c)))),
    h(
      "tbody",
      runs.map((r) =>
        h(
          "tr.click",
          { tabindex: 0, onclick: () => (location.hash = `#/run/${r.id}`), onkeydown: (e) => e.key === "Enter" && (location.hash = `#/run/${r.id}`) },
          h("td", when(r.started_at), r.clock_synced === 0 ? h("span.warn.small", " (clock?)") : null),
          h("td", devName.get(r.device_id) || short(r.device_id)),
          h("td", r.profile_id || "—"),
          h("td", status(r.status)),
          h("td.dim", r.summary?.steps ? fmt(r.summary.steps.length ?? r.summary.steps) : ""),
        ),
      ),
    ),
  );
}

VIEWS.runs = async (q) => {
  if (!devName.size) await loadDevices();
  const p = new URLSearchParams({ limit: "50" });
  if (q.get("device")) p.set("device_id", q.get("device"));
  if (q.get("before")) p.set("before", q.get("before"));
  const r = await api(`/runs?${p}`);
  const next = new URLSearchParams(q);
  if (r.next) next.set("before", r.next);
  return [
    h("h1", icon("autotest"), "Runs", q.get("device") ? h("span.dim", `· ${devName.get(q.get("device")) || short(q.get("device"))}`) : null),
    runsTable(r.runs),
    h("div.pager", q.get("before") ? h("a.btn.alt", { href: "#/runs" + (q.get("device") ? `?device=${q.get("device")}` : "") }, "newest") : null, r.next ? h("a.btn.alt", { href: `#/runs?${next}` }, "older →") : null),
  ];
};

VIEWS.run = async (_q, id) => {
  if (!devName.size) await loadDevices();
  const d = await api(`/runs/${encodeURIComponent(id)}`);
  const run = d.run;
  return [
    h("h1", icon("autotest"), run.profile_id || "run", status(run.status)),
    h(
      "p.dim",
      `${devName.get(run.device_id) || short(run.device_id)} · ${when(run.started_at)}`,
      run.finished_at ? ` → ${when(run.finished_at)}` : "",
      run.clock_synced ? "" : " · device clock was not synced",
      run.results_pruned ? " · result details expired (retention)" : "",
    ),
    d.findings.length
      ? [
          h("h2", icon("security"), " Findings"),
          h("table", h("tbody", d.findings.map((f) => h("tr", h("td", sev(f.severity)), h("td", f.title), h("td.dim", f.rule_id))))),
        ]
      : null,
    h("h2", "Results"),
    d.results.map((res) =>
      h(
        "details",
        h(
          "summary",
          status(res.status),
          " ",
          h("b", res.module_id),
          " ",
          h("span", res.message || ""),
        ),
        Object.keys(res.metrics || {}).length
          ? h("table", h("tbody", Object.entries(res.metrics).map(([k, v]) => h("tr", h("td.dim", k), h("td", fmt(v))))))
          : null,
        Object.entries(res.details || {}).map(([k, v]) =>
          Array.isArray(v) && v.length && typeof v[0] === "object"
            ? [h("h2.small", `${k} (${v.length})`), objTable(v)]
            : null,
        ),
        h("details", h("summary", "raw JSON"), h("pre", JSON.stringify(res, null, 2))),
      ),
    ),
  ];
};

VIEWS.findings = async (q) => {
  if (!devName.size) await loadDevices();
  const p = new URLSearchParams({ limit: "50" });
  if (q.get("before")) p.set("before", q.get("before"));
  const r = await api(`/findings?${p}`);
  return [
    h("h1", icon("security"), "Findings"),
    r.findings.length
      ? h(
          "table",
          h("thead", h("tr", ["When", "Severity", "Finding", "Rule", "Device", "Run"].map((c) => h("th", c)))),
          h(
            "tbody",
            r.findings.map((f) =>
              h(
                "tr",
                h("td", when(f.created_at)),
                h("td", sev(f.severity)),
                h("td", f.title),
                h("td.dim", f.rule_id),
                h("td", devName.get(f.device_id) || short(f.device_id)),
                h("td", f.run_id ? h("a", { href: `#/run/${f.run_id}` }, "run") : ""),
              ),
            ),
          ),
        )
      : h("p.dim", "No findings."),
    r.next ? h("div.pager", h("a.btn.alt", { href: `#/findings?before=${encodeURIComponent(r.next)}` }, "older →")) : null,
  ];
};

VIEWS.audit = async (q) => {
  if (!devName.size) await loadDevices();
  const dev = q.get("device");
  if (!dev) return [h("h1", icon("security"), "Audit log"), h("p.dim", "Pick a device on the overview.")];
  const p = new URLSearchParams({ device_id: dev, limit: "100" });
  if (q.get("before")) p.set("before", q.get("before"));
  const r = await api(`/audit?${p}`);
  const broken = r.linked.filter((x) => x === false).length;
  return [
    h("h1", icon("security"), "Audit log", h("span.dim", `· ${devName.get(dev) || short(dev)}`)),
    h("p", broken ? h("span.fail", `${broken} break(s) in the hash chain on this page`) : h("span.dim", "hash chain linked on this page")),
    h(
      "table",
      h("thead", h("tr", ["When", "Actor", "Action", "Detail", "Chain"].map((c) => h("th", c)))),
      h(
        "tbody",
        r.entries.map((e, i) =>
          h(
            "tr",
            h("td", when(e.ts)),
            h("td", e.actor),
            h("td", e.action),
            h("td.small", JSON.stringify(e.detail)),
            h("td", r.linked[i] === false ? h("span.fail", "BROKEN") : r.linked[i] ? "✓" : h("span.dim", "…")),
          ),
        ),
      ),
    ),
    r.next ? h("div.pager", h("a.btn.alt", { href: `#/audit?device=${dev}&before=${encodeURIComponent(r.next)}` }, "older →")) : null,
  ];
};

VIEWS.enroll = async () => {
  const { sites } = await api("/sites");
  const out = h("div");
  const form = h(
    "form.row",
    {
      onsubmit: async (e) => {
        e.preventDefault();
        const fd = new FormData(form);
        const r = await api("/enroll-codes", { method: "POST", json: { name: fd.get("name"), site_id: fd.get("site") || null } });
        out.replaceChildren(
          h("p", "Enter this code on the device (Settings → Cloud) within 15 minutes. It works once and is not shown again:"),
          h("div.code", r.code),
          h("p.dim", `for ${r.name} · expires ${when(r.expires_at)}`),
        );
        form.reset();
      },
    },
    h("label", "Device name", h("input", { name: "name", required: true, maxlength: 64, placeholder: "uconsole-1" })),
    h("label", "Site", h("select", { name: "site" }, h("option", { value: "" }, "— none —"), sites.map((s) => h("option", { value: s.id }, s.name)))),
    h("button.btn", { type: "submit" }, icon("import"), "Create code"),
  );
  return [h("h1", icon("import"), "Enroll a device"), form, out];
};

VIEWS.sites = async () => {
  const { sites } = await api("/sites");
  const form = h(
    "form.row",
    {
      onsubmit: async (e) => {
        e.preventDefault();
        await api("/sites", { method: "POST", json: { name: new FormData(form).get("name") } });
        toast("site added");
        route();
      },
    },
    h("label", "New site", h("input", { name: "name", required: true, maxlength: 80 })),
    h("button.btn", { type: "submit" }, icon("save"), "Add"),
  );
  return [
    h("h1", icon("airmapper"), "Sites"),
    form,
    sites.length ? h("table", h("tbody", sites.map((s) => h("tr", h("td", s.name), h("td.dim", when(s.created_at)))))) : h("p.dim", "No sites."),
  ];
};

const PROFILE_TEMPLATE = {
  id: "my-profile",
  name: "My profile",
  description: "",
  interface: "test-wired",
  steps: [{ module: "wired.link" }, { module: "wired.dhcp" }, { module: "net.dns", config: { names: ["example.com"] } }, { module: "net.gateway" }],
};

VIEWS.profiles = async () => {
  const { profiles } = await api("/profiles");
  const ta = h("textarea", { spellcheck: "false", "aria-label": "profile JSON" });
  ta.value = JSON.stringify(PROFILE_TEMPLATE, null, 2);
  const save = async () => {
    let p;
    try {
      p = JSON.parse(ta.value);
    } catch (e) {
      return toast(`not valid JSON: ${e.message}`, true);
    }
    await api(`/profiles/${encodeURIComponent(p.id)}`, { method: "PUT", json: p });
    toast(`saved ${p.id} — devices pick it up on their next config pull`);
    route();
  };
  return [
    h("h1", icon("details"), "Profiles"),
    h("p.dim", "Profiles here are pushed to every device (built-in ones with the same id are overridden). Credentials never go in a profile — they stay on the device."),
    profiles.length
      ? h(
          "table",
          h("thead", h("tr", ["Id", "Name", "Interface", "Steps", "Updated", ""].map((c) => h("th", c)))),
          h(
            "tbody",
            profiles.map((p) =>
              h(
                "tr",
                h("td", p.id),
                h("td", p.name),
                h("td.dim", p.interface),
                h("td.dim", p.steps.map((s) => s.module).join(" → ")),
                h("td.dim", when(p.updated_at)),
                h(
                  "td",
                  h("button.btn.alt.small", { onclick: () => { const { updated_at, ...x } = p; ta.value = JSON.stringify(x, null, 2); ta.focus(); } }, "edit"),
                  " ",
                  h(
                    "button.btn.danger.small",
                    {
                      onclick: async () => {
                        if (!confirm(`Delete profile ${p.id}?`)) return;
                        await api(`/profiles/${encodeURIComponent(p.id)}`, { method: "DELETE", json: {} });
                        route();
                      },
                    },
                    "delete",
                  ),
                ),
              ),
            ),
          ),
        )
      : h("p.dim", "No cloud profiles."),
    h("h2", "Edit"),
    ta,
    h("p", h("button.btn", { onclick: save }, icon("save"), "Save profile")),
  ];
};

VIEWS.settings = async () => {
  const s = await api("/settings");
  const field = (k, label) => h("label", label, h("input", { name: k, type: "number", min: 7, max: 3650, value: s[k] }));
  const form = h(
    "form.row",
    {
      onsubmit: async (e) => {
        e.preventDefault();
        await api("/settings", { method: "POST", json: Object.fromEntries(new FormData(form)) });
        toast("saved");
      },
    },
    field("retention_result_days", "Result details kept (days)"),
    field("retention_finding_days", "Findings kept (days)"),
    field("retention_usage_days", "Usage history kept (days)"),
    h("button.btn", { type: "submit" }, icon("save"), "Save"),
  );
  return [
    h("h1", icon("settings"), "Settings"),
    h("p.dim", "A daily job prunes old data so the free D1 database stays small. Runs and their summaries are kept; audit logs are never pruned."),
    form,
  ];
};

// ---- router

const NAV = [
  ["", "results", "Overview"],
  ["runs", "autotest", "Runs"],
  ["findings", "security", "Findings"],
  ["enroll", "import", "Enroll"],
  ["profiles", "details", "Profiles"],
  ["sites", "airmapper", "Sites"],
  ["settings", "settings", "Settings"],
];

async function route() {
  const [path, query] = location.hash.replace(/^#\/?/, "").split("?");
  const [view, arg] = (path || "").split("/");
  for (const a of document.querySelectorAll("nav a")) a.classList.toggle("on", a.dataset.view === view);
  const fn = VIEWS[view] || VIEWS[""];
  try {
    const out = await fn(new URLSearchParams(query || ""), arg ? decodeURIComponent(arg) : "");
    main.replaceChildren(...[out].flat(3).filter(Boolean));
  } catch (e) {
    main.replaceChildren(h("h1", icon("cancel"), "Error"), h("p.fail", e.message));
  }
}

function boot() {
  const t = document.createElement("template");
  t.innerHTML = WORDMARK; // generated constant
  $("#brand").append(t.content);
  $("#nav").append(...NAV.map(([v, ic, label]) => h("a", { href: `#/${v}`, "data-view": v }, icon(ic), label)));
  api("/me").then((m) => ($("#who").textContent = m.email), () => {});
  addEventListener("hashchange", route);
  addEventListener("unhandledrejection", (e) => toast(e.reason?.message || String(e.reason), true));
  route();
}
boot();
