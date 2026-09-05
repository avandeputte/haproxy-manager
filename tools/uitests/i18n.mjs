// The UI speaks the browser's language, all of it.
//
// Two halves. The first is the mechanism: the language is picked from the
// browser's list the way a browser would pick it, a dictionary loads, t()
// fills placeholders and tn() counts. The second is the promise: every page
// and every dialog is rendered in German, every button on them is pressed,
// and whatever appears -- page, dialog, confirm() text, alert() text -- is
// searched for the English that has a German translation. A string someone
// forgot to route through t() shows up here as the English it still is.
//
// The fixtures are deliberately nonsense ("zz-…"): anything the server says
// is data, and data that happened to be English would look like a miss.
import "./stub-dom.mjs";

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const root = process.cwd() + "/static/js/";

/* ---- the mechanism ---- */
const { pickLanguage, initLanguage, currentLanguage, setDictionary, t, tn, translateStatic, LANGUAGES } =
  await import(root + "i18n.js");

ok(pickLanguage(["de-CH", "en"]) === "de", "de-CH finds the German dictionary");
ok(pickLanguage(["en-GB", "de"]) === "en", "English first on the list means English, even with German after it");
ok(pickLanguage(["pt-BR"]) === "pt", "pt-BR finds Portuguese");
ok(pickLanguage(["no"]) === "nb" && pickLanguage(["nn-NO"]) === "nb", "no and nn find the Norwegian dictionary");
ok(pickLanguage(["zz", "xx-YY"]) === "en", "a list of unknown languages falls back to English");
ok(pickLanguage([]) === "en" && pickLanguage(undefined) === "en", "no list at all is English");
ok(pickLanguage(["xx", "fr-BE"]) === "fr", "an unknown language is skipped for the next one");

ok(t("Save") === "Save", "with nothing loaded, t() is the English");
ok(t("v{version} available", { version: "1.2" }) === "v1.2 available", "placeholders are filled in");
ok(t("{a} and {b}", { a: 1 }) === "1 and {b}", "a placeholder with no value is left visible rather than blanked");

globalThis.document.documentElement = { dataset: {}, lang: "" };
let lang = await initLanguage("de");
ok(lang === "de" && currentLanguage() === "de", "the German dictionary loads");
ok(document.documentElement.lang === "de", "and the document is marked as German");
ok(t("Save") === "Speichern", "t() answers in German");
ok(t("zz-not-a-key") === "zz-not-a-key", "an unknown key falls through as itself");
ok(tn(1, "{n} line", "{n} lines") !== tn(2, "{n} line", "{n} lines") &&
   tn(1, "{n} line", "{n} lines").includes("1") && tn(2, "{n} line", "{n} lines").includes("2"),
   "tn() picks the form by count and fills {n}");

lang = await initLanguage("xx");
ok(lang === "en" && t("Save") === "Save", "a language with no dictionary falls back to English");

setDictionary("fr", { "{n} line": "{n} ligne", "{n} lines": "{n} lignes" });
ok(tn(0, "{n} line", "{n} lines") === "0 ligne" && tn(2, "{n} line", "{n} lines") === "2 lignes",
   "French puts zero with the singular");
setDictionary("en", {});

/* translateStatic: a marked element is translated in place, the English kept
   on the attribute; an attribute is translated the same way. */
{
  setDictionary("de", { "Sign in": "Anmelden", "Menu": "Menü" });
  const mk = (text, attrs) => ({
    textContent: text, attrs: Object.assign({}, attrs),
    getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; },
    setAttribute(k, v){ this.attrs[k] = v; },
  });
  const h2 = mk("Sign in", { "data-i18n": "" });
  const btn = mk("", { "aria-label": "Menu", "data-i18n-aria-label": "" });
  const fake = { querySelectorAll: sel => sel === "[data-i18n]" ? [h2] : sel === "[data-i18n-aria-label]" ? [btn] : [] };
  translateStatic(fake);
  ok(h2.textContent === "Anmelden" && h2.attrs["data-i18n"] === "Sign in",
     "a data-i18n element is translated and keeps its English on the attribute");
  ok(btn.attrs["aria-label"] === "Menü" && btn.attrs["data-i18n-aria-label"] === "Menu",
     "a data-i18n-<attr> attribute is translated the same way");
  translateStatic(fake);
  ok(h2.textContent === "Anmelden", "a second pass still knows what to look up");
  setDictionary("en", {});
}

/* ---- the promise: nothing English is left on any page ---- */
const de = (await import(root + "i18n/de.js")).default;
/* Every English key that has a different German: if it appears in what was
   rendered, that text did not go through t(). Short keys ("on", "set") are
   left out: they are substrings of too much. So is any key that occurs
   inside the German itself -- a product's own menu path quoted as it is
   ("Applications › Providers › Create"), a unit name ("keepalived.service"),
   a HAProxy log line -- because a German page is allowed to say those and
   nothing could tell a miss from a mention. A placeholder matches anything
   short of a tag or an attribute; a hyphen counts as part of a word, because
   German compounds English words freely ("Backup-Server"). */
const pattern = k => new RegExp("(^|[^A-Za-z-])" +
  k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\\{\w+\\\}/g, "[^\"<>]*?") + "([^A-Za-z-]|$)");
const germanText = Object.values(de).join("\n");
const english = Object.entries(de)
  .filter(([k, v]) => k !== v && k.length >= 5 && !k.includes("\n"))
  .map(([k]) => [k, pattern(k)])
  .filter(([, re]) => !re.test(germanText));
/* Only what a person sees or hears: markup attributes are English by
   construction (class="pill up", data-event="service"). */
const visible = text => text.replace(/\s([\w-]+)=("[^"]*"|'[^']*'|[^\s>]+)/g,
  (m, name) => ["title", "placeholder", "aria-label", "alt"].includes(name) ? m : " ");
ok(english.length > 500, "the German dictionary is large enough to be worth sweeping (" + english.length + ")");

const row = (n) => ({ id: "id-" + n, name: "obj-" + n, username: "obj-" + n, enabled: true,
  address: "10.0.0." + n, port: 80, binds: "0.0.0.0:80", mode: "http", domains: "zz-" + n + ".test",
  type: "http", method: "dns01", dns_provider: "dns_zz", has_password: n % 2 === 0,
  managed_by: n === 1 ? "zz-svc" : undefined, groups: [], servers: [], conditions: [],
  healthcheck_enabled: true, healthcheck: "id-1", email: "zz@zz.test", ca: "letsencrypt" });
const FIX = {
  "whoami": { authenticated: true, username: "zz-user", admin_username: "zz-user", peers: 2, totp_enabled: false, email: "zz@zz.test" },
  "status": { hostname: "zz-host", version: "9.9.9", role: "active", vips: ["10.0.0.9"], vip_held: ["10.0.0.9"],
              haproxy: "active", keepalived: "inactive", dirty: true, update_available: true, latest_version: "9.9.10",
              certs: [{ id: "id-1", name: "obj-1", domains: ["zz.test"], status: "expiring", days_left: 3, expires_iso: "2026-01-01T00:00:00+00:00",
                        last_issue: { ok: false, time: "2026-01-01T00:00:00+00:00", seconds: 2, error: "zz-error" }, not_issued_for: ["zz2.test"], auto_renew: false },
                      { id: "id-2", name: "obj-2", domains: ["zz2.test"], status: "placeholder" },
                      { id: "id-3", name: "obj-3", domains: ["zz3.test"], status: "missing", last_issue: { ok: true, time: "2026-01-01T00:00:00+00:00", seconds: 2 } }],
              api_key_fp: "zzfp", renewal_note: "zz-note", read_only: false, edit_override: false },
  "setup/state": { complete: true, hostname: "zz-host", interfaces: [{ name: "eth9", addresses: ["10.0.0.1"] }, { name: "eth8", addresses: [] }], suggested_url: "http://zz:8080" },
  "cluster": { live: false, age_seconds: 7,
    summary: { reachable: 1, total: 3, config_rev: 5, config_agreed: false, warnings: ["zz-warning"] },
    nodes: [
      { name: "node-a", hostname: "node-a", self: true, reachable: true, role: "active", haproxy: "active", keepalived: "active", vips: ["10.0.0.9"], vip_held: ["10.0.0.9"],
        config_fp: "abcdef12", config_rev: 5, certs_total: 2, certs_bad: 1, version: "9.9.9", ms: 3, dirty: true,
        config_objects: { "haproxy.servers": [["id-1", "obj-1", "h1"], ["id-2", "obj-2", "h2"]] }, config_parts: { "haproxy.zz": "s1" } },
      { name: "node-b", hostname: "node-b", reachable: true, role: "passive", haproxy: "failed", keepalived: "disabled", vips: ["10.0.0.9"], vip_held: [],
        config_fp: "abcdef34", config_rev: 4, certs_total: 2, certs_bad: 0, version: "9.9.8", update_available: true, url: "http://node-b:8080",
        config_objects: { "haproxy.servers": [["id-1", "obj-1", "h9"]] }, config_parts: { "haproxy.zz": "s2" },
        config_leak: { source: "node-a", mine: "aa", theirs: "bb" } },
      { name: "node-c", reachable: false, url: "http://node-c:8080", error: "zz-error", vips: [], vip_held: [] }] },
  "cluster/settings": { vips: "10.0.0.9/24", vrid: 51, auth_pass: "zz", state: "BACKUP", nopreempt: true, advert_int: 1, track_haproxy: true, track_mode: "responding", custom: "" },
  "local": { node_url: "http://zz:8080", api_key: "zz-key", keepalived: { interface: "eth9", priority: 100 }, sync: { auto_sync: true } },
  "peers": [{ id: "p1", name: "node-b", url: "http://node-b.zz:8080", has_key: true, is_own_key: false, key_fp: "zzfp2", enabled: true },
            { id: "p2", name: "node-c", url: "http://10.0.0.3:8080", has_key: false, enabled: false }],
  "peers/p1/test": { ok: true, hostname: "node-b", version: "9.9.8", role: "passive", note: "zz-note" },
  "peers/p2/test": { ok: false, error: "zz-error" },
  "sync/push": { ok: false, results: [{ name: "node-b", ok: true }, { name: "node-c", ok: false, error: "zz-error" }], warning: "zz-warning" },
  "keepalived/status": { ok: true, hostname: "zz-host", enabled: true, interface: "eth7", interface_exists: false,
    interfaces: [{ name: "eth9", addresses: ["10.0.0.1"] }, { name: "lo", addresses: [] }], validation: { ran: true, ok: false, output: "zz-out" },
    config_present: false, config_path: "/zz/keepalived.conf", service: "inactive", vips: ["10.0.0.9"], vip_held: [], vrrp_state: "BACKUP",
    vrrp_state_source: "zz-source", vrid: 51, priority: 100, unicast_peer: [], log: "zz-log" },
  "cluster/unicast/apply": { steps: ["zz-step"], warnings: ["zz-warning"], note: "zz-note" },
  "stats": { ok: true, frontends: [{ proxy: "fe-zz", status: "OPEN", scur: 1, smax: 2, stot: 3, rate: 1, rate_max: 2, bin: 1024, bout: 2048, dreq: 0, ereq: 0 }],
    backends: [{ proxy: "be-zz", status: "UP", servers_up: 1, servers_total: 2, algo: "roundrobin", scur: 1, stot: 2, qcur: 0, bin: 1, bout: 1, econ: 0, downtime: 0,
      servers: [{ name: "srv-1", addr: "10.0.0.1:80", status: "UP", lastchg: 100, bck: "0", weight: "1", scur: 0, smax: 0, stot: 0, qcur: 0, bin: 0, bout: 0, check_status: "L7OK", check_code: "200", check_duration: "3", chkfail: 0, chkdown: 0, downtime: 0 },
                { name: "srv-2", status: "DOWN", lastchg: 5, bck: "1", weight: "1", scur: 0, smax: 0, stot: 0, qcur: 0, bin: 0, bout: 0, chkfail: 1, chkdown: 1, downtime: 9 }] },
              { proxy: "be-empty", status: "DOWN", servers_up: 0, servers_total: 0, servers: [], scur: 0, stot: 0, qcur: 0, bin: 0, bout: 0, econ: 0, downtime: 0 }] },
  "traffic": { at: [1, 61, 121], span: "3 min", series: { "be_zz": { req: [1, 2, 3], e5: [0, 1, 0] } } },
  "watchdog": { settings: { enabled: true, haproxy: true, keepalived: true, probe_urls: true, interval: 20, max_restarts: 3, window: 900 },
    services: { haproxy: { state: "ok", detail: "" }, keepalived: { state: "down", blocked: "zz-blocked", restart_error: "zz-error", action: "zz-action" } },
    self: { ok: true, ms: 4 }, systemd: false, last_run: "2026-01-01T00:00:00+00:00",
    duplicate_addresses: [{ address: "10.0.0.9", interface: "eth9" }], events: [{ time: "2026-01-01T00:00:00+00:00", unit: "haproxy", level: "warning", message: "zz-message" }] },
  "notify": { settings: { enabled: true, min_severity: "warning", repeat_hours: 6, service_grace_seconds: 30, events: {},
    destinations: [{ id: "d1", name: "dest-1", type: "smtp", enabled: true, host: "zz.test", to: "zz@zz.test" },
                   { id: "d2", name: "dest-2", type: "pushover", enabled: false, has_token: true, has_user: false },
                   { name: "dest-3", type: "webhook", url: "http://zz.test/hook" }],
    mqtt: { enabled: false } }, recent: [{ time: "2026-01-01T00:00:00+00:00", destination: "dest-1", ok: true }, { time: "2026-01-01T00:00:00+00:00", destination: "dest-1", ok: false, detail: "zz-detail" }] },
  "notify/test": { ok: false, error: "zz-error" },
  "hass/test": { ok: false, error: "zz-error" },
  "version": { version: "9.9.9", latest: "9.9.10", available: true, checked: "2026-01-01T00:00:00+00:00", repo: "zz/repo", ref: "main", error: "zz-error", peers: 2, can_update: false, cannot_update_reason: "zz-reason" },
  "update/log": { log: "zz-log", running: false, version: "9.9.10" },
  "update": { note: "", nodes: [{ name: "node-b", ok: false, error: "zz-error" }] },
  "webui": { enabled: true, url: "https://ui.zz.test", shared_url: "https://shared.zz.test", certificate: "auto", port: 8080, listen: "0.0.0.0", exposed_directly: true,
    hosts: ["ui.zz.test"], extra_rules: [{ name: "rule-zz", hosts: ["old.zz.test"] }], address_checks: [{ which: "zz-which", message: "zz-message" }] },
  "access/oauth": { enabled: true, issuer: "https://idp.zz.test/", client_id: "zz-client", has_client_secret: true, auth_host: "auth.zz.test", cookie_domain: "zz.test",
    scopes: "openid email profile", session_hours: 12, redirect_uri: "https://auth.zz.test/.ham-sso/callback", unreachable_hosts: ["out.other.test"] },
  "access/oauth/test": { ok: false, error: "zz-error" },
  "access/oauth/rotate": { ok: true },
  "history": { snapshots: [{ id: "s1", at: "2026-01-02T00:00:00+00:00", rev: 5, summary: "zz-summary", current: true },
                           { id: "s2", at: "2026-01-01T00:00:00+00:00", rev: 4 }] },
  "history/s2/diff": { parts: [{ part: "haproxy.servers", objects: [{ name: "obj-1", state: "added" }, { name: "obj-2", state: "changed" }] }] },
  "history/s1/diff": { parts: [] },
  "history/s2/restore": { note: "" },
  "logs": { entries: [{ ts: 1, source: "haproxy", level: "INFO", text: "zz-line" }], failed: ["zz-failed"] },
  "services": [{ id: "svc-1", url: "https://app.zz.test", urls: ["https://app.zz.test"], targets: ["http://10.0.0.1:80"], pool: "be-zz", scheme: "https", enabled: true,
                 auth: { enabled: true, group_names: [], exempt: "10.0.0.0/8" }, oauth: { enabled: true, allow: ["*"] }, allow_src: "10.0.0.0/8", certificate: "obj-1", certificate_match: "wildcard", health: { type: "http" } },
               { id: "svc-2", url: "tcp://0.0.0.0:3306", urls: ["tcp://0.0.0.0:3306"], targets: [], pool: "", scheme: "tcp", enabled: false, maintenance: true, managed: "web-ui" }],
  "probes": { results: [{ url: "https://app.zz.test", state: "down", note: "zz-note" }] },
  "services/svc-1": { removed: [{ type: "zz", name: "obj" }], note: "zz-note" },
  "recipes": { recipes: [{ id: "r1", name: "zz-recipe", category: "zz-cat", summary: "zz-summary", notes: "zz-notes", fields: { target: "http://10.0.0.1:80" } }] },
  "acme/health": { ok: false, problem: "zz-problem", hint: "zz-hint", path: "/zz/acme.sh", version: "3.0" },
  "acme/dnsapi": { hooks: [{ hook: "dns_zz", title: "zz-provider", options: [{ name: "ZZ_KEY", optional: false, desc: "zz-desc" }], options_alt: [{ name: "ZZ_ALT", optional: true }], docs: "zz.test/docs" }], note: "zz-dnsnote" },
  "acme/cover": { covered: true, status: "valid", how: "wildcard", name: "obj-1", domains: ["*.zz.test"], days_left: 30 },
  "acme/renew": { results: { "obj-1": { ok: true }, "obj-2": { ok: false, error: "zz-error" } } },
  "acme/issue/id-1": { ok: false, error: "zz-error", log: "zz-log" },
  "acme/log/id-1": { ok: true, entry: { ok: false, error: "zz-error", time: "2026-01-01T00:00:00+00:00", seconds: 3, log: "zz-log" } },
  "apply": { ok: true, warnings: ["zz-warning"], steps: ["zz-step"], haproxy_check: "zz-check", keepalived_check: "zz-kcheck" },
  "haproxy/settings": { maxconn: 1 }, "acme/settings": { enabled: true }, "preview": { haproxy: "zz-cfg" },
  "validate": { ok: false, message: "zz-message" },
  "haproxy/preview-object": { text: "zz-text" },
  "2fa/setup": { secret: "ZZSECRET", matrix: [[1, 0], [0, 1]] },
  "2fa/enable": { recovery: ["zz-1", "zz-2"] },
  "wizard/publish": { public: "https://app.zz.test", target: "http://10.0.0.1:80", actions: [{ action: "created", type: "zz-type", name: "obj-1" }], warnings: ["zz-warning"], preview: "zz-cfg", applied: { ok: false, error: "zz-error" } },
  "wizard/certificate": { domains: ["zz.test"], actions: [{ action: "reused", type: "zz-type", name: "obj-1" }], warnings: [], issued: { ok: false, error: "zz-error", log: "zz-log" } },
  "import/config": { restored: { haproxy: { servers: 2 } }, source: "zz-host", exported: "2026-01-01T00:00:00+00:00" },
  "setup/join": { steps: ["zz-step"], note: "zz-note", api_key: "zz-key", synced: false },
  "setup/create": { steps: ["zz-step"], applied: { ok: false, error: "zz-error" }, api_key: "zz-key" },
  "password": { nodes: [{ name: "node-b", ok: false, error: "zz-error" }] },
};
const confirms = [], alerts = [];
globalThis.confirm = m => { confirms.push(String(m)); return false; };
globalThis.alert = m => { alerts.push(String(m)); };
/* node makes navigator a getter; a browser would simply have one */
Object.defineProperty(globalThis, "navigator", { value: { languages: ["de-DE", "en"], platform: "zz" }, configurable: true });
globalThis.fetch = async (url) => {
  const path = String(url).replace(/^\/api\//, "").split("?")[0];
  const body = path in FIX ? FIX[path] : /^[a-z]+\/[a-z]+$/.test(path) ? [row(1), row(2)] : {};
  return { ok: true, status: 200, json: async () => body, text: async () => "" };
};

const { NAV, route, doApply, refreshStatus, renderBanner } = await import(root + "shell.js");
const { E, openEditor } = await import(root + "entities.js");
const { showLogin, openAccount, refreshWho } = await import(root + "auth.js");
const { openWizard } = await import(root + "pages/services.js");
const { openCertWizard } = await import(root + "pages/certificates.js");
const { setupChoice, setupJoin, setupCreate } = await import(root + "pages/setup.js");
const { peerEditor } = await import(root + "pages/cluster.js");
await import(root + "main.js");        /* picks German from navigator.languages */
ok(currentLanguage() === "de", "main.js chose German from the browser's list");

const content = document.querySelector("#content");
/* Everything under an element, one part per line. The stub's own .text glues
   adjacent nodes together ("zz-reason" + "Edit here anyway"), which would hide
   a word boundary from the search below. */
const textOf = n => [n.innerHTML, n.textContent, ...n.children.map(textOf)].filter(Boolean).join("\n");
const dlg = () => document.querySelector("#dlgtitle").textContent + "\n" +
  textOf(document.querySelector("#dlgbody")) + "\n" + textOf(document.querySelector("#dlgfoot"));
const page = () => textOf(content);
const buttons = (n, out = []) => { if (n.tagName === "button" && n.onclick) out.push(n); n.children.forEach(c => buttons(c, out)); return out; };
const seen = [];       /* [what, text] */
const note = (what, text) => { if (text && text.trim()) seen.push([what, visible(text)]); };
const press = async (b, what) => {
  try { await b.onclick({ target: b, preventDefault(){} }); } catch (e) { /* thin fixtures; the text is what matters */ }
  note(what + " > " + (b.textContent || "?"), dlg());
  note(what + " > " + (b.textContent || "?") + " (page)", page());
};
/* Press every button on a page, and every button on the dialog each opens. */
const pressAll = async (what) => {
  for (const b of buttons(content)) {
    document.querySelector("#dlgbody").children.length = 0;
    document.querySelector("#dlgfoot").children.length = 0;
    await press(b, what);
    for (const d of buttons(document.querySelector("#dlgbody")).concat(buttons(document.querySelector("#dlgfoot"))))
      await press(d, what + " > " + (b.textContent || "?"));
  }
};
const openDialog = async (what, fn) => {
  document.querySelector("#dlgbody").children.length = 0;
  document.querySelector("#dlgfoot").children.length = 0;
  try { await fn(); } catch (e) { ok(false, what + " opened without throwing -- " + e.message); }
  note(what, dlg());
  for (const d of buttons(document.querySelector("#dlgbody")).concat(buttons(document.querySelector("#dlgfoot"))))
    await press(d, what);
};

let pages = 0;
for (const [key] of NAV) {
  if (key === "grp") continue;
  pages++;
  globalThis.location.hash = "#/" + key;
  content.innerHTML = ""; content.children.length = 0;
  try { await route(); } catch (e) { /* route() catches its own */ }
  note("page " + (key || "overview"), page());
  note("title " + (key || "overview"), document.querySelector("#pagetitle").textContent);
  await pressAll("page " + (key || "overview"));
}
note("nav", textOf(document.querySelector("#navlinks")));
await refreshStatus();
note("node strip", textOf(document.querySelector("#nodestrip")));
note("apply button", document.querySelector("#applybtn").textContent);
renderBanner({ read_only: true, read_only_reason: "zz-reason" });
note("read-only banner", textOf(document.querySelector("#banner")));
for (const b of buttons(document.querySelector("#banner"))) await press(b, "read-only banner");
renderBanner({ edit_override: true });
note("unlocked banner", textOf(document.querySelector("#banner")));
await refreshWho();
note("who", textOf(document.querySelector("#whofoot")));
showLogin(true);
note("login (setup)", ["#logintitle", "#loginintro", "#lbtn"].map(s => document.querySelector(s).textContent).join("\n"));
document.querySelector("#login").classList.remove("show");
showLogin(false);
note("login", ["#logintitle", "#loginintro", "#lbtn"].map(s => document.querySelector(s).textContent).join("\n"));
await openDialog("apply", doApply);
for (const key of Object.keys(E)) {
  await openDialog("new " + key, () => openEditor(key));
  await openDialog("edit " + key, () => openEditor(key, row(1)));
}
await openDialog("publish wizard", () => openWizard());
await openDialog("edit service", () => openWizard({ service_id: "svc-1", url: "https://app.zz.test", target: "10.0.0.1:80" }));
await openDialog("certificate wizard", () => openCertWizard());
await openDialog("account", () => openAccount());
const st = FIX["setup/state"];
await openDialog("setup: choice", () => setupChoice(st));
await openDialog("setup: join", () => setupJoin(st));
await openDialog("setup: create", () => setupCreate(st));
await openDialog("peer editor", () => peerEditor(null, () => {}));
confirms.forEach(c => note("confirm", c));
alerts.forEach(a => note("alert", a));

ok(pages > 20 && seen.length > 100, "rendered " + pages + " pages and " + seen.length + " views, dialogs and prompts");
let misses = 0;
const reported = new Set();
for (const [what, text] of seen) {
  for (const [k, re] of english) {
    if (!re.test(text) || reported.has(k + "@" + what)) continue;
    reported.add(k + "@" + what);
    if (misses++ < 60) console.log("  ENGLISH  " + what.padEnd(40) + " " + JSON.stringify(k));
  }
}
ok(misses === 0, misses ? misses + " English strings were shown in a German UI" : "nothing English was shown in a German UI");

console.log(fail ? `\n${fail} failed` : "\nthe UI speaks the browser's language");
process.exit(fail ? 1 : 0);
