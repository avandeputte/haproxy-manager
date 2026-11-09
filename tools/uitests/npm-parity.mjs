/* The NPM-parity features from the browser's side: the publish wizard's
 * redirect mode and HSTS, the settings for unknown hosts, IPv6 and the
 * WebSocket timeout, and the certificate page's upload, replace and download. */
let parseHTML;
for (const where of ["linkedom", process.env.LINKEDOM]) {
  if (!where) continue;
  try { ({ parseHTML } = await import(where)); break; } catch { /* try the next */ }
}
if (!parseHTML) {
  console.log("  skipped: no DOM available (npm i linkedom, or set LINKEDOM)");
  process.exit(0);
}
const REPO = process.cwd();
const { document, window } = parseHTML(`<!doctype html><html><body>
<div id="ovl"><div id="dlg"><div class="hd"><h3 id="dlgtitle"></h3>
<button id="dlgclose"></button></div><div class="bd" id="dlgbody"></div>
<div class="ft" id="dlgfoot"></div></div></div>
<aside id="nav"><div class="foot" id="whofoot"></div></aside>
<div id="content"></div></body></html>`);
globalThis.document = document; globalThis.window = window;
globalThis.location = { hash: "#/p:services" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = () => 0;
globalThis.confirm = () => true;
/* linkedom's selects: see proxy-protocol.mjs */
const optProto = Object.getPrototypeOf(document.createElement("option"));
Object.defineProperty(optProto, "selected", {
  configurable: true,
  get() { return this.hasAttribute("selected"); },
  set(v) {
    if (v) { const prev = this.parentElement && this.parentElement.querySelector("option[selected]");
             if (prev && prev !== this) prev.removeAttribute("selected"); this.setAttribute("selected", ""); }
    else this.removeAttribute("selected");
  },
});
const selProto = Object.getPrototypeOf(document.createElement("select"));
Object.defineProperty(selProto, "value", {
  configurable: true,
  get() { const o = this.querySelector("option[selected]") || this.querySelector("option"); return o ? o.value : ""; },
  set(v) { const o = [...this.querySelectorAll("option")].find(x => x.value === String(v)); if (o) o.selected = true; },
});

const SERVICES = [{
  id: "r1", url: "http://old.example.com", urls: ["http://old.example.com"], scheme: "http",
  targets: [], pool: "old", enabled: true, health: { type: "none" },
  redirect: { to: "https://new.example.com", code: 308, keep_path: true }, hsts: false,
}];
const CERTS = [{ id: "c1", name: "issued", domains: "a.example.com", auto_renew: true },
               { id: "c2", name: "bought", domains: "shop.example.com", source: "custom", auto_renew: false }];
let sent = null, path = null, downloads = [];
globalThis.fetch = async (u, o) => {
  const p = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) { sent = JSON.parse(o.body); path = p; }
  const bodies = {
    services: SERVICES, traffic: { at: [], series: {} }, probes: { results: [] },
    "access/groups": [], "acme/accounts": [], "acme/challenges": [], "haproxy/addresslists": [],
    "haproxy/errorpages": [], "haproxy/rules": [], "haproxy/conditions": [], recipes: { ok: true, recipes: [] },
    "acme/certificates": CERTS, "acme/status": {}, "acme/health": {},
    "wizard/publish": { ok: true, actions: [], warnings: [], public: "", target: "", preview: "" },
    "acme/certificates/upload": { ok: true, names: ["shop.example.com"], note: "Apply to serve it." },
  };
  return { ok: true, status: 200, json: async () => bodies[p] ?? {}, text: async () => "" };
};

const { E, S, renderEntity } = await import(REPO + "/static/js/entities.js");
const { openWizard, servicesCard } = await import(REPO + "/static/js/pages/services.js");
const core = await import(REPO + "/static/js/core.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const $ = s => document.querySelector(s);
const findButton = (root, label) => [...root.querySelectorAll("button")].find(b => b.textContent === label) || null;
/* a field sits in its cell, a checkbox one level deeper: either one hidden hides the row */
const rowHidden = k => { const el = $('[data-field="' + k + '"]');
  return !!el && (el.parentNode.style.display === "none" || el.parentNode.parentNode.style.display === "none"); };
const setSelect = (sel, v) => { sel.value = v; sel.dispatchEvent(new window.Event("change")); };

// -- the services table names a redirect -------------------------------------------
const card = await servicesCard();
ok(card.textContent.includes("redirects to https://new.example.com") && card.textContent.includes("path kept"),
   "a redirect service says where it sends people, instead of its servers");

// -- the wizard: forward or redirect ---------------------------------------------------
openWizard();
ok(!rowHidden("target") && rowHidden("redirect_to"), "forwarding asks for servers, not an address");
setSelect($("#f_action"), "redirect");
ok(rowHidden("target") && !rowHidden("redirect_to") && !rowHidden("redirect_code") && !rowHidden("redirect_keep_path"),
   "redirecting asks where to, with which code, keeping the path or not");
ok(rowHidden("health_enabled") && rowHidden("balance"), "and hides the health check and balancing: there are no servers");
$("#f_url").value = "http://old.example.com";
$("#f_redirect_to").value = "https://new.example.com";
setSelect($("#f_redirect_code"), "308");
sent = null;
await findButton($("#dlgfoot"), "Publish").onclick();
ok(sent.redirect && sent.redirect.to === "https://new.example.com" && sent.redirect.code === 308
   && sent.redirect.keep_path === true && sent.target === "" && !("action" in sent),
   "publishing sends the redirect, and no servers");
$("#f_url").value = "tcp://0.0.0.0:5432";
$("#f_url").dispatchEvent(new window.Event("change"));
ok(rowHidden("action") && !rowHidden("target"), "a tcp:// service cannot redirect: the choice goes away");

// -- HSTS --------------------------------------------------------------------------------
$("#dlgbody").innerHTML = "";
openWizard();
$("#f_url").value = "https://secure.example.com";
$("#f_url").dispatchEvent(new window.Event("change"));
ok(!rowHidden("hsts") && rowHidden("hsts_subdomains"), "HSTS is offered for HTTPS; subdomains only once it is on");
$("#f_hsts").checked = true; $("#f_hsts").dispatchEvent(new window.Event("change"));
ok(!rowHidden("hsts_subdomains"), "on, the subdomains option appears");
$("#f_target").value = "10.0.0.5:80";
sent = null;
await findButton($("#dlgfoot"), "Publish").onclick();
ok(sent.hsts === true && sent.hsts_subdomains === false && !sent.redirect, "and is sent with the service");

// -- editing a redirect service comes back in redirect mode ---------------------------------
$("#dlgbody").innerHTML = "";
openWizard({ service_id: "r1", url: "http://old.example.com", action: "redirect", redirect_to: "https://new.example.com",
             redirect_code: 308, redirect_keep_path: true });
ok($("#f_action").value === "redirect" && $("#f_redirect_to").value === "https://new.example.com"
   && $("#f_redirect_code").value === "308" && rowHidden("target"), "editing shows the redirect as it is");

// -- settings ------------------------------------------------------------------------------
const sf = S["haproxy-settings"].fields.map(f => f.k);
ok(["timeout_tunnel", "ipv6", "default_site", "default_site_url"].every(k => sf.includes(k)),
   "HAProxy Settings carries the WebSocket timeout, IPv6 and what unknown hosts get");
ok(E["haproxy/backends"].fields.some(f => f.k === "hsts") && E["haproxy/backends"].fields.some(f => f.k === "redirect_to"),
   "and a Backend Pool can be given HSTS or a redirect directly");

// -- certificates ---------------------------------------------------------------------------
globalThis.location = { hash: "#/acme/certificates" };
const realDownload = core.download;
await renderEntity("acme/certificates");
const content = $("#content");
ok(!!findButton(content, "Upload a certificate"), "the Certificates page offers an upload");
const rows = [...content.querySelectorAll("tbody tr")];
const actions = r => [...r.querySelectorAll("button")].map(b => b.textContent);
ok(actions(rows[0]).includes("Issue") && !actions(rows[0]).includes("Replace") && actions(rows[0]).includes("Download"),
   "an issued certificate is issued and downloaded, not replaced");
ok(!actions(rows[1]).includes("Issue") && actions(rows[1]).includes("Replace") && actions(rows[1]).includes("Download"),
   "an uploaded one is replaced and downloaded, never issued");
ok(rows[1].textContent.includes("uploaded"), "and says it was uploaded");
findButton(content, "Upload a certificate").onclick();
ok(!!$("#f_up_name") && !!$("#f_up_cert") && !!$("#f_up_key") && !!$("#f_up_chain"),
   "the upload asks for a name, the certificate, its key and an optional chain");
$("#f_up_name").value = "bought2";
$("#f_up_cert").value = "-----BEGIN CERTIFICATE-----x"; $("#f_up_key").value = "-----BEGIN PRIVATE KEY-----y";
sent = null;
await findButton($("#dlgfoot"), "Upload").onclick();
ok(path === "acme/certificates/upload" && sent.name === "bought2" && sent.cert.startsWith("-----BEGIN CERTIFICATE")
   && sent.key.startsWith("-----BEGIN PRIVATE KEY") && sent.id === undefined, "and sends them to be checked");
ok($("#dlgbody").textContent.includes("covering shop.example.com"), "then says which names it covers");

console.log(fail ? `\n${fail} failed` : "\nwhat an NPM user expects, on the page");
process.exit(fail ? 1 : 0);
