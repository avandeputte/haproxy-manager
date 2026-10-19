/* The PROXY protocol, from the forms' side.
 *
 * A Real Server has a select -- off, version 1, version 2 -- and the server
 * list names the haproxy.cfg keyword when it is on. The publish form has the
 * same select, sends what is chosen (an empty string for off, which is how an
 * edit turns it off), and an edited service comes back showing what its
 * servers have. None of that is visible from the API tests.
 */
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
<div id="login"><form id="loginbox"><input id="lu"><input id="lp">
<div id="lp2wrap" hidden><input id="lp2"></div><div id="lerr"></div>
<button id="lbtn"></button><h2 id="logintitle"></h2><p id="loginintro"></p></form></div>
<div id="content"></div></body></html>`);
globalThis.document = document; globalThis.window = window;
globalThis.location = { hash: "#/p:services" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = () => 0;

const SERVICES = [{
  id: "m1", url: "tcp://0.0.0.0:25", urls: ["tcp://0.0.0.0:25"],
  scheme: "tcp", targets: ["tcp://10.0.0.25:25"], pool: "smtp", enabled: true,
  health: { type: "tcp" }, proxy_protocol: "v1",
}];

let sent = null;
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) sent = JSON.parse(o.body);
  const bodies = {
    services: SERVICES, traffic: { at: [], series: {} },
    "access/groups": [], "acme/accounts": [], "acme/challenges": [],
    recipes: { ok: true, recipes: [] },
    "wizard/publish": { ok: true, actions: [], warnings: [], public: "", target: "", preview: "" },
  };
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const { E } = await import(REPO + "/static/js/entities.js");
const { fieldRow, readForm } = await import(REPO + "/static/js/core.js");
const { openWizard, servicesCard, WIZ_FIELDS } = await import(REPO + "/static/js/pages/services.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const findButton = (root, label) =>
  [...root.querySelectorAll("button")].find(b => b.textContent === label) || null;
const rowHidden = k => {
  const el = document.querySelector('[data-field="' + k + '"]');
  return !!el && (el.parentNode.style.display === "none" ||
                  el.parentNode.parentNode.style.display === "none");
};
/* linkedom (0.18) gets two things about selects wrong, and both matter here:
   setting selected=false on any option clears whichever one is selected, so
   selectOption's loop leaves a match marked only if it is the last option;
   and a select with no option marked reports no value, where a browser
   reports the first. Put both right before any form is drawn, so the checks
   below see what a browser would. */
const optProto = Object.getPrototypeOf(document.createElement("option"));
Object.defineProperty(optProto, "selected", {
  configurable: true,
  get() { return this.hasAttribute("selected"); },
  set(v) {
    if (v) {
      const prev = this.parentElement && this.parentElement.querySelector("option[selected]");
      if (prev && prev !== this) prev.removeAttribute("selected");
      this.setAttribute("selected", "");
    } else this.removeAttribute("selected");
  },
});
const selProto = Object.getPrototypeOf(document.createElement("select"));
Object.defineProperty(selProto, "value", {
  configurable: true,
  get() { const o = this.querySelector("option[selected]") || this.querySelector("option"); return o ? o.value : ""; },
  set(v) { const o = [...this.querySelectorAll("option")].find(x => x.value === String(v)); if (o) o.selected = true; },
});
const optionText = sel => [...sel.options].map(o => o.value + "=" + o.textContent).join(", ");

// -- the Real Server editor ----------------------------------------------------
const srvField = E["haproxy/servers"].fields.find(f => f.k === "proxy_protocol");
ok(!!srvField && srvField.t === "select", "a Real Server has a PROXY protocol select");
const holder = document.createElement("div");
fieldRow(srvField, undefined).forEach(el => holder.appendChild(el));
document.body.appendChild(holder);
let sel = holder.querySelector("select");
ok(optionText(sel) === "=Off, v1=Version 1 (text), v2=Version 2 (binary)",
   "offering off and the two versions, in words: " + optionText(sel));
ok(sel.value === "", "a new server starts with it off");
ok(readForm([srvField]).proxy_protocol === "", "and saves off as an empty value");
holder.innerHTML = "";
fieldRow(srvField, "v2").forEach(el => holder.appendChild(el));
sel = holder.querySelector("select");
ok(sel.value === "v2" && readForm([srvField]).proxy_protocol === "v2",
   "a server that has v2 opens on v2 and saves it unchanged");
holder.remove();

const opts = E["haproxy/servers"].cols.find(c => c[0] === "opts")[2];
ok(opts({ ssl: true, proxy_protocol: "v2", backup: true }) === "ssl, send-proxy-v2, backup",
   "the server list names the keyword beside the other options");
ok(opts({ proxy_protocol: "v1" }) === "send-proxy" && opts({ proxy_protocol: "" }) === "—"
   && opts({ proxy_protocol: "junk" }) === "—",
   "v1 reads send-proxy; off or anything unknown shows nothing");

// -- the publish form ----------------------------------------------------------
ok(WIZ_FIELDS.some(f => f.k === "proxy_protocol"), "the publish form has it too");
openWizard();
document.querySelector("#f_url").value = "tcp://0.0.0.0:25";
document.querySelector("#f_url").dispatchEvent(new window.Event("input"));
document.querySelector("#f_target").value = "10.0.0.25:25";
const wsel = document.querySelector("#f_proxy_protocol");
ok(!!wsel && wsel.value === "", "it opens off for a new service");
ok(!rowHidden("proxy_protocol"), "and is shown for a tcp:// service");
wsel.value = "v2";
sent = null;
await findButton(document.querySelector("#dlgfoot"), "Publish").onclick();
ok(!!sent && sent.proxy_protocol === "v2", "publishing sends the version chosen");
wsel.value = "";
sent = null;
await findButton(document.querySelector("#dlgfoot"), "Publish").onclick();
ok(!!sent && "proxy_protocol" in sent && sent.proxy_protocol === "",
   "off is sent as an empty value, which is how an edit switches it off");

// -- editing a service shows what its servers have -------------------------------
document.querySelector("#dlgbody").innerHTML = "";
const card = await servicesCard();
const edit = findButton(card, "Edit");
ok(!!edit, "the service can be edited from the list");
edit.onclick();
ok(document.querySelector("#f_proxy_protocol").value === "v1",
   "editing it opens on the version its servers use");

console.log(fail ? `\n${fail} failed` : "\nthe PROXY protocol reaches both forms and comes back");
process.exit(fail ? 1 : 0);
