/* DNS alias mode from the browser's side: the challenge type editor has the
 * alias field, and the certificate wizard shows it for a new DNS-01 challenge
 * type only -- and sends it only then, so a value left in the hidden row
 * cannot fail a request for an HTTP-01 certificate. */
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

let sent = null, path = null;
globalThis.fetch = async (u, o) => {
  const p = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) { sent = JSON.parse(o.body); path = p; }
  const bodies = {
    "acme/accounts": [{ id: "a1", name: "le", email: "", ca: "letsencrypt" }],
    "acme/challenges": [{ id: "h1", name: "http", method: "http01" }],
    "acme/certificates": [], "acme/status": {}, "acme/health": { ok: true }, "acme/dnsapis": { ok: true, hooks: [] },
    "wizard/certificate": { ok: true, domains: ["app.example.com"], actions: [], warnings: [] },
  };
  return { ok: true, status: 200, json: async () => bodies[p] ?? {}, text: async () => "" };
};

const { E, openEditor } = await import(REPO + "/static/js/entities.js");
const { openCertWizard } = await import(REPO + "/static/js/pages/certificates.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const $ = s => document.querySelector(s);
const findButton = (root, label) => [...root.querySelectorAll("button")].find(b => b.textContent === label) || null;
const shown = k => { let el = $("#f_" + k); if (!el) return false;
  while (el.parentNode && !el.parentNode.classList.contains("frm")) el = el.parentNode;
  const lab = $('label[for="f_' + k + '"]');
  return el.style.display !== "none" && (!lab || lab.style.display !== "none"); };
const setSelect = (sel, v) => { sel.value = v; sel.dispatchEvent(new window.Event("change")); };

// -- the challenge type editor -----------------------------------------------------
ok(E["acme/challenges"].fields.some(f => f.k === "challenge_alias"), "a challenge type has the alias field");
await openEditor("acme/challenges", { id: "c1", name: "cf", method: "dns01", dns_provider: "dns_cf",
                                      dns_credentials: "CF_Token=x", challenge_alias: "alias.example.net" });
ok($("#f_challenge_alias") && $("#f_challenge_alias").value === "alias.example.net", "the editor shows the stored alias");

// -- the certificate wizard --------------------------------------------------------
await openCertWizard();
ok(!shown("challenge_alias"), "an existing challenge type: no alias row");
setSelect($("#f_challenge_id"), "__new__");
ok(!shown("challenge_alias"), "a new HTTP-01 challenge type: none either");
setSelect($("#f_ch_method"), "dns01");
ok(shown("challenge_alias") && shown("dns_provider"), "a new DNS-01 challenge type shows it, with the DNS hook");
$("#f_domains").value = "app.example.com";
$("#f_challenge_alias").value = "alias.example.net";
$("#f_issue").checked = false;
sent = null;
await findButton(document, "Preview").onclick();
ok(path === "wizard/certificate" && sent && sent.challenge.method === "dns01"
   && sent.challenge.challenge_alias === "alias.example.net", "DNS-01 sends the alias as typed");
setSelect($("#f_ch_method"), "http01");
ok(!shown("challenge_alias"), "back to HTTP-01 the row is hidden, its value still in it");
sent = null;
await findButton(document, "Preview").onclick();
ok(sent && sent.challenge.method === "http01" && sent.challenge.challenge_alias === "",
   "and HTTP-01 is sent without what was left in the hidden row");

console.log(fail ? "\n" + fail + " failed" : "\nall passed");
process.exit(fail ? 1 : 0);
