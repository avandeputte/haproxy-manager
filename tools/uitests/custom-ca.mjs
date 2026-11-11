/* A custom ACME server from the browser's side: the account editor and the
 * certificate wizard show the directory URL and the CA certificate to trust
 * only for "custom", and send them; the accounts list and the wizard's
 * account picker name a custom CA by its address. */
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


const ACCOUNTS = [
  { id: "a1", name: "le", email: "", ca: "letsencrypt" },
  { id: "a2", name: "corp", email: "ops@corp.lan", ca: "custom",
    server: "https://a2c.corp.lan/directory", ca_bundle: "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----" },
];
let sent = null, path = null;
globalThis.fetch = async (u, o) => {
  const p = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) { sent = JSON.parse(o.body); path = p; }
  const bodies = {
    "acme/accounts": ACCOUNTS, "acme/challenges": [{ id: "h1", name: "http", method: "http01" }],
    "acme/certificates": [], "acme/status": {}, "acme/health": {}, "acme/dnsapis": { ok: true, hooks: [] },
    "wizard/certificate": { ok: true, domains: ["app.corp.lan"], actions: [], warnings: [] },
  };
  return { ok: true, status: 200, json: async () => bodies[p] ?? {}, text: async () => "" };
};

const { E, openEditor, renderEntity } = await import(REPO + "/static/js/entities.js");
const { openCertWizard } = await import(REPO + "/static/js/pages/certificates.js");
const { CA_CHOICES } = await import(REPO + "/static/js/core.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const $ = s => document.querySelector(s);
const findButton = (root, label) => [...root.querySelectorAll("button")].find(b => b.textContent === label) || null;
/* hidden when its cell (or the label in front of it) is display:none */
const shown = k => { let el = $("#f_" + k); if (!el) return false;
  while (el.parentNode && !el.parentNode.classList.contains("frm")) el = el.parentNode;
  const lab = $('label[for="f_' + k + '"]');
  return el.style.display !== "none" && (!lab || lab.style.display !== "none"); };
const setSelect = (sel, v) => { sel.value = v; sel.dispatchEvent(new window.Event("change")); };

// -- "custom" is a choice, in both places --------------------------------------------
ok(CA_CHOICES.includes("custom") && E["acme/accounts"].fields.find(f => f.k === "ca").o.includes("custom"),
   "the account editor and the certificate wizard offer custom");

// -- the account editor ------------------------------------------------------------
openEditor("acme/accounts");
ok(!shown("server") && !shown("ca_bundle"), "a new account hides the address and CA certificate");
setSelect($("#f_ca"), "custom");
ok(shown("server") && shown("ca_bundle"), "picking custom shows them");
setSelect($("#f_ca"), "zerossl");
ok(!shown("server") && !shown("ca_bundle"), "picking a public CA hides them again");

openEditor("acme/accounts", ACCOUNTS[1]);
ok($("#f_ca").value === "custom" && shown("server") && $("#f_server").value === "https://a2c.corp.lan/directory"
   && $("#f_ca_bundle").value.includes("BEGIN CERTIFICATE"), "editing a custom account shows its address and certificate");
openEditor("acme/accounts", ACCOUNTS[0]);
ok(!shown("server"), "editing a Let's Encrypt account does not");

// -- the accounts list names a custom CA's address ---------------------------------
const box = document.createElement("div"); document.body.appendChild(box);
await renderEntity("acme/accounts", box);
const corpRow = [...box.querySelectorAll("tr")].find(tr => tr.textContent.includes("corp"));
ok(!!corpRow && corpRow.textContent.includes("https://a2c.corp.lan/directory"), "the list shows a custom CA's address");

// -- the certificate wizard --------------------------------------------------------
await openCertWizard();
const acc = $("#f_account_id");
ok([...acc.querySelectorAll("option")].some(o => o.textContent === "corp (a2c.corp.lan)"),
   "an existing custom account is offered by its server's host name");
setSelect(acc, "__new__");
ok(shown("acc_ca") && !shown("acc_server") && !shown("acc_ca_bundle"), "a new account: the address waits for custom");
setSelect($("#f_acc_ca"), "custom");
ok(shown("acc_server") && shown("acc_ca_bundle"), "custom shows the address and the CA certificate");
setSelect(acc, "a1");
ok(!shown("acc_server") && !shown("acc_ca"), "an existing account hides the new-account rows again");
setSelect(acc, "__new__");
$("#f_domains").value = "app.corp.lan";
$("#f_acc_name").value = "corp2";
$("#f_acc_server").value = "https://ca2.corp.lan/acme/directory";
$("#f_acc_ca_bundle").value = "-----BEGIN CERTIFICATE-----\nBB\n-----END CERTIFICATE-----";
$("#f_issue").checked = false;
await findButton(document, "Create").onclick();
ok(path === "wizard/certificate" && sent && sent.account.ca === "custom"
   && sent.account.server === "https://ca2.corp.lan/acme/directory" && sent.account.ca_bundle.includes("BB"),
   "the new custom account is sent with its address and certificate");
setSelect($("#f_acc_ca"), "letsencrypt");
sent = null;
await findButton(document, "Preview").onclick();
ok(sent && sent.account.ca === "letsencrypt" && sent.account.server === "" && sent.account.ca_bundle === "",
   "a public CA is sent without the address and certificate typed for custom");

console.log(fail ? "\n" + fail + " failed" : "\nall passed");
process.exit(fail ? 1 : 0);
