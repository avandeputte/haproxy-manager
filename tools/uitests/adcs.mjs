/* Active Directory Certificate Services from the browser's side: the account
 * editor and the certificate wizard show the CA server, template and
 * credentials for "adcs" only, with the CA name and domain for MS-ICPR and
 * the CA certificate for web enrollment; the accounts list and the wizard's
 * picker name the CA by its server; the connection test sends what is typed;
 * and the certificates page says when acme2certifier is missing. */
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
  { id: "a2", name: "corp", email: "", ca: "adcs", adcs_method: "msicpr", adcs_host: "ca01.corp.lan",
    adcs_ca_name: "Corp Issuing CA", adcs_template: "WebServer", adcs_auth: "kerberos", adcs_domain: "corp.lan",
    adcs_dc: "", adcs_user: "svc-acme", adcs_password: "pw" },
];
let sent = null, path = null;
let health = { ok: true, adcs: { wanted: true, installed: false, impacket: false, install_error: "curl: (6) no route" } };
globalThis.fetch = async (u, o) => {
  const p = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) { sent = JSON.parse(o.body); path = p; }
  const bodies = {
    "acme/accounts": ACCOUNTS, "acme/challenges": [{ id: "h1", name: "http", method: "http01" }],
    "acme/certificates": [], "acme/status": {}, "acme/health": health, "acme/dnsapis": { ok: true, hooks: [] },
    "wizard/certificate": { ok: true, domains: ["app.corp.lan"], actions: [], warnings: [] },
    "acme/adcs/test": { ok: false, message: "Failed to connect to endpoint mapper" },
    "acme/adcs/config": { ok: true, config: "[CAhandler]\nhandler_module = x\npassword = ********\ntimeout = 30\n" },
  };
  return { ok: true, status: 200, json: async () => bodies[p] ?? {}, text: async () => "" };
};

const { E, openEditor, renderEntity } = await import(REPO + "/static/js/entities.js");
const { openCertWizard, certificateNotices, loadAcmeHealth } = await import(REPO + "/static/js/pages/certificates.js");
const { CA_CHOICES } = await import(REPO + "/static/js/core.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const $ = s => document.querySelector(s);
const findButton = (root, label) => [...root.querySelectorAll("button")].find(b => b.textContent === label) || null;
const shown = k => { let el = $("#f_" + k); if (!el) return false;
  while (el.parentNode && !el.parentNode.classList.contains("frm")) el = el.parentNode;
  const lab = $('label[for="f_' + k + '"]');
  return el.style.display !== "none" && (!lab || lab.style.display !== "none"); };
const setSelect = (sel, v) => { sel.value = v; sel.dispatchEvent(new window.Event("change")); };
const ADCS = ["adcs_method", "adcs_host", "adcs_ca_name", "adcs_template", "adcs_auth", "adcs_domain", "adcs_dc", "adcs_user", "adcs_password", "adcs_extra"];

// -- "adcs" is a choice, named in words ----------------------------------------------
const choice = CA_CHOICES.find(o => o && o.value === "adcs");
ok(!!choice && /Active Directory/.test(choice.label), "the CA pickers offer Active Directory Certificate Services");

// -- the account editor ------------------------------------------------------------
openEditor("acme/accounts");
ok(ADCS.every(k => !shown(k)) && shown("eab_kid"), "a new account hides the AD CS rows and shows EAB");
setSelect($("#f_ca"), "adcs");
ok(ADCS.every(k => shown(k)), "picking Active Directory shows them all for MS-ICPR");
ok(!shown("server") && !shown("ca_bundle") && !shown("eab_kid") && !shown("eab_hmac"),
   "and hides the directory URL, the CA certificate and EAB");
ok($("#f_adcs_template").value === "WebServer" && $("#f_adcs_auth").value === "kerberos",
   "WebServer and Kerberos are the defaults");
ok(!!findButton($("#dlgbody"), "Test the connection to the CA"), "the connection test is offered");
setSelect($("#f_adcs_method"), "certsrv");
ok(!shown("adcs_ca_name") && !shown("adcs_domain") && !shown("adcs_dc") && shown("ca_bundle") && shown("adcs_host"),
   "web enrollment drops the CA name and domain and asks for the CA certificate to trust");
ok($("#f_adcs_auth").value === "ntlm" && $('#f_adcs_auth option[value="kerberos"]').disabled
   && !$('#f_adcs_auth option[value="basic"]').disabled, "and takes NTLM or basic, not Kerberos");
setSelect($("#f_adcs_method"), "msicpr");
ok($("#f_adcs_auth").value === "ntlm" && !$('#f_adcs_auth option[value="kerberos"]').disabled
   && $('#f_adcs_auth option[value="basic"]').disabled, "back to MS-ICPR: NTLM stays, basic is out");
setSelect($("#f_ca"), "letsencrypt");
ok(ADCS.every(k => !shown(k)) && shown("eab_kid"), "a public CA hides them again");

openEditor("acme/accounts", ACCOUNTS[1]);
ok($("#f_ca").value === "adcs" && shown("adcs_host") && $("#f_adcs_host").value === "ca01.corp.lan"
   && $("#f_adcs_ca_name").value === "Corp Issuing CA" && $("#f_adcs_user").value === "svc-acme",
   "editing an AD CS account shows its server, CA name and service account");
$("#f_adcs_password").value = "typed";
await findButton($("#dlgbody"), "Test the connection to the CA").onclick();
ok(path === "acme/adcs/test" && sent && sent.adcs_host === "ca01.corp.lan" && sent.adcs_password === "typed"
   && sent.adcs_method === "msicpr" && sent.adcs_ca_name === "Corp Issuing CA",
   "the connection test sends the account as typed");
ok($("#dlgbody").textContent.includes("Failed to connect to endpoint mapper"), "and shows what came back");
$("#f_adcs_extra").value = "[CAhandler]\ntimeout: 30";
await findButton($("#dlgbody"), "Show the configuration").onclick();
ok(path === "acme/adcs/config" && sent && sent.adcs_extra === "[CAhandler]\ntimeout: 30" && sent.adcs_password === "typed",
   "the configuration view sends the account as typed, extra settings included");
ok($("#dlgbody").textContent.includes("timeout = 30") && $("#dlgbody").textContent.includes("********"),
   "and shows the configuration it got back");

// -- the accounts list names the CA by its server ---------------------------------
const box = document.createElement("div"); document.body.appendChild(box);
await renderEntity("acme/accounts", box);
const corpRow = [...box.querySelectorAll("tr")].find(tr => tr.textContent.includes("corp"));
ok(!!corpRow && corpRow.textContent.includes("Active Directory") && corpRow.textContent.includes("ca01.corp.lan")
   && corpRow.textContent.includes("WebServer"), "the list says Active Directory, the CA server and the template");

// -- the certificate wizard --------------------------------------------------------
await openCertWizard();
const acc = $("#f_account_id");
ok([...acc.querySelectorAll("option")].some(o => o.textContent === "corp (ca01.corp.lan)"),
   "an existing AD CS account is offered by its CA server");
setSelect(acc, "__new__");
ok(shown("acc_ca") && ADCS.every(k => !shown("acc_" + k)) && shown("acc_eab_kid"),
   "a new account: the AD CS rows wait for Active Directory");
setSelect($("#f_acc_ca"), "adcs");
ok(ADCS.every(k => shown("acc_" + k)) && !shown("acc_server") && !shown("acc_eab_kid"),
   "Active Directory shows them and hides the directory URL and EAB");
setSelect(acc, "a1");
ok(ADCS.every(k => !shown("acc_" + k)) && !shown("acc_ca"), "an existing account hides the new-account rows again");
setSelect(acc, "__new__");
$("#f_domains").value = "app.corp.lan";
$("#f_acc_name").value = "corp2";
$("#f_acc_adcs_host").value = "ca02.corp.lan";
$("#f_acc_adcs_ca_name").value = "Corp CA 2";
$("#f_acc_adcs_domain").value = "corp.lan";
$("#f_acc_adcs_user").value = "svc";
$("#f_acc_adcs_password").value = "secret";
$("#f_acc_eab_kid").value = "leftover";
$("#f_issue").checked = false;
await findButton(document, "Create").onclick();
ok(path === "wizard/certificate" && sent && sent.account.ca === "adcs" && sent.account.adcs_host === "ca02.corp.lan"
   && sent.account.adcs_ca_name === "Corp CA 2" && sent.account.adcs_template === "WebServer"
   && sent.account.adcs_auth === "kerberos" && sent.account.adcs_user === "svc" && sent.account.adcs_password === "secret",
   "the new AD CS account is sent with its server, CA name, template and credentials");
ok(sent.account.eab_kid === "" && sent.account.server === "" && sent.account.adcs_extra === "", "and without EAB or a directory URL, the extra settings empty");
setSelect($("#f_acc_ca"), "letsencrypt");
sent = null;
await findButton(document, "Preview").onclick();
ok(sent && sent.account.ca === "letsencrypt" && !("adcs_host" in sent.account) && sent.account.eab_kid === "leftover",
   "a public CA is sent without the AD CS fields, EAB as typed");

// -- the certificates page says when acme2certifier is missing ----------------------
await loadAcmeHealth();
let cards = certificateNotices().filter(Boolean);
let card = cards.find(c => c.textContent.includes("acme2certifier is not installed"));
ok(!!card && card.textContent.includes("no route") && !!findButton(card, "Install acme2certifier now"),
   "a node that wants AD CS and lacks acme2certifier is told, with the last failure and an install button");
await findButton(card, "Install acme2certifier now").onclick();
ok(path === "acme/adcs/install", "the button asks the node to install it");
health = { ok: true, adcs: { wanted: true, installed: true, impacket: false } };
await loadAcmeHealth();
card = certificateNotices().filter(Boolean).find(c => c.textContent.includes("Impacket is not installed"));
ok(!!card && !findButton(card, "Install acme2certifier now"), "with acme2certifier but no Impacket: a note, no button");
health = { ok: true, adcs: { wanted: true, installed: true, impacket: true } };
await loadAcmeHealth();
ok(!certificateNotices().filter(Boolean).some(c => c.textContent.includes("acme2certifier")), "all there: nothing said");
health = { ok: true, adcs: { wanted: false, installed: false, impacket: false } };
await loadAcmeHealth();
ok(!certificateNotices().filter(Boolean).some(c => c.textContent.includes("acme2certifier")),
   "no AD CS account: nothing said either");
health = { ok: true, adcs: { wanted: true, installed: false, impacket: false, installing: true } };
await loadAcmeHealth();
ok(!certificateNotices().filter(Boolean).some(c => c.textContent.includes("acme2certifier")),
   "while the node is installing it by itself: nothing said, and no button to press");

console.log(fail ? "\n" + fail + " failed" : "\nall passed");
process.exit(fail ? 1 : 0);
