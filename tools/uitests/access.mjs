/* Requiring a sign-in, from the wizard's side.
 *
 * What the form sends is the whole feature as far as the browser is concerned:
 * a flat auth_enabled / auth_groups / auth_realm becomes one auth object, and
 * a service that already requires a sign-in has to come back into the form
 * with the right groups ticked. Neither is visible from reading the page.
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

const GROUPS = [{ id: "g1", name: "staff" }, { id: "g2", name: "admins" }];
const SERVICES = [{
  id: "r1", url: "https://shop.example.com", urls: ["https://shop.example.com"],
  scheme: "https", targets: ["http://10.0.0.5:80"], pool: "shop", enabled: true,
  health: { type: "http" }, certificate: "shop",
  auth: { enabled: true, groups: ["g1"], group_names: ["staff"], realm: "The Shop" },
}];

let sent = null;
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) sent = JSON.parse(o.body);
  const bodies = {
    services: SERVICES, traffic: { at: [], series: {} },
    "access/groups": GROUPS, "acme/accounts": [], "acme/challenges": [],
    recipes: { ok: true, recipes: [] },
    "wizard/publish": { ok: true, actions: [], warnings: [], public: "", target: "", preview: "" },
  };
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const { E } = await import(REPO + "/static/js/entities.js");
const { NAV } = await import(REPO + "/static/js/shell.js");
const { openWizard, servicesCard, WIZ_FIELDS } = await import(REPO + "/static/js/pages/services.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const findButton = (root, label) =>
  [...root.querySelectorAll("button")].find(b => b.textContent === label) || null;

// -- the pages exist and are reachable --------------------------------------
ok(!!E["access/users"] && !!E["access/groups"], "there are Users and Groups pages");
ok(NAV.some(x => x[0] === "access/users") && NAV.some(x => x[0] === "access/groups"),
   "and both are in the menu");
ok(E["access/users"].fields.some(f => f.k === "password" && f.t === "password"),
   "a user has a password field, typed as one");
ok(E["access/users"].refs.includes("access/groups"),
   "the user editor loads the groups it offers");
ok(E["haproxy/backends"].fields.some(f => f.k === "auth_enabled"),
   "a pool can be made to require a sign-in from the Advanced page too");

// -- the table says what a service requires ---------------------------------
const card = await servicesCard();
ok(card.textContent.includes("sign-in required"),
   "a service that asks for a sign-in says so in the list");
ok(card.textContent.includes("staff"), "naming the groups it admits");

// -- publishing a new service -----------------------------------------------
openWizard();
const body = document.querySelector("#dlgbody");
ok(!!document.querySelector("#f_auth_enabled"), "the wizard offers a sign-in");
const groupsBox = document.querySelector("#f_auth_groups");
ok(!!groupsBox && [...groupsBox.querySelectorAll("input")].length === 2,
   "with the groups that exist to pick from");

document.querySelector("#f_url").value = "https://shop.example.com";
document.querySelector("#f_target").value = "http://10.0.0.5:80";
document.querySelector("#f_auth_enabled").checked = true;
// a real click sets both, and readForm reads the :checked selector
const g2 = [...groupsBox.querySelectorAll("input")].find(c => c.value === "g2");
g2.checked = true; g2.setAttribute("checked", "");
document.querySelector("#f_auth_realm").value = "Admin only";

sent = null;
await findButton(document.querySelector("#dlgfoot"), "Publish").onclick();
ok(!!sent && !!sent.auth, "publishing sends one auth object, not three loose fields");
ok(sent.auth.enabled === true && JSON.stringify(sent.auth.groups) === '["g2"]' &&
   sent.auth.realm === "Admin only", "carrying what was ticked and typed");
ok(!("auth_enabled" in sent) && !("auth_groups" in sent) && !("auth_realm" in sent),
   "and the flat form fields are not sent as well");

// -- editing one that already requires it -----------------------------------
document.querySelector("#dlgbody").innerHTML = "";
const svc = SERVICES[0];
openWizard({
  service_id: svc.id, url: svc.urls.join("\n"), target: svc.targets.join(", "),
  name: svc.pool, auth_enabled: svc.auth.enabled, auth_groups: svc.auth.groups,
  auth_realm: svc.auth.realm,
});
ok(document.querySelector("#f_auth_enabled").checked === true,
   "editing shows the sign-in already switched on");
ok(document.querySelector("#f_auth_realm").value === "The Shop", "with its prompt");
const ticked = [...document.querySelector("#f_auth_groups").querySelectorAll("input")]
  .filter(c => c.checked).map(c => c.value);
ok(JSON.stringify(ticked) === '["g1"]', "and the group it admits ticked");

sent = null;
await findButton(document.querySelector("#dlgfoot"), "Publish").onclick();
ok(sent && sent.service_id === "r1" && sent.auth.enabled === true,
   "saving the edit keeps the sign-in on the same service");

// -- a raw TCP port has nowhere to put a sign-in ----------------------------
ok(WIZ_FIELDS.some(f => f.k === "auth_enabled"), "the field is part of the wizard");
document.querySelector("#f_url").value = "tcp://0.0.0.0:3306";
document.querySelector("#f_url").dispatchEvent(new window.Event("change"));
const row = document.querySelector('[data-field="auth_enabled"]');
ok(row.parentNode.style.display === "none" ||
   row.parentNode.parentNode.style.display === "none",
   "a tcp:// URL hides it rather than offering something that cannot work");
/* The same wiring drives every other row that comes and goes. It used to be
   attached while the form was still detached, where nothing can be found by
   id, so the form never reacted to anything typed into it. */
const cert = document.querySelector('[data-field="cert_mode"]');
ok(cert.parentNode.style.display === "none",
   "and the certificate rows go with it, so the form reacts at all");

console.log(fail ? `\n${fail} failed` : "\nthe sign-in reaches the wizard and comes back");
process.exit(fail ? 1 : 0);
