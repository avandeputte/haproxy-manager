/* Single sign-on, from the browser's side.
 *
 * What the wizard sends is the contract: flat oauth_enabled / oauth_allow
 * become one oauth object, a service that already requires SSO comes back
 * into the form with its list intact, and the services table says who a
 * protected service admits. None of that is visible from the API tests.
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
  id: "r1", url: "https://shop.example.com", urls: ["https://shop.example.com"],
  scheme: "https", targets: ["http://10.0.0.5:80"], pool: "shop", enabled: true,
  health: { type: "http" },
  oauth: { enabled: true, allow: ["alice@example.com", "@corp.example.com"] },
}];

let sent = null;
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) sent = JSON.parse(o.body);
  const bodies = {
    services: SERVICES, traffic: { at: [], series: {} },
    "access/groups": [], "acme/accounts": [], "acme/challenges": [],
    recipes: { ok: true, recipes: [] },
    "access/oauth": { enabled: true, issuer: "https://idp.example.net",
                      has_client_secret: true, auth_host: "auth.example.com",
                      cookie_domain: "example.com", scopes: "openid email profile",
                      session_hours: 12,
                      redirect_uri: "https://auth.example.com/.ham-sso/callback" },
    "wizard/publish": { ok: true, actions: [], warnings: [], preview: "" },
  };
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const { E } = await import(REPO + "/static/js/entities.js");
const { NAV } = await import(REPO + "/static/js/shell.js");
const { openWizard, servicesCard, WIZ_FIELDS } = await import(REPO + "/static/js/pages/services.js");
const { renderSso } = await import(REPO + "/static/js/pages/sso.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };

// -- the pieces exist --------------------------------------------------------
ok(WIZ_FIELDS.some(f => f.k === "oauth_enabled") && WIZ_FIELDS.some(f => f.k === "oauth_allow"),
   "the wizard offers SSO beside basic auth");
ok(E["haproxy/backends"].fields.some(f => f.k === "oauth_enabled"),
   "and the pool editor from the Advanced page too");
ok(NAV.some(x => x[0] === "p:sso"), "Single sign-on is in the menu");

// -- the table says who is admitted ------------------------------------------
const card = await servicesCard();
ok(card.textContent.includes("sign-in via SSO"),
   "a protected service says so in the list");
ok(card.textContent.includes("alice@example.com") &&
   card.textContent.includes("@corp.example.com"), "naming who it admits");

// -- editing round-trips the list --------------------------------------------
await openWizard({
  service_id: "r1", url: "https://shop.example.com", target: "http://10.0.0.5:80",
  oauth_enabled: true, oauth_allow: "alice@example.com\n@corp.example.com",
});
const allowField = document.querySelector("#f_oauth_allow");
ok(allowField && allowField.value.includes("alice@example.com"),
   "an edit brings the allow-list back into the form");
const pub = [...document.querySelectorAll("button")].find(b => /^(Publish|Save)/.test(b.textContent));
pub.click();
await new Promise(r => queueMicrotask(r));
ok(sent && sent.oauth && sent.oauth.enabled === true &&
   sent.oauth.allow.includes("alice@example.com"),
   "and what is sent nests the flat fields into one oauth object");
ok(!("oauth_enabled" in sent) && !("oauth_allow" in sent),
   "with the flat spellings gone from the wire");

// -- the settings page -------------------------------------------------------
location.hash = "#/p:sso";
await renderSso();
const page = document.querySelector("#content");
ok(page.textContent.includes("Single sign-on"), "the settings page renders");
ok(page.textContent.includes("https://auth.example.com/.ham-sso/callback"),
   "and shows the redirect URI to register at the provider");
ok(!!document.querySelector("#f_client_secret") &&
   document.querySelector("#f_client_secret").value === "",
   "the client secret is never echoed back into the form");
ok([...page.querySelectorAll("button")].some(b => b.textContent === "Rotate secret"),
   "the kill switch is a button");
ok(!!document.querySelector("#f_allow_unverified") &&
   !document.querySelector("#f_allow_unverified").checked,
   "accepting unverified email claims is offered, and off");
for (const prov of ["authentik", "Authelia", "Google"]) {
  const d = [...page.querySelectorAll("details summary")].find(x => x.textContent === prov);
  ok(!!d, "there are setup steps for " + prov);
}
ok(page.textContent.split("https://auth.example.com/.ham-sso/callback").length >= 3,
   "each guide carries the real redirect URI, not a placeholder");
ok(page.textContent.includes("accounts.google.com"),
   "and Google's fixed issuer is spelled out");
ok(!page.textContent.includes("<sign-in host>") && !page.textContent.includes("<authentik host>")
   && !page.textContent.includes("<application slug>"),
   "no angle-bracket placeholders anywhere -- every URL is a real one");
ok(page.textContent.includes("https://authentik.example.com/application/o/haproxy-manager/"),
   "the authentik issuer is built from the saved cookie domain");
ok(page.textContent.includes("- " + "https://auth.example.com/.ham-sso/callback"),
   "the Authelia client block is paste-ready, redirect URI included");
ok(page.textContent.includes("client_id: haproxy-manager"),
   "with a concrete client id");

console.log(fail ? `\n${fail} failed` : "\nthe browser's half of SSO holds together");
process.exit(fail ? 1 : 0);
