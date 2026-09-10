/* A rate limit per client, from the wizard's side.
 *
 * The form carries two numbers -- how many, over how long -- and the second
 * means nothing without the first, so its row comes and goes with it. A
 * service that has a limit says so in the list and comes back into the edit
 * form with both numbers. None of that is visible from the API tests.
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
  health: { type: "http" }, certificate: "shop", rate_limit: 100, rate_window: 10,
}, {
  id: "r2", url: "tcp://0.0.0.0:3306", urls: ["tcp://0.0.0.0:3306"],
  scheme: "tcp", targets: ["10.0.0.6:3306"], pool: "db", enabled: true,
  health: { type: "none" }, rate_limit: 20, rate_window: 60,
}, {
  id: "r3", url: "https://open.example.com", urls: ["https://open.example.com"],
  scheme: "https", targets: ["http://10.0.0.7:80"], pool: "open", enabled: true,
  health: { type: "none" }, certificate: "open", rate_limit: "", rate_window: 10,
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

// -- both editors carry it ---------------------------------------------------
ok(WIZ_FIELDS.some(f => f.k === "rate_limit") && WIZ_FIELDS.some(f => f.k === "rate_window"),
   "the wizard has a limit and a window");
ok(E["haproxy/backends"].fields.some(f => f.k === "rate_limit" && f.t === "number"),
   "so does the Backend Pools editor, typed as a number");

// -- the list says what a service allows -------------------------------------
const card = await servicesCard();
ok(card.textContent.includes("at most 100 requests per 10 s per client"),
   "a limited HTTP service says how much in the list");
ok(card.textContent.includes("at most 20 connections per 60 s per client"),
   "a TCP one counts connections instead");
ok(!card.textContent.includes("at most  ") && (card.textContent.match(/at most /g) || []).length === 2,
   "and a service without a limit says nothing about one");

// -- publishing: the window only matters once there is a limit ---------------
openWizard();
const limit = document.querySelector("#f_rate_limit");
ok(!!limit && limit.type === "number", "the wizard offers a limit, as a number");
ok(document.querySelector("#f_rate_window").value === "10", "the window starts at 10 seconds");
ok(rowHidden("rate_window"), "but its row is hidden while there is no limit");

document.querySelector("#f_url").value = "https://shop.example.com";
document.querySelector("#f_target").value = "http://10.0.0.5:80";
limit.value = "100";
limit.dispatchEvent(new window.Event("input"));
ok(!rowHidden("rate_window"), "typing a limit brings the window row out");
document.querySelector("#f_rate_window").value = "30";

sent = null;
await findButton(document.querySelector("#dlgfoot"), "Publish").onclick();
ok(!!sent && sent.rate_limit === 100 && sent.rate_window === 30,
   "publishing sends both as numbers");

// -- clearing it sends an empty string, which the server reads as no limit --
limit.value = "";
limit.dispatchEvent(new window.Event("input"));
ok(rowHidden("rate_window"), "clearing the limit hides the window again");
sent = null;
await findButton(document.querySelector("#dlgfoot"), "Publish").onclick();
ok(!!sent && sent.rate_limit === "" && "rate_limit" in sent,
   "an empty limit is sent as empty, not left out -- that is how an edit switches it off");

// -- editing a limited service shows the numbers it has ----------------------
document.querySelector("#dlgbody").innerHTML = "";
const edit = findButton(card, "Edit");
ok(!!edit, "a service can be edited from the list");
edit.onclick();
ok(document.querySelector("#f_rate_limit").value === "100" &&
   document.querySelector("#f_rate_window").value === "10",
   "editing shows the limit and window the service has");
ok(!rowHidden("rate_window"), "with the window row visible from the start");

console.log(fail ? `\n${fail} failed` : "\na pool's ceiling reaches the wizard and comes back");
process.exit(fail ? 1 : 0);
