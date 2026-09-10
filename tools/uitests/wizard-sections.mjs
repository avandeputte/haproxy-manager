/* The publish wizard as sections.
 *
 * The form grew a field at a time until it was a wall. It is now a handful
 * of sections under headings, and the optional ones open with a checkbox:
 * nothing of a section shows until it is ticked, and an unticked section is
 * off when the form is sent, whatever its hidden fields still hold. That
 * last part is the contract -- a limit typed and then unticked must not be
 * published -- and none of it can be seen from the API tests.
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
<div id="content"></div></body></html>`);
globalThis.document = document; globalThis.window = window;
globalThis.location = { hash: "#/p:services" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = (f) => { f(); return 0; };

const RECIPES = [
  { id: "quiet", name: "Quiet", category: "Test", summary: "", notes: "",
    fields: { url: "https://q.example.com", health: "none", balance: "leastconn" } },
  { id: "db", name: "Database", category: "Test", summary: "", notes: "",
    fields: { url: "tcp://0.0.0.0:5432", health: "pgsql", health_user: "haproxy" } },
];
let sent = null;
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) sent = JSON.parse(o.body);
  const bodies = {
    services: [], traffic: { at: [], series: {} }, probes: { results: [] },
    "access/groups": [], "acme/accounts": [], "acme/challenges": [],
    recipes: { ok: true, recipes: RECIPES },
    "wizard/publish": { ok: true, actions: [], warnings: [], public: "", target: "", preview: "" },
  };
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const { openWizard, WIZ_SECTIONS, WIZ_FIELDS } = await import(REPO + "/static/js/pages/services.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const $ = (sel) => document.querySelector(sel);
const findButton = (root, label) =>
  [...root.querySelectorAll("button")].find(b => b.textContent === label) || null;
const hidden = (el) => {
  for (let n = el; n && n.id !== "dlgbody"; n = n.parentNode) if (n.style && n.style.display === "none") return true;
  return false;
};
const rowHidden = k => hidden($('[data-field="' + k + '"]'));
const headings = () => [...document.querySelectorAll("#dlgbody .fsec")];
const headingHidden = title => hidden(headings().find(h => h.textContent === title));
const chosen = sel => ([...sel.options].find(o => o.selected) || {}).value;
const pick = (sel, v) => { [...sel.options].forEach(o => { o.selected = o.value === v; }); };
const tick = (k, on) => { const el = $("#f_" + k); el.checked = on; el.dispatchEvent(new window.Event("change")); };
const publish = async () => { sent = null; await findButton($("#dlgfoot"), "Publish").onclick(); return sent; };

// -- the shape ---------------------------------------------------------------
openWizard();
ok(headings().map(h => h.textContent).join("|") ===
   "Service|Certificate|Health check|Balancing and timeouts|Allowed networks|Rate limiting|Sign-in|Single sign-on (OIDC)",
   "the form is eight sections, in this order: " + headings().map(h => h.textContent).join(", "));
const order = [...document.querySelectorAll("#dlgbody .fsec, #dlgbody [data-field]")]
  .map(e => e.classList.contains("fsec") ? "#" + e.textContent : e.getAttribute("data-field"));
ok(order.indexOf("#Rate limiting") < order.indexOf("rate_enabled") &&
   order.indexOf("rate_enabled") < order.indexOf("rate_limit") &&
   order.indexOf("rate_limit") < order.indexOf("#Sign-in"), "a section's checkbox comes first, its settings after, under its heading");
ok(WIZ_SECTIONS.filter(s => s.toggle).map(s => s.toggle).join(",") ===
   "health_enabled,allow_enabled,rate_enabled,auth_enabled,oauth_enabled",
   "five sections are optional, each opened by one checkbox");
ok(WIZ_SECTIONS.every(s => !s.toggle || s.fields[0].k === s.toggle), "and the checkbox is the first thing in each");
ok(WIZ_FIELDS.length === WIZ_SECTIONS.reduce((n, s) => n + s.fields.length, 0), "WIZ_FIELDS is every section's fields, flat");

// -- optional sections show nothing until ticked ---------------------------------
ok($("#f_health_enabled").checked === true && !rowHidden("health") && !rowHidden("check_port"),
   "a new service checks its servers by default, so that section starts open");
ok(![...$("#f_health").options].some(o => o.value === "none"), "\"none\" is not a check type any more; the checkbox says that");
for (const [k, first] of [["allow_enabled", "allow_src"], ["rate_enabled", "rate_limit"],
                          ["auth_enabled", "auth_realm"], ["oauth_enabled", "oauth_allow"]]) {
  ok($("#f_" + k).checked === false && rowHidden(first), k + " starts off, with " + first + " out of sight");
  tick(k, true);
  ok(!rowHidden(first), "ticking it shows " + first);
  tick(k, false);
  ok(rowHidden(first), "unticking hides it again");
}
tick("health_enabled", false);
ok(rowHidden("health") && rowHidden("check_port") && rowHidden("notify_mode"),
   "with the check off, its type, port and alerting go too -- nothing is lost without a check");

// -- what is sent: an unticked section is off, whatever it holds -------------
$("#f_url").value = "https://shop.example.com";
$("#f_target").value = "http://10.0.0.5:80";
tick("allow_enabled", true); $("#f_allow_src").value = "10.0.0.0/8"; tick("allow_enabled", false);
tick("rate_enabled", true); $("#f_rate_limit").value = "100"; tick("rate_enabled", false);
let d = await publish();
ok(d.health.type === "none", "the check off is sent as type none");
ok(d.allow_src === "", "a network typed and then unticked is not sent");
ok(d.rate_limit === "", "nor a limit");
ok(!("health_enabled" in d) && !("allow_enabled" in d) && !("rate_enabled" in d),
   "the checkboxes themselves stay in the form");
tick("health_enabled", true); tick("allow_enabled", true); tick("rate_enabled", true);
d = await publish();
ok(d.health.type !== "none" && d.allow_src === "10.0.0.0/8" && d.rate_limit === 100,
   "ticked, the same fields are sent as they stand");

// -- a raw TCP port loses the sections that need a host name -----------------
$("#f_url").value = "tcp://0.0.0.0:3306";
$("#f_url").dispatchEvent(new window.Event("change"));
ok(headingHidden("Certificate") && headingHidden("Sign-in") && headingHidden("Single sign-on (OIDC)"),
   "tcp:// hides Certificate, Sign-in and SSO, headings included");
ok(rowHidden("cert_mode") && rowHidden("auth_enabled") && rowHidden("oauth_enabled"), "and their checkboxes");
ok(!headingHidden("Health check") && !headingHidden("Rate limiting") && !rowHidden("rate_limit"),
   "the sections that work for TCP stay");
$("#f_url").value = "https://shop.example.com";
$("#f_url").dispatchEvent(new window.Event("change"));
ok(!headingHidden("Certificate"), "and come back with an https URL");

// -- editing: the sections that are on are those the service uses -----------
$("#dlgbody").innerHTML = "";
openWizard({ service_id: "r1", url: "https://shop.example.com", target: "http://10.0.0.5:80",
             health: "none", allow_src: "192.168.0.0/16", rate_limit: 50, rate_window: 10 });
ok($("#f_health_enabled").checked === false && rowHidden("health"), "a service with no check comes back with that section off");
ok($("#f_allow_enabled").checked === true && !rowHidden("allow_src") && $("#f_allow_src").value === "192.168.0.0/16",
   "one with an allow-list comes back with that section open and filled");
ok($("#f_rate_enabled").checked === true && $("#f_rate_limit").value === "50", "and a limit likewise");
d = await publish();
ok(d.service_id === "r1" && d.health.type === "none" && d.allow_src === "192.168.0.0/16" && d.rate_limit === 50,
   "saving it unchanged sends what it had");
$("#dlgbody").innerHTML = "";
openWizard({ service_id: "r2", url: "https://shop.example.com", target: "http://10.0.0.5:80" });
ok($("#f_health_enabled").checked === true && $("#f_allow_enabled").checked === false && $("#f_rate_enabled").checked === false,
   "a prefill that says nothing gets the defaults: a check, no allow-list, no limit");

console.log(fail ? `\n${fail} failed` : "\nthe form is sections, and an unticked one is off");
process.exit(fail ? 1 : 0);
