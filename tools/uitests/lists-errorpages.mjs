/* Address lists, any-of rules and error pages, from the browser's side.
 *
 * The API tests check what is stored and rendered; this checks the pages
 * offer it: the wizard sends the lists a service names and clears them with
 * the section, the services table names them, the Rules page shows a rule's
 * two lists -- and a rule from before 2.0 as the two lists it means -- and
 * the error page editor can read a local file into its field.
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
globalThis.FileReader = class {
  readAsText(f) { this.result = f.text; this.onload && this.onload(); }
};

const LISTS = [{ id: "l1", name: "friends", networks: "192.168.1.0/24\n203.0.113.7" },
               { id: "l2", name: "office", networks: "10.9.0.0/16" }];
const CONDS = [{ id: "c1", name: "host-tv" }, { id: "c2", name: "host-films" }, { id: "c3", name: "lan" }];
const SERVICES = [{
  id: "r1", url: "https://shop.example.com", urls: ["https://shop.example.com"],
  scheme: "https", targets: ["http://10.0.0.5:80"], pool: "shop", enabled: true,
  health: { type: "http" }, allow_src: "", allow_lists: ["l1"], allow_list_names: ["friends"],
  auth: { enabled: true, groups: [], group_names: [], realm: "", exempt: "",
          exempt_lists: ["l2"], exempt_list_names: ["office"] },
}];
let sent = null;
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) sent = JSON.parse(o.body);
  const bodies = {
    services: SERVICES, traffic: { at: [], series: {} }, probes: { results: [] },
    "access/groups": [], "acme/accounts": [], "acme/challenges": [],
    "haproxy/addresslists": LISTS, "haproxy/conditions": CONDS, "haproxy/backends": [],
    "haproxy/errorpages": [],
    recipes: { ok: true, recipes: [] },
    "wizard/publish": { ok: true, actions: [], warnings: [], public: "", target: "", preview: "" },
  };
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const { E, openEditor } = await import(REPO + "/static/js/entities.js");
const { NAV } = await import(REPO + "/static/js/shell.js");
const { lists } = await import(REPO + "/static/js/core.js");
const { openWizard, servicesCard } = await import(REPO + "/static/js/pages/services.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const findButton = (root, label) =>
  [...root.querySelectorAll("button")].find(b => b.textContent === label) || null;
const tick = (box, id, on) => {
  const c = [...box.querySelectorAll("input")].find(x => x.value === id);
  c.checked = on; if (on) c.setAttribute("checked", ""); else c.removeAttribute("checked");
};

// -- the pages exist and are reachable --------------------------------------
ok(!!E["haproxy/addresslists"] && !!E["haproxy/errorpages"], "there are Address Lists and Error Pages pages");
ok(NAV.some(x => x[0] === "haproxy/addresslists") && NAV.some(x => x[0] === "haproxy/errorpages"),
   "and both are in the menu");
ok(E["haproxy/backends"].refs.includes("haproxy/addresslists") && E["haproxy/backends"].refs.includes("haproxy/errorpages"),
   "the pool editor loads the lists and pages it offers");
ok(E["haproxy/conditions"].fields.some(f => f.k === "type" && f.o.includes("source_list"))
   && E["haproxy/conditions"].fields.some(f => f.k === "list" && f.ref === "haproxy/addresslists"),
   "a condition can name a list");

// -- the services table names the lists ---------------------------------------
const card = await servicesCard();
ok(card.textContent.includes("only from friends"), "a service naming a list says so in the table");
ok(card.textContent.includes("except from office"), "and so does a sign-in that lists skip");

// -- the wizard sends what was ticked, and clears it with the section ---------
openWizard();
const allowBox = document.querySelector("#f_allow_lists");
ok(!!allowBox && [...allowBox.querySelectorAll("input")].length === 2,
   "the Allowed networks section offers the lists that exist");
document.querySelector("#f_url").value = "https://shop.example.com";
document.querySelector("#f_target").value = "http://10.0.0.5:80";
document.querySelector("#f_allow_enabled").checked = true;
tick(allowBox, "l1", true);
document.querySelector("#f_auth_enabled").checked = true;
tick(document.querySelector("#f_auth_exempt_lists"), "l2", true);
sent = null;
await findButton(document.querySelector("#dlgfoot"), "Publish").onclick();
ok(JSON.stringify(sent.allow_lists) === '["l1"]', "publishing sends the allow lists as their own field");
ok(JSON.stringify(sent.auth.exempt_lists) === '["l2"]' && !("auth_exempt_lists" in sent),
   "and the exempt lists inside auth, not as a loose field");
document.querySelector("#f_allow_enabled").checked = false;
sent = null;
await findButton(document.querySelector("#dlgfoot"), "Publish").onclick();
ok(JSON.stringify(sent.allow_lists) === "[]" && sent.allow_src === "",
   "unticking the section sends no lists, whatever is still ticked");

// -- editing a service that names lists but types no network -------------------
document.querySelector("#dlgbody").innerHTML = "";
openWizard({ service_id: "r1", url: "https://shop.example.com", target: "http://10.0.0.5:80",
             allow_src: "", allow_lists: ["l1"], auth_enabled: true, auth_exempt_lists: ["l2"] });
ok(document.querySelector("#f_allow_enabled").checked === true, "the section opens for a list alone");
ok([...document.querySelector("#f_allow_lists").querySelectorAll("input")].filter(c => c.checked).map(c => c.value).join() === "l1",
   "with the list ticked");
ok([...document.querySelector("#f_auth_exempt_lists").querySelectorAll("input")].filter(c => c.checked).map(c => c.value).join() === "l2",
   "and the exempt list ticked");

// -- the Rules page: two lists, and the old shape read as them ------------------
lists["haproxy/conditions"] = CONDS;
const col = E["haproxy/rules"].cols.find(c => c[0] === "cond")[2];
ok(col({ any_of: ["c1", "c2"], conditions: ["c3"] }) === "host-tv | host-films + lan",
   "the table shows any-of as alternatives and all-of after a plus");
ok(col({ conditions: ["c1", "c2"], operator: "or" }) === "host-tv | host-films",
   "a rule from before 2.0 with \"or\" reads as alternatives");
ok(col({ conditions: ["c1", "c3"] }) === "host-tv, lan", "and one with \"and\" as it always did");
ok(col({}) === "always", "no conditions is always");
const shown = E["haproxy/rules"].prepare({ id: "r", operator: "or", conditions: ["c1", "c2"] });
ok(JSON.stringify(shown.any_of) === '["c1","c2"]' && shown.conditions.length === 0,
   "the editor opens an old \"or\" rule with its conditions under Any of");
ok(!E["haproxy/rules"].fields.some(f => f.k === "operator"), "and no longer offers an operator to choose");
ok(E["haproxy/rules"].fields.some(f => f.k === "any_of") && E["haproxy/rules"].fields.some(f => f.k === "conditions"),
   "but the two lists");

// -- the error page editor reads a file into its field ---------------------------
lists["haproxy/errorpages"] = [];
openEditor("haproxy/errorpages");
const file = document.querySelector("#f_html_file");
ok(!!file && file.type === "file", "the editor has a file picker");
file.files = [{ text: "<h1>{error_code}</h1>" }];
file.dispatchEvent(new window.Event("change"));
ok(document.querySelector("#f_html").value === "<h1>{error_code}</h1>",
   "choosing a file puts its text in the HTML field; nothing is sent anywhere");
ok(E["haproxy/errorpages"].fields.find(f => f.k === "everywhere").d === true,
   "a new page is for every service unless said otherwise");

console.log(fail ? `\n${fail} failed` : "\nthe pages offer what the API stores");
process.exit(fail ? 1 : 0);
