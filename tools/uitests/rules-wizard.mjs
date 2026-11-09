/* The rule wizard, from the browser's side.
 *
 * The API test checks what the request builds; this checks the dialog sends
 * that request: the listeners ticked, the conditions typed and picked in
 * their two groups, the action with only its own fields shown -- and that a
 * rule opened for editing comes back with what it holds, a pre-2.0 "or"
 * rule included. And that the verdict is drawn.
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
globalThis.location = { hash: "#/haproxy/rules" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = () => 0;
/* linkedom gets two things about selects wrong (see proxy-protocol.mjs):
   setting selected=false on any option clears the selection, and a select
   with no option marked reports no value. Put both right before any form is
   drawn, so the wizard's own reads see what a browser would. */
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

const FES = [{ id: "fe1", name: "https-443", binds: "0.0.0.0:443", mode: "http", rules: ["r1"] },
             { id: "fe2", name: "db-5432", binds: "0.0.0.0:5432", mode: "tcp", rules: [] }];
const CONDS = [{ id: "c1", name: "host-tv" }, { id: "c2", name: "host-films" }, { id: "c3", name: "lan" }];
const RULES = [{ id: "r1", name: "to-tv", type: "use_backend", backend: "b1", operator: "or", conditions: ["c1", "c2"] }];
let sent = null, reply = { ok: true, actions: [{ action: "created", type: "Rule", name: "x" }], warnings: [],
                           validation: { ok: true, message: "haproxy -c accepts it" }, preview: "frontend fe_x" };
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) sent = JSON.parse(o.body);
  const bodies = {
    "haproxy/rules": RULES, "haproxy/conditions": CONDS, "haproxy/backends": [{ id: "b1", name: "tv" }],
    "haproxy/frontends": FES, "haproxy/addresslists": [{ id: "l1", name: "friends" }],
    "wizard/rule": reply,
  };
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const { E, renderEntity } = await import(REPO + "/static/js/entities.js");
const { openRuleWizard, COND_LABEL, ACTION_LABEL } = await import(REPO + "/static/js/pages/rules.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const $ = s => document.querySelector(s);
const findButton = (root, label) => [...root.querySelectorAll("button")].find(b => b.textContent === label) || null;
/* pick an option, then say it changed, as a click would */
const setSelect = (sel, v) => { sel.value = v; sel.dispatchEvent(new window.Event("change")); };
/* a field's row: the wizard hides the cell an input sits in, and labels that cell */
const cell = id => $(id).parentNode;

// -- reachable from the Rules page ---------------------------------------------
await renderEntity("haproxy/rules");
const head = $("#content").querySelector(".hd");
ok(!!findButton(head, "New rule"), "the Rules page offers the wizard");
ok(!findButton(head, "Raw fields"), "and no second editor beside it");
ok(typeof E["haproxy/rules"].wizard === "function" && !E["haproxy/rules"].rowActions, "Edit opens the wizard");
const navKeys = (await import(REPO + "/static/js/shell.js")).NAV.map(x => x[0]);
ok(navKeys.indexOf("haproxy/conditions") === navKeys.indexOf("haproxy/rules") + 1 && !findButton(head, "Conditions"),
   "Conditions has its own menu entry, under Rules, rather than a button here");
ok(E["haproxy/rules"].refs.includes("haproxy/frontends"), "the page loads the listeners the wizard offers");

// -- a new rule ------------------------------------------------------------------
openRuleWizard();
const lst = $("#f_rw_listeners");
ok([...lst.querySelectorAll("input")].length === 2 && lst.textContent.includes("0.0.0.0:5432 tcp"),
   "ON: the listeners, with their binds and a tcp mark");
findButton($("#f_rw_any").parentNode, "Add condition").onclick();
findButton($("#f_rw_any").parentNode, "Add condition").onclick();
findButton($("#f_rw_all").parentNode, "Add condition").onclick();
const rows = [...$("#f_rw_any").querySelectorAll(".condrow")];
ok(rows.length === 2, "WHEN: conditions are added as rows");
rows[0].querySelector('[data-role="value"]').value = "tv.example.com";
setSelect(rows[1].querySelector('[data-role="type"]'), "host_ends_with");
rows[1].querySelector('[data-role="value"]').value = ".films.example.com";
rows[1].querySelector('[data-role="negate"]').checked = true;
const all = $("#f_rw_all").querySelector(".condrow");
setSelect(all.querySelector('[data-role="type"]'), "source_list");
ok(all.querySelector('[data-role="value"]').style.display === "none" && all.querySelector('[data-role="list"]').style.display === "",
   "an address-list condition shows the list picker instead of a value");
setSelect(all.querySelector('[data-role="list"]'), "l1");
setSelect($("#f_rw_all_pick"), "c3");
ok($("#f_rw_all").querySelectorAll(".condrow").length === 2 && $("#f_rw_all").textContent.includes("lan"),
   "an existing condition can be picked into a group");
const action = $("#f_rw_action");
ok(cell("#f_rw_backend").style.display === "" && cell("#f_rw_param1").style.display === "none",
   "THEN: routing shows the pool and nothing else");
setSelect(action, "http_request_set_header");
ok(cell("#f_rw_backend").style.display === "none" && cell("#f_rw_param1").style.display === "" && cell("#f_rw_param2").style.display === "",
   "setting a header shows its name and value");
ok(cell("#f_rw_param1").previousElementSibling.textContent === "Header name", "labelled for what the action needs");
$("#f_rw_param1").value = "X-Seen"; $("#f_rw_param2").value = "yes";
[...lst.querySelectorAll("input")][0].checked = true; [...lst.querySelectorAll("input")][0].setAttribute("checked", "");
sent = null;
await findButton($("#dlgfoot"), "Preview").onclick();
ok(sent && sent.dry_run === true, "Preview asks without saving");
ok(JSON.stringify(sent.listeners) === '["fe1"]', "sending the listeners ticked");
ok(sent.any_of.length === 2 && sent.any_of[0].type === "host_matches" && sent.any_of[0].value === "tv.example.com"
   && sent.any_of[1].type === "host_ends_with" && sent.any_of[1].negate === true,
   "the typed conditions, type, value and negation");
ok(sent.all_of.length === 2 && sent.all_of[0].type === "source_list" && sent.all_of[0].list === "l1"
   && sent.all_of[1].id === "c3", "the list picked, and the existing condition by id");
ok(sent.action.type === "http_request_set_header" && sent.action.param1 === "X-Seen" && sent.action.param2 === "yes"
   && sent.action.test === "if", "and the action with its fields");
ok($("#dlgbody").textContent.includes("HAProxy accepts it"), "the verdict is drawn");
reply = Object.assign({}, reply, { validation: { ok: false, message: "parsing [x:3] : error detected" } });
await findButton($("#dlgfoot"), "Preview").onclick();
ok($("#dlgbody").textContent.includes("HAProxy refuses it") && $("#dlgbody").textContent.includes("error detected"),
   "and a refusal shows HAProxy's words");

// -- editing a pre-2.0 rule ------------------------------------------------------------
$("#dlgbody").innerHTML = "";
openRuleWizard(RULES[0]);
ok($("#f_rw_name").value === "to-tv", "editing shows the rule's name");
ok([...$("#f_rw_listeners").querySelectorAll("input")].filter(c => c.checked).map(c => c.value).join() === "fe1",
   "and ticks the listener that holds it");
ok([...$("#f_rw_any").querySelectorAll(".condrow")].map(r => r.dataset.id).join() === "c1,c2"
   && $("#f_rw_all").querySelectorAll(".condrow").length === 0,
   "an \"or\" rule from before 2.0 opens with its conditions under Any of");
ok($("#f_rw_action").value === "use_backend", "with its action");
sent = null;
await findButton($("#dlgfoot"), "Preview").onclick();
ok(sent.id === "r1" && sent.any_of.map(c => c.id).join() === "c1,c2", "and sends them back by id, naming the rule");
ok(Object.keys(COND_LABEL).length === 13 && Object.keys(ACTION_LABEL).length === 10, "every type and action has words");

console.log(fail ? `\n${fail} failed` : "\non these, when this, then that");
process.exit(fail ? 1 : 0);
