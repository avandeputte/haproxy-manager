/* The condition wizard, from the browser's side: reachable from the
 * Conditions page, one type's fields at a time, Try it sends the sample and
 * draws both verdicts, and an existing condition comes back as it is. */
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
globalThis.location = { hash: "#/haproxy/conditions" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = () => 0;
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

let sent = null;
let reply = { ok: true, actions: [{ action: "created", type: "Condition", name: "host-app" }],
              preview: "acl acl_host-app hdr(host),regsub(':[0-9]+$','') -i app.example.com",
              validation: { ok: true, message: "haproxy -c accepts it" }, matches: true };
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) sent = JSON.parse(o.body);
  const bodies = {
    "haproxy/conditions": [{ id: "c1", name: "lan", type: "source_ip", value: "192.168.0.0/16", negate: true }],
    "haproxy/addresslists": [{ id: "l1", name: "friends" }],
    "wizard/condition": reply,
  };
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const { E, renderEntity } = await import(REPO + "/static/js/entities.js");
const { openConditionWizard } = await import(REPO + "/static/js/pages/conditions.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const $ = s => document.querySelector(s);
const findButton = (root, label) => [...root.querySelectorAll("button")].find(b => b.textContent === label) || null;
const cell = id => $(id).parentNode;
const setSelect = (sel, v) => { sel.value = v; sel.dispatchEvent(new window.Event("change")); };

await renderEntity("haproxy/conditions");
const head = $("#content").querySelector(".hd");
ok(!!findButton(head, "New condition") && !findButton(head, "Raw fields"), "the Conditions page offers the wizard, and nothing beside it");
ok(typeof E["haproxy/conditions"].wizard === "function" && !E["haproxy/conditions"].rowActions,
   "Edit opens the wizard: there is no second way");

openConditionWizard();
ok(cell("#f_cw_value").style.display === "" && cell("#f_cw_param").style.display === "none" && cell("#f_cw_list").style.display === "none",
   "a host test shows a value and nothing else");
ok(cell("#f_cw_s_host").style.display === "" && cell("#f_cw_s_path").style.display === "none",
   "and asks for a sample host, not a path");
setSelect($("#f_cw_type"), "http_header");
ok(cell("#f_cw_param").style.display === "" && cell("#f_cw_s_header").style.display === "",
   "a header test asks for the header's name and a sample value");
setSelect($("#f_cw_type"), "source_list");
ok(cell("#f_cw_list").style.display === "" && cell("#f_cw_value").style.display === "none" && cell("#f_cw_s_src").style.display === "",
   "an address-list test shows the list picker and asks for a sample address");
setSelect($("#f_cw_type"), "host_matches");
$("#f_cw_value").value = "app.example.com";
$("#f_cw_negate").checked = true;
$("#f_cw_s_host").value = "app.example.com:8443";
sent = null;
await findButton($("#dlgfoot"), "Try it").onclick();
ok(sent.dry_run === true && sent.type === "host_matches" && sent.value === "app.example.com" && sent.negate === true
   && sent.sample.host === "app.example.com:8443", "Try it sends the test and the sample without saving");
ok($("#dlgbody").textContent.includes("matches the sample") && $("#dlgbody").textContent.includes("HAProxy accepts it")
   && $("#dlgbody").textContent.includes("acl acl_host-app"), "and draws both verdicts and the acl line");
reply = Object.assign({}, reply, { matches: null, validation: { ok: false, message: "parsing [x:3] : unknown fetch" } });
await findButton($("#dlgfoot"), "Try it").onclick();
ok($("#dlgbody").textContent.includes("only HAProxy can judge a raw ACL") && $("#dlgbody").textContent.includes("unknown fetch"),
   "a raw ACL is left to HAProxy, whose refusal is shown in its words");

$("#dlgbody").innerHTML = "";
openConditionWizard({ id: "c1", name: "lan", type: "source_ip", value: "192.168.0.0/16", negate: true });
ok($("#f_cw_type").value === "source_ip" && $("#f_cw_value").value === "192.168.0.0/16" && $("#f_cw_negate").checked === true
   && $("#f_cw_name").value === "lan", "editing shows the condition as it is");
sent = null;
await findButton($("#dlgfoot"), "Save").onclick();
ok(sent.id === "c1" && !sent.dry_run, "and Save names it");

console.log(fail ? `\n${fail} failed` : "\none test, asked in words, tried before it is saved");
process.exit(fail ? 1 : 0);
