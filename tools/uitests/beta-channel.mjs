/* The beta channel, from the Updates page.

   The switch is on the page that shows the offer, and changing it has to
   change the offer at once: a node that has just said it wants betas should
   see one, and a node that has just said it does not should not still be
   looking at an "update available" for one.

   The choice is the cluster's (#39): the page sends it to its own node, which
   makes it on the node holding the virtual IP, and the page says where. */
let parseHTML;
for (const where of ["linkedom", process.env.LINKEDOM]) {
  if (!where) continue;
  try { ({ parseHTML } = await import(where)); break; } catch { /* try the next */ }
}
if (!parseHTML) {
  console.log("  skipped: no DOM available (npm i linkedom, or set LINKEDOM)");
  process.exit(0);
}
const { document, window } = parseHTML(`<!doctype html><html><body>
<div id="ovl"><div id="dlg"><div class="hd"><h3 id="dlgtitle"></h3>
<button id="dlgclose"></button></div><div class="bd" id="dlgbody"></div>
<div class="ft" id="dlgfoot"></div></div></div>
<aside id="nav"><div class="foot" id="whofoot"></div></aside>
<div id="content"></div></body></html>`);
globalThis.document = document; globalThis.window = window;
globalThis.location = { hash: "#/p:updates" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };

const calls = [];
let version = {};
let answer = { ok: true, made_on: "", here: true };     // what the server says of where the choice went
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  calls.push({ path, method: (o && o.method) || "GET", body: o && o.body ? JSON.parse(o.body) : null });
  if (path === "version/beta" && o && o.method === "PUT") {
    // the server's answer to the switch: the next check reads the beta branch
    version = o.body.includes('"beta":true')
      ? { ...version, beta: true, latest: "1.95.0-beta.1", latest_ref: "beta", latest_is_beta: true, available: true }
      : { ...version, beta: false, latest: "", latest_ref: "main", latest_is_beta: false, available: false };
  }
  const bodies = { version, "version/beta": answer, "version/check": {}, "update/log": { ok: true, log: "", running: false } };
  return { ok: true, status: 200, json: async () => bodies[path] || {}, text: async () => "" };
};
const { renderUpdates } = await import("../../static/js/pages/updates.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const text = () => document.querySelector("#content").textContent;
const box = () => document.querySelector("#f_update_beta");
const updateButton = () => [...document.querySelectorAll("#content button")].find(b => b.textContent.startsWith("Update"));

version = { version: "1.94.2", this_is_beta: false, latest: "1.94.2", latest_ref: "main", latest_is_beta: false,
            available: false, checked: "", repo: "avandeputte/haproxy-manager", ref: "main",
            beta: false, beta_ref: "beta", can_update: true, cannot_update_reason: "", updating: false, peers: 0 };
await renderUpdates();
ok(box() !== null && box().checked === false, "the page offers the beta switch, off");
ok(/Also offer beta versions/.test(text()), "in those words");
ok(!/beta for betas/.test(text()) && /\(main\)/.test(text()), "the check is described as reading main only");
ok(updateButton().disabled === true, "nothing to update to");

calls.length = 0;
box().checked = true;
box().dispatchEvent(new window.Event("change"));
await new Promise(r => setTimeout(r, 20));
const put = calls.find(c => c.path === "version/beta" && c.method === "PUT");
ok(!!put && put.body.beta === true, "ticking it sends the choice, for the installation");
ok(!calls.some(c => c.path === "local"), "and no longer saves it as this node's own");
ok(!/choice is shared/.test(text()), "a single node is not told about clusters");
ok(calls.findIndex(c => c.path === "version/check") > calls.indexOf(put), "and checks again straight away");
ok(/1\.95\.0-beta\.1/.test(text()), "the beta is then shown as published");
ok(/beta for betas/.test(text()), "and the check is described as reading both branches");
ok(!updateButton().disabled && /Update to 1\.95\.0-beta\.1/.test(updateButton().textContent),
   "with the update button offering it by name");
ok([...document.querySelectorAll("#content .pill")].some(p => p.textContent === "beta"),
   "marked as a beta beside the version");

calls.length = 0;
box().checked = false;
box().dispatchEvent(new window.Event("change"));
await new Promise(r => setTimeout(r, 20));
const off = calls.find(c => c.path === "version/beta" && c.method === "PUT");
ok(!!off && off.body.beta === false, "unticking sends that too");
ok(!/1\.95\.0-beta\.1/.test(text()) && updateButton().disabled === true,
   "and the beta is no longer on offer");

version = { ...version, version: "1.95.0-beta.1", this_is_beta: true };
await renderUpdates();
ok([...document.querySelectorAll("#content .pill")].some(p => p.textContent === "beta"),
   "a node running a beta says so beside its installed version");

// -- in a cluster: one choice, made where the virtual IP is --------------------
version = { ...version, version: "1.94.2", this_is_beta: false, beta: false, latest: "", latest_is_beta: false,
            available: false, peers: 2 };
await renderUpdates();
ok(/In a cluster the choice is shared: every node offers the same versions\./.test(text()),
   "a node with others beside it says the choice is everyone's");
answer = { ok: true, made_on: "haproxy1", here: true };
box().checked = true;
box().dispatchEvent(new window.Event("change"));
await new Promise(r => setTimeout(r, 20));
ok(box().checked === true && /Set on haproxy1, which holds the virtual IP\./.test(text()),
   "ticked on a passive node, the page says which node made it");
ok(!/next sync/.test(text()), "and nothing more when this node has it already");
answer = { ok: true, made_on: "haproxy1", here: false };
box().checked = false;
box().dispatchEvent(new window.Event("change"));
await new Promise(r => setTimeout(r, 20));
ok(/Set on haproxy1.*This node takes it with the next sync\./.test(text()),
   "a node that does not have it yet says when it will");

console.log(fail ? `\n${fail} failed` : "\nbetas are asked for once, for every node");
process.exit(fail ? 1 : 0);
