/* Updating the whole cluster from one node.

   The failure that matters is a node that does not take the instruction:
   nothing retries it, so it stays on the old version, and a cluster running
   two versions is exactly the thing the Cluster page warns about. It has to
   be named on the spot. */
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
<div id="login"><form id="loginbox"><input id="lu"><input id="lp">
<div id="lp2wrap" hidden><input id="lp2"></div><div id="lerr"></div>
<button id="lbtn"></button><h2 id="logintitle"></h2><p id="loginintro"></p></form></div>
<div id="content"></div></body></html>`);
globalThis.document = document; globalThis.window = window;
globalThis.location = { hash: "#/" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };

let sent = null, asked = [], answer = true, version = {}, reply = {};
globalThis.confirm = (q) => { asked.push(q); return answer; };
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body && path === "update") sent = JSON.parse(o.body);
  const bodies = { version, update: reply, "update/log": { ok: true, log: "", running: false } };
  return { ok: true, status: 200, json: async () => bodies[path] || {}, text: async () => "" };
};
const { renderUpdates } = await import("../../static/js/pages/updates.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const base = { version: "1.68.2", latest: "1.69.0", available: true, checked: "",
               repo: "avandeputte/haproxy-manager", ref: "main", can_update: true,
               cannot_update_reason: "", updating: false };
const field = () => document.querySelector("#f_update_peers");
const press = async () => {
  sent = null; asked = [];
  const b = [...document.querySelectorAll("#content button")]
    .find(x => x.textContent.startsWith("Update"));
  await b.onclick();
};

version = { ...base, peers: 2 };
reply = { ok: true, note: "running", nodes: [{ ok: true, name: "haproxy2" },
                                             { ok: true, name: "haproxy3" }] };
await renderUpdates();
ok(field() !== null, "with other nodes, it offers to update them too");
ok(field().checked === true, "ticked, because visiting each node is the thing being avoided");
ok(/other 2 nodes/.test($("#content").textContent), "it says how many");
ok(/told first/.test($("#content").textContent),
   "and that they go first, which is the part that is not obvious");

await press();
ok(sent && sent.peers === true, "pressing Update asks for them too");
ok(/other 2/.test(asked[0]), "and the confirmation says so before anything happens");

version = { ...base, peers: 2 };
reply = { ok: true, note: "running",
          nodes: [{ ok: true, name: "haproxy2" },
                  { ok: false, name: "haproxy3", error: "connection refused" }] };
await renderUpdates();
await press();
const text = $("#content").textContent;
ok(/haproxy3/.test(text), "a node that did not take it is named");
ok(/connection refused/.test(text), "with the reason");
ok(/stay on 1.68.2/.test(text), "and what it is left running");
ok(!/haproxy2<\/b>: /.test($("#content").innerHTML), "the ones that started are not listed as failures");

version = { ...base, peers: 2 };
reply = { ok: true, note: "running" };
await renderUpdates();
field().checked = false;
await press();
ok(sent && sent.peers === false, "unticked, only this node is updated");

version = { ...base, peers: 0 };
await renderUpdates();
ok(field() === null, "a single node is not offered the choice at all");

console.log(fail ? `\n${fail} failed` : "\nthe whole cluster updates from one node");
process.exit(fail ? 1 : 0);

function $(sel) { return document.querySelector(sel); }
