/* Copying the login to the other nodes.

   The failure that matters is the quiet one: the password changes here, one
   node does not take it, and nobody finds out until a failover puts that node
   in front and the login stops working. So the dialog has to say which node
   refused, and must not close as if everything went through. */
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
<div id="ovl"><div id="dlg" role="dialog" aria-modal="true">
<div class="hd"><h3 id="dlgtitle"></h3><button id="dlgclose"></button></div>
<div class="bd" id="dlgbody"></div><div class="ft" id="dlgfoot"></div></div></div>
<aside id="nav"><div class="foot" id="whofoot"></div></aside>
<div id="login"><form id="loginbox"><input id="lu"><input id="lp">
<div id="lp2wrap" hidden><input id="lp2"></div><div id="lerr"></div>
<button id="lbtn"></button><h2 id="logintitle"></h2><p id="loginintro"></p></form></div>
<div id="content"></div></body></html>`);
globalThis.document = document; globalThis.window = window;
globalThis.location = { hash: "#/" }; globalThis.MutationObserver = class { observe(){} };

let sent = null, reply = { ok: true };
let whoami = { authenticated: true, username: "admin", email: "a@b.c", peers: 2 };
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) sent = JSON.parse(o.body);
  const body = path === "whoami" ? whoami : reply;
  return { ok: true, status: 200, json: async () => body, text: async () => "" };
};
const { refreshWho, openAccount } = await import(REPO + "/static/js/auth.js");
let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const open = async () => { await refreshWho(); openAccount(); };
const field = k => document.querySelector("#f_" + k);
const save = () => [...document.querySelectorAll("#dlgfoot button")]
  .find(b => b.textContent === "Save");
const shown = () => document.querySelector("#ovl").className;

await open();
ok(field("propagate") !== null, "with peers, the dialog offers to apply it to them");
ok(field("propagate").checked === true, "and offers it ticked, which is the usual intent");
ok(document.querySelector("#dlgbody").textContent.includes("2 other nodes"),
   "it says how many nodes that is");
ok(document.querySelector("#dlgbody").textContent.includes("never the password"),
   "and that the password itself does not travel");

field("new").value = "hunter2hunter2";
field("new2").value = "hunter2hunter2";
field("current").value = "old-one";
reply = { ok: true, username: "admin", nodes: [{ ok: true, name: "proxy2" },
                                               { ok: true, name: "proxy3" }] };
save().dispatchEvent(new window.Event("click"));
await new Promise(r => setTimeout(r, 0));
ok(sent.propagate === true, "ticked, it asks the server to propagate");
ok(sent.new === "hunter2hunter2", "and sends the new password to this node");

// the one that matters
await open();
field("new").value = "hunter2hunter2";
field("new2").value = "hunter2hunter2";
field("current").value = "old-one";
reply = { ok: true, username: "admin",
          nodes: [{ ok: true, name: "proxy2" },
                  { ok: false, name: "proxy3", error: "connection refused" }] };
save().dispatchEvent(new window.Event("click"));
await new Promise(r => setTimeout(r, 0));
const err = document.querySelector("#dlgfoot .err");
ok(/proxy3/.test(err.innerHTML), "when a node refuses, it names that node");
ok(/connection refused/.test(err.innerHTML), "and says why");
ok(!/proxy2/.test(err.innerHTML), "and does not blame the ones that worked");
ok(/old login/.test(err.textContent), "it says what that node is left with");
ok(shown().includes("show"), "the dialog stays open, so the failure is not missed");

// unticked
await open();
field("propagate").checked = false;
field("new").value = "hunter2hunter2";
field("new2").value = "hunter2hunter2";
field("current").value = "old-one";
reply = { ok: true, username: "admin" };
save().dispatchEvent(new window.Event("click"));
await new Promise(r => setTimeout(r, 0));
ok(sent.propagate === false, "unticked, nothing is propagated");

// a single node has nowhere to send it
whoami = { authenticated: true, username: "admin", email: "", peers: 0 };
await open();
ok(field("propagate") === null, "with no peers, the option is not offered at all");

console.log(fail ? `\n${fail} failed` : "\nthe login can be copied to the other nodes");
process.exit(fail ? 1 : 0);
