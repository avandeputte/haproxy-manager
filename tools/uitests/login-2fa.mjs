/* The login screen's second step must survive the background pollers.
 *
 * After a session expires, the 10-second status tick keeps firing, every
 * tick gets a 401, and every 401 calls showLogin(). Re-initialising a form
 * that is already on screen hid the code field and wiped the code being
 * typed -- which read as the field "timing out" by itself, mid-sign-in.
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
<div id="lp2wrap" hidden><input id="lp2"></div>
<div id="lcodewrap" hidden><input id="lcode"></div>
<div id="lerr"></div>
<button id="lbtn"></button><h2 id="logintitle"></h2><p id="loginintro"></p></form></div>
<div id="content"></div></body></html>`);
globalThis.document = document; globalThis.window = window;
globalThis.location = { hash: "#/", host: "node1:8080" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
let cleared = [];
globalThis.setTimeout = (fn, ms) => 91;
globalThis.setInterval = (fn, ms) => 17;
globalThis.clearInterval = (id) => cleared.push(["interval", id]);
globalThis.clearTimeout = (id) => cleared.push(["timeout", id]);
globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({}), text: async () => "" });

const { showLogin } = await import(REPO + "/static/js/auth.js");
const { state } = await import(REPO + "/static/js/state.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };

// the login screen comes up; the person enters the password; the server asks
// for the second factor and the code field is revealed
showLogin(false);
ok(document.querySelector("#lcodewrap").hasAttribute("hidden"),
   "the code field starts hidden");
document.querySelector("#lcodewrap").removeAttribute("hidden");
document.querySelector("#lcode").value = "123";       // half-typed
document.querySelector("#lu").value = "alex";
document.querySelector("#lp").value = "hunter2secret";

// ...and a background poller's 401 lands
state.ticker = 17; state.pageTimer = 91;
showLogin();
ok(!document.querySelector("#lcodewrap").hasAttribute("hidden"),
   "a 401 from a background poll does not hide the code field");
ok(document.querySelector("#lcode").value === "123",
   "nor wipe the half-typed code");
ok(document.querySelector("#lp").value === "hunter2secret",
   "nor the password waiting to be resubmitted with it");
ok(state.ticker === null && cleared.some(c => c[0] === "interval"),
   "and the status ticker is stopped -- a login screen has nothing to poll");
ok(state.pageTimer === null && cleared.some(c => c[0] === "timeout"),
   "along with any page refresh timer");

// signing out shows the form fresh -- the guard is only for an already-open one
document.querySelector("#login").classList.remove("show");
showLogin(false);
ok(document.querySelector("#lcodewrap").hasAttribute("hidden"),
   "a login screen opened anew still starts at step one");

console.log(fail ? `\n${fail} failed` : "\nthe second step survives the pollers");
process.exit(fail ? 1 : 0);
