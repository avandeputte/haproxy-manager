/* Every value a record carries is written into a table cell as text, never as
   markup. Two cells -- a pool's balance algorithm and a monitor's interval --
   were once written raw, so a value saved through the API as <img onerror=...>
   became an element on the page of whoever opened the list. Under a real DOM
   the check is simple: render the list and look for the element. */
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
globalThis.location = { hash: "#/haproxy/backends" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = () => 0;

/* The payload is a tag with an event handler, which is what an attacker
   would plant; the marker element says whether it was parsed as markup. */
const PAYLOAD = '<img src=x onerror="document.body.dataset.pwned=1">';
const bodies = {
  "haproxy/backends": [{ id: "b1", name: "shop", mode: "http", balance: PAYLOAD, servers: [],
                         healthcheck_enabled: false }],
  "haproxy/healthchecks": [{ id: "h1", name: "ping", type: "tcp", interval: PAYLOAD }],
  "haproxy/servers": [], "access/groups": [], "haproxy/addresslists": [],
  "haproxy/errorpages": [], "haproxy/rules": [], "haproxy/conditions": [],
};
globalThis.fetch = async (u) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  return { ok: true, status: 200, json: async () => bodies[path] || [], text: async () => "" };
};
const { renderEntity } = await import("../../static/js/entities.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const content = document.querySelector("#content");

await renderEntity("haproxy/backends");
ok(content.querySelectorAll("img").length === 0, "a pool's balance value does not become an element");
ok(content.textContent.includes("<img"), "and is shown as the text it is");

await renderEntity("haproxy/healthchecks");
ok(content.querySelectorAll("img").length === 0, "a monitor's interval value does not become an element");
ok(content.textContent.includes("<img"), "and is shown as the text it is");

/* The log view writes the level and the source into class attributes; both
   are the parser's words, but a cell is a cell. */
bodies["logs"] = { entries: [{ ts: "2026-01-01T00:00:00+00:00", source: 'x" onmouseover="1', level: "INFO", text: "hello" }], failed: [] };
globalThis.location = { hash: "#/p:logs" };
/* linkedom's <select> has no value setter; the page assigns one, as a browser allows */
const sel = window.HTMLSelectElement && window.HTMLSelectElement.prototype;
if (sel) Object.defineProperty(sel, "value", { configurable: true, get() { return this._v || ""; }, set(v) { this._v = v; } });
const { renderLogs } = await import("../../static/js/pages/logs.js");
await renderLogs();
const cell = content.querySelector(".logview td.s") || content.querySelector("td.s");
ok(cell && !cell.hasAttribute("onmouseover"), "a log line's source cannot add an attribute to its cell");

process.exit(fail ? 1 : 0);
