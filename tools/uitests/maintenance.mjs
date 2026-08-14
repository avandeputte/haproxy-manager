/* Pausing a service from the Services page.
 *
 * The table has to say a service is paused, the button has to read the other
 * way around from the state, and clicking it has to send the opposite of what
 * is -- none of which is visible from the API tests, which never execute the
 * page.
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
globalThis.confirm = () => true;

const SERVICES = [
  { id: "r1", url: "https://shop.example.com", urls: ["https://shop.example.com"],
    scheme: "https", targets: ["http://10.0.0.5:80"], pool: "shop", enabled: true,
    health: { type: "http" }, maintenance: false },
  { id: "r2", url: "https://wiki.example.com", urls: ["https://wiki.example.com"],
    scheme: "https", targets: ["http://10.0.0.6:80"], pool: "wiki", enabled: true,
    health: { type: "http" }, maintenance: true },
];

const calls = [];
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.method === "POST") calls.push([path, JSON.parse(o.body)]);
  const bodies = { services: SERVICES, traffic: { at: [], series: {} } };
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const { E } = await import(REPO + "/static/js/entities.js");
const { servicesCard } = await import(REPO + "/static/js/pages/services.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const buttons = (row) => [...row.querySelectorAll("button")].map(b => b.textContent);

const card = await servicesCard();
const rows = [...card.querySelectorAll("tbody tr")];
ok(rows.length === 2, "both services are listed");
ok(!rows[0].textContent.includes("paused") && rows[0].textContent.includes("shop"),
   "a running service carries no paused pill");
ok(rows[1].textContent.includes("paused") && rows[1].textContent.includes("503"),
   "a paused one says so, and says what callers get");
ok(buttons(rows[0]).includes("Pause") && !buttons(rows[0]).includes("Resume"),
   "a running service offers Pause");
ok(buttons(rows[1]).includes("Resume") && !buttons(rows[1]).includes("Pause"),
   "and a paused one offers Resume");

// clicking sends the opposite of the current state, to the right service
[...rows[0].querySelectorAll("button")].find(b => b.textContent === "Pause").click();
await new Promise(r => queueMicrotask(r));
ok(calls.some(([p, b]) => p === "services/r1/maintenance" && b.on === true),
   "Pause asks the API to pause that service");
[...rows[1].querySelectorAll("button")].find(b => b.textContent === "Resume").click();
await new Promise(r => queueMicrotask(r));
ok(calls.some(([p, b]) => p === "services/r2/maintenance" && b.on === false),
   "Resume asks it to resume");

// the pool editor can do the same from the Advanced page
ok(E["haproxy/backends"].fields.some(f => f.k === "maintenance" && f.t === "bool"),
   "the pool editor carries the maintenance switch too");

console.log(fail ? `\n${fail} failed` : "\npausing reads and writes the right way around");
process.exit(fail ? 1 : 0);
