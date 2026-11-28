/* A page asks the server for what it needs together, and for each thing once.
 *
 * The Overview drew its cluster card and waited for it before asking for the
 * services card, so the page took two round trips in a row where one would
 * do. And a reference list two cards both need was fetched twice. The fetch
 * stub here holds every answer at a gate, so what was asked for before
 * anything was answered is exactly what was asked for in parallel. */
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
globalThis.location = { hash: "" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = () => 0;

const node = { id: "self", name: "n1", hostname: "n1", self: true, reachable: true, role: "standalone",
               haproxy: "active", keepalived: "disabled", vips: [], vip_held: [], dirty: false,
               certs_total: 0, certs_bad: 0, version: "1.0.0", update_available: false, url: "", ms: 0 };
const bodies = {
  status: { haproxy: "active", keepalived: "disabled", vips: [], vip_held: [], dirty: false, certs: [],
            renewal_note: "", role: "standalone", hostname: "n1", version: "1.0.0" },
  cluster: { ok: true, live: true, age_seconds: 0, nodes: [node],
             summary: { active: 0, reachable: 1, total: 1, warnings: [] } },
  services: [], traffic: { at: [], series: {} }, probes: { results: [] },
};
let release = () => {};
let gate = Promise.resolve();
const hold = () => { gate = new Promise(r => { release = r; }); };
let asked = [];
globalThis.fetch = async (u) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  asked.push(path);
  await gate;
  return { ok: true, status: 200, json: async () => bodies[path] ?? [], text: async () => "" };
};

const { list, lists } = await import(REPO + "/static/js/core.js");
const { renderOverview } = await import(REPO + "/static/js/pages/overview.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const settle = () => new Promise(r => setImmediate(r));

/* the Overview: the status first (it decides the page), then both cards together */
hold();
const drawing = renderOverview();
await settle();
ok(asked.join() === "status", "the Overview reads the status before anything else: " + asked.join(", "));
release(); hold();
await settle();
ok(asked.includes("cluster") && asked.includes("services"),
   "the cluster card and the services card are asked for together, not one after the other: "
   + asked.slice(1).join(", "));
release();
await drawing;
const heads = [...document.querySelectorAll("#content .card h2")].map(h => h.textContent);
ok(heads.join() === "Cluster,Services,Certificates", "and the cards appear in their order: " + heads.join(", "));

/* a list asked for twice while in flight is read once */
asked = []; hold();
const both = Promise.all([list("haproxy/servers", true), list("haproxy/servers", true)]);
await settle();
ok(asked.filter(p => p === "haproxy/servers").length === 1, "two concurrent asks for one list are one request");
release();
const [a, b] = await both;
ok(a === b && lists["haproxy/servers"] === a, "and both get the same answer, which the cache then holds");
asked = [];
await list("haproxy/servers");
ok(asked.length === 0, "a cached list is not read again unless asked fresh");
await list("haproxy/servers", true);
ok(asked.length === 1, "asked fresh, it is");

console.log(fail ? `\n${fail} failed` : "\nthe pages ask together, and once");
process.exit(fail ? 1 : 0);
