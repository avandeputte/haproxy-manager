/* What a large installation sends to the browser, from the browser's side.
 *
 * The API tests check that a narrower traffic answer and a brief status
 * exist; this checks the pages ask for them, and draw the right numbers from
 * what comes back. The sparkline is drawn from buckets, so the count beside it
 * has to come from the server's totals -- a page that summed the points would
 * quietly show a fraction of the day's requests. And the Cluster page has a
 * new thing to say when the configuration is too big to compare object by
 * object, which must not be mistaken for nodes on different versions.
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

const asked = [];
let bodies = {};
globalThis.fetch = async (u) => {
  const full = String(u).replace(/^\/api\//, "");
  asked.push(full);
  const path = full.split("?")[0];
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const { servicesCard } = await import(REPO + "/static/js/pages/services.js");
const { renderStats } = await import(REPO + "/static/js/pages/stats.js");
const { clusterCard } = await import(REPO + "/static/js/pages/cluster.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const labels = html => [...html.matchAll(/aria-label="([^"]*)"/g)].map(m => m[1]);

// -- the Services page ---------------------------------------------------------
const SERVICES = [
  { id: "r1", url: "https://shop.example.com", urls: ["https://shop.example.com"],
    scheme: "https", targets: ["http://10.0.0.5:80"], pool: "shop", enabled: true,
    health: { type: "http" }, maintenance: false },
];
// three points standing for a day: the busiest minute of each bucket
const TRAFFIC = { at: [1000, 1840, 2680], bucket: 840,
                  series: { be_shop: { req: [1, 2, 3], e5: [0, 0, 1] } },
                  totals: { be_shop: { req: 500, e5: 7 } } };
bodies = { services: SERVICES, traffic: TRAFFIC };
let card = await servicesCard();
ok(asked.includes("traffic?series=req,e5&points=110"),
   "the Services page asks for the two lines it draws, about a point a pixel");
let seen = labels(card.innerHTML);
ok(seen.includes("500 requests") && seen.includes("7 server errors"),
   "the counts beside the line are the day's totals, not the sum of the points: " + seen.join(" / "));

bodies = { services: SERVICES, traffic: { at: TRAFFIC.at, series: TRAFFIC.series } };
card = await servicesCard();
seen = labels(card.innerHTML);
ok(seen.includes("6 requests") && seen.includes("1 server errors"),
   "without totals (an older node mid-upgrade), the points are summed as before: " + seen.join(" / "));

// -- the Statistics page -------------------------------------------------------
const server = (name) => ({
  name, addr: "10.0.0.1:80", status: "UP", lastchg: "10", bck: "0", weight: "1",
  scur: "1", smax: "5", stot: "50", qcur: "0", bin: "1", bout: "2",
  check_status: "L7OK", check_code: "200", check_duration: "3",
  chkfail: "0", chkdown: "0", downtime: "0",
});
const STATS = {
  ok: true,
  frontends: [{ proxy: "fe_https-443", status: "OPEN", scur: "1", smax: "9",
                stot: "99", rate: "2", rate_max: "7", bin: "1", bout: "2",
                dreq: "0", ereq: "0" }],
  backends: [
    { proxy: "be_shop", status: "UP", servers_up: 1, servers_total: 1, algo: "roundrobin",
      scur: "1", stot: "10", qcur: "0", bin: "1", bout: "2",
      econ: "0", downtime: "0", servers: [server("web1")] },
  ],
};
globalThis.location = { hash: "#/p:stats" };
bodies = { stats: STATS, traffic: TRAFFIC };
asked.length = 0;
await renderStats();
ok(asked.includes("traffic?series=req,e5&points=220"),
   "the Statistics page asks the same way, wider");
const content = document.querySelector("#content");
const trafficCard = [...content.children].find(el => el.dataset.card === "traffic");
ok(!!trafficCard, "and draws the traffic card from it");
const cells = trafficCard ? [...trafficCard.querySelectorAll("tbody td")].map(td => td.textContent.trim()) : [];
ok(cells.some(c => c === "500") && cells.some(c => c === "7"),
   "its Requests and Server errors columns show the totals: " + cells.join(" | "));
ok(cells.some(c => /^3\b/.test(c)),
   "and the busiest minute is the highest point, which the buckets keep: " + cells.join(" | "));

// -- the Cluster page ----------------------------------------------------------
const node = (name, objects, extra) => Object.assign({
  name, hostname: name, reachable: true, url: "http://" + name + ":8080",
  role: "active", haproxy: "active", keepalived: "active", vips: [], vip_held: [],
  certs_total: 0, certs_bad: 0, version: "1.100.2", config_rev: 4,
  config_fp: name.slice(0, 8), config_objects: objects, config_parts: {},
}, extra || {});
const render = async (nodes) => {
  bodies = { cluster: { ok: true, nodes, live: true, age_seconds: 0,
                        summary: { total: nodes.length, reachable: nodes.length, active: 1,
                                   warnings: [], config_rev: 4, config_agreed: false,
                                   config_behind: [], config_differs_in: " -- they differ in haproxy.backends" } } };
  globalThis.location = { hash: "#/p:cluster" };
  return (await clusterCard()).textContent;
};
asked.length = 0;
let text = await render([node("proxy1", {}, { config_objects_capped: true }),
                         node("proxy2", {}, { config_objects_capped: true })]);
ok(!asked.some(u => /^status(\?|$)/.test(u) && u !== "status?brief=1"),
   "nothing on the Cluster page asks for the full status");
ok(/more objects than the nodes list one by one/.test(text),
   "over the cap, it says the configuration is too big to compare object by object");
ok(!/not all on the same version/.test(text),
   "and does not blame the versions for it");
text = await render([node("proxy1", {}), node("proxy2", {})]);
ok(/not all on the same version/.test(text) && !/more objects/.test(text),
   "a node that simply reports nothing is still read as an older version");

// -- the ten-second poll -------------------------------------------------------
// Every open tab asks for the status every ten seconds. Checked at the source:
// the ticker lives in the shell, which draws the whole page to import, and
// what matters is that no page anywhere still asks for the full form.
const { readFileSync, readdirSync } = await import("node:fs");
const js = dir => readdirSync(dir).filter(f => f.endsWith(".js"))
  .map(f => ({ f, s: readFileSync(dir + "/" + f, "utf8") }));
const sources = [...js(REPO + "/static/js"), ...js(REPO + "/static/js/pages")];
const fullForm = sources.filter(x => /api\("status"\)/.test(x.s)).map(x => x.f);
ok(!fullForm.length, "no page asks for the full status: " + (fullForm.join(", ") || "none"));
const shell = sources.find(x => x.f === "shell.js").s;
ok(/setInterval\(refreshStatus/.test(shell) && /api\("status\?brief=1"\)/.test(shell),
   "and the ten-second poll asks briefly");

console.log(fail ? `\n${fail} failed` : "\nthe pages ask for less and show the same");
process.exit(fail ? 1 : 0);
