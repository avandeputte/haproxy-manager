/* The Statistics page refreshes every five seconds.

   Rebuilding it wholesale made it blink: emptying the container takes
   everything off screen for as long as it takes to build the replacement, and
   takes the table sorting and any text selection with it. What is checked here
   is that a refresh which changes nothing touches nothing, and that one which
   changes a single pool touches only that pool. */
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
globalThis.location = { hash: "#/p:stats" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = () => 0;          // no self-scheduling in a test

let stats = null, traffic = { at: [], series: {} };
globalThis.fetch = async (u) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  const bodies = { stats, traffic };
  return { ok: true, status: 200, json: async () => bodies[path] || {},
           text: async () => "" };
};
const { renderStats } = await import("../../static/js/pages/stats.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const content = document.querySelector("#content");
const cards = () => [...content.children].map(el => el.dataset.card);

const server = (name, scur) => ({
  name, addr: "10.0.0.1:80", status: "UP", lastchg: "10", bck: "0", weight: "1",
  scur: String(scur), smax: "5", stot: "50", qcur: "0", bin: "1", bout: "2",
  check_status: "L7OK", check_code: "200", check_duration: "3",
  chkfail: "0", chkdown: "0", downtime: "0",
});
const snapshot = (shopSessions, blogSessions) => ({
  ok: true,
  frontends: [{ proxy: "fe_https-443", status: "OPEN", scur: "1", smax: "9",
                stot: "99", rate: "2", rate_max: "7", bin: "1", bout: "2",
                dreq: "0", ereq: "0" }],
  backends: [
    { proxy: "be_shop", status: "UP", servers_up: 1, servers_total: 1, algo: "roundrobin",
      scur: String(shopSessions), stot: "10", qcur: "0", bin: "1", bout: "2",
      econ: "0", downtime: "0", servers: [server("web1", shopSessions)] },
    { proxy: "be_blog", status: "UP", servers_up: 1, servers_total: 1, algo: "roundrobin",
      scur: String(blogSessions), stot: "10", qcur: "0", bin: "1", bout: "2",
      econ: "0", downtime: "0", servers: [server("web2", blogSessions)] },
  ],
});

stats = snapshot(1, 1);
await renderStats();
ok(cards().join(",") === "listeners,be:be_shop,be:be_blog",
   "one card per listener and pool: " + cards().join(", "));

// nothing changed
const before = [...content.children];
const beforeHtml = before.map(el => el.innerHTML);
await renderStats();
ok([...content.children].every((el, i) => el === before[i]),
   "a refresh that changes nothing keeps the very same elements");
ok([...content.children].every((el, i) => el.innerHTML === beforeHtml[i]),
   "and their contents");

// one pool changed
stats = snapshot(1, 42);
const shopEl = content.children[1], blogEl = content.children[2];
const shopHtml = shopEl.innerHTML;
await renderStats();
ok(content.children[1] === shopEl && content.children[1].innerHTML === shopHtml,
   "a pool whose figures did not move is not touched");
ok(content.children[2] === blogEl && content.children[2].innerHTML !== shopHtml,
   "the pool that changed is updated in place, not replaced");
ok(/42/.test(content.children[2].innerHTML), "with the new figures");

// a pool appears and another goes away
stats = { ...snapshot(1, 1), backends: [snapshot(1, 1).backends[0],
          { proxy: "be_wiki", status: "UP", servers_up: 1, servers_total: 1,
            algo: "roundrobin", scur: "1", stot: "1", qcur: "0", bin: "1", bout: "2",
            econ: "0", downtime: "0", servers: [server("web3", 1)] }] };
await renderStats();
ok(cards().join(",") === "listeners,be:be_shop,be:be_wiki",
   "a pool that appears is added and one that goes away is removed: " + cards().join(", "));
ok(content.children[1] === shopEl, "and the surviving pool is still the same element");

// the history is only re-read once a minute, not on every refresh
let asked = 0;
globalThis.fetch = async (u) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (path === "traffic") asked++;
  return { ok: true, status: 200, json: async () => ({ stats, traffic }[path] || {}),
           text: async () => "" };
};
await renderStats();
await renderStats();
await renderStats();
ok(asked === 0, "the history is not re-read on every five-second refresh");

console.log(fail ? `\n${fail} failed` : "\nrefreshing touches only what changed");
process.exit(fail ? 1 : 0);
