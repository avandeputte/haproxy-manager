/* What the nodes disagree about.

   The first version of this said "they differ in haproxy.backends" and left
   the reader to compare two configurations by hand, which is no better than
   saying nothing. It has to name the object and say which node is the odd one
   out. */
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

let snapshot = null;
globalThis.fetch = async (u) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  const bodies = { cluster: snapshot };
  return { ok: true, status: 200, json: async () => bodies[path] || {},
           text: async () => "" };
};
const { clusterCard } = await import("../../static/js/pages/cluster.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };

const node = (name, objects, parts) => ({
  name, hostname: name, reachable: true, url: "http://" + name + ":8080",
  role: "active", haproxy: "active", keepalived: "active", vips: [], vip_held: [],
  certs_total: 0, certs_bad: 0, version: "1.65.0", config_rev: 4,
  config_fp: JSON.stringify(objects).slice(0, 8),
  config_objects: objects, config_parts: parts || {},
});

const render = async (nodes, agreed) => {
  snapshot = { ok: true, nodes, live: true, age_seconds: 0,
               summary: { total: nodes.length, reachable: nodes.length, active: 1,
                          warnings: [], config_rev: 4, config_agreed: agreed,
                          config_behind: [], config_differs_in: "" } };
  const card = await clusterCard();
  return card.textContent;
};

// an object one node has and another does not
let text = await render([
  node("proxy1", { "haproxy.backends": [["b1", "shop", "aaa"], ["b2", "blog", "bbb"]] }),
  node("proxy2", { "haproxy.backends": [["b1", "shop", "aaa"]] }),
], false);
ok(/What differs/.test(text), "it says what differs, not that something does");
ok(/blog/.test(text), "it names the object: blog");
ok(/only on proxy1/.test(text), "and where it is");
ok(/missing from proxy2/.test(text), "and where it is not");
ok(!/shop/.test(text), "the objects that match are not listed");

// the same object, different contents
text = await render([
  node("proxy1", { "acme.certificates": [["c1", "wildcard", "aaa"]] }),
  node("proxy2", { "acme.certificates": [["c1", "wildcard", "zzz"]] }),
  node("proxy3", { "acme.certificates": [["c1", "wildcard", "aaa"]] }),
], false);
ok(/wildcard/.test(text), "an object that exists everywhere but differs is named");
ok(/different contents/.test(text), "and the problem is stated");
ok(/proxy1 \+ proxy3/.test(text) && /proxy2/.test(text),
   "with the nodes grouped by what they hold, so the odd one out is obvious");

// settings have no id and are compared whole
text = await render([
  node("proxy1", { "haproxy.backends": [] }, { "haproxy.settings": "aaa" }),
  node("proxy2", { "haproxy.backends": [] }, { "haproxy.settings": "bbb" }),
], false);
ok(/haproxy.settings/.test(text), "settings are compared too, whole");

// everything matches but the page was told they differ
text = await render([
  node("proxy1", { "haproxy.backends": [["b1", "shop", "aaa"]] }),
  node("proxy2", { "haproxy.backends": [["b1", "shop", "aaa"]] }),
], false);
ok(/Every shared object matches/.test(text),
   "when every object matches it says so rather than showing an empty table");
ok(/Refresh/.test(text), "and says what to do about it");

// a node on an older version reports nothing to compare
text = await render([
  node("proxy1", { "haproxy.backends": [["b1", "shop", "aaa"]] }),
  { name: "proxy2", hostname: "proxy2", reachable: true, url: "", role: "passive",
    haproxy: "active", keepalived: "active", vips: [], vip_held: [], certs_total: 0,
    certs_bad: 0, version: "1.60.0", config_rev: 0, config_fp: "" },
], false);
ok(/not all on the same version/.test(text),
   "a node that reports nothing is explained, not silently ignored");

// and none of this appears when they agree
text = await render([
  node("proxy1", { "haproxy.backends": [["b1", "shop", "aaa"]] }),
  node("proxy2", { "haproxy.backends": [["b1", "shop", "aaa"]] }),
], true);
ok(!/What differs/.test(text) && !/Every shared object matches/.test(text),
   "nothing is shown at all when the nodes agree");

console.log(fail ? `\n${fail} failed` : "\nthe page names what differs and who has it");
process.exit(fail ? 1 : 0);
