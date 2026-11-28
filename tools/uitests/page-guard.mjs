/* A page that awaits the server must not paint once the person has moved on.
 *
 * Save on these pages draws the page again by calling its own renderer, not
 * route(), so nothing serialises it with a navigation: navigate while that
 * render waits for the server and it lands on the page you went to, under or
 * over it. pageGuard() is the answer every other such page uses -- check the
 * hash after each await, and do nothing when it has changed. */
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

/* every answer waits at a gate the test opens, so a render can be caught
   mid-await while the hash changes under it */
let release = () => {};
let gate = Promise.resolve();
const hold = () => { gate = new Promise(r => { release = r; }); };
const bodies = {
  "access/oauth": { enabled: false, redirect_uri: "", unreachable_hosts: [] },
  "cloudflare/settings": { enabled: false, status: {} },
  version: { version: "1.0.0", latest: "", repo: "x/y", ref: "main", beta_ref: "beta", peers: 0 },
  webui: { enabled: false, port: 8080, url: "", shared_url: "", hosts: [], extra_rules: [], address_checks: [] },
};
globalThis.fetch = async (u) => {
  await gate;
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const pages = {
  sso: (await import(REPO + "/static/js/pages/sso.js")).renderSso,
  cloudflare: (await import(REPO + "/static/js/pages/cloudflare.js")).renderCloudflare,
  updates: (await import(REPO + "/static/js/pages/updates.js")).renderUpdates,
  webui: (await import(REPO + "/static/js/pages/webui.js")).renderWebui,
};

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const content = document.querySelector("#content");

for (const [name, render] of Object.entries(pages)) {
  /* drawn in place: the page paints */
  location.hash = "#/p:" + name;
  content.innerHTML = "";
  await render();
  ok(content.children.length > 0, name + ": renders when it is the page on screen");

  /* navigated away while it waited: the page it left for is untouched */
  hold();
  const pending = render();
  location.hash = "#/p:elsewhere";
  content.innerHTML = '<div class="card" id="elsewhere">the page navigated to</div>';
  release();
  await pending;
  ok(content.children.length === 1 && content.querySelector("#elsewhere"),
     name + ": a render overtaken by a navigation paints nothing");
}

console.log(fail ? `\n${fail} failed` : "\nno page paints after the person has moved on");
process.exit(fail ? 1 : 0);
