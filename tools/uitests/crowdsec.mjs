/* The CrowdSec page, from the browser's side: the fields, what Save sends,
 * the install button on a node without the bouncer, and the captcha rows
 * that follow the mode. */
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
globalThis.location = { hash: "#/p:crowdsec" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = () => 0;

let settings = { enabled: false, api_url: "", has_api_key: false, mode: "ban", captcha_provider: "", skip_lists: [],
                 status: { installed: false, version: "", service: "missing", active: false } };
let sent = null, lastPath = null;
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  /* the path that carried a body: a save is followed by a status poll */
  if (o && o.body) { sent = JSON.parse(o.body); lastPath = path; }
  const bodies = {
    "crowdsec/settings": o && o.method === "PUT" ? { ok: true, status: settings.status } : settings,
    "haproxy/addresslists": [{ id: "l1", name: "lan" }],
    "crowdsec/install": { ok: true, message: "installed", status: { installed: true, version: "0.4.0", service: "inactive" } },
    "crowdsec/test": { ok: false, message: "the LAPI did not answer" },
    status: { dirty: false, crowdsec: { on: true, bouncer: "active" }, vips: [], vip_held: [], haproxy: "active", keepalived: "disabled" },
  };
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const { renderCrowdsec } = await import(REPO + "/static/js/pages/crowdsec.js");
const { NAV } = await import(REPO + "/static/js/shell.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const $ = s => document.querySelector(s);
const findButton = (root, label) => [...root.querySelectorAll("button")].find(b => b.textContent === label) || null;

ok(NAV.some(x => x[0] === "p:crowdsec" && x[1] === "CrowdSec"), "CrowdSec is in the menu");
await renderCrowdsec();
const content = $("#content");
ok(content.textContent.includes("bouncer not installed"), "a node without the bouncer says so");
ok(!!findButton(content, "Install on this node"), "and offers to install it");
ok(!!$("#f_enabled") && !!$("#f_api_url") && !!$("#f_api_key") && $("#f_api_key").type === "password",
   "the settings: switch, LAPI URL, a key typed as a password");
const skip = $("#f_skip_lists");
ok(!!skip && [...skip.querySelectorAll("input")].length === 1, "the address lists to never ask about");
const cell = id => $(id).parentNode;
ok(cell("#f_captcha_provider").style.display === "none", "captcha rows are hidden in ban mode");
$("#f_enabled").checked = true;
$("#f_api_url").value = "http://192.168.1.5:8080/";
$("#f_api_key").value = "abc";
[...skip.querySelectorAll("input")][0].checked = true; [...skip.querySelectorAll("input")][0].setAttribute("checked", "");
sent = null;
await findButton(content, "Save").onclick();
ok(lastPath === "crowdsec/settings" && sent.enabled === true && sent.api_url === "http://192.168.1.5:8080/"
   && sent.api_key === "abc" && JSON.stringify(sent.skip_lists) === '["l1"]',
   "Save sends the switch, the URL, the key and the lists");
await findButton(content, "Test the LAPI connection").onclick();
ok(lastPath === "crowdsec/test" && sent.api_url === "http://192.168.1.5:8080/" && content.textContent.includes("not reachable"),
   "the test asks with what is typed and shows the verdict");
await findButton(content, "Install on this node").onclick();
ok(lastPath === "crowdsec/install" && content.textContent.includes("bouncer 0.4.0 installed"),
   "installing redraws the node's state");

console.log(fail ? `\n${fail} failed` : "\nthe page says what the node has and sends what was typed");
process.exit(fail ? 1 : 0);
