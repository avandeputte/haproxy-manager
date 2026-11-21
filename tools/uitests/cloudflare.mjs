/* The Cloudflare page, from the browser's side: the fields, what Save sends,
 * the install button on a node without cloudflared, and the buttons that
 * only a connected tunnel has. */
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
globalThis.location = { hash: "#/p:cloudflare" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = () => 0;

globalThis.confirm = () => true;
let settings = { enabled: false, has_api_token: false, account_id: "", tunnel_name: "haproxy-manager", tunnel_id: "", origin_port: 7811,
                 status: { installed: false, version: "", service: "missing", connected: false, configured: false, hosts: [], in_step: true } };
const connected = { installed: true, version: "2026.11.1", service: "active", connected: true, configured: true,
                    hosts: ["shop.example.com"], in_step: false };
let sent = null, lastPath = null;
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) { sent = JSON.parse(o.body); lastPath = path; }
  const bodies = {
    "cloudflare/settings": o && o.method === "PUT" ? { ok: true, status: connected } : settings,
    "cloudflare/install": { ok: true, message: "installed", status: { installed: true, version: "2026.11.1", service: "inactive", hosts: [], in_step: true } },
    "cloudflare/test": { ok: true, message: "the token works: it can manage tunnels, and sees 1 zone(s)" },
    "cloudflare/sync": { ok: true, message: "cloudflare: DNS record for shop.example.com", status: Object.assign({}, connected, { in_step: true }) },
    "cloudflare/disconnect": { ok: true, message: "cloudflare: tunnel \"haproxy-manager\" deleted" },
    status: { dirty: false, crowdsec: { on: false }, cloudflare: { on: true, connector: "active" }, vips: [], vip_held: [], haproxy: "active", keepalived: "disabled" },
  };
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const { renderCloudflare } = await import(REPO + "/static/js/pages/cloudflare.js");
const { NAV } = await import(REPO + "/static/js/shell.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const $ = s => document.querySelector(s);
const findButton = (root, label) => [...root.querySelectorAll("button")].find(b => b.textContent === label) || null;

ok(NAV.some(x => x[0] === "p:cloudflare" && x[1] === "Cloudflare"), "Cloudflare is in the menu, under Access");
await renderCloudflare();
const content = $("#content");
ok(content.textContent.includes("beta"), "the page says it is a beta");
ok(content.textContent.includes("cloudflared not installed") && !!findButton(content, "Install on this node"),
   "a node without cloudflared says so and offers to install it");
ok(content.textContent.includes("not connected"), "and that no tunnel is connected yet");
ok(!!$("#f_enabled") && !!$("#f_api_token") && $("#f_api_token").type === "password" && $("#f_tunnel_name").value === "haproxy-manager"
   && String($("#f_origin_port").value) === "7811",
   "the settings: switch, a token typed as a password, the tunnel's name and the first loopback port");
ok(!findButton(content, "Sync now") && !findButton(content, "Disconnect"), "nothing to sync or disconnect before a tunnel exists");
await findButton(content, "Install on this node").onclick();
ok(lastPath === "cloudflare/install" && content.textContent.includes("cloudflared 2026.11.1 installed"), "installing redraws the node's state");
$("#f_enabled").checked = true;
$("#f_api_token").value = "tok";
await findButton(content, "Test the token").onclick();
ok(lastPath === "cloudflare/test" && sent.api_token === "tok" && Object.keys(sent).length === 2
   && content.textContent.includes("the token works") && content.querySelector(".pill.up") !== null,
   "the test asks with the token that is typed and shows the verdict");
sent = null;
await findButton(content, "Save").onclick();
ok(lastPath === "cloudflare/settings" && sent.enabled === true && sent.api_token === "tok" && sent.tunnel_name === "haproxy-manager",
   "Save sends the switch, the token and the tunnel's name");
ok(content.textContent.includes("connected, 1 host name(s) published") && content.textContent.includes("shop.example.com")
   && content.textContent.includes("Cloudflare is behind"),
   "saving redraws the tunnel: connected, what is published, and that Cloudflare has yet to be told");

settings = Object.assign({}, settings, { enabled: true, has_api_token: true, status: connected });
await renderCloudflare();
ok(!findButton(content, "Install on this node") && content.textContent.includes("cloudflared 2026.11.1 installed"),
   "a node with cloudflared shows its version and no install button");
ok(!!findButton(content, "Sync now") && !!findButton(content, "Disconnect"), "a connected tunnel can be synced and disconnected");
await findButton(content, "Sync now").onclick();
ok(lastPath === "cloudflare/sync" && !content.textContent.includes("Cloudflare is behind"), "Sync now tells Cloudflare and redraws: no longer behind");
await findButton(content, "Disconnect").onclick();
ok(lastPath === "cloudflare/disconnect", "Disconnect asks first, then takes the tunnel away");

console.log(fail ? `\n${fail} failed` : "\nthe page says what the node and the tunnel are doing, and sends what was typed");
process.exit(fail ? 1 : 0);
