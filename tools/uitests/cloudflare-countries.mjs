/* A service limited to countries, from the browser's side: the field in the
 * Cloudflare section, the list saying which countries, Edit bringing them
 * back into the form, and what Save sends. */
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
globalThis.location = { hash: "#/p:services" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = () => 0;

const SERVICES = [{
  id: "r1", url: "http://shop.example.com", urls: ["http://shop.example.com"],
  scheme: "http", targets: ["http://10.0.0.5:80"], pool: "shop", enabled: true,
  health: { type: "http" },
  cloudflare: { enabled: true, access: "public", allow: "", only: true, countries: "US CA" },
}];

let sent = null;
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) sent = JSON.parse(o.body);
  const bodies = {
    services: SERVICES, traffic: { at: [], series: {} },
    "access/groups": [], "acme/accounts": [], "acme/challenges": [],
    recipes: { ok: true, recipes: [] },
    "wizard/publish": { ok: true, actions: [], warnings: [], preview: "" },
  };
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const { servicesCard, WIZ_SECTIONS } = await import(REPO + "/static/js/pages/services.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };

const sec = WIZ_SECTIONS.find(s => s.title === "Cloudflare");
const keys = sec.fields.map(f => f.k);
ok(keys.includes("cf_countries") && keys.indexOf("cf_countries") < keys.indexOf("cf_only"),
   "the Cloudflare section has the countries field, before Through Cloudflare only");
ok(/Zone WAF: Edit/.test(sec.fields.find(f => f.k === "cf_countries").h),
   "its hint names the token right it needs");

const card = await servicesCard();
ok(card.textContent.includes("through Cloudflare") && card.textContent.includes("from US CA only"),
   "the list says the service is reached through Cloudflare from those countries only");

const edit = [...card.querySelectorAll("button")].find(b => b.textContent === "Edit");
edit.onclick ? await edit.onclick() : edit.click();
await new Promise(r => queueMicrotask(r));
const field = document.querySelector("#f_cf_countries");
ok(field && field.value === "US CA", "Edit brings the countries back into the form");
field.value = "us gb";
const pub = [...document.querySelectorAll("button")].find(b => /^(Publish|Save)/.test(b.textContent));
pub.click();
await new Promise(r => queueMicrotask(r));
ok(sent && sent.cloudflare && sent.cloudflare.countries === "us gb" && sent.cloudflare.only === true,
   "Save sends what was typed inside the cloudflare object, beside the rest of it");
ok(!("cf_countries" in sent), "and not as a loose field");

console.log(fail ? `\n${fail} failed` : "\nthe form says where a service may be reached from, and sends it");
process.exit(fail ? 1 : 0);
