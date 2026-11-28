/* Editing a service must send the redirect as it is, not as the form's default.
 *
 * The HTTP-to-HTTPS redirect is one checkbox on the publish form, on by
 * default. Edit refilled every other field from the service and left this one
 * at its default, so saving any HTTPS service -- to change a timeout, say --
 * asked for the redirect again and turned back on what had been turned off.
 * The list now reports the redirect, Edit shows it, and Save sends it. */
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

const service = (redirect) => ({
  id: "r1", url: "https://app.example.com", urls: ["https://app.example.com"],
  scheme: "https", targets: ["http://10.0.0.5:8080"], pool: "app", enabled: true,
  health: { type: "http" }, http_redirect: redirect,
});
let services = [service(false)];
let sent = null;
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body) sent = JSON.parse(o.body);
  const bodies = {
    services, traffic: { at: [], series: {} },
    "access/groups": [], "acme/accounts": [], "acme/challenges": [],
    recipes: { ok: true, recipes: [] },
    "acme/cover": { covered: false },
    "wizard/publish": { ok: true, actions: [], warnings: [], preview: "" },
  };
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const { servicesCard, openWizard } = await import(REPO + "/static/js/pages/services.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const settle = () => new Promise(r => queueMicrotask(r));

async function editAndSave() {
  const card = await servicesCard();
  const edit = [...card.querySelectorAll("button")].find(b => b.textContent === "Edit");
  edit.onclick ? await edit.onclick() : edit.click();
  await settle();
  const box = document.querySelector("#f_http_redirect");
  const pub = [...document.querySelectorAll("#dlgfoot button")].find(b => b.textContent === "Publish");
  sent = null;
  await pub.onclick();
  await settle();
  return { box, sent };
}

/* a new service: the default still stands */
openWizard();
ok(document.querySelector("#f_http_redirect").checked === true, "publishing anew offers the redirect, on");

/* the redirect was turned off: Edit shows it off, Save sends it off */
let r = await editAndSave();
ok(r.box && r.box.checked === false, "Edit shows the redirect as it is: off");
ok(r.sent && r.sent.http_redirect === false, "and Save sends it off, so the edit does not turn it back on");
ok(r.sent && r.sent.service_id === "r1", "as an edit of that service");

/* it is on: Edit shows it on, Save sends it on */
services = [service(true)];
r = await editAndSave();
ok(r.box && r.box.checked === true, "a service whose redirect is on shows it on");
ok(r.sent && r.sent.http_redirect === true, "and Save sends it on");

console.log(fail ? `\n${fail} failed` : "\nan edit sends the redirect as it stands");
process.exit(fail ? 1 : 0);
