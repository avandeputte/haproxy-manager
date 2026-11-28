/* The field lists live twice -- once in the browser, once on the server --
 * and nothing joined them until now. A field the form sends that the server
 * never reads is a setting that silently does nothing; a value the server
 * reports that the Edit form never refills is a setting that silently resets
 * to its default when the service is saved for some other reason, which is
 * how the HTTP-to-HTTPS redirect kept turning itself back on.
 *
 * Nothing moves: both copies are read where they are and compared. */
import fs from "node:fs";
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

/* The body is caught before it is serialised: linkedom's <select> reports no
   value, and JSON leaves out a key whose value is undefined, so the keys are
   read off the object the form built rather than off the wire. */
let sent = null;
const stringify = JSON.stringify;
JSON.stringify = (v, ...rest) => { if (v && typeof v === "object" && "url" in v) sent = v; return stringify(v, ...rest); };
globalThis.fetch = async () =>
  ({ ok: true, status: 200, json: async () => ({ ok: true, actions: [], warnings: [], recipes: [] }), text: async () => "" });
const read = (p) => fs.readFileSync(REPO + "/" + p, "utf8");
/* the body keys a Flask handler reads: body.get("k"), body["k"], "k" in body */
const bodyKeys = (py) => new Set([...py.matchAll(/body(?:\.get\(|\[)"(\w+)"|"(\w+)" in body/g)].map(m => m[1] || m[2]));
/* one handler's text, from its decorator to the next route */
const handler = (py, route) => {
  const at = py.indexOf(route);
  const rest = py.slice(at);
  const next = rest.slice(1).search(/^@app\./m);
  return next < 0 ? rest : rest.slice(0, next + 1);
};

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const diff = (a, b) => [...a].filter(x => !b.has(x));

/* ---- the publish form against POST /api/wizard/publish ---- */
const { openWizard, WIZ_FIELDS } = await import(REPO + "/static/js/pages/services.js");
openWizard();
document.querySelector("#f_url").value = "https://app.example.com";
document.querySelector("#f_target").value = "10.0.0.5:8080";
const preview = () => [...document.querySelectorAll("#dlgfoot button")].find(b => b.textContent === "Preview").onclick();
await preview();
const clientSends = new Set(Object.keys(sent));
/* a redirect is sent only when the service is one */
[...document.querySelector("#f_action").options].forEach(o => { o.selected = o.value === "redirect"; });
await preview();
Object.keys(sent).forEach(k => clientSends.add(k));
const publish = bodyKeys(handler(read("ham/recipes.py"), '@app.post("/api/wizard/publish")'));
/* keys the form only sends when editing, or that the server derives */
["service_id", "certificate_id"].forEach(k => clientSends.add(k));
ok(diff(clientSends, publish).length === 0,
   "every field the publish form sends is read by the server: " + (diff(clientSends, publish).join(", ") || "all of them"));
ok(diff(publish, clientSends).length === 0,
   "and every field the server reads, the form sends: " + (diff(publish, clientSends).join(", ") || "all of them"));

/* ---- what the Edit button refills against what GET /api/services reports ---- */
const services = read("static/js/pages/services.js");
const editBlock = services.slice(services.indexOf("openWizard({"), services.indexOf("})));", services.indexOf("openWizard({")));
const prefilled = new Set([...editBlock.matchAll(/\bs\.(\w+)/g)].map(m => m[1]));
const reported = new Set([...handler(read("ham/webui.py"), '@app.get("/api/services")').matchAll(/"(\w+)":/g)].map(m => m[1]));
const missing = diff(prefilled, reported);
ok(missing.length === 0,
   "every value the Edit button refills comes back from GET /api/services: " + (missing.join(", ") || "all of them"));
/* and the wizard's own top-level fields are all either refilled or derived (the checkboxes that only open a section) */
const derived = new Set(["health_enabled", "allow_enabled", "rate_enabled", "cert_mode", "apply", "account", "challenge", "url"]);
const refilled = new Set([...editBlock.matchAll(/[,{\n]\s*(\w+):(?!\/)/g)].map(m => m[1]));
const notRefilled = WIZ_FIELDS.map(f => f.k).filter(k => !refilled.has(k) && !derived.has(k));
ok(notRefilled.length === 0,
   "every field on the form is refilled by Edit, bar the ones that only open a section or choose a certificate: "
   + (notRefilled.join(", ") || "all of them"));

/* ---- the Web UI access form against POST /api/webui ---- */
const { WEBUI_FIELDS } = await import(REPO + "/static/js/pages/webui.js");
const webuiSends = new Set(WEBUI_FIELDS.map(f => f.k));
const webui = bodyKeys(handler(read("ham/webui.py"), '@app.post("/api/webui")'));
ok(diff(webuiSends, webui).length === 0,
   "every field the Web UI access form sends is read: " + (diff(webuiSends, webui).join(", ") || "all of them"));
ok(diff(webui, webuiSends).length === 0,
   "and nothing is read that the form does not send: " + (diff(webui, webuiSends).join(", ") || "nothing"));

/* ---- the AD CS account fields against ham/adcs.py ---- */
const { ADCS_FIELDS } = await import(REPO + "/static/js/core.js");
const adcsJs = new Set(ADCS_FIELDS.map(f => f.k));
const adcsPy = read("ham/adcs.py");
const fieldsBlock = adcsPy.slice(adcsPy.indexOf("\nFIELDS = {"), adcsPy.indexOf("}", adcsPy.indexOf("\nFIELDS = {")));
const adcsServer = new Set([...fieldsBlock.matchAll(/"(adcs_\w+)":/g)].map(m => m[1]));
ok(adcsServer.size > 5 && diff(adcsJs, adcsServer).length === 0 && diff(adcsServer, adcsJs).length === 0,
   "the AD CS account fields are the same list in core.js and adcs.py: "
   + ([...diff(adcsJs, adcsServer), ...diff(adcsServer, adcsJs)].join(", ") || "they match"));
/* and the defaults agree where both sides state one */
const defaultsOff = ADCS_FIELDS.filter(f => f.d !== undefined).filter(f => {
  const m = fieldsBlock.match(new RegExp('"' + f.k + '": "([^"]*)"'));
  return m && m[1] !== "" && m[1] !== String(f.d);
}).map(f => f.k);
ok(defaultsOff.length === 0, "and their defaults agree: " + (defaultsOff.join(", ") || "they do"));

console.log(fail ? `\n${fail} failed` : "\nthe two copies of every field list agree");
process.exit(fail ? 1 : 0);
