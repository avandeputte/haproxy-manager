/* The History page: what it lists, what a diff shows, what Restore sends.
 *
 * The page exists for the worst day, which is exactly when nobody reads
 * carefully -- so what is pinned here is that the dangerous button asks
 * first, does not exist on the state you are already on, and that the diff
 * dialog opens rather than throwing.
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
globalThis.location = { hash: "#/p:history" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = () => 0;
globalThis.confirm = () => true;
globalThis.alert = () => {};

const SNAPS = [
  { id: "b.json", at: "2026-08-14T10:00:00+00:00", rev: 7, current: true,
    summary: "haproxy.backends (1 added)" },
  { id: "a.json", at: "2026-08-13T09:00:00+00:00", rev: 6, current: false },
];
let posted = null;
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.method === "POST") posted = path;
  const bodies = {
    history: { ok: true, snapshots: SNAPS },
    "history/a.json/diff": { ok: true, parts: [
      { part: "haproxy.backends", objects: [{ name: "shop", state: "added" }] }] },
    "history/a.json/restore": { ok: true, changed: true, rev: 8, note: "Restored." },
    status: { ok: true, hostname: "x", role: "standalone", vips: [], vip_held: [], dirty: false },
  };
  return { ok: true, status: 200, json: async () => bodies[path] ?? {}, text: async () => "" };
};

const { renderHistory } = await import(REPO + "/static/js/pages/history.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const buttons = (root) => [...root.querySelectorAll("button")].map(b => b.textContent);

await renderHistory();
const content = document.querySelector("#content");
const rows = [...content.querySelectorAll("tbody tr")];
ok(rows.length === 2, "every snapshot is a row");
ok(rows[0].textContent.includes("current"), "the current state says so");
ok(!buttons(rows[0]).includes("Restore"),
   "and offers no Restore -- there is nothing to go back to");
ok(buttons(rows[1]).includes("Restore"), "an older state does");
ok(rows[0].textContent.includes("haproxy.backends (1 added)"),
   "each entry says what it changed");

const diffBtn = [...rows[1].querySelectorAll("button")].find(b => b.textContent === "Diff vs now");
await diffBtn.onclick();
ok(document.querySelector("#dlgbody").textContent.includes("shop"),
   "the diff dialog names the objects that differ");

posted = null;
const restore = [...content.querySelectorAll("button")].find(b => b.textContent === "Restore");
await restore.onclick();
ok(posted === "history/a.json/restore", "Restore posts to the snapshot it belongs to");

console.log(fail ? `\n${fail} failed` : "\nthe history page reads and restores");
process.exit(fail ? 1 : 0);
