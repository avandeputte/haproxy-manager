/* What makes the UI usable on a phone.
 *
 * Two mechanisms, neither visible from reading a page: every cell carries the
 * name of its column, because on a narrow screen the heading row is gone and
 * a bare value has nothing to say what it is; and every table sits in a box
 * that can scroll, because a table wider than the screen otherwise widens the
 * page and the phone zooms the whole UI out to fit it.
 *
 * The stylesheet is checked here too. It is the only place these decisions
 * live, and a media query that stops matching takes the layout with it.
 */
import { readFileSync } from "node:fs";

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
<div id="scrim"></div>
<aside id="nav"><div id="navlinks"></div><div class="foot" id="whofoot"></div></aside>
<div id="main"><div id="topbar"><button id="navtoggle" aria-expanded="false"></button>
<h1 id="pagetitle"></h1><div id="nodestrip"></div>
<button class="btn pri" id="applybtn"></button></div>
<div id="banner"></div><div id="content"></div></div>
<div id="ovl"><div id="dlg"><div class="hd"><h3 id="dlgtitle"></h3>
<button id="dlgclose"></button></div><div class="bd" id="dlgbody"></div>
<div class="ft" id="dlgfoot"></div></div></div>
<div id="login"><form id="loginbox"><input id="lu"><input id="lp">
<div id="lp2wrap" hidden><input id="lp2"></div><div id="lerr"></div>
<button id="lbtn"></button><h2 id="logintitle"></h2><p id="loginintro"></p></form></div>
</body></html>`);
globalThis.document = document; globalThis.window = window;
globalThis.location = { hash: "#/p:services" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = () => 0; globalThis.setInterval = () => 0;
globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({}), text: async () => "" });

const { enhanceTables } = await import(REPO + "/static/js/core.js");
const { setNavOpen, wireNav } = await import(REPO + "/static/js/shell.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };

// -- the labels --------------------------------------------------------------
const content = document.querySelector("#content");
content.innerHTML = `<div class="card"><div><table>
<thead><tr><th>Public URL</th><th>Forwards to</th><th></th></tr></thead>
<tbody>
<tr><td>https://shop.example.com</td><td>10.0.0.5:80</td><td><button>Edit</button></td></tr>
<tr><td colspan="3">nothing here</td></tr>
</tbody></table></div></div>`;
enhanceTables(content);
const cells = [...content.querySelectorAll("tbody tr")][0].children;
ok(cells[0].dataset.label === "Public URL" && cells[1].dataset.label === "Forwards to",
   "every cell carries the name of its column");
ok(!cells[2].dataset.label && cells[2].dataset.actions === "1",
   "the column with no heading is marked as the row's actions instead");
const spanning = [...content.querySelectorAll("tbody tr")][1].children[0];
ok(!spanning.dataset.label && !spanning.dataset.actions,
   "a cell spanning the table is a note, not a field, and is left alone");

// Running again must not pile up wrappers or change anything.
const wrapsBefore = content.querySelectorAll(".tscroll").length;
enhanceTables(content);
enhanceTables(content);
ok(content.querySelectorAll(".tscroll").length === wrapsBefore && wrapsBefore === 1,
   "the table is wrapped in one scrollable box, however often the page refreshes");
ok(content.querySelector(".tscroll > table") !== null, "with the table inside it");
ok(content.querySelector(".card > div > .tscroll") !== null,
   "and the box stays where the table was");

// -- the log is left as a stream --------------------------------------------
content.innerHTML = `<div class="card"><div class="logview"><table><thead><tr>
<th>Time</th><th>Source</th><th>Message</th></tr></thead>
<tbody><tr><td class="t">12:00</td><td class="s">manager</td><td class="m">hello</td></tr>
</tbody></table></div></div>`;
enhanceTables(content);
ok(!content.querySelector("td").dataset.label && !content.querySelector(".tscroll"),
   "the log is read as a stream, so it is neither labelled nor wrapped");

// -- the menu drawer ---------------------------------------------------------
wireNav();
const toggle = document.querySelector("#navtoggle");
ok(!document.body.classList.contains("navopen"), "the menu starts closed");
toggle.dispatchEvent(new window.Event("click"));
ok(document.body.classList.contains("navopen"), "the menu button opens it");
ok(toggle.getAttribute("aria-expanded") === "true", "and says so for a screen reader");
document.querySelector("#scrim").dispatchEvent(new window.Event("click"));
ok(!document.body.classList.contains("navopen"), "tapping beside it closes it again");
setNavOpen(true);
ok(document.body.classList.contains("navopen"), "it can be opened directly");
setNavOpen(false);
ok(toggle.getAttribute("aria-expanded") === "false", "closing updates the button too");

// -- the stylesheet ----------------------------------------------------------
const css = readFileSync(REPO + "/static/css/app.css", "utf8");
const at = (q) => {
  const i = css.indexOf("@media (max-width:" + q + "px)");
  if (i < 0) return "";
  let depth = 0, j = css.indexOf("{", i);
  for (let k = j; k < css.length; k++) {
    if (css[k] === "{") depth++;
    else if (css[k] === "}" && --depth === 0) return css.slice(j, k);
  }
  return "";
};
const drawer = at(840), phone = at(680);
ok(/#nav\{[^}]*position:fixed/.test(drawer), "the sidebar becomes a drawer on a narrow screen");
ok(/\.navopen #nav\{[^}]*transform:none/.test(drawer), "which the menu button slides in");
ok(/#navtoggle\{display:block\}/.test(drawer), "and that is where the menu button appears");
ok(/#topbar\{[^}]*position:sticky/.test(drawer),
   "the bar holding it stays put as the page scrolls");
ok(/\.tscroll\{overflow-x:auto\}/.test(drawer), "wide tables scroll inside their card");
ok(/#content thead\{display:none\}/.test(phone) && /#content td\{[^}]*/.test(phone),
   "on a phone the rows become blocks and the heading row goes");
ok(/data-label\)/.test(phone), "each value is introduced by its column name");
ok(/overflow-wrap:anywhere/.test(phone), "a long URL breaks rather than widening the page");
ok(/minmax\(0,1fr\)/.test(phone),
   "and the cards on a grid may shrink below their widest word, for the same reason");
ok(/font-size:16px/.test(phone),
   "fields are 16px, the size below which a phone zooms in on focus and never back out");
ok(/#dlg\{[^}]*height:100%/.test(phone), "a dialog takes the whole screen");
ok(css.indexOf("color-scheme:dark") > 0,
   "the controls the browser paints itself follow the theme");

console.log(fail ? `\n${fail} failed` : "\nthe narrow-screen layout is wired up");
process.exit(fail ? 1 : 0);
