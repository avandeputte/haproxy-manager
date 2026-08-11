// Prove the DOM half works against a real DOM, not a stub: clicking a heading
// must actually reorder the rows in the document.
// Needs a real DOM, which is not worth a dependency in the repository:
//     npm i linkedom   (anywhere, then run with NODE_PATH set)
// Skips itself when it is not there, so the suite still runs.
let parseHTML;
for (const where of ["linkedom", process.env.LINKEDOM]) {
  if (!where) continue;
  try { ({ parseHTML } = await import(where)); break; } catch { /* try the next */ }
}
if (!parseHTML) {
  console.log("  skipped: no DOM available. npm i linkedom here, or point LINKEDOM at it:");
  console.log("           LINKEDOM=/path/to/node_modules/linkedom node tools/uitests/table-sorting-dom.mjs");
  process.exit(0);
}
const REPO = process.cwd();

const html = `<!doctype html><html><body>
<div id="ovl"><div id="dlg"><div id="dlgtitle"></div><button id="dlgclose"></button>
<div id="dlgbody"></div><div id="dlgfoot"></div></div></div>
<div id="content">
<table>
  <thead><tr><th>Server</th><th>Sessions</th><th>Traffic</th><th></th></tr></thead>
  <tbody>
    <tr><td>web3</td><td>10</td><td>900 MB</td><td><button>Edit</button></td></tr>
    <tr><td>web1</td><td>100</td><td>1.2 GB</td><td><button>Edit</button></td></tr>
    <tr><td>web2</td><td>9</td><td>12 kB</td><td><button>Edit</button></td></tr>
    <tr><td class=tot colspan=4>total</td></tr>
  </tbody>
</table></div></body></html>`;
const { document, window } = parseHTML(html);
globalThis.document = document;
globalThis.window = window;
globalThis.location = { hash: "#/p:stats" };
globalThis.MutationObserver = window.MutationObserver || class { observe(){} };
globalThis.fetch = async () => ({ ok:true, status:200, json: async()=>({}), text: async()=>"" });

const { enhanceTables } = await import(REPO + "/static/js/core.js");
const table = document.querySelector("table");
enhanceTables(document.querySelector("#content"));

const names = () => [...table.querySelectorAll("tbody tr")].map(r => r.children[0].textContent);
let fail = 0;
const ok = (c,m) => { console.log((c?"  PASS  ":"  FAIL  ")+m); if(!c) fail++; };

const heads = [...table.querySelectorAll("thead th")];
ok(heads[0].classList.contains("sortable"), "headings become clickable");
ok(!heads[3].classList.contains("sortable"), "the actions column does not");

heads[0].dispatchEvent(new window.Event("click"));
ok(names().slice(0,3).join()==="web1,web2,web3", "clicking Server sorts by name: " + names().join());
ok(heads[0].classList.contains("sorted-asc"), "the heading shows the direction");

heads[0].dispatchEvent(new window.Event("click"));
ok(names().slice(0,3).join()==="web3,web2,web1", "clicking again reverses: " + names().join());
ok(heads[0].classList.contains("sorted-desc"), "and the indicator follows");

heads[1].dispatchEvent(new window.Event("click"));
ok(names().slice(0,3).join()==="web2,web3,web1", "sessions sort numerically: " + names().join());
ok(!heads[0].classList.contains("sorted-desc"), "the old column's indicator clears");

heads[2].dispatchEvent(new window.Event("click"));
ok(names().slice(0,3).join()==="web2,web3,web1", "traffic sorts by size: " + names().join());

ok(names().slice(-1)[0]==="total", "the totals row stays at the bottom");

// a second pass must not double-bind
enhanceTables(document.querySelector("#content"));
heads[0].dispatchEvent(new window.Event("click"));
ok(names().slice(0,3).join()==="web1,web2,web3", "re-enhancing does not bind twice: " + names().join());

console.log(fail ? "\n" + fail + " FAILED" : "\nsorting works against a real DOM");
process.exit(fail?1:0);
