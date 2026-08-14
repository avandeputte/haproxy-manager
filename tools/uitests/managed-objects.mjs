// An object a service owns must be marked in the table and warned about in the
// editor; a hand-made one must be left alone.
import "./stub-dom.mjs";

const OWNED = {id:"1", name:"shop", managed_by:"shop", mode:"http"};
const MINE  = {id:"2", name:"hand-made", mode:"http"};
globalThis.fetch = async (url) => {
  const path = String(url).replace(/^\/api\//,"").split("?")[0];
  const body = path === "haproxy/backends" ? [OWNED, MINE]
             : /^[a-z]+\/[a-z]+$/.test(path) ? [] : {};
  return { ok:true, status:200, json: async()=>body, text: async()=>"" };
};
const root = process.cwd() + "/static/js/";
const { renderEntity, openEditor } = await import(root + "entities.js");
const c = document.querySelector("#content");

let fail = 0;
const ok = (cond,m) => { console.log((cond?"  PASS  ":"  FAIL  ")+m); if(!cond) fail++; };

await renderEntity("haproxy/backends");
const table = c.children.map(x => x.text).join("");
const badges = (table.match(/>service</g) || []).length;
ok(badges === 1, "exactly one row is badged, and there is one owned object (" + badges + ")");
ok(table.includes("Part of the service shop"), "the badge names the service");
ok(table.includes("Change it under Services"), "the badge says where to change it");

openEditor("haproxy/backends", OWNED);
let dlg = document.querySelector("#dlgbody").children.map(x => x.text).join("");
ok(dlg.includes("belongs to the service"), "the editor warns for an owned object");
ok(dlg.includes("publishing that service again rebuilds"), "it says why");
const wrapOwned = document.querySelector("#dlgbody").children[0];
/* warning + tab strip + form + cfg pane: the warning must not displace the rest */
ok(wrapOwned && wrapOwned.children.length === 4,
   "the dialog holds the warning, the tabs, the form and the cfg pane");

openEditor("haproxy/backends", MINE);
const wrapMine = document.querySelector("#dlgbody").children.slice(-1)[0];
dlg = wrapMine ? wrapMine.text : "";
ok(!dlg.includes("belongs to the service"), "no warning for a hand-made object");
ok(wrapMine && wrapMine.children.length === 3, "and no warning block, just tabs, form and cfg pane");

console.log(fail ? "\n"+fail+" FAILED" : "\nservice-owned objects are marked and explained");
process.exit(fail?1:0);
