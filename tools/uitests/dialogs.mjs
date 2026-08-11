// Open the dialogs. Rendering a page does not exercise them, which is how a
// dialog that threw before it could open shipped: the button did nothing and
// every test still passed.
import "./stub-dom.mjs";

const DESTS = [{id:"1",name:"ops",type:"smtp",enabled:true,host:"smtp.example.com",to:"o@e.com"}];
globalThis.fetch = async (url) => {
  const path = String(url).replace(/^\/api\//,"").split("?")[0];
  const body = path === "notify"
    ? {ok:true, settings:{enabled:true,min_severity:"warning",repeat_hours:6,
                          events:{}, destinations:DESTS}, recent:[]}
    : /^[a-z]+\/[a-z]+$/.test(path) ? [] : {};
  return { ok:true, status:200, json: async()=>body, text: async()=>"" };
};
const root = process.cwd() + "/static/js/";
const { renderNotify } = await import(root + "pages/notify.js");

let fail = 0;
const ok = (c,m) => { console.log((c?"  PASS  ":"  FAIL  ")+m); if(!c) fail++; };
const find = (n,label) => {
  if (n.tagName==="button" && n.textContent===label) return n;
  for (const c of n.children) { const r = find(c,label); if (r) return r; }
  return null;
};

await renderNotify();
const content = document.querySelector("#content");

for (const [label, what] of [["Add a destination","adding"], ["Edit","editing"]]) {
  const b = find(content, label);
  ok(!!b, what + ": the button exists");
  if (!b) continue;
  document.querySelector("#dlgbody").children.length = 0;
  let threw = null;
  try { b.onclick(); } catch (e) { threw = e; }
  ok(!threw, what + ": clicking it opens the dialog" + (threw ? " -- " + threw.message : ""));
  const body = document.querySelector("#dlgbody").children[0];
  ok(!!body && body.children.length > 0, what + ": the dialog has a form");
}

// switching the type must repaint the type-specific fields
const add = find(content, "Add a destination");
document.querySelector("#dlgbody").children.length = 0;
add.onclick();
const form = document.querySelector("#dlgbody").children[0];
const sel = (function walk(n){ if(n.tagName==="select") return n;
  for(const c of n.children){ const r=walk(c); if(r) return r; } return null; })(form);
ok(!!sel, "the type selector is in the dialog");
if (sel) {
  sel.value = "webhook";
  let threw = null;
  try { sel.onchange({target:sel}); } catch (e) { threw = e; }
  ok(!threw, "changing the type repaints" + (threw ? " -- " + threw.message : ""));
}

console.log(fail ? "\n"+fail+" FAILED" : "\nthe dialogs open");
process.exit(fail?1:0);
