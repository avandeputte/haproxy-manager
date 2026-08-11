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
<div id="ovl"><div id="dlgtitle"></div><button id="dlgclose"></button>
<div id="dlgbody"></div><div id="dlgfoot"></div></div>
<aside id="nav"><div class="foot" id="whofoot"></div></aside>
<div id="login"><form id="loginbox"><input id="lu"><input id="lp">
<div id="lp2wrap" hidden><input id="lp2"></div><div id="lerr"></div>
<button id="lbtn"></button><h2 id="logintitle"></h2><p id="loginintro"></p></form></div>
<div id="content"></div></body></html>`);
globalThis.document=document; globalThis.window=window;
globalThis.location={hash:"#/"}; globalThis.MutationObserver=class{observe(){}};
let sent=null;
globalThis.fetch=async(u,o)=>{ if(o&&o.body)sent=JSON.parse(o.body);
  return {ok:true,status:200,json:async()=>({authenticated:true,username:"admin",email:"a@b.c"}),text:async()=>""}; };
const { refreshWho, openAccount } = await import(REPO+"/static/js/auth.js");
let fail=0; const ok=(c,m)=>{console.log((c?"  PASS  ":"  FAIL  ")+m); if(!c)fail++;};

await refreshWho();
const foot=document.querySelector("#whofoot");
ok(foot.querySelector(".who")!==null, "the name block uses the styled class");
ok(foot.querySelector(".who small").textContent==="Signed in as", "the label is its own block, so nothing runs together");
const gear=foot.querySelector(".gear");
ok(gear!==null, "there is a gear beside the name");
ok(gear.parentNode.className==="whorow" && gear.previousElementSibling.className==="who",
   "it sits on the same row as the name, not on a line of its own");
ok(foot.children.length===2 && foot.children[1].textContent==="Sign out",
   "Sign out keeps its own full-width row below");
ok(gear.querySelector("svg")!==null, "it draws an icon");

gear.dispatchEvent(new window.Event("click"));
const dlg=document.querySelector("#dlgbody").textContent;
ok(document.querySelector("#dlgtitle").textContent==="Account", "the gear opens the account dialog");
ok(dlg.includes("Email"), "it offers an email");
ok(dlg.includes("New password"), "and a password change");
ok(document.querySelector("#f_email").value==="a@b.c", "the current email is filled in");
console.log(fail?"\n"+fail+" FAILED":"\nthe account gear works");
process.exit(fail?1:0);
