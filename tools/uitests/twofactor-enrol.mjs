// Enrolling a second factor sends the password along with the proof.
//
// The server refuses an enrolment that carries no password, so that a stolen
// session cannot swap the owner's second factor for one the thief holds. The
// dialog has to ask for it, and send it; a dialog that asks and forgets to
// send is a dead end for every user.
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
<div id="ovl"><div id="dlg" role="dialog" aria-modal="true">
<div class="hd"><h3 id="dlgtitle"></h3><button id="dlgclose"></button></div>
<div class="bd" id="dlgbody"></div><div class="ft" id="dlgfoot"></div></div></div>
<aside id="nav"><div class="foot" id="whofoot"></div></aside>
<div id="login"><form id="loginbox"><input id="lu"><input id="lp">
<div id="lp2wrap" hidden><input id="lp2"></div><div id="lerr"></div>
<button id="lbtn"></button><h2 id="logintitle"></h2><p id="loginintro"></p></form></div>
<div id="content"></div></body></html>`);
globalThis.document=document; globalThis.window=window;
globalThis.location={hash:"#/"}; globalThis.MutationObserver=class{observe(){}};
globalThis.alert=()=>{};
const calls=[];
const answers={
  "2fa/setup": {secret:"ZZSECRET", matrix:[[1,0],[0,1]]},
  "2fa/enable": {ok:true, recovery:["zz-1","zz-2"]},
};
globalThis.fetch=async(u,o)=>{
  const path=String(u).replace(/^.*\/api\//,"");
  calls.push({path, body:o&&o.body?JSON.parse(o.body):null});
  const a=answers[path]||{authenticated:true,username:"admin",email:"a@b.c"};
  return {ok:true,status:200,json:async()=>a,text:async()=>""};
};
const { refreshWho, openAccount } = await import(REPO+"/static/js/auth.js");
let fail=0; const ok=(c,m)=>{console.log((c?"  PASS  ":"  FAIL  ")+m); if(!c)fail++;};
const tick=()=>new Promise(r=>setTimeout(r,0));

await refreshWho();
openAccount();
const setup=[...document.querySelectorAll("#dlgfoot button, #dlgbody button")].find(b=>b.textContent==="Set up...");
ok(setup!==undefined, "the account dialog offers to set the second factor up");
setup.dispatchEvent(new window.Event("click"));
await tick(); await tick();
ok(document.querySelector("#dlgtitle").textContent==="Two-factor authentication", "it opens the enrolment dialog");
ok(document.querySelector("#f_totp_code")!==null, "which asks for the code from the app");
const pw=document.querySelector("#f_pw_on");
ok(pw!==null && pw.getAttribute("type")==="password", "and for the current password, as a password field");
ok(document.querySelector("#dlgbody").textContent.includes("Current password"), "labelled as such");

document.querySelector("#f_totp_code").value="123456";
pw.value="zz-pass";
const go=[...document.querySelectorAll("#dlgfoot button")].find(b=>b.textContent==="Verify and turn on");
ok(go!==undefined, "Verify and turn on is the action");
go.dispatchEvent(new window.Event("click"));
await tick(); await tick();
const enable=calls.find(c=>c.path==="2fa/enable");
ok(enable!==undefined, "pressing it asks the server to enable");
ok(enable && enable.body.secret==="ZZSECRET" && enable.body.code==="123456", "with the secret and the code");
ok(enable && enable.body.password==="zz-pass", "and with the password typed");
ok(document.querySelector("#dlgtitle").textContent==="Recovery codes" &&
   document.querySelector("#dlgbody").textContent.includes("zz-1"), "then shows the recovery codes");

console.log(fail?"\n"+fail+" FAILED":"\nthe second factor is enrolled with the password in hand");
process.exit(fail?1:0);
