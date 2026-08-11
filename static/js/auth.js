import { setUnauthorisedHandler } from "./core.js";
import { $, api, esc } from "./core.js";
import { boot } from "./shell.js";
import { maybeSetupWizard } from "./pages/setup.js";
import { state } from "./state.js";

/* ---- authentication ---- */

export function showLogin(setup){
  const s=setup!==undefined?setup:state.who.needs_setup;
  $("#logintitle").textContent=s?"Create an administrator":"Sign in";
  $("#loginintro").textContent=s
    ? "This node has no administrator yet. Choose the credentials you will use to sign in."
    : "haproxy-manager on "+location.host;
  $("#lp2wrap").hidden=!s;
  $("#lp").autocomplete=s?"new-password":"current-password";
  $("#lbtn").textContent=s?"Create and sign in":"Sign in";
  $("#lerr").textContent="";
  if(!s&&state.who.admin_username)$("#lu").value=state.who.admin_username;   // only once signed in before
  $("#login").classList.add("show");
  setTimeout(()=>{($("#lu").value?$("#lp"):$("#lu")).focus();},30);
}
export function hideLogin(){$("#login").classList.remove("show");$("#lp").value="";$("#lp2").value="";}
export async function refreshWho(){
  try{state.who=await api("whoami");}catch(e){/* whoami is public; ignore */}
  const f=$("#whofoot");f.innerHTML="";
  if(state.who.authenticated){
    const d=document.createElement("div");d.className="state.who";
    d.innerHTML="<small>Signed in as</small>"+esc(state.who.username);
    const b=document.createElement("button");b.className="lo";b.textContent="Sign out";
    b.onclick=async()=>{try{await api("logout","POST",{});}catch(e){}
      state.who={authenticated:false,needs_setup:false,username:"",admin_username:state.who.admin_username};
      showLogin(false);};
    f.appendChild(d);f.appendChild(b);
  }else if(state.who.needs_setup){
    const d=document.createElement("div");d.className="state.who";
    d.innerHTML="<small>Security</small>no administrator";
    f.appendChild(d);
  }
  return state.who;
}
$("#loginbox").addEventListener("submit",async e=>{
  e.preventDefault();
  const err=$("#lerr"),b=$("#lbtn"),setup=!$("#lp2wrap").hidden;
  const u=$("#lu").value.trim(),p=$("#lp").value;
  if(setup&&p!==$("#lp2").value){err.textContent="The two passwords do not match.";return;}
  b.disabled=true;err.textContent="";
  try{
    await api(setup?"setup":"login","POST",{username:u,password:p});
    hideLogin();await refreshWho();boot();
    maybeSetupWizard();
  }catch(ex){err.textContent=ex.message;}
  b.disabled=false;
});

setUnauthorisedHandler(showLogin);   /* core.js calls this on any 401 */
