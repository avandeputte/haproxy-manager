import { setUnauthorisedHandler } from "./core.js";
import { $, api, btn, closeDlg, esc, fieldEl, fieldRow, openDlg } from "./core.js";
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
/* Account settings on a gear beside the name rather than a page of their own:
   changing a password is something you do from wherever you are, not something
   you navigate to. */
export function openAccount(){
  const body=document.createElement("div");body.className="frm";
  const fields=[
    {k:"username",l:"Username",t:"text"},
    {k:"email",l:"Email",t:"text",h:"Optional. Offered as the default for ACME accounts and notifications."},
    {k:"current",l:"Current password",t:"password",h:"Only needed to change the password"},
    {k:"new",l:"New password",t:"password",h:"At least 8 characters. Leave empty to keep the current one."},
    {k:"new2",l:"Repeat new password",t:"password"},
  ];
  fields.forEach(f=>fieldRow(f,f.k==="username"?(state.who.username||state.who.admin_username)
                             :f.k==="email"?(state.who.email||""):"")
                 .forEach(el=>body.appendChild(el)));
  const err=document.createElement("div");err.className="err";
  openDlg("Account",body,[err,btn("Cancel","",closeDlg),
    btn("Save","pri",async()=>{
      const val=k=>{const el=fieldEl(k);return el?el.value:"";};
      const nw=val("new");
      if(nw&&nw!==val("new2")){err.textContent="The two new passwords do not match.";return;}
      if(nw&&!val("current")){err.textContent="Enter the current password to change it.";return;}
      try{
        await api("password","POST",{username:val("username").trim(),email:val("email").trim(),
                                     current:val("current"),new:nw});
        closeDlg();await refreshWho();
      }catch(e){err.textContent=e.message;}
    })]);
}

export async function refreshWho(){
  try{state.who=await api("whoami");}catch(e){/* whoami is public; ignore */}
  const f=$("#whofoot");f.innerHTML="";
  if(state.who.authenticated){
    const d=document.createElement("div");d.className="who";
    d.innerHTML="<small>Signed in as</small>"+esc(state.who.username);
    const g=document.createElement("button");g.className="lo gear";
    g.title="Account";g.setAttribute("aria-label","Account settings");
    g.innerHTML='<svg width="13" height="13" viewBox="0 0 16 16" aria-hidden="true">'+
      '<circle cx="8" cy="8" r="2.4" fill="none" stroke="currentColor" stroke-width="1.6"/>'+
      '<path fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" '+
      'd="M8 1.4v1.7M8 12.9v1.7M14.6 8h-1.7M3.1 8H1.4M12.7 3.3l-1.2 1.2M4.5 11.5l-1.2 1.2'+
      'M12.7 12.7l-1.2-1.2M4.5 4.5L3.3 3.3"/></svg>';
    g.onclick=openAccount;
    const b=document.createElement("button");b.className="lo";b.textContent="Sign out";
    b.onclick=async()=>{try{await api("logout","POST",{});}catch(e){}
      state.who={authenticated:false,needs_setup:false,username:"",admin_username:state.who.admin_username};
      showLogin(false);};
    f.appendChild(d);f.appendChild(g);f.appendChild(b);
  }else if(state.who.needs_setup){
    const d=document.createElement("div");d.className="who";
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
