import { setUnauthorisedHandler } from "./core.js";
import { $, api, btn, closeDlg, esc, fieldEl, fieldRow, openDlg } from "./core.js";
import { boot } from "./shell.js";
import { maybeSetupWizard } from "./pages/setup.js";
import { state } from "./state.js";
import { THEMES, applyTheme, currentTheme } from "./theme.js";

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
/* The account dialog: the username, an email and the password, opened by the
   gear beside the name. It is reachable from every page because changing a
   password is something you do from wherever you happen to be. */
export function openAccount(){
  const body=document.createElement("div");body.className="frm";
  const fields=[
    {k:"username",l:"Username",t:"text"},
    {k:"email",l:"Email",t:"text",h:"Optional. Offered as the default for ACME accounts and notifications."},
    {k:"theme",l:"Appearance",t:"select",o:THEMES,d:"system",
     h:"system follows what this machine is set to. Kept with your account, so it "+
       "follows you to another browser."},
    {k:"current",l:"Current password",t:"password",h:"Only needed to change the password"},
    {k:"new",l:"New password",t:"password",h:"At least 8 characters. Leave empty to keep the current one."},
    {k:"new2",l:"Repeat new password",t:"password"},
  ];
  /* The login is node-local, so this is offered rather than assumed -- but it
     is offered, because one node with a different password is usually an
     accident you find out about during a failover. Only shown when there is
     somewhere to send it. */
  const peers=state.who.peers||0;
  if(peers)fields.push({k:"propagate",l:"Apply to the other nodes",t:"bool",d:true,
    h:"Sends the new login to the "+peers+" other node"+(peers===1?"":"s")+
      ". Only the stored hash travels, never the password."});
  fields.forEach(f=>fieldRow(f,f.k==="username"?(state.who.username||state.who.admin_username)
                             :f.k==="email"?(state.who.email||"")
                             :f.k==="theme"?currentTheme()
                             :f.k==="propagate"?true:"")
                 .forEach(el=>body.appendChild(el)));
  const err=document.createElement("div");err.className="err";
  const out=document.createElement("div");out.className="hint";out.style.marginTop="10px";
  body.appendChild(out);
  /* Applied as it is chosen: an appearance you cannot see until you save is a
     guess. Choosing and then closing without saving puts it back. */
  const wasTheme=currentTheme();
  /* Wired after openDlg: fieldEl looks inside the dialog, and until openDlg
     puts this body there it finds nothing. */
  const wireTheme=()=>{
    const el=fieldEl("theme");
    if(el)el.addEventListener("change",()=>applyTheme(el.value));
  };
  openDlg("Account",body,[err,btn("Cancel","",()=>{applyTheme(wasTheme);closeDlg();}),
    btn("Save","pri",async()=>{
      const val=k=>{const el=fieldEl(k);return el?el.value:"";};
      const nw=val("new");
      if(nw&&nw!==val("new2")){err.textContent="The two new passwords do not match.";return;}
      if(nw&&!val("current")){err.textContent="Enter the current password to change it.";return;}
      const box=fieldEl("propagate");
      try{
        const r=await api("password","POST",{username:val("username").trim(),email:val("email").trim(),
                                     current:val("current"),new:nw,
                                     theme:val("theme"),
                                     propagate:!!(box&&box.checked)});
        const failed=(r.nodes||[]).filter(n=>!n.ok);
        if(failed.length){
          /* Saved here either way: the local change is done and reporting it as
             a failure would be worse than telling you exactly which node to fix. */
          err.innerHTML="Saved on this node, but not on "+
            failed.map(n=>"<b>"+esc(n.name)+"</b>: "+esc(n.error||"")).join("; ")+
            ". Those nodes keep the old login until you change it there.";
          out.textContent="";
          return;
        }
        closeDlg();await refreshWho();
      }catch(e){err.textContent=e.message;}
    })]);
  wireTheme();
}

export async function refreshWho(){
  try{state.who=await api("whoami");}catch(e){/* whoami is public; ignore */}
  /* The account's choice is the real one; localStorage only carries it far
     enough to paint the first frame. */
  if(state.who.theme&&state.who.theme!==currentTheme())applyTheme(state.who.theme);
  const f=$("#whofoot");f.innerHTML="";
  if(state.who.authenticated){
    const d=document.createElement("div");d.className="who";
    d.innerHTML="<small>Signed in as</small>"+esc(state.who.username);
    const g=document.createElement("button");g.className="lo gear";
    g.title="Account";g.setAttribute("aria-label","Account settings");
    g.innerHTML='<svg width="15" height="15" viewBox="0 0 16 16" aria-hidden="true">'+
      '<path fill="currentColor" fill-rule="evenodd" d="M6.27 0.80 L9.73 0.80 L10.10 2.92 L10.10 2.92 L11.87 1.69 L14.31 4.13 L13.08 5.90 L13.08 5.90 L15.20 6.27 L15.20 9.73 L13.08 10.10 L13.08 10.10 L14.31 11.87 L11.87 14.31 L10.10 13.08 L10.10 13.08 L9.73 15.20 L6.27 15.20 L5.90 13.08 L5.90 13.08 L4.13 14.31 L1.69 11.87 L2.92 10.10 L2.92 10.10 L0.80 9.73 L0.80 6.27 L2.92 5.90 L2.92 5.90 L1.69 4.13 L4.13 1.69 L5.90 2.92 L5.90 2.92 Z M5.50 8.00 a2.50 2.50 0 1 0 5.00 0 a2.50 2.50 0 1 0 -5.00 0 Z"/></svg>';
    g.onclick=openAccount;
    const b=document.createElement("button");b.className="lo";b.textContent="Sign out";
    b.onclick=async()=>{try{await api("logout","POST",{});}catch(e){}
      state.who={authenticated:false,needs_setup:false,username:"",admin_username:state.who.admin_username};
      showLogin(false);};
    /* name and gear share a row; Sign out keeps the full width below it */
    const row=document.createElement("div");row.className="whorow";
    row.appendChild(d);row.appendChild(g);
    f.appendChild(row);f.appendChild(b);
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
