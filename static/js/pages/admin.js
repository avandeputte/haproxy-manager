import { refreshWho } from "../auth.js";
import { $, api, btn, fieldRow } from "../core.js";
import { state } from "../state.js";

/* ---- admin login page ---- */
export async function renderAdmin(){
  const c=$("#content");c.innerHTML="";
  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>Administrator login</h2></div>';
  const bd=document.createElement("div");bd.className="bd";
  bd.innerHTML='<p class=hint style="margin-bottom:14px">The username and password used to sign in to this UI. '+
    'Node-local: set it separately on each node, it is never synced. The password is stored as a PBKDF2-SHA256 hash.</p>';
  const frm=document.createElement("div");frm.className="frm";
  [{k:"username",l:"Username",t:"text"},
   {k:"current",l:"Current password",t:"password"},
   {k:"new",l:"New password",t:"password",h:"At least 8 characters"},
   {k:"new2",l:"Repeat new password",t:"password"}]
    .forEach(f=>fieldRow(f,f.k==="username"?(state.who.username||state.who.admin_username):"").forEach(el=>frm.appendChild(el)));
  bd.appendChild(frm);
  const foot=document.createElement("div");foot.style.marginTop="16px";
  const msg=document.createElement("span");msg.className="hint";msg.style.marginLeft="10px";
  foot.appendChild(btn("Save","pri",async()=>{
    const u=document.getElementById("f_username").value.trim();
    const cur=document.getElementById("f_current").value;
    const nw=document.getElementById("f_new").value;
    if(nw!==document.getElementById("f_new2").value){msg.textContent="The two new passwords do not match.";return;}
    try{
      await api("password","POST",{username:u,current:cur,new:nw});
      msg.textContent="Saved. Your session was renewed.";
      ["current","new","new2"].forEach(k=>{document.getElementById("f_"+k).value="";});
      await refreshWho();
    }catch(e){msg.textContent=e.message;}
  }));
  foot.appendChild(msg);bd.appendChild(foot);card.appendChild(bd);c.appendChild(card);
}
