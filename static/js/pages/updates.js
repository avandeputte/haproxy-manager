import { $, api, btn, esc } from "../core.js";

import { fmtTime } from "../pages/certificates.js";
import { state } from "../state.js";

/* ---- version and updates ---- */
export async function renderUpdates(){
  const c=$("#content");c.innerHTML="";
  const v=await api("version");
  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>Version</h2></div>';
  const bd=document.createElement("div");bd.className="bd";
  bd.innerHTML='<div class=grid style="margin-bottom:16px">'+
    '<div class=stat><div class=k>Installed</div><div class=v>'+esc(v.version)+"</div></div>"+
    '<div class=stat><div class=k>Published</div><div class=v>'+esc(v.latest||"—")+"</div></div>"+
    '<div class=stat><div class=k>Status</div><div class="v" style="font-size:13px">'+
      (v.available?'<span class="pill warn">update available</span>'
                  :v.latest?'<span class="pill up">up to date</span>':'<span class="pill off">not checked yet</span>')+"</div></div>"+
    '<div class=stat><div class=k>Last checked</div><div class="v" style="font-size:13px">'+
      (v.checked?fmtTime(v.checked):"never")+"</div></div></div>"+
    '<p class=hint>Checked once a day against <span class=mono>'+esc(v.repo)+"</span> ("+esc(v.ref)+")."+
    (v.error?" Last check failed: "+esc(v.error):"")+"</p>";
  const row=document.createElement("div");row.style.marginTop="14px";
  const msg=document.createElement("div");msg.className="hint";msg.style.marginTop="12px";
  /* Updating a cluster one node at a time means visiting each one and waiting.
     Offered only when there is somewhere to send it. */
  let alsoPeers=null;
  if(v.peers){
    const lbl=document.createElement("label");
    lbl.style.cssText="display:block;margin-bottom:10px";
    alsoPeers=document.createElement("input");alsoPeers.type="checkbox";
    alsoPeers.checked=true;alsoPeers.id="f_update_peers";
    lbl.appendChild(alsoPeers);
    lbl.appendChild(document.createTextNode(" Update the other "+v.peers+" node"+
      (v.peers===1?"":"s")+" as well"));
    const h=document.createElement("div");h.className="hint";
    h.textContent="They are told first, while this node is still running to tell them, "+
      "and each restarts when its own update finishes. The Cluster page shows the "+
      "version every node ends up on.";
    lbl.appendChild(h);
    row.appendChild(lbl);
  }
  row.appendChild(btn("Check now","",async()=>{
    msg.textContent="Checking...";
    try{await api("version/check","POST",{});await renderUpdates();}
    catch(e){msg.textContent=e.message;}
  }));
  row.appendChild(document.createTextNode(" "));
  const up=btn(v.available?("Update to "+v.latest):"Update","pri",async()=>{
    const peers=!!(alsoPeers&&alsoPeers.checked);
    if(!confirm("Update haproxy-manager from "+v.version+" to "+(v.latest||"the published version")+
                (peers?" on this node and the other "+v.peers+"?":"?")+"\n\n"+
                "The installer runs on each node and that node's service restarts when it "+
                "finishes. Your configuration, certificates and login are kept. HAProxy keeps "+
                "serving traffic throughout."))return;
    up.disabled=true;msg.textContent="Starting the updater...";
    try{
      const r=await api("update","POST",{peers:peers});
      msg.textContent=r.note||"Update started.";
      /* A node that did not take it is named: it stays on the old version, and
         nothing retries it, so it has to be visible. */
      const failed=(r.nodes||[]).filter(x=>!x.ok);
      if(failed.length){
        const w=document.createElement("div");w.className="err";w.style.marginTop="8px";
        w.innerHTML="Not started on "+failed.map(x=>"<b>"+esc(x.name)+"</b>: "+
                     esc(x.error||"")).join("; ")+". Those nodes stay on "+esc(v.version)+".";
        msg.appendChild(w);
      }
      watchUpdate(msg);
    }catch(e){msg.textContent=e.message;up.disabled=false;}
  });
  if(!v.can_update||!v.available)up.disabled=true;
  row.appendChild(up);
  if(!v.can_update){
    const w=document.createElement("div");w.className="hint";w.style.marginTop="10px";
    w.textContent="One-click update is not available here: "+v.cannot_update_reason;
    row.appendChild(w);
  }
  bd.appendChild(row);bd.appendChild(msg);card.appendChild(bd);c.appendChild(card);

  const logCard=document.createElement("div");logCard.className="card";
  logCard.innerHTML='<div class=hd><h2>Update log</h2></div>';
  const lb=document.createElement("div");lb.className="bd";
  const pre=document.createElement("pre");pre.id="updlog";pre.textContent="(nothing yet)";
  lb.appendChild(pre);logCard.appendChild(lb);c.appendChild(logCard);
  try{const l=await api("update/log");if(l.log)pre.textContent=l.log;if(l.running)watchUpdate(msg);}catch(e){}
}
/* Poll the log while the updater runs; the service restarts underneath us. */
export function watchUpdate(msg){
  const tick=async()=>{
    let alive=true;
    try{
      const l=await api("update/log");
      const pre=document.getElementById("updlog");
      if(pre&&l.log)pre.textContent=l.log;
      if(!l.running){
        alive=false;
        msg.innerHTML="Update finished &mdash; now running <b>"+esc(l.version)+"</b>. Reload the page.";
      }
    }catch(e){msg.textContent="Service is restarting...";}   // expected mid-update
    if(alive)state.pageTimer=setTimeout(tick,3000);
  };
  state.pageTimer=setTimeout(tick,3000);
}
