import { $, api, btn, esc, fieldRow, readForm } from "../core.js";
import { t, tn } from "../i18n.js";
import { refreshStatus } from "../shell.js";
import { CERT_MODE_LABEL } from "../pages/services.js";

/* ---- HTTPS for this UI ---- */
export const WEBUI_FIELDS=[
 {k:"enabled",l:"Serve the UI through HAProxy",t:"bool"},
 {k:"url",l:"This node's address",t:"text",h:"e.g. https://proxy1.example.com -- reaches this node specifically"},
 {k:"shared_url",l:"Shared address (optional)",t:"text",
  h:"e.g. https://proxy.example.com -- point it at the virtual IP and it reaches whichever node is active. Every node answers for it, so this setting is shared across the cluster."},
 {k:"certificate",l:"Certificate",t:"select",d:"auto",o:["auto","new","none"]},
 {k:"http_redirect",l:"Redirect HTTP to HTTPS",t:"bool",d:true},
 {k:"apply",l:"Apply immediately",t:"bool",d:true},
];
/* The opening line depends on how you got here. Offering to publish the UI
   "instead of http://<host>" reads as nonsense when <host> is the published
   address you are already reading it through -- which is exactly the case
   after this page has done its job. */
export function blurb(cur){
  const here=(location.protocol||"http:")+"//"+location.host;
  const trim=u=>String(u||"").replace(/\/+$/,"").toLowerCase();
  const at="<span class=mono>"+esc(here)+"</span>";
  if(cur.enabled&&trim(cur.shared_url)===trim(here))
    return t("You are reading this through the shared address {here}, which reaches whichever node currently holds the virtual IP.",{here:at});
  if(cur.enabled&&trim(cur.url)===trim(here))
    return t("You are reading this through {here}, which reaches this node specifically.",{here:at});
  if(cur.enabled)
    return t("This management UI is published over HTTPS, though you have reached it directly at {here} rather than through one of its names.",{here:at});
  return t("Publish this management UI as a normal service, so it is reachable by name over HTTPS instead of {here}.",{here:at});
}

export async function renderWebui(){
  const c=$("#content");c.innerHTML="";
  const cur=await api("webui");
  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>'+t("Web UI access")+'</h2></div>';
  const bd=document.createElement("div");bd.className="bd";
  bd.innerHTML='<p class=hint style="margin-bottom:14px">'+blurb(cur)+' '+
    t("It builds the same objects the publish wizard would: a pool pointing at "+
      "<span class=mono>127.0.0.1:{port}</span>, a host rule, the HTTPS listener and a certificate.",{port:esc(cur.port)})+'</p>';
  /* The setting says what should be published; this says what is. They come
     apart -- a name that stopped being published looks like the node being
     down, and the form still shows the address that was typed. */
  if(cur.enabled){
    const state=document.createElement("p");state.className="hint";
    state.style.marginBottom="14px";
    const want=[cur.url,cur.shared_url].filter(Boolean)
      .map(u=>String(u).replace(/^https?:\/\//,"").replace(/\/.*$/,"").toLowerCase());
    const have=cur.hosts||[];
    const missing=want.filter(h=>have.indexOf(h)<0);
    state.innerHTML=t("This node answers for {names}.",{names:
      have.length?have.map(h=>'<span class=mono>'+esc(h)+"</span>").join(", ")
                 :"<b>"+t("nothing")+"</b>"});
    if(missing.length)
      state.innerHTML+=' <b style="color:var(--drift)">'+
        tn(missing.length,"{names} is not routed here","{names} are not routed here",{names:missing.map(esc).join(", ")})+
        "</b> — "+tn(missing.length,"Save rebuilds the service and adds it.","Save rebuilds the service and adds them.");
    bd.appendChild(state);
  }
  /* Where the names point. A name resolving somewhere this node is not looks
     exactly like the node being down, and no amount of looking at HAProxy
     shows it. */
  /* Why the Services page can show the same address twice: more than one rule
     routes to this node's UI service. Both send traffic to the same pool, so
     nothing is broken -- but two rows for one service is a puzzle. */
  if((cur.extra_rules||[]).length){
    const box=document.createElement("div");box.className="hint";
    box.style.cssText="margin-bottom:14px";
    const n=cur.extra_rules.length;
    box.innerHTML=t("This node has {n} rules routing to its own UI service, which is why it appears "+
      "more than once on the Services page. Both send traffic to the same place, so nothing is broken; ",{n:n+1})+
      tn(n,"the extra one is left over from an older version.","the extra ones are left over from an older version.")+" "+
      t("The extra: {rules}.",{rules:cur.extra_rules.map(r=>"<span class=mono>"+esc(r.name)+"</span>"+
        (r.hosts&&r.hosts.length?" ("+r.hosts.map(esc).join(", ")+")":"")).join(", ")});
    const b=btn(tn(n,"Remove the extra rule","Remove the extra rules"),"sm warn",async()=>{
      if(!confirm(tn(n,"Remove {n} leftover rule routing to this node's UI service?",
                       "Remove {n} leftover rules routing to this node's UI service?")+"\n\n"+
                  t("The rule this node uses is kept, and the service is rebuilt and applied afterwards.")))return;
      b.disabled=true;b.textContent=t("removing...");
      try{const r=await api("webui/tidy","POST",{});
        await renderWebui();
        if(r.applied&&r.applied.ok===false)alert(t("Removed, but Apply failed: {error}",{error:r.applied.error||""}));
      }catch(e){alert(e.message);b.disabled=false;}
    });
    const row=document.createElement("div");row.style.marginTop="8px";row.appendChild(b);
    box.appendChild(row);
    bd.appendChild(box);
  }
  (cur.address_checks||[]).forEach(c=>{
    const el=document.createElement("p");el.className="hint";
    el.style.cssText="margin-bottom:14px;color:var(--drift)";
    el.innerHTML="! <b>"+esc(c.which)+":</b> "+esc(c.message);
    bd.appendChild(el);
  });
  const frm=document.createElement("div");frm.className="frm";
  const rows={};
  WEBUI_FIELDS.forEach(f=>{
    const v=f.k==="enabled"?cur.enabled:f.k==="url"?cur.url
           :f.k==="shared_url"?cur.shared_url:f.k==="certificate"?cur.certificate:undefined;
    const cells=fieldRow(f,v);rows[f.k]=cells;cells.forEach(el=>frm.appendChild(el));
  });
  bd.appendChild(frm);
  const sel=frm.querySelector("#f_certificate");
  if(sel)[...sel.options].forEach(o=>{o.textContent=t(CERT_MODE_LABEL[o.value]||o.value);});
  const sync=()=>{
    const on=frm.querySelector("#f_enabled").checked;
    ["url","shared_url","certificate","http_redirect"].forEach(k=>(rows[k]||[]).forEach(el=>{el.style.display=on?"":"none";}));
  };
  frm.querySelector("#f_enabled").addEventListener("change",sync);sync();

  const out=document.createElement("div");out.style.marginTop="14px";
  const msg=document.createElement("div");msg.className="hint";msg.style.marginTop="12px";
  const foot=document.createElement("div");foot.style.marginTop="16px";
  foot.appendChild(btn(t("Save"),"pri",async()=>{
    const d=readForm(WEBUI_FIELDS);
    msg.textContent=t("Saving...");out.innerHTML="";
    try{
      const r=await api("webui","POST",d);
      msg.innerHTML=esc(r.note||t("Saved."))+(r.url?" "+t("You should be able to reach it at <b>{url}</b> once DNS points here.",{url:esc(r.url)}):"");
      if(r.actions&&r.actions.length){
        out.innerHTML="<table><tbody>"+r.actions.map(a=>"<tr><td style='width:90px'><span class='pill "+
          (a.action==="created"?"up":a.action==="updated"?"warn":"off")+"'>"+esc(t(a.action))+"</span></td><td>"+
          esc(a.type)+"</td><td class=mono>"+esc(a.name)+"</td></tr>").join("")+"</tbody></table>";
      }
      if(r.removed&&r.removed.length){
        out.innerHTML="<table><tbody>"+r.removed.map(x=>"<tr><td style='width:90px'><span class='pill off'>"+t("removed")+"</span></td><td>"+
          esc(x.type)+"</td><td class=mono>"+esc(x.name)+"</td></tr>").join("")+"</tbody></table>";
      }
      (r.warnings||[]).forEach(w=>{const d2=document.createElement("div");d2.className="hint";d2.style.marginTop="10px";
        d2.textContent="! "+w;out.appendChild(d2);});
      if(r.applied)msg.innerHTML+=r.applied.ok?" "+t("Applied."):(" "+t("Apply FAILED: {error}",{error:esc(r.applied.error||"")}));
      refreshStatus();
    }catch(e){msg.textContent=e.message;}
  }));
  bd.appendChild(foot);bd.appendChild(msg);bd.appendChild(out);
  if(cur.exposed_directly){
    const w=document.createElement("p");w.className="hint";w.style.marginTop="16px";
    w.innerHTML=t("This UI currently listens on <span class=mono>{addr}</span>, reachable from anywhere "+
      "in plain HTTP. Once the HTTPS name works, set <span class=mono>HAM_LISTEN=127.0.0.1</span> in the "+
      "service unit and restart it, so only HAProxy can reach the UI.",{addr:esc(cur.listen)+":"+esc(cur.port)});
    bd.appendChild(w);
  }
  card.appendChild(bd);c.appendChild(card);
}
