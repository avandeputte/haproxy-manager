import { api, btn, closeDlg, esc, fieldRow, openDlg, readForm } from "../core.js";
import { boot, refreshStatus, route } from "../shell.js";
import { state } from "../state.js";

/* ---- first-run setup ---- */

export const JOIN_FIELDS=[
 {k:"peer_url",l:"An existing node",t:"text",h:"e.g. http://10.0.0.1:8080 -- any node already in the cluster"},
 {k:"peer_api_key",l:"Its API key",t:"password",h:"From Cluster > This node on that node"},
 {k:"node_url",l:"This node's URL",t:"text",h:"How the other nodes should reach this one"},
 {k:"interface",l:"Interface for the virtual IP",t:"combo",o:()=>state.setupIfaceOptions,
  h:"Leave empty to join without running Keepalived here yet"},
 {k:"priority",l:"Priority",t:"number",d:100,h:"Higher wins. Give every node a different value."},
 {k:"verify_tls",l:"Verify its TLS certificate",t:"bool"},
];
export const CREATE_FIELDS=[
 {k:"mode",l:"This node will",t:"select",d:"cluster",o:["cluster","standalone"]},
 {k:"vips",l:"Virtual IP addresses",t:"textarea",h:"One per line with prefix, e.g. 192.0.2.10/24. Other nodes will share these."},
 {k:"vrid",l:"Virtual router ID",t:"number",d:51,h:"1-255, unique among other VRRP groups on the network"},
 {k:"auth_pass",l:"VRRP password",t:"password",h:"Only the first 8 characters are used"},
 {k:"interface",l:"Interface",t:"combo",o:()=>state.setupIfaceOptions,h:"The interface that will carry the virtual IP"},
 {k:"priority",l:"Priority",t:"number",d:150,h:"Higher wins; this node is usually the preferred one"},
 {k:"node_url",l:"This node's URL",t:"text",h:"How other nodes will reach this one"},
];
export const MODE_LABEL={cluster:"start a new cluster with a shared virtual IP",
                  standalone:"run on its own -- no virtual IP, no other nodes"};

export async function maybeSetupWizard(){
  let st;
  try{st=await api("setup/state");}catch(e){return false;}
  if(st.complete)return false;
  state.setupIfaceOptions=(st.interfaces||[]).map(i=>({value:i.name,
    label:i.name+(i.addresses.length?" ("+i.addresses.join(", ")+")":" (no address)")}));
  setupChoice(st);
  return true;
}
export function setupChoice(st){
  const wrap=document.createElement("div");
  wrap.innerHTML='<p class=hint style="margin-bottom:16px">This is a fresh install of haproxy-manager on '+
    '<b>'+esc(st.hostname)+'</b>. What should it be?</p>';
  const mk=(title,text,fn)=>{
    const b=document.createElement("button");b.className="btn";
    b.style.cssText="display:block;width:100%;text-align:left;padding:14px 16px;margin-bottom:10px";
    b.innerHTML="<b>"+esc(title)+"</b><div class=hint style='margin-top:4px'>"+esc(text)+"</div>";
    b.onclick=fn;return b;
  };
  wrap.appendChild(mk("Join an existing cluster",
    "Point it at a node that is already running. It registers itself there and receives the whole "+
    "configuration, the cluster settings and the list of the other nodes.",()=>setupJoin(st)));
  wrap.appendChild(mk("Create a new cluster, or run standalone",
    "Set up the virtual IP this cluster will share, or skip that and run this node on its own. "+
    "Other nodes can join it later.",()=>setupCreate(st)));
  openDlg("Welcome",wrap,[
    btn("Set this up later","",async()=>{try{await api("setup/skip","POST",{});}catch(e){}closeDlg();boot();}),
  ]);
}
export function setupResult(title,r,extra){
  const wrap=document.createElement("div");
  wrap.innerHTML="<table><tbody>"+(r.steps||[]).map(s=>"<tr><td style='width:26px'>"+
      '<span class="pill up">&#10003;</span></td><td>'+esc(s)+"</td></tr>").join("")+"</tbody></table>"+
    (r.note?'<div class=hint style="margin-top:12px">! '+esc(r.note)+"</div>":"")+
    (r.applied?'<div class=hint style="margin-top:12px">'+(r.applied.ok?"Configuration applied."
        :"Apply failed: "+esc(r.applied.error||""))+"</div>":"")+
    (r.api_key?'<div class=hint style="margin-top:12px">This node\'s API key: <span class=mono>'+
        esc(r.api_key)+"</span><br>Other nodes need it to sync here.</div>":"")+
    (extra?'<div class=hint style="margin-top:12px">'+extra+"</div>":"");
  openDlg(title,wrap,[btn("Finish","pri",()=>{closeDlg();refreshStatus();route();})]);
}
export function setupForm(title,fields,intro,submit,st){
  const wrap=document.createElement("div");
  const p=document.createElement("p");p.className="hint";p.style.marginBottom="14px";p.innerHTML=intro;
  wrap.appendChild(p);
  const frm=document.createElement("div");frm.className="frm";
  const rows={};
  fields.forEach(f=>{
    const v=f.k==="node_url"?st.suggested_url:undefined;
    const cells=fieldRow(f,v);rows[f.k]=cells;cells.forEach(el=>frm.appendChild(el));
  });
  wrap.appendChild(frm);
  const sel=frm.querySelector("#f_mode");
  if(sel){
    [...sel.options].forEach(o=>{o.textContent=MODE_LABEL[o.value]||o.value;});
    const sync=()=>{const cluster=sel.value==="cluster";
      ["vips","vrid","auth_pass","interface","priority"].forEach(k=>
        (rows[k]||[]).forEach(el=>{el.style.display=cluster?"":"none";}));};
    sel.addEventListener("change",sync);sync();
  }
  const err=document.createElement("div");err.className="err";
  const go=btn("Continue","pri",async()=>{
    err.textContent="";go.disabled=true;
    try{await submit(readForm(fields));}
    catch(e){err.textContent=e.message;go.disabled=false;}
  });
  openDlg(title,wrap,[err,btn("Back","",()=>setupChoice(st)),go]);
}
export function setupJoin(st){
  setupForm("Join an existing cluster",JOIN_FIELDS,
    "This node will register itself with the node you name and ask it to send everything over. "+
    "Nothing on the other nodes changes except that they learn about this one.",
    async d=>{
      const r=await api("setup/join","POST",d);
      setupResult("Joined the cluster",r,
        r.synced?"":"Open the active node and press <b>Sync to all nodes now</b> to send the configuration here.");
    },st);
}
export function setupCreate(st){
  setupForm("Create a new cluster",CREATE_FIELDS,
    "Set the virtual IP the nodes will share. Other nodes join later by pointing at this one &mdash; "+
    "they will need this node's API key, shown at the end.",
    async d=>{
      const r=await api("setup/create","POST",d);
      setupResult(d.mode==="cluster"?"Cluster created":"Ready",r,
        "Next: <b>Services &rsaquo; Publish a service</b> to put something behind HAProxy.");
    },st);
}
