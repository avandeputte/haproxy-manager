import { $, HEALTH_LABEL, api, btn, closeDlg, esc, fieldRow, list, openDlg, readForm, showText } from "../core.js";
import { refreshStatus, route } from "../shell.js";
import { CERT_STATUS } from "../pages/certificates.js";
import { state } from "../state.js";

/* ---- services (the simple view) ---- */
export const WIZ_FIELDS=[
 {k:"url",l:"Public URLs",t:"textarea",
  h:"One per line. Several names are alternatives that all reach the same servers, e.g. "+
    "https://app.example.com and https://www.example.com. A path like /api is allowed on a single "+
    "URL, and tcp://0.0.0.0:3306 forwards a raw TCP port."},
 {k:"target",l:"Forward to",t:"text",
  h:"e.g. http://192.168.1.100:1781. Several (comma separated) are load balanced, and each may be named: galera1=192.168.1.81:3306"},
 {k:"name",l:"Name",t:"text",h:"Optional -- derived from the host name or port when left empty"},
 {k:"balance",l:"Load balancing",t:"select",d:"roundrobin",o:["roundrobin","leastconn","source","static-rr","uri"],
  h:"source keeps a client on one server by IP; the default for tcp:// services"},
 {k:"persistence",l:"Stickiness",t:"select",d:"none",o:["none","source","cookie"],
  h:"source = a stick table on the client IP (works for TCP). cookie = HTTP only."},
 {k:"stick_type",l:"Stick table type",t:"select",d:"ip",o:["ip","ipv6"],h:"ip stores IPv4 addresses; ipv6 also holds IPv4-mapped ones"},
 {k:"stick_size",l:"Stick table size",t:"text",d:"50k"},
 {k:"stick_expire",l:"Stick table expiry",t:"text",d:"30m"},
 {k:"cert_mode",l:"Certificate",t:"select",d:"auto",
  o:["auto","new","none"],
  h:"HTTPS only. \"auto\" reuses an existing certificate that already covers this host -- including a wildcard -- and only requests a new one when nothing does."},
 {k:"account",l:"ACME account",t:"ref",ref:"acme/accounts",h:"For a new certificate; only needed when you have more than one"},
 {k:"challenge",l:"Challenge type",t:"ref",ref:"acme/challenges"},
 {k:"health",l:"Health check",t:"select",d:"http",o:["none","tcp","http","pgsql","mysql"],
  h:"How HAProxy decides a server is alive. Dead servers are taken out of rotation."},
 {k:"health_interval",l:"Check every",t:"text",d:"2s",h:"e.g. 2s, 10s"},
 {k:"health_uri",l:"Request path",t:"text",d:"/",h:"For the HTTP check, e.g. /health"},
 {k:"health_status",l:"Expected status",t:"text",d:"200",h:"For the HTTP check. Leave empty to accept any 2xx/3xx."},
 {k:"health_method",l:"Request method",t:"select",d:"GET",o:["GET","HEAD","OPTIONS","POST"]},
 {k:"health_version",l:"HTTP version",t:"select",d:"",o:["","HTTP/1.1","HTTP/2"],
  h:"Leave empty unless the checked service needs one -- Patroni's REST API wants HTTP/2"},
 {k:"health_host",l:"Host header",t:"text",h:"Sent with the check request, e.g. localhost"},
 {k:"health_user",l:"Database user",t:"text",h:"For the database checks. Only the login handshake runs -- no password is sent -- so an unprivileged account is enough."},
 {k:"check_port",l:"Check port",t:"text",
  h:"Optional. Check a different port from the one traffic uses -- e.g. route to PostgreSQL on 5432 while checking Patroni's HTTP API on 8008."},
 {k:"timeout_connect",l:"Connect timeout",t:"text",h:"Optional, for this pool only, e.g. 5s"},
 {k:"timeout_server",l:"Server timeout",t:"text",h:"Optional, for this pool only, e.g. 30s. Long-lived connections such as databases usually need more than the default."},
 {k:"log_health_checks",l:"Log health check changes",t:"bool",h:"option log-health-checks -- records every up/down transition"},
 {k:"http_redirect",l:"Redirect HTTP to HTTPS",t:"bool",d:true,h:"Also listens on port 80 and sends visitors to HTTPS"},
 {k:"apply",l:"Apply immediately",t:"bool",d:true,h:"Write haproxy.cfg and reload once the objects are created"},
];
/* which of the health_* rows make sense for each check kind */
export const HEALTH_SHOWS={none:[],tcp:["health_interval"],
  http:["health_interval","health_uri","health_status","health_method","health_version","health_host"],
  pgsql:["health_interval","health_user"],mysql:["health_interval","health_user"]};
export const CERT_MODE_LABEL={auto:"auto -- reuse one that covers this host",
                       new:"always request a new certificate",
                       none:"no certificate"};

/* Tell the user which certificate a host will end up using, before they commit. */
export async function updateCertNote(note){
  const raw=(document.getElementById("f_url")||{}).value||"";
  const mode=(document.getElementById("f_cert_mode")||{}).value||"auto";
  let host="";
  try{host=new URL(raw.includes("://")?raw:"https://"+raw).hostname;}catch(e){}
  if(!host||!raw.trim().toLowerCase().startsWith("https")){note.innerHTML="";return;}
  if(mode==="none"){note.innerHTML='<span class=sub>No certificate will be attached -- the listener still needs one to start TLS.</span>';return;}
  if(mode==="new"){note.innerHTML='<span class=sub>A new certificate will be requested for '+esc(host)+".</span>";return;}
  note.innerHTML='<span class=sub>Checking for an existing certificate...</span>';
  try{
    const r=await api("acme/cover?host="+encodeURIComponent(host));
    if(r.covered){
      const cls=CERT_STATUS[r.status]?CERT_STATUS[r.status][0]:"off";
      note.innerHTML='<span class="pill '+cls+'">'+esc(r.how==="wildcard"?"wildcard match":"exact match")+"</span> "+
        "Will reuse <b>"+esc(r.name)+"</b> <span class=mono>("+esc(r.domains.join(", "))+")</span>"+
        (r.days_left!==null&&r.days_left!==undefined?" &mdash; expires in "+esc(r.days_left)+" days":"")+
        ". No new certificate will be requested.";
    }else{
      note.innerHTML='<span class=sub>No existing certificate covers '+esc(host)+
        " &mdash; a new one will be requested. Tip: a wildcard certificate for <span class=mono>*."+
        esc(host.split('.').slice(1).join('.'))+"</span> would cover every subdomain at once.</span>";
    }
  }catch(e){note.innerHTML='<span class=sub>'+esc(e.message)+"</span>";}
}

let recipes=null;                      /* fetched once, then reused */
export async function loadRecipes(){
  if(recipes)return recipes;
  try{recipes=(await api("recipes")).recipes||[];}catch(e){recipes=[];}
  return recipes;
}

export function openWizard(prefill){
  const wrap=document.createElement("div");

  /* A recipe fills in everything except the name to publish and the servers
     behind it. Only offered for a new service: applying one to an existing
     service would quietly rewrite settings that are already in use. */
  let picker=null;
  if(!prefill){
    picker=document.createElement("div");
    picker.className="bd";
    picker.style.cssText="border:1px solid var(--hair);border-radius:6px;padding:10px 12px;margin-bottom:14px";
    picker.innerHTML='<div class=fl style="margin-bottom:6px">Start from a recipe</div>';
    const sel=document.createElement("select");sel.id="f_recipe";
    sel.innerHTML='<option value="">Nothing — fill it in myself</option>';
    const note=document.createElement("div");note.className="hint";note.style.marginTop="8px";
    note.textContent="Well-known services come with the right ports, checks and timeouts already set.";
    picker.appendChild(sel);picker.appendChild(note);
    loadRecipes().then(list=>{
      const byCat={};
      list.forEach(r=>{(byCat[r.category]=byCat[r.category]||[]).push(r);});
      Object.keys(byCat).forEach(cat=>{
        const g=document.createElement("optgroup");g.label=cat;
        byCat[cat].forEach(r=>{
          const o=document.createElement("option");o.value=r.id;o.textContent=r.name;g.appendChild(o);
        });
        sel.appendChild(g);
      });
      sel.onchange=()=>{
        const r=list.find(x=>x.id===sel.value);
        if(!r){note.textContent="Well-known services come with the right ports, checks and timeouts already set.";return;}
        note.innerHTML="<b>"+esc(r.summary)+"</b><br>"+esc(r.notes);
        Object.keys(r.fields).forEach(k=>{
          const cell=(rows[k]||[])[1];
          const el=cell&&cell.querySelector("input,select,textarea");
          if(!el)return;
          if(el.type==="checkbox")el.checked=!!r.fields[k];
          else el.value=r.fields[k];
        });
        syncRows();
      };
    });
    wrap.appendChild(picker);
  }

  const frm=document.createElement("div");frm.className="frm";
  const rows={};
  WIZ_FIELDS.forEach(f=>{
    const cells=fieldRow(f,prefill?prefill[f.k]:undefined);
    rows[f.k]=cells;
    cells.forEach(el=>frm.appendChild(el));
  });
  wrap.appendChild(frm);
  // friendlier labels than the raw option values
  const sel=frm.querySelector("#f_cert_mode");
  if(sel)[...sel.options].forEach(o=>{o.textContent=CERT_MODE_LABEL[o.value]||o.value;});
  const hsel=frm.querySelector("#f_health");
  if(hsel)[...hsel.options].forEach(o=>{o.textContent=HEALTH_LABEL[o.value]||o.value;});
  const setRow=(k,on)=>{(rows[k]||[]).forEach(el=>{el.style.display=on?"":"none";});};
  const syncRows=()=>{
    const show=HEALTH_SHOWS[hsel?hsel.value:"none"]||[];
    ["health_interval","health_uri","health_status","health_user","health_method",
     "health_version","health_host"].forEach(k=>setRow(k,show.includes(k)));
    setRow("check_port",(hsel?hsel.value:"none")!=="none");
    // tcp:// forwards a raw port: no host name, so no certificate and no redirect
    const isTcp=((document.getElementById("f_url")||{}).value||"").trim().toLowerCase().startsWith("tcp");
    ["cert_mode","account","challenge","http_redirect"].forEach(k=>setRow(k,!isTcp));
    const st=(document.getElementById("f_persistence")||{}).value;
    ["stick_type","stick_size","stick_expire"].forEach(k=>setRow(k,st==="source"));
    /* A raw TCP port cannot answer an HTTP check -- unless the check is aimed at
       a different port, which is exactly how Patroni is fronted: traffic to
       PostgreSQL on 5432, the check to its REST API on 8008. */
    const cport=((document.getElementById("f_check_port")||{}).value||"").trim();
    if(isTcp&&!cport&&hsel&&hsel.value==="http")hsel.value="tcp";
  };
  if(hsel)hsel.addEventListener("change",syncRows);
  ["f_url","f_persistence"].forEach(id=>{
    const el=document.getElementById(id);
    if(el){el.addEventListener("change",syncRows);el.addEventListener("blur",syncRows);}
  });
  syncRows();
  const note=document.createElement("div");note.className="hint";note.style.margin="2px 0 0";
  const noteRow=document.createElement("div");noteRow.appendChild(note);
  frm.appendChild(document.createElement("div"));frm.appendChild(noteRow);
  ["f_url","f_cert_mode"].forEach(id=>{
    const el=document.getElementById(id);
    if(el){el.addEventListener("change",()=>updateCertNote(note));el.addEventListener("blur",()=>updateCertNote(note));}
  });
  updateCertNote(note);
  const out=document.createElement("div");out.style.marginTop="16px";wrap.appendChild(out);
  const err=document.createElement("div");err.className="err";

  const read=()=>{
    const d=readForm(WIZ_FIELDS);
    d.certificate=d.cert_mode!=="none";        // "none" attaches nothing
    d.new_certificate=d.cert_mode==="new";     // otherwise reuse whatever covers the host
    if(prefill&&prefill.certificate_id&&d.cert_mode==="auto")d.certificate_id=prefill.certificate_id;
    if(prefill&&prefill.service_id)d.service_id=prefill.service_id;   // edit, not publish anew
    d.health={type:d.health,interval:d.health_interval,uri:d.health_uri,
              status:d.health_status,user:d.health_user,method:d.health_method,
              version:d.health_version,host:d.health_host};
    ["cert_mode","health_interval","health_uri","health_status","health_user",
     "health_method","health_version","health_host"].forEach(k=>delete d[k]);
    return d;   // balance / persistence / stick_* / check_port / log_health_checks pass straight through
  };
  const show=(r,saved)=>{
    out.innerHTML="";
    const box=document.createElement("div");box.className="card";box.style.margin="0";
    box.innerHTML='<div class=hd><h2>'+(saved?"Created":"What this will create")+'</h2></div>';
    const bd=document.createElement("div");bd.className="bd";
    bd.innerHTML='<div class=mono style="margin-bottom:10px">'+esc(r.public)+" &rarr; "+esc(r.target)+"</div>"+
      "<table><tbody>"+r.actions.map(a=>"<tr><td style='width:90px'><span class='pill "+
        (a.action==="created"?"up":a.action==="updated"?"warn":"off")+"'>"+esc(a.action)+"</span></td><td>"+
        esc(a.type)+"</td><td class=mono>"+esc(a.name)+"</td></tr>").join("")+"</tbody></table>"+
      (r.warnings||[]).map(w=>'<div class=hint style="margin-top:10px">! '+esc(w)+"</div>").join("");
    bd.appendChild(btn("Show the generated haproxy.cfg","sm",()=>showText("haproxy.cfg (preview)",r.preview)));
    if(saved&&r.applied)bd.appendChild(document.createTextNode(" "+(r.applied.ok?"Applied.":"Apply FAILED: "+(r.applied.error||""))));
    box.appendChild(bd);out.appendChild(box);
  };

  const preview=btn("Preview","",async()=>{
    err.textContent="";
    try{show(await api("wizard/publish","POST",Object.assign(read(),{dry_run:true})),false);}
    catch(e){err.textContent=e.message;}
  });
  const create=btn("Publish","pri",async()=>{
    err.textContent="";create.disabled=true;
    try{
      const r=await api("wizard/publish","POST",read());
      show(r,true);
      create.disabled=true;preview.disabled=true;
      await route();refreshStatus();
    }catch(e){err.textContent=e.message;create.disabled=false;}
  });
  openDlg(prefill?"Edit service":"Publish a service",wrap,[err,btn("Close","",closeDlg),preview,create]);
}

export async function renderServices(){
  const c=$("#content");c.innerHTML="";
  c.appendChild(await servicesCard());
}

/* The services table, shared by the Services page and the Overview. */
export async function servicesCard(){
  const [svcs]=await Promise.all([api("services"),list("acme/accounts",true),list("acme/challenges",true)]);
  const card=document.createElement("div");card.className="card";
  const hd=document.createElement("div");hd.className="hd";
  hd.innerHTML="<h2>Services</h2><div class=sp></div>";
  if(!state.readOnly)hd.appendChild(btn("Publish a service","pri sm",()=>openWizard()));
  card.appendChild(hd);
  const bd=document.createElement("div");
  if(!svcs.length){
    bd.innerHTML='<div class=empty>Nothing published yet.<br><br>'+
      '"Publish a service" maps a public URL such as <span class=mono>https://app.example.com</span> to a server '+
      'such as <span class=mono>http://192.168.1.100:1781</span> and creates everything HAProxy needs for it.</div>';
  }else{
    const t=document.createElement("table");
    t.innerHTML="<thead><tr><th>Public URL</th><th>Forwards to</th><th>Certificate</th><th></th></tr></thead>";
    const tb=document.createElement("tbody");
    svcs.forEach(s=>{
      const tr=document.createElement("tr");
      tr.innerHTML="<td>"+(s.urls||[s.url]).map(u=>"<span class=mono>"+esc(u)+"</span>").join("<br>")+
          (s.managed==="web-ui"?'<div class=sub>this node\'s own web UI &mdash; managed under '+
             'System &rsaquo; Web UI access, and never synced to the other nodes</div>':"")+
          (s.enabled?"":"<div class=sub>disabled</div>")+"</td>"+
        "<td class=mono>"+(s.targets.length?s.targets.map(esc).join("<br>"):"<span class=sub>no server</span>")+
          "<div class=sub>pool "+esc(s.pool||"—")+"</div></td>"+
        /* just which certificate serves it; its state lives on the Certificates page */
        "<td>"+(s.certificate
                 ? esc(s.certificate)+(s.certificate_match==="wildcard"?" <span class=sub>(wildcard)</span>":"")
                 : '<span class=sub>&mdash;</span>')+"</td>";
      const act=document.createElement("td");act.style.textAlign="right";act.style.whiteSpace="nowrap";
      if(!state.readOnly&&s.managed!=="web-ui"){
      act.appendChild(btn("Edit","sm",()=>openWizard({
        service_id:s.id,
        url:(s.urls||[s.url]).join("\n"),
        target:s.targets.map(t=>s.scheme==="tcp"?t.replace(/^tcp:\/\//,""):t).join(", "),
        name:s.pool||"",
        balance:s.balance,persistence:s.persistence,stick_type:s.stick_type,
        stick_size:s.stick_size,stick_expire:s.stick_expire,
        log_health_checks:s.log_health_checks,check_port:s.check_port,
        health:(s.health||{}).type,health_interval:(s.health||{}).interval,
        health_uri:(s.health||{}).uri,health_status:(s.health||{}).status,
        health_user:(s.health||{}).user,health_method:(s.health||{}).method,
        health_version:(s.health||{}).version,health_host:(s.health||{}).host,
        timeout_connect:s.timeout_connect,timeout_server:s.timeout_server,
        certificate_id:s.certificate_id,
      })));
      act.appendChild(document.createTextNode(" "));
      act.appendChild(btn("Delete","sm dngr",async()=>{
        if(!confirm("Remove "+s.url+"?\n\nThe rule, its conditions, the backend pool and its servers are deleted "+
                    "when nothing else uses them. Certificates and the listening service are kept."))return;
        try{
          const r=await api("services/"+s.id,"DELETE");
          showText("Removed "+s.url,(r.removed||[]).map(x=>"- "+x.type+" "+x.name).join("\n")+"\n\n"+r.note);
          await route();refreshStatus();
        }catch(e){alert(e.message);}
      }));}
      tr.appendChild(act);tb.appendChild(tr);
    });
    t.appendChild(tb);bd.appendChild(t);
    const hint=document.createElement("div");hint.className="hint";hint.style.padding="10px 16px";
    hint.textContent="Each row is a host name routed to a backend pool. The Advanced pages expose the same objects individually.";
    bd.appendChild(hint);
  }
  card.appendChild(bd);
  return card;
}
