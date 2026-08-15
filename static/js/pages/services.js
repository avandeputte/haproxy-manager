import { $, HEALTH_LABEL, api, btn, closeDlg, esc, fieldEl, fieldRow, list, openDlg, readForm, showText } from "../core.js";
import { refreshStatus, route } from "../shell.js";
import { CERT_STATUS } from "../pages/certificates.js";
import { state } from "../state.js";
import { sparkCaption, trafficSpark } from "../sparkline.js";

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
 {k:"notify_mode",l:"Alert when",t:"select",d:"servers",o:["servers","outage","off"],
  h:"What losing a server means here. For a pool where only one server is meant to pass -- a Patroni leader, a primary with standbys -- the rest failing is normal running, so alert only when no server is left."},
 {k:"allow_src",l:"Allowed networks",t:"textarea",
  h:"Optional. One address or CIDR per line, e.g. 192.168.0.0/16 -- requests from anywhere else are refused. Works for tcp:// services too. Empty allows all."},
 {k:"auth_enabled",l:"Require a sign-in",t:"bool",
  h:"Ask visitors for a user name and password before letting them through. HAProxy checks it, so an unauthenticated request never reaches the servers. Manage the accounts under Sign-in."},
 {k:"auth_groups",l:"Allowed groups",t:"refmulti",ref:"access/groups",
  h:"Leave nothing ticked to admit any user"},
 {k:"auth_realm",l:"Sign-in prompt",t:"text",
  h:"What the browser shows above its password box. Defaults to the service name."},
 {k:"auth_exempt",l:"Skip the sign-in from",t:"textarea",
  h:"Optional. Networks trusted without a password -- typically the LAN, e.g. 192.168.1.0/24. Everyone else is asked to sign in."},
 {k:"oauth_enabled",l:"Require single sign-on (OIDC)",t:"bool",
  h:"Send visitors to the identity provider before letting them through. HAProxy verifies the session and this service's allow-list on every request. Configure the provider under Sign-in > Single sign-on."},
 {k:"oauth_allow",l:"Allowed identities",t:"textarea",
  h:"One per line: an email, a whole domain as @example.com, or * for anyone the provider signs in."},
 {k:"oauth_forward",l:"Pass the signed-in email to the servers",t:"bool",
  h:"Sets X-Auth-Request-Email and Remote-User on forwarded requests, so apps that trust a "+
    "proxy identity (Grafana auth-proxy and friends) sign the visitor in themselves. Any copy "+
    "of these headers a client sends is stripped on every service, so the value is always this "+
    "proxy's word. Only safe while the app is reachable through the proxy alone."},
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
export const NOTIFY_MODE_LABEL={servers:"a server is lost",
                       outage:"no server is left -- some servers down is normal here",
                       off:"never -- this service looks after itself"};

/* Tell the user which certificate a host will end up using, before they commit. */
export async function updateCertNote(note){
  const raw=(fieldEl("url")||{}).value||"";
  const mode=(fieldEl("cert_mode")||{}).value||"auto";
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
  const nsel=frm.querySelector("#f_notify_mode");
  if(nsel)[...nsel.options].forEach(o=>{o.textContent=NOTIFY_MODE_LABEL[o.value]||o.value;});
  const setRow=(k,on)=>{(rows[k]||[]).forEach(el=>{el.style.display=on?"":"none";});};
  const val=k=>((fieldEl(k)||{}).value||"");
  const syncRows=()=>{
    const show=HEALTH_SHOWS[hsel?hsel.value:"none"]||[];
    ["health_interval","health_uri","health_status","health_user","health_method",
     "health_version","health_host"].forEach(k=>setRow(k,show.includes(k)));
    setRow("check_port",(hsel?hsel.value:"none")!=="none");
    // tcp:// forwards a raw port: no host name, so no certificate and no redirect
    const isTcp=val("url").trim().toLowerCase().startsWith("tcp");
    ["cert_mode","account","challenge","http_redirect"].forEach(k=>setRow(k,!isTcp));
    /* Basic authentication is part of HTTP; a raw TCP port has nowhere to
       carry it, so the whole idea is hidden rather than offered and refused. */
    const authOn=!isTcp&&!!(fieldEl("auth_enabled")||{}).checked;
    setRow("auth_enabled",!isTcp);
    ["auth_groups","auth_realm","auth_exempt"].forEach(k=>setRow(k,authOn));
    const oauthOn=!isTcp&&!!(fieldEl("oauth_enabled")||{}).checked;
    setRow("oauth_enabled",!isTcp);
    setRow("oauth_allow",oauthOn);
    setRow("oauth_forward",oauthOn);
    ["stick_type","stick_size","stick_expire"].forEach(k=>setRow(k,val("persistence")==="source"));
    /* A raw TCP port cannot answer an HTTP check -- unless the check is aimed at
       a different port, which is exactly how Patroni is fronted: traffic to
       PostgreSQL on 5432, the check to its REST API on 8008. */
    if(isTcp&&!val("check_port").trim()&&hsel&&hsel.value==="http")hsel.value="tcp";
  };
  const note=document.createElement("div");note.className="hint";note.style.margin="2px 0 0";
  const noteRow=document.createElement("div");noteRow.appendChild(note);
  frm.appendChild(document.createElement("div"));frm.appendChild(noteRow);
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
    d.auth={enabled:d.auth_enabled,groups:d.auth_groups,realm:d.auth_realm,
            exempt:d.auth_exempt};
    d.oauth={enabled:d.oauth_enabled,allow:d.oauth_allow,forward:d.oauth_forward};
    ["cert_mode","health_interval","health_uri","health_status","health_user",
     "health_method","health_version","health_host",
     "auth_enabled","auth_groups","auth_realm","auth_exempt",
     "oauth_enabled","oauth_allow","oauth_forward"].forEach(k=>delete d[k]);
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

  /* Only now are these fields in the document, and only elements that are in
     it can be found by id or usefully listened to. Wiring the form while it
     was still being built left every one of these listeners on nothing: the
     rows that should appear and disappear as the URL changes stayed as they
     were first drawn. */
  if(hsel)hsel.addEventListener("change",syncRows);
  ["url","persistence","auth_enabled"].forEach(k=>{
    const el=fieldEl(k);
    if(el){el.addEventListener("change",syncRows);el.addEventListener("input",syncRows);
           el.addEventListener("blur",syncRows);}
  });
  ["url","cert_mode"].forEach(k=>{
    const el=fieldEl(k);
    if(el){el.addEventListener("change",()=>updateCertNote(note));
           el.addEventListener("blur",()=>updateCertNote(note));}
  });
  syncRows();
  updateCertNote(note);
}

export async function renderServices(){
  const c=$("#content");c.innerHTML="";
  c.appendChild(await servicesCard());
}

/* The services table, shared by the Services page and the Overview. */
export async function servicesCard(){
  /* The history is a separate read and a failure to get it must not take the
     page with it: a sparkline is the least important thing on it. */
  const [svcs,traffic,probes]=await Promise.all([
    api("services"),
    api("traffic").catch(()=>({at:[],series:{}})),
    /* the last round of URL probes; their absence must not cost the page */
    api("probes").catch(()=>({results:[]})),
    list("acme/accounts",true),list("acme/challenges",true),
    /* the wizard's group picker reads this cache */
    list("access/groups",true)]);
  /* keyed by URL, kept only when something is wrong: a page dotted with green
     "fine" pills says less than one red pill on the row that is not */
  const probeBad={};
  (probes.results||[]).forEach(p=>{if(p.state!=="ok")probeBad[p.url]=p;});
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
    t.innerHTML="<thead><tr><th>Public URL</th><th>Forwards to</th><th>Traffic</th>"+
      "<th>Certificate</th><th></th></tr></thead>";
    const tb=document.createElement("tbody");
    svcs.forEach(s=>{
      const tr=document.createElement("tr");
      const auth=s.auth||{};
      tr.innerHTML="<td>"+(s.urls||[s.url]).map(u=>"<span class=mono>"+esc(u)+"</span>"+
          (probeBad[u]?' <span class="pill '+(probeBad[u].state==="down"?"down":"warn")+
            '" title="'+esc(probeBad[u].note)+'">'+
            (probeBad[u].state==="down"?"not answering":"certificate")+"</span>":"")).join("<br>")+
          (s.managed==="web-ui"?'<div class=sub>this node\'s own web UI &mdash; managed under '+
             'Settings &rsaquo; Web UI access, and never synced to the other nodes</div>':"")+
          /* Whether a visitor is asked to sign in belongs beside the address:
             it is part of what this URL does, not a detail of the pool. */
          (auth.enabled?'<div class=sub>sign-in required &mdash; '+
             ((auth.group_names||[]).length?esc(auth.group_names.join(", ")):"any user")+
             (auth.exempt?", except from "+esc(auth.exempt.split("\n").join(", ")):"")+"</div>":"")+
          ((s.oauth||{}).enabled?'<div class=sub>sign-in via SSO &mdash; '+
             esc(((s.oauth||{}).allow||[]).map(a=>a==="*"?"anyone the provider signs in":a).join(", "))+"</div>":"")+
          (s.allow_src?'<div class=sub>only from '+
             esc(s.allow_src.split("\n").join(", "))+"</div>":"")+
          (s.maintenance?'<div><span class="pill warn">paused &mdash; answering 503</span></div>':"")+
          (s.enabled?"":"<div class=sub>disabled</div>")+"</td>"+
        "<td class=mono>"+(s.targets.length?s.targets.map(esc).join("<br>"):"<span class=sub>no server</span>")+
          "<div class=sub>pool "+esc(s.pool||"—")+"</div></td>"+
        /* Requests a minute over the last day, with server errors over them.
           Answers "when did this start", which the live figures cannot. */
        "<td>"+trafficSpark((traffic.series||{})["be_"+(s.pool||"")],{width:110,height:22})+
          (traffic.at&&traffic.at.length?'<div class=sub>'+esc(sparkCaption(traffic.at))+"</div>":"")+
        "</td>"+
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
        notify_mode:s.notify_mode,
        health:(s.health||{}).type,health_interval:(s.health||{}).interval,
        health_uri:(s.health||{}).uri,health_status:(s.health||{}).status,
        health_user:(s.health||{}).user,health_method:(s.health||{}).method,
        health_version:(s.health||{}).version,health_host:(s.health||{}).host,
        timeout_connect:s.timeout_connect,timeout_server:s.timeout_server,
        auth_enabled:(s.auth||{}).enabled,auth_groups:(s.auth||{}).groups,
        auth_realm:(s.auth||{}).realm,auth_exempt:(s.auth||{}).exempt,
        oauth_enabled:(s.oauth||{}).enabled,
        oauth_allow:((s.oauth||{}).allow||[]).join("\n"),
        oauth_forward:(s.oauth||{}).forward,
        allow_src:s.allow_src,
        certificate_id:s.certificate_id,
      })));
      act.appendChild(document.createTextNode(" "));
      act.appendChild(btn(s.maintenance?"Resume":"Pause","sm"+(s.maintenance?" warn":""),async()=>{
        if(!s.maintenance&&!confirm("Pause "+s.url+"?\n\nEvery request is answered with a clean "+
            "503 until it is resumed. The servers and their health checks are untouched."))return;
        try{
          await api("services/"+s.id+"/maintenance","POST",{on:!s.maintenance});
          await route();refreshStatus();
        }catch(e){alert(e.message);}
      }));
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
