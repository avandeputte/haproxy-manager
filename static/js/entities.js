import { $, HEALTH_LABEL, api, btn, closeDlg, esc, fieldRow, list, lists, nameOf, openDlg, readForm, showText } from "./core.js";
import { refreshStatus, route } from "./shell.js";
import { certificateNotices, certExpiryCell, certLastCell, certStatusCell, dnsApiByHook, dnsApiOptions, dnsCredentialHelp, issueCert, loadAcmeHealth, loadCertStatus, loadDnsApis, openCertWizard, showCertLog } from "./pages/certificates.js";
import { state } from "./state.js";

/* ---- entity registry ---- */
/* Field types: text number bool select ref refmulti textarea password */
export const E={
 "haproxy/servers":{title:"Real Servers",add:"Add server",
  intro:"The upstream hosts traffic is forwarded to. Attach them to Backend Pools.",
  cols:[["name","Name"],["address","Address",r=>esc(r.address)+":"+esc(r.port)],
        ["opts","Options",r=>[r.ssl?"ssl":"",r.backup?"backup":""].filter(Boolean).join(", ")||"—"],
        ["enabled","Enabled",r=>r.enabled!==false?"yes":"no"]],
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"enabled",l:"Enabled",t:"bool",d:true},
   {k:"address",l:"Address",t:"text",h:"IP address or hostname of the real server"},
   {k:"port",l:"Port",t:"number"},
   {k:"weight",l:"Weight",t:"number",h:"Optional load-balancing weight (1-256)"},
   {k:"check_port",l:"Health check port",t:"text",h:"Optional. Leave empty to check the port traffic goes to."},
   {k:"ssl",l:"Encrypt to server (SSL)",t:"bool"},
   {k:"ssl_verify",l:"Verify server certificate",t:"bool"},
   {k:"backup",l:"Backup server",t:"bool",h:"Only receives traffic when all non-backup servers are down"},
   {k:"description",l:"Description",t:"text"}]},

 "haproxy/backends":{title:"Backend Pools",add:"Add pool",
  intro:"Groups of Real Servers with a balancing algorithm, health checks and persistence.",
  cols:[["name","Name"],["mode","Mode"],["balance","Balance",r=>r.balance||"roundrobin"],
        ["servers","Servers",r=>(r.servers||[]).map(id=>esc(nameOf("haproxy/servers",id))).join(", ")||"—"],
        ["hc","Check",r=>r.healthcheck_enabled?esc(nameOf("haproxy/healthchecks",r.healthcheck)):"off"]],
  refs:["haproxy/servers","haproxy/healthchecks","access/groups"],
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"enabled",l:"Enabled",t:"bool",d:true},
   {k:"mode",l:"Mode",t:"select",o:["http","tcp"],d:"http"},
   {k:"balance",l:"Balance algorithm",t:"select",o:["roundrobin","leastconn","source","static-rr","uri"],d:"roundrobin"},
   {k:"servers",l:"Servers",t:"refmulti",ref:"haproxy/servers"},
   {k:"healthcheck_enabled",l:"Enable health checking",t:"bool"},
   {k:"healthcheck",l:"Health Monitor",t:"ref",ref:"haproxy/healthchecks"},
   {k:"persistence",l:"Persistence",t:"select",o:["none","cookie","source"],d:"none",h:"cookie = HTTP only; source = stick table on the client IP, the usual choice for TCP"},
   {k:"cookie_name",l:"Cookie name",t:"text",h:"Defaults to SRVID"},
   {k:"timeout_connect",l:"Connect timeout",t:"text",h:"For this pool only, e.g. 5s"},
   {k:"timeout_server",l:"Server timeout",t:"text",h:"For this pool only, e.g. 30s"},
   {k:"timeout_check",l:"Check timeout",t:"text",h:"For this pool only"},
   {k:"stick_type",l:"Stick table type",t:"select",o:["ip","ipv6"],d:"ip",h:"HAProxy spells the IPv4 type \"ip\"; \"ipv4\" is not valid"},
   {k:"stick_size",l:"Stick table size",t:"text",h:"For source persistence, e.g. 50k"},
   {k:"stick_expire",l:"Stick table expiry",t:"text",h:"For source persistence, e.g. 30m"},
   {k:"log_health_checks",l:"Log health check changes",t:"bool",h:"option log-health-checks"},
   {k:"maintenance",l:"Maintenance mode",t:"bool",h:"Every request is answered with a clean 503 while on; the servers and their health checks stay untouched"},
   {k:"notify_mode",l:"Alert when",t:"select",o:["servers","outage","off"],d:"servers",
    h:"servers: any server lost is a warning. outage: alert only when no server is left -- for pools where only one is meant to pass, like a Patroni leader. off: never."},
   {k:"allow_src",l:"Allowed networks",t:"textarea",h:"Optional. One address or CIDR per line; requests from anywhere else are refused. Works in TCP mode too. An entry that does not parse refuses everyone rather than being ignored."},
   {k:"auth_enabled",l:"Require a sign-in",t:"bool",h:"HTTP basic authentication in front of this pool. HTTP mode only -- a raw TCP port has nowhere to put one."},
   {k:"auth_groups",l:"Allowed groups",t:"refmulti",ref:"access/groups",h:"Leave nothing ticked to admit any user"},
   {k:"auth_realm",l:"Sign-in prompt",t:"text",h:"What the browser shows above its password box. Defaults to the pool name."},
   {k:"auth_exempt_src",l:"Skip the sign-in from",t:"textarea",h:"Networks trusted without a password, one per line -- typically the LAN"},
   {k:"oauth_enabled",l:"Require single sign-on (OIDC)",t:"bool",
    h:"Send visitors to the identity provider first. One sign-in per service: not together with basic auth. Configure the provider under Sign-in > Single sign-on."},
   {k:"oauth_allow",l:"SSO allowed identities",t:"textarea",
    h:"One per line: an email, @example.com for a domain, or * for anyone the provider signs in."},
   {k:"custom",l:"Extra directives",t:"textarea",h:"Advanced. Raw lines added inside this backend, for anything the fields above do not cover -- for example \"http-reuse safe\". One per line. See the HAProxy configuration manual: https://docs.haproxy.org/2.6/configuration.html"}]},

 "haproxy/frontends":{title:"Public Services",add:"Add service",
  intro:"Listening sockets clients connect to (frontends). Certificates come from the Certificates page.",
  cols:[["name","Name"],["binds","Listen on",r=>"<span class=mono>"+esc((r.binds||"").split("\n").filter(Boolean).join(", "))+"</span>"],
        ["mode","Mode",r=>esc(r.mode||"http")+(r.ssl_enabled?" +ssl":"")],
        ["be","Default pool",r=>r.default_backend?esc(nameOf("haproxy/backends",r.default_backend)):"—"],
        ["enabled","Enabled",r=>r.enabled!==false?"yes":"no"]],
  refs:["haproxy/backends","haproxy/rules","acme/certificates"],
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"enabled",l:"Enabled",t:"bool",d:true},
   {k:"binds",l:"Listen addresses",t:"textarea",h:"One per line, e.g. 0.0.0.0:80 or the shared VIP such as 192.0.2.10:443"},
   {k:"mode",l:"Mode",t:"select",o:["http","tcp"],d:"http"},
   {k:"ssl_enabled",l:"Enable SSL offloading",t:"bool"},
   {k:"certificates",l:"Certificates",t:"refmulti",ref:"acme/certificates",h:"First certificate is the default; SNI selects among the rest"},
   {k:"http2",l:"Enable HTTP/2",t:"bool"},
   {k:"forwardfor",l:"Add X-Forwarded-For",t:"bool",d:true},
   {k:"http_to_https",l:"Redirect HTTP to HTTPS",t:"bool",h:"For plain HTTP services on port 80. ACME challenge requests are never redirected."},
   {k:"default_backend",l:"Default Backend Pool",t:"ref",ref:"haproxy/backends"},
   {k:"rules",l:"Rules",t:"refmulti",ref:"haproxy/rules",h:"Applied in the order shown here (the order of the Rules list)"},
   {k:"custom",l:"Extra directives",t:"textarea",h:"Advanced. Raw lines added inside this frontend, for anything the fields above do not cover. One per line. See the HAProxy configuration manual: https://docs.haproxy.org/2.6/configuration.html"}]},

 "haproxy/conditions":{title:"Conditions",add:"Add condition",
  intro:"Named tests (ACLs) evaluated against traffic. Combine them in Rules.",
  cols:[["name","Name"],["type","Type"],["value","Value",r=>"<span class=mono>"+esc((r.param?r.param+" = ":"")+(r.value||""))+"</span>"],
        ["negate","Negate",r=>r.negate?"yes":"no"]],
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"type",l:"Condition type",t:"select",o:["host_matches","host_starts_with","host_ends_with","path_matches","path_starts_with","path_ends_with","path_contains","url_parameter","http_header","source_ip","ssl_sni","custom"],d:"host_matches"},
   {k:"param",l:"Header / parameter name",t:"text",h:"Only for the http_header and url_parameter types"},
   {k:"value",l:"Value",t:"text",h:"For type custom: a raw ACL expression"},
   {k:"negate",l:"Negate",t:"bool"},
   {k:"description",l:"Description",t:"text"}]},

 "haproxy/rules":{title:"Rules",add:"Add rule",
  intro:"Actions taken when Conditions match: select a pool, redirect, set headers, deny.",
  cols:[["name","Name"],["type","Action"],
        ["cond","Conditions",r=>(r.conditions||[]).map(id=>esc(nameOf("haproxy/conditions",id))).join(", ")||"always"],
        ["tgt","Target",r=>r.type==="use_backend"?esc(nameOf("haproxy/backends",r.backend)):esc([r.param1,r.param2].filter(Boolean).join(" "))||"—"]],
  refs:["haproxy/conditions","haproxy/backends"],
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"type",l:"Action",t:"select",o:["use_backend","redirect_scheme_https","redirect_location","http_request_deny","http_request_set_header","http_request_del_header","http_response_set_header","tcp_request_content_accept","tcp_request_content_reject","custom"],d:"use_backend"},
   {k:"test",l:"Apply when",t:"select",o:["if","unless"],d:"if"},
   {k:"operator",l:"Combine conditions with",t:"select",o:["and","or"],d:"and"},
   {k:"conditions",l:"Conditions",t:"refmulti",ref:"haproxy/conditions",h:"Leave empty to apply unconditionally"},
   {k:"backend",l:"Backend Pool",t:"ref",ref:"haproxy/backends",h:"Only for the use_backend action"},
   {k:"param1",l:"Name / location / raw line",t:"text"},
   {k:"param2",l:"Value",t:"text"}]},

 "haproxy/healthchecks":{title:"Health Monitors",add:"Add monitor",
  intro:"How Backend Pools decide whether a Real Server is alive.",
  cols:[["name","Name"],["type","Type",r=>esc(HEALTH_LABEL[r.type]||r.type)],
        ["interval","Interval",r=>r.interval||"2s"],
        ["det","Detail",r=>r.type==="http"?"<span class=mono>"+esc((r.http_method||"GET")+" "+(r.http_uri||"/")+(r.expect_status?" -> "+r.expect_status:""))+"</span>"
              :(r.type==="pgsql"||r.type==="mysql")?"<span class=mono>user "+esc(r.db_user||"")+"</span>":"—"]],
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"type",l:"Type",t:"select",o:["tcp","http","ssl","pgsql","mysql"],d:"tcp"},
   {k:"interval",l:"Check interval",t:"text",h:"e.g. 2s"},
   {k:"http_method",l:"HTTP method",t:"select",o:["GET","HEAD","OPTIONS"],d:"GET"},
   {k:"http_uri",l:"HTTP request URI",t:"text",h:"e.g. /health"},
   {k:"expect_status",l:"Expected status",t:"text",h:"e.g. 200"},
 {k:"http_version",l:"HTTP version",t:"select",o:["","HTTP/1.1","HTTP/2"],d:"",h:"Only for the HTTP check"},
   {k:"http_host",l:"Host header",t:"text",h:"Only for the HTTP check"},
   {k:"db_user",l:"Database user",t:"text",h:"For the PostgreSQL and MySQL/MariaDB checks. Only the login handshake is performed -- no password is sent, so an account with no privileges is enough."},
   {k:"mysql_post41",l:"MySQL 4.1+ authentication",t:"bool",d:true,h:"Leave on for MariaDB and any modern MySQL"}]},

 /* Who a service may ask to sign in. Nothing to do with the login for this UI:
    these credentials are checked by HAProxy, in front of the service. */
 "access/users":{title:"Users",add:"Add user",
  intro:"People who may sign in to a service that asks for a password. HAProxy checks them itself, "+
        "so a request without a valid password never reaches the servers behind it. "+
        "They have no access to this management UI.",
  cols:[["username","User name"],
        ["groups","Groups",r=>(r.groups||[]).map(id=>esc(nameOf("access/groups",id))).join(", ")||"—"],
        ["pw","Password",r=>r.has_password?"set":'<span class="pill warn">not set</span>'],
        ["enabled","Enabled",r=>r.enabled!==false?"yes":"no"]],
  refs:["access/groups"],
  fields:[
   {k:"username",l:"User name",t:"text",h:"What they type in the browser's password box"},
   {k:"password",l:"Password",t:"password",h:"At least 8 characters. Leave empty when editing to keep the current one -- it cannot be read back."},
   {k:"groups",l:"Groups",t:"refmulti",ref:"access/groups",h:"A service can admit whole groups rather than naming people one at a time"},
   {k:"enabled",l:"Enabled",t:"bool",d:true,h:"Off keeps the account but stops it signing in anywhere"},
   {k:"description",l:"Description",t:"text"}]},

 "access/groups":{title:"Groups",add:"Add group",
  intro:"Named sets of users. A service admits groups, so who may reach it changes by moving people "+
        "in and out of a group rather than by editing the service.",
  cols:[["name","Name"],["description","Description"]],
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"description",l:"Description",t:"text"}]},

 "acme/accounts":{title:"ACME Accounts",add:"Add account",
  intro:"ACME accounts used to request certificates.",
  cols:[["name","Name"],["email","E-mail"],["ca","CA"]],
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"email",l:"E-mail address",t:"text"},
   {k:"ca",l:"Certificate authority",t:"select",o:["letsencrypt","letsencrypt_test","zerossl","buypass","google"],d:"letsencrypt",h:"Use letsencrypt_test while setting things up to avoid rate limits"},
   {k:"eab_kid",l:"EAB key ID",t:"text",h:"Only for ZeroSSL / Google"},
   {k:"eab_hmac",l:"EAB HMAC key",t:"password"}]},

 "acme/challenges":{title:"Challenge Types",add:"Add challenge type",
  intro:"How domain ownership is proven. HTTP-01 uses a local listener that HAProxy routes /.well-known/acme-challenge/ to; DNS-01 uses an acme.sh DNS hook.",
  cols:[["name","Name"],["method","Method"],
        ["prov","DNS provider",r=>r.method==="dns01"?"<span class=mono>"+esc(r.dns_provider||"")+"</span>"+
           (dnsApiByHook[r.dns_provider]?"<div class=sub>"+esc(dnsApiByHook[r.dns_provider].title)+"</div>":""):"—"]],
  pre:loadDnsApis,
  editorExtra:dnsCredentialHelp,
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"method",l:"Method",t:"select",o:["http01","dns01"],d:"http01"},
   {k:"dns_provider",l:"DNS API hook",t:"combo",o:()=>dnsApiOptions,
    h:"Pick the provider acme.sh should talk to. The list comes from the acme.sh installed on this node."},
   {k:"dns_credentials",l:"DNS API credentials",t:"textarea",
    h:"One KEY=value per line. Choosing a hook above fills in the names it needs."}]},

 "acme/certificates":{title:"Certificates",add:"Add certificate",
  intro:"Certificates are issued with acme.sh and written as combined PEMs to the HAProxy certificate directory. HAProxy is reloaded and the certificate is pushed to the other nodes automatically. "+
        "Until a certificate is issued, Apply installs a short-lived self-signed placeholder so HAProxy can still start.",
  cols:[["name","Name",r=>esc(r.name)+"<div class=sub>"+esc((r.domains||"").split(/\s+/).filter(Boolean).join(", "))+"</div>"],
        ["status","Status",r=>certStatusCell(r)],
        ["expires","Expires",r=>certExpiryCell(r)],
        ["last","Last issue",r=>certLastCell(r)]],
  refs:["acme/accounts","acme/challenges"],
  pre:async()=>{await loadCertStatus();await loadAcmeHealth();},
  notice:certificateNotices,
  rowActions:[
   {label:"Issue",fn:r=>issueCert(r,false),title:"Request the certificate from the CA now"},
   {label:"Force",fn:r=>issueCert(r,true),cls:"dngr",title:"Reissue even if not due for renewal"},
   {label:"Log",fn:r=>showCertLog(r),title:"acme.sh output of the last attempt"}],
  fields:[
   {k:"name",l:"Name",t:"text",h:"Also used as the PEM file name"},
   {k:"domains",l:"Domain names",t:"textarea",h:"One per line; the first is the certificate's primary name"},
   {k:"account",l:"Account",t:"ref",ref:"acme/accounts"},
   {k:"challenge",l:"Challenge Type",t:"ref",ref:"acme/challenges"},
   {k:"key_type",l:"Key type",t:"select",o:["ec-256","ec-384","rsa-2048","rsa-4096"],d:"ec-256"},
   {k:"auto_renew",l:"Auto-renew",t:"bool",d:true},
   ]},

};

/* settings pages: bound to a GET/PUT endpoint (or a sub-key of /api/local) */
export const S={
 "haproxy-settings":{title:"HAProxy Settings",ep:"haproxy/settings",
  intro:"Global and default parameters for the generated haproxy.cfg.",
  fields:[
   {k:"maxconn",l:"Maximum connections",t:"number"},
   {k:"nbthread",l:"Worker threads",t:"text",h:"Leave empty for the HAProxy default"},
   {k:"hard_stop_after",l:"Hard stop after",t:"text",
    h:"How long a reload waits for connections opened before it to finish, e.g. 60s. "+
      "A reload starts a new HAProxy and leaves the old one running until its connections "+
      "close; when this expires the old one closes whatever is left and logs "+
      "\"soft-stop running for too long, performing a hard-stop\" naming each listener and "+
      "how many connections it cut. That message is this setting working, not a fault. "+
      "Anything longer-lived than this -- a database session, a WebSocket, a stream -- is "+
      "dropped on every Apply and has to reconnect. Raise it to avoid that, or leave it "+
      "empty to wait indefinitely, at the cost of an old process lingering after every "+
      "reload for as long as its longest connection lasts."},
   {k:"ssl_min_ver",l:"Minimum TLS version",t:"select",o:["TLSv1.2","TLSv1.3"],d:"TLSv1.2"},
   {k:"ssl_ciphers",l:"SSL cipher list",t:"text",h:"Leave empty for the HAProxy default"},
   {k:"timeout_connect",l:"Connect timeout",t:"text"},
   {k:"timeout_client",l:"Client timeout",t:"text"},
   {k:"timeout_server",l:"Server timeout",t:"text"},
   {k:"retries",l:"Retries",t:"number"},
   {k:"redispatch",l:"Redispatch on failure",t:"bool",d:true},
   {k:"stats_enabled",l:"Enable statistics page",t:"bool"},
   {k:"stats_bind",l:"Statistics listen address",t:"text"},
   {k:"stats_uri",l:"Statistics URI",t:"text"},
   {k:"custom_global",l:"Extra global directives",t:"textarea",h:"Advanced. Raw lines added to the global section of haproxy.cfg, for settings this page does not cover -- for example \"tune.ssl.default-dh-param 2048\". One per line. Apply validates with haproxy -c first, so a mistake blocks the change rather than breaking HAProxy. See the HAProxy configuration manual: https://docs.haproxy.org/2.6/configuration.html"},
   {k:"custom_defaults",l:"Extra defaults directives",t:"textarea",h:"Advanced. Raw lines added to the defaults section, inherited by every service and pool -- for example \"option http-server-close\". One per line. Apply validates with haproxy -c first, so a mistake blocks the change rather than breaking HAProxy. See the HAProxy configuration manual: https://docs.haproxy.org/2.6/configuration.html"}]},
 /* One of three cards on the ACME Settings page, so it is named for what it
     configures rather than repeating the page title. */
 "acme-settings":{title:"Issuance and renewal",ep:"acme/settings",
  intro:"How acme.sh obtains and renews certificates on this node.",
  fields:[
   {k:"enabled",l:"Enabled",t:"bool",d:true},
   {k:"auto_renew",l:"Automatic renewal",t:"bool",d:true},
   {k:"renew_hours",l:"Renewal check interval (hours)",t:"number"},
   {k:"challenge_port",l:"HTTP-01 challenge port",t:"number",h:"Local port acme.sh listens on during HTTP-01 validation"},
   {k:"haproxy_integration",l:"HAProxy integration",t:"bool",d:true,h:"Route /.well-known/acme-challenge/ on all HTTP services to the local challenge listener"}]},
};

/* ---- CRUD views ---- */
/* `into` lets a page host several of these; on its own it takes over the page,
   which is what the navigation does for a plain CRUD entry. */
export async function renderEntity(key,into){
  const def=E[key];
  await Promise.all([list(key,true),...(def.refs||[]).map(r=>list(r,true))]);
  if(def.pre)await def.pre();
  const items=lists[key];
  const c=into||$("#content");
  if(!into)c.innerHTML="";
  /* a page may have more than one thing to say before its table */
  if(def.notice){
    const n=def.notice();
    (Array.isArray(n)?n:[n]).filter(Boolean).forEach(x=>c.appendChild(x));
  }
  const card=document.createElement("div");card.className="card";
  const hd=document.createElement("div");hd.className="hd";
  hd.innerHTML="<h2>"+esc(def.title)+"</h2><div class=sp></div>";
  if(!state.readOnly){
    if(key==="acme/certificates"){
      hd.appendChild(btn("Request a certificate","pri sm",()=>openCertWizard()));
      hd.appendChild(document.createTextNode(" "));
      hd.appendChild(btn(def.add,"sm",()=>openEditor(key)));
    }else{
      hd.appendChild(btn(def.add,"pri sm",()=>openEditor(key)));
    }
  }
  card.appendChild(hd);
  const bd=document.createElement("div");
  if(!items.length){
    bd.innerHTML='<div class="empty">'+esc(def.intro)+"<br><br>Nothing here yet -- use "+esc(def.add)+" to create the first entry.</div>";
  }else{
    const t=document.createElement("table");
    t.innerHTML="<thead><tr>"+def.cols.map(c=>"<th>"+esc(c[1])+"</th>").join("")+"<th></th></tr></thead>";
    const tb=document.createElement("tbody");
    items.forEach(row=>{
      const tr=document.createElement("tr");
      def.cols.forEach((col,ci)=>{
        const td=document.createElement("td");
        td.innerHTML=col[2]?col[2](row):esc(row[col[0]]??"");
        /* Mark what a published service owns, in the first column where the
           name is, so it is obvious before anything is clicked. */
        if(ci===0&&row.managed_by){
          td.innerHTML+=' <span class="pill off" title="Part of the service '+
            esc(row.managed_by)+'. Change it under Services, not here.">service</span>';
        }
        tr.appendChild(td);
      });
      const act=document.createElement("td");act.style.textAlign="right";act.style.whiteSpace="nowrap";
      (state.readOnly?[]:(def.rowActions||[])).forEach(a=>{
        const b=btn(a.label,"sm "+(a.cls||""),()=>a.fn(row));
        if(a.title)b.title=a.title;
        act.appendChild(b);act.appendChild(document.createTextNode(" "));
      });
      act.appendChild(btn(state.readOnly?"View":"Edit","sm",()=>openEditor(key,row)));
      if(!state.readOnly){
      act.appendChild(document.createTextNode(" "));
      act.appendChild(btn("Delete","sm dngr",async()=>{
        if(!confirm("Delete \""+row.name+"\"?"))return;
        /* re-render the page, not just this table: it may be one of several */
          try{await api(key+"/"+row.id,"DELETE");await route();refreshStatus();}
        catch(e){alert(e.message);}
      }));}
      tr.appendChild(act);tb.appendChild(tr);
    });
    t.appendChild(tb);bd.appendChild(t);
    const hint=document.createElement("div");hint.className="hint";hint.style.padding="10px 16px";
    hint.textContent=def.intro;bd.appendChild(hint);
  }
  card.appendChild(bd);c.appendChild(card);
}
export function openEditor(key,item){
  const def=E[key];
  const wrap=document.createElement("div");
  /* HAProxy objects get two tabs: the fields, and the exact haproxy.cfg they
     render to -- recomputed from what is currently typed, because a preview
     of the past answers a question nobody asked. Editing raw text happens in
     the Extra directives field; parsing a hand-written haproxy.cfg back into
     objects would be lossy guesswork dressed up as a feature. */
  const isHap=key.startsWith("haproxy/")&&key!=="haproxy/settings";
  if(item&&item.managed_by){
    /* Editing here is allowed -- sometimes it is the only way to set something
       the wizard does not expose -- but the next publish of that service will
       rebuild these objects, so say that plainly rather than silently losing
       the change later. */
    const w=document.createElement("div");
    w.className="hint";
    w.style.cssText="border:1px solid #e3cfa8;border-radius:6px;padding:10px 12px;"+
                    "margin-bottom:14px;color:var(--ink)";
    w.innerHTML="<b>This belongs to the service &ldquo;"+esc(item.managed_by)+"&rdquo;.</b><br>"+
      "Edit it under <b>Services</b> instead: publishing that service again rebuilds "+
      "these objects, and anything changed here that the service also sets would be "+
      "overwritten.";
    wrap.appendChild(w);
  }
  const frm=document.createElement("div");frm.className="frm";
  def.fields.forEach(f=>fieldRow(f,item?item[f.k]:undefined).forEach(el=>frm.appendChild(el)));
  if(def.editorExtra)def.editorExtra(frm,item);
  const cfgPane=document.createElement("div");cfgPane.hidden=true;
  if(isHap){
    const tabs=document.createElement("div");
    tabs.style.cssText="display:flex;gap:6px;border-bottom:1px solid var(--hair);margin-bottom:14px";
    const mk=label=>{const b=document.createElement("button");b.type="button";b.className="btn sm";
      b.style.cssText="border:0;border-radius:4px 4px 0 0;border-bottom:2px solid transparent";
      b.textContent=label;tabs.appendChild(b);return b;};
    const tFields=mk("Settings"),tCfg=mk("haproxy.cfg");
    const pre=document.createElement("pre");pre.textContent="";
    const note=document.createElement("div");note.className="hint";note.style.marginTop="8px";
    note.textContent="Exactly what Apply will write for this object, from the values as they "+
      "are now. Raw lines the fields do not cover go in Extra directives, under Settings.";
    cfgPane.appendChild(pre);cfgPane.appendChild(note);
    const show=which=>{
      frm.hidden=which!=="fields";cfgPane.hidden=which!=="cfg";
      tFields.style.borderBottomColor=which==="fields"?"var(--line)":"transparent";
      tCfg.style.borderBottomColor=which==="cfg"?"var(--line)":"transparent";
      if(which==="cfg"){
        pre.textContent="rendering...";
        api("haproxy/preview-object","POST",{col:key.split("/")[1],
            item:Object.assign({},item||{},readForm(def.fields))})
          .then(r=>{pre.textContent=r.text||r.note||"";})
          .catch(e=>{pre.textContent=e.message;});
      }
    };
    tFields.onclick=()=>show("fields");tCfg.onclick=()=>show("cfg");
    wrap.appendChild(tabs);
    show("fields");
  }
  wrap.appendChild(frm);
  wrap.appendChild(cfgPane);
  const err=document.createElement("div");err.className="err";
  openDlg((item?"Edit ":"New ")+def.title.replace(/s$/,""),wrap,[err,
    btn("Cancel","",closeDlg),
    btn("Save","pri",async()=>{
      const data=readForm(def.fields);
      try{
        if(item)await api(key+"/"+item.id,"PUT",Object.assign({},item,data));
        else await api(key,"POST",data);
        closeDlg();await route();refreshStatus();
      }catch(e){err.textContent=e.message;}
    })]);
}

/* ---- settings views ---- */
export async function renderSettings(key,into){
  const def=S[key];
  if(def.pre)await def.pre();
  let cur=await api(def.ep);
  if(def.sub)cur=cur[def.sub]||{};
  const c=into||$("#content");
  if(!into)c.innerHTML="";
  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>'+esc(def.title)+'</h2></div>';
  const bd=document.createElement("div");bd.className="bd";
  const intro=document.createElement("p");intro.className="hint";intro.style.marginBottom="14px";intro.textContent=def.intro;
  bd.appendChild(intro);
  const frm=document.createElement("div");frm.className="frm";
  def.fields.forEach(f=>fieldRow(f,cur[f.k]).forEach(el=>frm.appendChild(el)));
  bd.appendChild(frm);
  const foot=document.createElement("div");foot.style.marginTop="16px";
  const msg=document.createElement("span");msg.className="hint";msg.style.marginLeft="10px";
  const shared=!def.sub;          // sub-keyed pages write to local settings
  const save=btn("Save","pri",async()=>{
    const data=readForm(def.fields);
    try{
      await api(def.ep,"PUT",def.sub?{[def.sub]:data}:data);
      msg.textContent="Saved.";refreshStatus();
    }catch(e){
      msg.innerHTML='<span class="pill down">not saved</span>';
      showText("Not saved",e.message);
    }
  });
  if(state.readOnly&&shared){save.disabled=true;msg.textContent="Read-only on a passive node.";}
  foot.appendChild(save);
  if(shared){
    foot.appendChild(document.createTextNode(" "));
    foot.appendChild(btn("Validate","",async()=>{
      msg.textContent="Checking...";
      try{
        const r=await api("validate","POST",{section:def.ep.split("/")[0],settings:readForm(def.fields)});
        msg.innerHTML=r.ok?'<span class="pill up">valid</span> '+esc(r.message)
                          :'<span class="pill down">not valid</span>';
        if(!r.ok)showText("These settings would not work",r.message);
      }catch(e){msg.textContent=e.message;}
    }));
  }
  foot.appendChild(msg);
  bd.appendChild(foot);card.appendChild(bd);c.appendChild(card);
  if(def.extra)c.appendChild(def.extra());
}
