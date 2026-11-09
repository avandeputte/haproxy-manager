import { $, HEALTH_LABEL, PROXY_KEYWORD, PROXY_OPTIONS, api, btn, closeDlg, esc, fieldRow, list, lists, nameOf, openDlg, readForm, showText, trimHaproxy } from "./core.js";
import { t } from "./i18n.js";
import { refreshStatus, route } from "./shell.js";
import { certificateNotices, certExpiryCell, certLastCell, certStatusCell, dnsApiByHook, dnsApiOptions, dnsCredentialHelp, issueCert, loadAcmeHealth, loadCertStatus, loadDnsApis, openCertWizard, openDownload, openUpload, showCertLog } from "./pages/certificates.js";
import { ACTION_LABEL, COND_LABEL, openRuleWizard } from "./pages/rules.js";
import { openConditionWizard } from "./pages/conditions.js";
import { state } from "./state.js";

/* What a picked item is, in a few words, beside its name in a checklist. */
export function describeRule(r){
  const parts=[t(ACTION_LABEL[r.type]||r.type)];
  const when=ruleWords(r);
  if(when&&when!==t("always"))parts.push(t("when {conditions}",{conditions:when}));
  return parts.join(" \u00b7 ");
}
export function describePage(p){
  return (p.codes||"")+(p.everywhere!==false?" \u00b7 "+t("every service"):"");
}
export function describeList(l){
  const nets=(l.networks||"").split(/[\s,]+/).filter(Boolean);
  return nets.slice(0,3).join(", ")+(nets.length>3?" \u2026":"");
}
/* A rule's test in words: "(a or b) and c". A rule from before 2.0 with "or"
   over its one list is alternatives alone. */
export function ruleWords(r){
  const nm=id=>nameOf("haproxy/conditions",id);
  const any=(r.any_of||[]).concat(r.operator==="or"?(r.conditions||[]):[]).map(nm);
  const all=(r.operator==="or"?[]:(r.conditions||[])).map(nm);
  const anyText=any.join(" "+t("or")+" ");
  if(any.length&&all.length)return "("+anyText+") "+t("and")+" "+all.join(" "+t("and")+" ");
  if(any.length)return anyText;
  if(all.length)return all.join(" "+t("and")+" ");
  return t("always");
}

/* ---- entity registry ---- */
/* Field types: text number bool select ref refmulti textarea password.
   Every label, hint, heading and intro is English here and translated where
   it is drawn; `one` is the singular the editor's title needs. */
export const E={
 "haproxy/servers":{title:"Real Servers",one:"Real Server",add:"Add server",
  intro:"The upstream hosts traffic is forwarded to. Attach them to Backend Pools.",
  cols:[["name","Name"],["address","Address",r=>esc(r.address)+":"+esc(r.port)],
        ["opts","Options",r=>[r.ssl?"ssl":"",PROXY_KEYWORD[r.proxy_protocol]||"",
                              r.backup?"backup":""].filter(Boolean).join(", ")||"—"],
        ["enabled","Enabled",r=>r.enabled!==false?t("yes"):t("no")]],
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"enabled",l:"Enabled",t:"bool",d:true},
   {k:"address",l:"Address",t:"text",h:"IP address or hostname of the real server"},
   {k:"port",l:"Port",t:"number"},
   {k:"weight",l:"Weight",t:"number",h:"Optional load-balancing weight (1-256)"},
   {k:"check_port",l:"Health check port",t:"text",h:"Optional. Leave empty to check the port traffic goes to."},
   {k:"ssl",l:"Encrypt to server (SSL)",t:"bool"},
   {k:"ssl_verify",l:"Verify server certificate",t:"bool"},
   {k:"proxy_protocol",l:"PROXY protocol",t:"select",o:PROXY_OPTIONS,d:"",
    h:"Tells this server the visitor's real address, the way X-Forwarded-For does for HTTP, "+
     "and also works for tcp:// services. Only turn it on when the server is set up to expect it "+
     "(nginx proxy_protocol, Postfix, Dovecot, Traefik...): a server that is not refuses every "+
     "connection. Health checks to a separate check port are sent without it."},
   {k:"backup",l:"Backup server",t:"bool",h:"Only receives traffic when all non-backup servers are down"},
   {k:"description",l:"Description",t:"text"}]},

 "haproxy/backends":{title:"Backend Pools",one:"Backend Pool",add:"Add pool",
  intro:"Groups of Real Servers with a balancing algorithm, health checks and persistence.",
  cols:[["name","Name"],["mode","Mode"],["balance","Balance",r=>r.balance||"roundrobin"],
        ["servers","Servers",r=>(r.servers||[]).map(id=>esc(nameOf("haproxy/servers",id))).join(", ")||"—"],
        ["hc","Check",r=>r.healthcheck_enabled?esc(nameOf("haproxy/healthchecks",r.healthcheck)):t("off")]],
  refs:["haproxy/servers","haproxy/healthchecks","access/groups","haproxy/addresslists","haproxy/errorpages","haproxy/rules","haproxy/conditions"],
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
   {k:"allow_lists",l:"Allowed address lists",t:"refmulti",ref:"haproxy/addresslists",describe:describeList,h:"Named lists that count with the networks above. Edit a list once and every pool that names it follows."},
   {k:"rate_limit",l:"Requests per client",t:"number",
    h:"Optional. A client address that asks more than this many times in the window below is refused until it slows down -- HTTP answers 429, TCP drops the connection. Counted in the pool's stick table. Empty means no limit."},
   {k:"rate_window",l:"Rate window (seconds)",t:"number",d:10,h:"The sliding window the requests are counted over, e.g. 10. Only used when a limit is set."},
   {k:"auth_enabled",l:"Require a sign-in",t:"bool",h:"HTTP basic authentication in front of this pool. HTTP mode only -- a raw TCP port has nowhere to put one."},
   {k:"auth_groups",l:"Allowed groups",t:"refmulti",ref:"access/groups",h:"Leave nothing ticked to admit any user"},
   {k:"auth_realm",l:"Sign-in prompt",t:"text",h:"What the browser shows above its password box. Defaults to the pool name."},
   {k:"auth_exempt_src",l:"Skip the sign-in from",t:"textarea",h:"Networks trusted without a password, one per line -- typically the LAN"},
   {k:"auth_exempt_lists",l:"Skip the sign-in from these lists",t:"refmulti",ref:"haproxy/addresslists",describe:describeList,h:"Address lists trusted without a password, beside the networks above"},
   {k:"oauth_enabled",l:"Require single sign-on (OIDC)",t:"bool",
    h:"Send visitors to the identity provider first. One sign-in per service: not together with basic auth. Configure the provider under Access > Single sign-on."},
   {k:"oauth_allow",l:"SSO allowed identities",t:"textarea",
    h:"One per line: an email, @example.com for a domain, or * for anyone the provider signs in."},
   {k:"oauth_forward",l:"Pass the signed-in email to the servers",t:"bool",
    h:"X-Auth-Request-Email and Remote-User, set from the verified session; client-sent copies are stripped everywhere."},
   {k:"error_pages",l:"Error pages",t:"refmulti",ref:"haproxy/errorpages",describe:describePage,h:"Pages for this pool alone, over the ones that stand for every service. HTTP mode only."},
   {k:"hsts",l:"Send HSTS",t:"bool",h:"Strict-Transport-Security, over HTTPS only: browsers that have been here come back over HTTPS for two years without trying HTTP first. HTTP mode only."},
   {k:"hsts_subdomains",l:"HSTS for subdomains too",t:"bool",h:"Adds includeSubDomains: every name under this one must then work over HTTPS."},
   {k:"redirect_to",l:"Redirect to",t:"text",h:"Optional. An address starting with http:// or https://: every request is answered with a redirect there instead of reaching the servers."},
   {k:"redirect_code",l:"Redirect code",t:"select",o:[{value:301,label:"301 moved permanently"},{value:302,label:"302 found"},{value:307,label:"307 temporary, same method"},{value:308,label:"308 permanent, same method"}],d:301},
   {k:"redirect_keep_path",l:"Keep the path",t:"bool",d:true,h:"/a?b here arrives as /a?b there; off sends every request to the address as given."},
   {k:"rules",l:"Rules",t:"refmulti",ref:"haproxy/rules",filter:r=>r.type!=="use_backend",describe:describeRule,
    h:"Rules acted on inside this pool, so they reach this service alone: deny, headers, redirects, raw lines. Routing rules belong on the listener and are not offered."},
   {k:"custom",l:"Extra directives",t:"textarea",h:"Advanced. Raw lines added inside this backend, for anything the fields above do not cover -- for example \"http-reuse safe\". One per line. See the HAProxy configuration manual: https://docs.haproxy.org/2.6/configuration.html"}]},

 "haproxy/frontends":{title:"Public Services",one:"Public Service",add:"Add service",
  intro:"Listening sockets clients connect to (frontends). Certificates come from the Certificates page.",
  cols:[["name","Name"],["binds","Listen on",r=>"<span class=mono>"+esc((r.binds||"").split("\n").filter(Boolean).join(", "))+"</span>"],
        ["mode","Mode",r=>esc(r.mode||"http")+(r.ssl_enabled?" +ssl":"")],
        ["be","Default pool",r=>r.default_backend?esc(nameOf("haproxy/backends",r.default_backend)):"—"],
        ["enabled","Enabled",r=>r.enabled!==false?t("yes"):t("no")]],
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

 /* Reached from the Rules page rather than the menu: the wizards make
    conditions as they go, and this is where they are looked after. */
 "haproxy/conditions":{title:"Conditions",one:"Condition",add:"New condition",
  intro:"Named tests (ACLs) evaluated against traffic. Combine them in Rules.",
  cols:[["name","Name"],["type","Type",r=>esc(t(COND_LABEL[r.type]||r.type))],["value","Value",r=>"<span class=mono>"+esc(r.type==="source_list"?nameOf("haproxy/addresslists",r.list):(r.param?r.param+" = ":"")+(r.value||""))+"</span>"],
        ["negate","Negate",r=>r.negate?t("yes"):t("no")]],
  refs:["haproxy/addresslists"],
  wizard:r=>openConditionWizard(r),
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"type",l:"Condition type",t:"select",o:Object.keys(COND_LABEL).map(k=>({value:k,label:COND_LABEL[k]})),d:"host_matches"},
   {k:"param",l:"Header / parameter name",t:"text",h:"Only for the http_header and url_parameter types"},
   {k:"value",l:"Value",t:"text",h:"Several values separated by spaces match any of them -- two host names, two networks. For type custom: a raw ACL expression."},
   {k:"list",l:"Address list",t:"ref",ref:"haproxy/addresslists",h:"Only for the source_list type: the request comes from one of the list's networks"},
   {k:"negate",l:"Negate",t:"bool"},
   {k:"description",l:"Description",t:"text"}]},

 "haproxy/rules":{title:"Rules",one:"Rule",add:"New rule",
  intro:"Actions taken when Conditions match: select a pool, redirect, set headers, deny.",
  cols:[["name","Name"],["type","Action",r=>esc(t(ACTION_LABEL[r.type]||r.type))],
        ["cond","Conditions",r=>esc(ruleWords(r))],
        ["tgt","Target",r=>r.type==="use_backend"?esc(nameOf("haproxy/backends",r.backend)):esc([r.param1,r.param2].filter(Boolean).join(" "))||"—"]],
  refs:["haproxy/conditions","haproxy/backends","haproxy/frontends","haproxy/addresslists"],
  wizard:r=>openRuleWizard(r),
  links:[["haproxy/conditions","Conditions"]],
  /* A rule saved before 2.0 held one list and an operator; shown here as the
     two lists it means, and saved that way. */
  prepare:r=>r.operator==="or"?Object.assign({},r,{any_of:(r.any_of||[]).concat(r.conditions||[]),conditions:[],operator:"and"}):r,
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"type",l:"Action",t:"select",o:Object.keys(ACTION_LABEL).map(k=>({value:k,label:ACTION_LABEL[k]})),d:"use_backend"},
   {k:"test",l:"Apply when",t:"select",o:["if","unless"],d:"if"},
   {k:"any_of",l:"Any of these conditions",t:"refmulti",ref:"haproxy/conditions",h:"One of them must match -- several host names, say"},
   {k:"conditions",l:"All of these conditions",t:"refmulti",ref:"haproxy/conditions",h:"Every one of them must match, together with one of the above. Leave both empty to apply unconditionally."},
   {k:"backend",l:"Backend Pool",t:"ref",ref:"haproxy/backends",h:"Only for the use_backend action"},
   {k:"param1",l:"Name / location / raw line",t:"text"},
   {k:"param2",l:"Value",t:"text"}]},

 "haproxy/addresslists":{title:"Address Lists",one:"Address List",add:"Add list",
  intro:"Named sets of networks. A service's allowed networks, the networks that skip its sign-in and a source_list condition can name a list, so an address that changes is changed here once rather than on every service.",
  cols:[["name","Name"],["networks","Networks",r=>"<span class=mono>"+esc((r.networks||"").split(/[\s,]+/).filter(Boolean).join(", "))+"</span>"],
        ["description","Description"]],
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"networks",l:"Networks",t:"textarea",h:"One address or CIDR per line, e.g. 192.168.1.0/24 or 203.0.113.7"},
   {k:"description",l:"Description",t:"text"}]},

 "haproxy/errorpages":{title:"Error Pages",one:"Error Page",add:"Add page",
  intro:"What visitors see when HAProxy itself answers with an error: no server left, a refused address, a rate limit, a paused service. Every node writes the pages to disk at Apply. HAProxy can only replace the responses it generates, and a page must fit its 16 kB buffer.",
  cols:[["name","Name"],["codes","Status codes",r=>"<span class=mono>"+esc(r.codes||"")+"</span>"],
        ["everywhere","Used for",r=>r.everywhere!==false?t("every service"):t("the pools that pick it")]],
  /* A page is usually written elsewhere and pasted in. This reads a local
     file into the field in the browser; nothing is uploaded, the page is
     saved with the configuration like any other field. */
  editorExtra:(frm)=>{
    const lab=document.createElement("label");lab.className="fl";lab.textContent=t("Load from file");
    const cell=document.createElement("div");
    const inp=document.createElement("input");inp.type="file";inp.accept=".html,.htm,text/html";inp.id="f_html_file";
    inp.addEventListener("change",()=>{
      const f=inp.files&&inp.files[0];if(!f)return;
      const rd=new FileReader();
      rd.onload=()=>{const ta=document.getElementById("f_html");if(ta)ta.value=String(rd.result||"");};
      rd.readAsText(f);
    });
    const h=document.createElement("div");h.className="hint";
    h.textContent=t("Reads a local .html file into the field above. Nothing is uploaded: the page is saved with the configuration.");
    cell.appendChild(inp);cell.appendChild(h);
    frm.appendChild(lab);frm.appendChild(cell);
  },
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"codes",l:"Status codes",t:"text",d:"503",h:"Space separated. HAProxy generates 400, 401, 403, 404, 405, 407, 408, 410, 413, 425, 429, 431, 500, 501, 502, 503 and 504; a 404 from a server behind the proxy passes through as it is."},
   {k:"everywhere",l:"Use for every service",t:"bool",d:true,h:"Off: only the Backend Pools that pick this page use it"},
   {k:"html",l:"HTML",t:"textarea",h:"The whole page. {error_code} and {error_message} are filled in per status code, so one page can serve several. Keep images as links or inline SVG: the whole response must fit HAProxy's 16 kB buffer."},
   {k:"description",l:"Description",t:"text"}]},

 "haproxy/healthchecks":{title:"Health Monitors",one:"Health Monitor",add:"Add monitor",
  intro:"How Backend Pools decide whether a Real Server is alive.",
  cols:[["name","Name"],["type","Type",r=>esc(t(HEALTH_LABEL[r.type]||r.type))],
        ["interval","Interval",r=>r.interval||"2s"],
        ["det","Detail",r=>r.type==="http"?"<span class=mono>"+esc((r.http_method||"GET")+" "+(r.http_uri||"/")+(r.expect_status?" -> "+r.expect_status:""))+"</span>"
              :(r.type==="pgsql"||r.type==="mysql")?"<span class=mono>"+t("user {name}",{name:esc(r.db_user||"")})+"</span>":"—"]],
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"type",l:"Type",t:"select",o:["tcp","http","ssl","pgsql","mysql"],d:"tcp"},
   {k:"interval",l:"Check interval",t:"text",h:"e.g. 2s"},
   {k:"http_method",l:"HTTP method",t:"select",o:["GET","HEAD","OPTIONS","POST"],d:"GET"},
   {k:"http_uri",l:"HTTP request URI",t:"text",h:"e.g. /health"},
   {k:"expect_status",l:"Expected status",t:"text",h:"e.g. 200"},
 {k:"http_version",l:"HTTP version",t:"select",o:["","HTTP/1.1","HTTP/2"],d:"",h:"Only for the HTTP check"},
   {k:"http_host",l:"Host header",t:"text",h:"Only for the HTTP check"},
   {k:"db_user",l:"Database user",t:"text",h:"For the PostgreSQL and MySQL/MariaDB checks. Only the login handshake is performed -- no password is sent, so an account with no privileges is enough."},
   {k:"mysql_post41",l:"MySQL 4.1+ authentication",t:"bool",d:true,h:"Leave on for MariaDB and any modern MySQL"}]},

 /* Who a service may ask to sign in. Nothing to do with the login for this UI:
    these credentials are checked by HAProxy, in front of the service. */
 "access/users":{title:"Users",one:"User",add:"Add user",
  intro:"People who may sign in to a service that asks for a password. HAProxy checks them itself, "+
        "so a request without a valid password never reaches the servers behind it. "+
        "They have no access to this management UI.",
  cols:[["username","User name"],
        ["groups","Groups",r=>(r.groups||[]).map(id=>esc(nameOf("access/groups",id))).join(", ")||"—"],
        ["pw","Password",r=>r.has_password?t("set"):'<span class="pill warn">'+t("not set")+'</span>'],
        ["enabled","Enabled",r=>r.enabled!==false?t("yes"):t("no")]],
  refs:["access/groups"],
  fields:[
   {k:"username",l:"User name",t:"text",h:"What they type in the browser's password box"},
   {k:"password",l:"Password",t:"password",h:"At least 8 characters. Leave empty when editing to keep the current one -- it cannot be read back."},
   {k:"groups",l:"Groups",t:"refmulti",ref:"access/groups",h:"A service can admit whole groups rather than naming people one at a time"},
   {k:"enabled",l:"Enabled",t:"bool",d:true,h:"Off keeps the account but stops it signing in anywhere"},
   {k:"description",l:"Description",t:"text"}]},

 "access/groups":{title:"Groups",one:"Group",add:"Add group",
  intro:"Named sets of users. A service admits groups, so who may reach it changes by moving people "+
        "in and out of a group rather than by editing the service.",
  cols:[["name","Name"],["description","Description"]],
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"description",l:"Description",t:"text"}]},

 "acme/accounts":{title:"ACME Accounts",one:"ACME Account",add:"Add account",
  intro:"ACME accounts used to request certificates.",
  cols:[["name","Name"],["email","E-mail"],["ca","CA"]],
  fields:[
   {k:"name",l:"Name",t:"text"},
   {k:"email",l:"E-mail address",t:"text"},
   {k:"ca",l:"Certificate authority",t:"select",o:["letsencrypt","letsencrypt_test","zerossl","buypass","google"],d:"letsencrypt",h:"Use letsencrypt_test while setting things up to avoid rate limits"},
   {k:"eab_kid",l:"EAB key ID",t:"text",h:"Only for ZeroSSL / Google"},
   {k:"eab_hmac",l:"EAB HMAC key",t:"password"}]},

 "acme/challenges":{title:"Challenge Types",one:"Challenge Type",add:"Add challenge type",
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

 "acme/certificates":{title:"Certificates",one:"Certificate",add:"Add certificate",
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
   {label:"Issue",fn:r=>issueCert(r,false),when:r=>r.source!=="custom",title:"Request the certificate from the CA now"},
   {label:"Force",fn:r=>issueCert(r,true),cls:"dngr",when:r=>r.source!=="custom",title:"Reissue even if not due for renewal"},
   {label:"Log",fn:r=>showCertLog(r),when:r=>r.source!=="custom",title:"acme.sh output of the last attempt"},
   {label:"Replace",fn:r=>openUpload(r),when:r=>r.source==="custom",title:"Upload a new certificate and key under this name"},
   {label:"Download",fn:r=>openDownload(r),title:"The certificate and chain, or the private key"}],
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
   {k:"timeout_tunnel",l:"WebSocket idle timeout",t:"text",d:"1h",
    h:"How long an upgraded connection -- a WebSocket, a terminal -- may sit idle before it is closed (timeout tunnel). Empty falls back to the client and server timeouts, which cut an idle WebSocket after 50 seconds."},
   {k:"ipv6",l:"Listen on IPv6 too",t:"bool",d:true,
    h:"Services that listen on every address answer over IPv6 as well (bind ::: v4v6). Skipped by itself on a node without IPv6; turn it off where IPv6 exists but is broken."},
   {k:"default_site",l:"Unknown hosts",t:"select",o:[{value:"503",label:"503 -- HAProxy's own answer"},{value:"404",label:"404 not found -- the 404 error page when there is one"},{value:"drop",label:"drop the connection, say nothing"},{value:"redirect",label:"redirect to an address"}],d:"503",
    h:"What a request for a host name no service answers gets, on every HTTP listener without a default Backend Pool."},
   {k:"default_site_url",l:"Unknown hosts redirect to",t:"text",h:"Only for redirect: an address starting with http:// or https://"},
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
  hd.innerHTML="<h2>"+esc(t(def.title))+"</h2><div class=sp></div>";
  if(!state.readOnly){
    if(key==="acme/certificates"){
      hd.appendChild(btn(t("Request a certificate"),"pri sm",()=>openCertWizard()));
      hd.appendChild(document.createTextNode(" "));
      hd.appendChild(btn(t("Upload a certificate"),"sm",()=>openUpload()));
      hd.appendChild(document.createTextNode(" "));
      hd.appendChild(btn(t(def.add),"sm",()=>openEditor(key)));
    }else if(def.wizard){
      /* the wizard is the editor: it asks for everything the fields hold */
      hd.appendChild(btn(t(def.add),"pri sm",()=>def.wizard()));
    }else{
      hd.appendChild(btn(t(def.add),"pri sm",()=>openEditor(key)));
    }
  }
  /* pages reached from here rather than from the menu */
  (def.links||[]).forEach(([target,label])=>{
    hd.appendChild(document.createTextNode(" "));
    const a=btn(t(label),"sm",()=>{location.hash="#/"+target;});
    hd.appendChild(a);
  });
  if(false){
  }
  card.appendChild(hd);
  const bd=document.createElement("div");
  if(!items.length){
    bd.innerHTML='<div class="empty">'+esc(t(def.intro))+"<br><br>"+
      t("Nothing here yet -- use {add} to create the first entry.",{add:esc(t(def.add))})+"</div>";
  }else{
    const tbl=document.createElement("table");
    tbl.innerHTML="<thead><tr>"+def.cols.map(c=>"<th>"+esc(t(c[1]))+"</th>").join("")+"<th></th></tr></thead>";
    const tb=document.createElement("tbody");
    items.forEach(row=>{
      const tr=document.createElement("tr");
      def.cols.forEach((col,ci)=>{
        const td=document.createElement("td");
        td.innerHTML=col[2]?col[2](row):esc(row[col[0]]??"");
        /* Mark what a published service owns, in the first column where the
           name is, so it is obvious before anything is clicked. */
        if(ci===0&&row.managed_by){
          td.innerHTML+=' <span class="pill off" title="'+
            esc(t("Part of the service {name}. Change it under Services, not here.",{name:row.managed_by}))+
            '">'+t("service")+'</span>';
        }
        tr.appendChild(td);
      });
      const act=document.createElement("td");act.style.textAlign="right";act.style.whiteSpace="nowrap";
      (state.readOnly?[]:(def.rowActions||[])).filter(a=>!a.when||a.when(row)).forEach(a=>{
        const b=btn(t(a.label),"sm "+(a.cls||""),()=>a.fn(row));
        if(a.title)b.title=t(a.title);
        act.appendChild(b);act.appendChild(document.createTextNode(" "));
      });
      act.appendChild(btn(state.readOnly?t("View"):t("Edit"),"sm",()=>(def.wizard&&!state.readOnly?def.wizard(row):openEditor(key,row))));
      if(!state.readOnly){
      act.appendChild(document.createTextNode(" "));
      act.appendChild(btn(t("Delete"),"sm dngr",async()=>{
        /* users are named by username, everything else by name */
        if(!confirm(t("Delete \"{name}\"?",{name:row.name||row.username||t("this")})))return;
        /* re-render the page, not just this table: it may be one of several */
          try{await api(key+"/"+row.id,"DELETE");await route();refreshStatus();}
        catch(e){alert(e.message);}
      }));}
      tr.appendChild(act);tb.appendChild(tr);
    });
    tbl.appendChild(tb);bd.appendChild(tbl);
    const hint=document.createElement("div");hint.className="hint";hint.style.padding="10px 16px";
    hint.textContent=t(def.intro);bd.appendChild(hint);
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
  const isHap=key.startsWith("haproxy/");   // settings are their own page, never an entity key here
  if(item&&item.managed_by){
    /* Editing here is allowed -- sometimes it is the only way to set something
       the wizard does not expose -- but the next publish of that service will
       rebuild these objects, so say that plainly rather than silently losing
       the change later. */
    const w=document.createElement("div");
    w.className="hint";
    w.style.cssText="border:1px solid #e3cfa8;border-radius:6px;padding:10px 12px;"+
                    "margin-bottom:14px;color:var(--ink)";
    w.innerHTML="<b>"+t("This belongs to the service &ldquo;{name}&rdquo;.",{name:esc(item.managed_by)})+"</b><br>"+
      t("Edit it under <b>Services</b> instead: publishing that service again rebuilds "+
        "these objects, and anything changed here that the service also sets would be "+
        "overwritten.");
    wrap.appendChild(w);
  }
  const frm=document.createElement("div");frm.className="frm";
  const shown=item&&def.prepare?def.prepare(item):item;
  def.fields.forEach(f=>fieldRow(f,shown?shown[f.k]:undefined).forEach(el=>frm.appendChild(el)));
  if(def.editorExtra)def.editorExtra(frm,item);
  const cfgPane=document.createElement("div");cfgPane.hidden=true;
  if(isHap){
    const tabs=document.createElement("div");
    tabs.style.cssText="display:flex;gap:6px;border-bottom:1px solid var(--hair);margin-bottom:14px";
    const mk=label=>{const b=document.createElement("button");b.type="button";b.className="btn sm";
      b.style.cssText="border:0;border-radius:4px 4px 0 0;border-bottom:2px solid transparent";
      b.textContent=label;tabs.appendChild(b);return b;};
    const tFields=mk(t("Settings")),tCfg=mk("haproxy.cfg");
    const pre=document.createElement("pre");pre.textContent="";
    const note=document.createElement("div");note.className="hint";note.style.marginTop="8px";
    note.textContent=t("Exactly what Apply will write for this object, from the values as they "+
      "are now. Raw lines the fields do not cover go in Extra directives, under Settings.");
    cfgPane.appendChild(pre);cfgPane.appendChild(note);
    const show=which=>{
      frm.hidden=which!=="fields";cfgPane.hidden=which!=="cfg";
      tFields.style.borderBottomColor=which==="fields"?"var(--line)":"transparent";
      tCfg.style.borderBottomColor=which==="cfg"?"var(--line)":"transparent";
      if(which==="cfg"){
        pre.textContent=t("rendering...");
        api("haproxy/preview-object","POST",{col:key.split("/")[1],
            item:Object.assign({},shown||{},readForm(def.fields))})
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
  openDlg(t(item?"Edit {what}":"New {what}",{what:t(def.one)}),wrap,[err,
    btn(t("Cancel"),"",closeDlg),
    btn(t("Save"),"pri",async()=>{
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
  card.innerHTML='<div class=hd><h2>'+esc(t(def.title))+'</h2></div>';
  const bd=document.createElement("div");bd.className="bd";
  const intro=document.createElement("p");intro.className="hint";intro.style.marginBottom="14px";intro.textContent=t(def.intro);
  bd.appendChild(intro);
  const frm=document.createElement("div");frm.className="frm";
  def.fields.forEach(f=>fieldRow(f,cur[f.k]).forEach(el=>frm.appendChild(el)));
  bd.appendChild(frm);
  const foot=document.createElement("div");foot.style.marginTop="16px";
  const msg=document.createElement("span");msg.className="hint";msg.style.marginLeft="10px";
  const shared=!def.sub;          // sub-keyed pages write to local settings
  const save=btn(t("Save"),"pri",async()=>{
    const data=readForm(def.fields);
    try{
      await api(def.ep,"PUT",def.sub?{[def.sub]:data}:data);
      msg.textContent=shared?t("Saved. Apply to make it so; the other nodes follow."):t("Saved.");refreshStatus();
    }catch(e){
      msg.innerHTML='<span class="pill down">'+t("not saved")+'</span>';
      showText(t("Not saved"),trimHaproxy(e.message));
    }
  });
  if(state.readOnly&&shared){save.disabled=true;msg.textContent=t("Read-only on a passive node.");}
  foot.appendChild(save);
  if(shared){
    foot.appendChild(document.createTextNode(" "));
    foot.appendChild(btn(t("Validate"),"",async()=>{
      msg.textContent=t("Checking...");
      try{
        const r=await api("validate","POST",{section:def.ep.split("/")[0],settings:readForm(def.fields)});
        msg.innerHTML=r.ok?'<span class="pill up">'+t("valid")+'</span> '+esc(r.message)
                          :'<span class="pill down">'+t("not valid")+'</span>';
        if(!r.ok)showText(t("These settings would not work"),trimHaproxy(r.message));
      }catch(e){msg.textContent=e.message;}
    }));
  }
  foot.appendChild(msg);
  bd.appendChild(foot);card.appendChild(bd);c.appendChild(card);
  if(def.extra)c.appendChild(def.extra());
}
