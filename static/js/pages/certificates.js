import { $, ADCS_FIELDS, CA_CHOICES, api, btn, closeDlg, esc, fieldRow, list, lists, localTime, openDlg, readForm, showText, download } from "../core.js";
import { E, renderEntity } from "../entities.js";
import { t, tn } from "../i18n.js";
import { refreshStatus, route } from "../shell.js";
import { state } from "../state.js";

/* ---- acme.sh DNS hooks ---- */

export let dnsApiByHook={};
export let dnsApiOptions=[];
export let dnsApiNote="";
export async function loadDnsApis(){
  if(state.dnsApis.length)return state.dnsApis;
  try{
    const r=await api("acme/dnsapi");
    state.dnsApis=r.hooks||[];dnsApiNote=r.note||"";
    dnsApiByHook={};state.dnsApis.forEach(h=>{dnsApiByHook[h.hook]=h;});
    dnsApiOptions=state.dnsApis.map(h=>({value:h.hook,label:h.title+" ("+h.hook+")"}));
  }catch(e){state.dnsApis=[];dnsApiNote=e.message;}
  return state.dnsApis;
}
export function varList(list){
  return list.map(o=>'<span class=mono>'+esc(o.name)+"</span>"+
    (o.optional?" <span class=sub>"+t("(optional)")+"</span>":"")+
    (o.desc?" &mdash; "+esc(o.desc):"")).join("<br>");
}
/* Show what the chosen hook needs, and offer to seed the credentials box. */
export function dnsCredentialHelp(frm){
  const sel=frm.querySelector("#f_dns_provider"),creds=frm.querySelector("#f_dns_credentials");
  if(!sel||!creds)return;
  const note=document.createElement("div");note.className="hint";note.style.marginTop="6px";
  creds.parentNode.appendChild(note);
  const render=()=>{
    const h=dnsApiByHook[sel.value.trim()];
    if(!sel.value.trim()){note.innerHTML=dnsApiNote?esc(dnsApiNote):"";return;}
    if(!h){note.innerHTML='<span class=sub>'+t("Unknown hook &mdash; it will be passed to acme.sh as typed.")+'</span>';return;}
    let html=t("<b>{name}</b> needs:",{name:esc(h.title)})+"<br>"+(h.options.length?varList(h.options):"<span class=sub>"+t("no credentials")+"</span>");
    if(h.options_alt.length)html+="<br><i>"+t("or instead:")+"</i><br>"+varList(h.options_alt);
    if(h.docs)html+='<br><a href="'+esc(h.docs.startsWith("http")?h.docs:"https://"+h.docs)+'" target="_blank" rel="noopener">'+t("documentation")+'</a>';
    note.innerHTML=html;
    const need=(h.options.length?h.options:h.options_alt).filter(o=>!o.optional);
    if(need.length){
      const b=btn(t("Fill in the variable names"),"sm",()=>{
        const have=creds.value.split("\n").map(l=>l.split("=")[0].trim()).filter(Boolean);
        const add=need.filter(o=>!have.includes(o.name)).map(o=>o.name+"=");
        if(add.length)creds.value=(creds.value.trim()?creds.value.replace(/\s*$/,"")+"\n":"")+add.join("\n")+"\n";
      });
      b.style.marginTop="8px";note.appendChild(document.createElement("br"));note.appendChild(b);
    }
  };
  sel.addEventListener("change",render);sel.addEventListener("blur",render);render();
}

/* ---- certificate wizard ---- */
export const NEWOPT="__new__";
/* What an account's CA is called in a picker: a public CA by its short name,
   your own by the server that runs it. */
const caLabel=a=>a.ca==="custom"?(String(a.server||"").replace(/^https?:\/\//,"").split("/")[0]||"custom")
  :a.ca==="adcs"?(a.adcs_host||"adcs"):(a.ca||"letsencrypt");
/* Which rows an account's CA calls for beyond the common ones: a custom CA its
   address and certificate; AD CS its server and credentials, with the CA name
   and the domain for MS-ICPR and the CA certificate to trust for web enrollment
   over HTTPS. EAB is a public CA's thing, or a custom one's. */
export const CA_EXTRA=["server","ca_bundle",...ADCS_FIELDS.map(f=>f.k),"eab_kid","eab_hmac"];
export function caFieldsShown(ca,method){
  if(ca==="custom")return ["server","ca_bundle","eab_kid","eab_hmac"];
  if(ca!=="adcs")return ["eab_kid","eab_hmac"];
  const keys=ADCS_FIELDS.map(f=>f.k).filter(k=>method!=="certsrv"||!["adcs_ca_name","adcs_domain","adcs_dc"].includes(k));
  return method==="certsrv"?keys.concat(["ca_bundle"]):keys;
}
/* Show the rows the chosen CA calls for, keep the authentication to what the
   enrollment method takes, and offer to try the connection to the CA. `p` is
   the field prefix ("" in the editor, "acc_" in the wizard); `when` says
   whether the account rows are on at all. Returns the function that syncs. */
export function caRows(frm,p,when){
  p=p||"";when=when||(()=>true);
  const sel=frm.querySelector("#f_"+p+"ca");if(!sel)return ()=>{};
  const rowOf=k=>{let cell=frm.querySelector("#f_"+p+k);if(!cell)return [];
    while(cell.parentNode&&cell.parentNode!==frm&&!(cell.parentNode.classList&&cell.parentNode.classList.contains("frm")))cell=cell.parentNode;
    return [frm.querySelector('label[for="f_'+p+k+'"]'),cell].filter(Boolean);};
  const method=frm.querySelector("#f_"+p+"adcs_method"),auth=frm.querySelector("#f_"+p+"adcs_auth");
  adcsTestRow(frm,p);
  const sync=()=>{
    const on=when()?caFieldsShown(sel.value,method?method.value:"msicpr"):[];
    CA_EXTRA.forEach(k=>rowOf(k).forEach(el=>{el.style.display=on.includes(k)?"":"none";}));
    if(auth&&method){
      const takes=method.value==="certsrv"?["ntlm","basic"]:["kerberos","ntlm"];
      [...auth.querySelectorAll("option")].forEach(o=>{o.disabled=!takes.includes(o.value);});
      if(!takes.includes(auth.value))auth.value=takes[0];
    }
  };
  sel.addEventListener("change",sync);if(method)method.addEventListener("change",sync);sync();
  return sync;
}
/* Under the extra settings: "Test the connection", which asks the CA for
   nothing but a connection with the account as typed, so a wrong name or
   password shows before the first certificate is requested; and "Show the
   configuration", the acme_srv.cfg acme2certifier would be given, password
   masked. In the last AD CS cell, so they show and hide with the rows. */
function adcsTestRow(frm,p){
  const last=frm.querySelector("#f_"+p+"adcs_extra");if(!last)return;
  const box=document.createElement("div");box.style.marginTop="8px";
  const out=document.createElement("div");out.className="hint";out.style.cssText="margin-top:6px;white-space:pre-wrap";
  const typed=()=>{
    const body={};
    ADCS_FIELDS.forEach(f=>{const el=frm.querySelector("#f_"+p+f.k);if(el)body[f.k]=el.value;});
    const cb=frm.querySelector("#f_"+p+"ca_bundle");if(cb)body.ca_bundle=cb.value;
    return body;
  };
  const test=btn(t("Test the connection to the CA"),"sm",async()=>{
    test.disabled=true;out.textContent=t("Asking the CA...");
    try{const r=await api("acme/adcs/test","POST",typed());
      out.innerHTML='<span class="pill '+(r.ok?"up":"down")+'">'+(r.ok?t("reachable"):t("failed"))+"</span> "+esc(r.message||"");}
    catch(e){out.textContent=e.message;}
    test.disabled=false;
  });
  const show=btn(t("Show the configuration"),"sm",async()=>{
    try{const r=await api("acme/adcs/config","POST",typed());
      if(r.ok)showText("acme_srv.cfg",r.config);else out.textContent=r.error||"";}
    catch(e){out.textContent=e.message;}
  });
  show.style.marginLeft="6px";
  box.appendChild(test);box.appendChild(show);box.appendChild(out);last.parentNode.appendChild(box);
}
export const CERT_WIZ=[
 {k:"domains",l:"Domain names",t:"textarea",h:"One per line. The first is the certificate's primary name. A wildcard such as *.example.com needs DNS-01."},
 {k:"name",l:"Certificate name",t:"text",h:"Optional -- taken from the first domain when left empty"},
 {k:"account_id",l:"ACME account",t:"select",o:[]},
 {k:"acc_name",l:"New account name",t:"text"},
 {k:"acc_email",l:"E-mail address",t:"text",h:"Where the CA sends expiry warnings"},
 {k:"acc_ca",l:"Certificate authority",t:"select",o:CA_CHOICES,d:"letsencrypt",
  h:"letsencrypt_test issues untrusted certificates but has no rate limits -- ideal while setting things up"},
 {k:"acc_server",l:"ACME directory URL",t:"text",h:"Your own ACME server's directory, such as https://ca.example.lan/directory -- for example acme2certifier in front of Active Directory Certificate Services, step-ca or Vault"},
 {k:"acc_ca_bundle",l:"CA certificate to trust",t:"textarea",h:"Optional. The PEM certificate of the CA that signed the ACME server's own HTTPS certificate, if this node does not trust it already"},
 ...ADCS_FIELDS.map(f=>Object.assign({},f,{k:"acc_"+f.k})),
 {k:"acc_eab_kid",l:"EAB key ID",t:"text",h:"Google, SSL.com and Actalis need one, from your account with them, and so may your own CA. ZeroSSL gets its own from the e-mail address."},
 {k:"acc_eab_hmac",l:"EAB HMAC key",t:"password"},
 {k:"challenge_id",l:"Challenge type",t:"select",o:[]},
 {k:"ch_name",l:"New challenge name",t:"text"},
 {k:"ch_method",l:"Validation method",t:"select",o:["http01","dns01"],d:"http01",
  h:"HTTP-01 needs port 80 reachable from the internet. DNS-01 works behind a firewall and is the only way to get a wildcard."},
 {k:"dns_provider",l:"DNS API hook",t:"combo",o:()=>dnsApiOptions,h:"The provider acme.sh should talk to"},
 {k:"dns_credentials",l:"DNS API credentials",t:"textarea",h:"One KEY=value per line"},
 {k:"key_type",l:"Key type",t:"select",o:["ec-256","ec-384","rsa-2048","rsa-4096"],d:"ec-256"},
 {k:"auto_renew",l:"Renew automatically",t:"bool",d:true},
 {k:"issue",l:"Request it now",t:"bool",d:true,h:"Runs acme.sh straight away; leave off to just create the objects"},
];
export async function openCertWizard(){
  await Promise.all([list("acme/accounts",true),list("acme/challenges",true),loadDnsApis()]);
  const accounts=lists["acme/accounts"]||[],challenges=lists["acme/challenges"]||[];
  const fields=CERT_WIZ.map(f=>{
    if(f.k==="account_id")return Object.assign({},f,{o:accounts.map(a=>({value:a.id,label:a.name+" ("+caLabel(a)+")"})).concat([{value:NEWOPT,label:"Create a new account..."}])});
    if(f.k==="challenge_id")return Object.assign({},f,{o:challenges.map(c=>({value:c.id,label:c.name+" ("+(c.method||"http01")+")"})).concat([{value:NEWOPT,label:"Create a new challenge type..."}])});
    return f;
  });
  const wrap=document.createElement("div");
  const frm=document.createElement("div");frm.className="frm";
  const rows={};
  fields.forEach(f=>{const cells=fieldRow(f,f.k==="account_id"&&!accounts.length?NEWOPT
                                          :f.k==="challenge_id"&&!challenges.length?NEWOPT:undefined);
    rows[f.k]=cells;cells.forEach(el=>frm.appendChild(el));});
  wrap.appendChild(frm);
  const out=document.createElement("div");out.style.marginTop="16px";wrap.appendChild(out);
  const err=document.createElement("div");err.className="err";

  const setRow=(k,on)=>{(rows[k]||[]).forEach(el=>{el.style.display=on?"":"none";});};
  const caSync=caRows(frm,"acc_",()=>frm.querySelector("#f_account_id").value===NEWOPT);
  const sync=()=>{
    const newAcc=frm.querySelector("#f_account_id").value===NEWOPT;
    ["acc_name","acc_email","acc_ca"].forEach(k=>setRow(k,newAcc));
    caSync();
    const newCh=frm.querySelector("#f_challenge_id").value===NEWOPT;
    const method=frm.querySelector("#f_ch_method").value;
    ["ch_name","ch_method"].forEach(k=>setRow(k,newCh));
    ["dns_provider","dns_credentials"].forEach(k=>setRow(k,newCh&&method==="dns01"));
  };
  ["f_account_id","f_challenge_id","f_ch_method"].forEach(id=>{
    const el=frm.querySelector("#"+id);if(el)el.addEventListener("change",sync);});
  dnsCredentialHelp(frm);
  sync();

  const read=()=>{
    const d=readForm(fields);
    const body={domains:d.domains,name:d.name,key_type:d.key_type,
                auto_renew:d.auto_renew,issue:d.issue};
    body.account=d.account_id===NEWOPT
      ? Object.assign({name:d.acc_name||("account-"+(d.acc_ca||"letsencrypt")),email:d.acc_email,ca:d.acc_ca,
         server:d.acc_ca==="custom"?d.acc_server:"",
         ca_bundle:d.acc_ca==="custom"||d.acc_ca==="adcs"?d.acc_ca_bundle:"",
         eab_kid:d.acc_ca==="adcs"?"":d.acc_eab_kid,eab_hmac:d.acc_ca==="adcs"?"":d.acc_eab_hmac},
         d.acc_ca==="adcs"?Object.fromEntries(ADCS_FIELDS.map(f=>[f.k,d["acc_"+f.k]])):{})
      : {id:d.account_id};
    body.challenge=d.challenge_id===NEWOPT
      ? {name:d.ch_name||(d.ch_method==="dns01"?("dns-"+(d.dns_provider||"01")):"http-01"),
         method:d.ch_method,dns_provider:d.dns_provider,dns_credentials:d.dns_credentials}
      : {id:d.challenge_id};
    return body;
  };
  const show=(r,saved)=>{
    out.innerHTML="";
    const box=document.createElement("div");box.className="card";box.style.margin="0";
    box.innerHTML='<div class=hd><h2>'+(saved?t("Done"):t("What this will create"))+'</h2></div>'+
      '<div class=bd><div class=mono style="margin-bottom:10px">'+esc((r.domains||[]).join(", "))+"</div>"+
      "<table><tbody>"+(r.actions||[]).map(a=>"<tr><td style='width:90px'><span class='pill "+
        (a.action==="created"?"up":a.action==="updated"?"warn":"off")+"'>"+esc(t(a.action))+"</span></td><td>"+
        esc(a.type)+"</td><td class=mono>"+esc(a.name)+"</td></tr>").join("")+"</tbody></table>"+
      (r.warnings||[]).map(w=>'<div class=hint style="margin-top:10px">! '+esc(w)+"</div>").join("")+
      (r.issued?('<div style="margin-top:12px">'+(r.issued.ok
          ?'<span class="pill up">'+t("issued")+'</span> '+t("The certificate is deployed.")
          :'<span class="pill down">'+t("failed")+'</span> '+esc(r.issued.error||""))+"</div>"):"")+"</div>";
    if(r.issued&&r.issued.log){
      const b=btn(t("Show the acme.sh log"),"sm",()=>showText("acme.sh",r.issued.log));
      b.style.margin="0 16px 16px";box.appendChild(b);
    }
    out.appendChild(box);
  };

  const prev=btn(t("Preview"),"",async()=>{
    err.textContent="";
    try{show(await api("wizard/certificate","POST",Object.assign(read(),{dry_run:true,issue:false})),false);}
    catch(e){err.textContent=e.message;}
  });
  const go=btn(t("Create"),"pri",async()=>{
    err.textContent="";go.disabled=true;prev.disabled=true;
    const body=read();
    if(body.issue)show({domains:(body.domains||"").split(/[\s,]+/).filter(Boolean),actions:[],
                        warnings:[t("Running acme.sh -- this can take a minute.")]},false);
    try{
      const r=await api("wizard/certificate","POST",body);
      show(r,true);
      lists["acme/accounts"]=null;lists["acme/challenges"]=null;
      await route();refreshStatus();
    }catch(e){err.textContent=e.message;go.disabled=false;prev.disabled=false;}
  });
  openDlg(t("Request a certificate"),wrap,[err,btn(t("Close"),"",closeDlg),prev,go]);
}

/* ---- acme.sh health ---- */
export let acmeHealth=null;
export async function loadAcmeHealth(){
  try{acmeHealth=await api("acme/health");}catch(e){acmeHealth=null;}
  return acmeHealth;
}
/* A certificate needs an account to be issued under and a challenge type to
   prove the domain with. Without either, "Request a certificate" leads to a
   wizard that cannot finish, so say it here where the attempt starts. */
export function acmeSetupNotice(){
  const accounts=lists["acme/accounts"]||[], challenges=lists["acme/challenges"]||[];
  if(accounts.length&&challenges.length)return null;
  const card=document.createElement("div");card.className="card";
  card.style.borderColor="#e3cfa8";
  card.innerHTML='<div class=hd><h2>'+t("Set up ACME first")+'</h2></div>'+
    '<div class=bd><p>'+
      (!accounts.length&&!challenges.length
        ?t("Issuing a certificate needs an ACME account and a challenge type, and this node has neither yet.")
        :!accounts.length
        ?t("Issuing a certificate needs an ACME account, and this node has none yet.")
        :t("Issuing a certificate needs a challenge type, and this node has none yet."))+'</p>'+
    '<p class=hint style="margin-top:8px">'+
      t("An account is who the certificate is requested as; a challenge type is how the "+
        "certificate authority checks you control the domain &mdash; HTTP-01 over port 80, "+
        "or DNS-01 through your DNS provider for wildcards.")+'</p></div>';
  const foot=document.createElement("div");foot.className="bd";
  foot.style.cssText="border-top:1px solid var(--hair)";
  foot.appendChild(btn(t("Open ACME Settings"),"pri",()=>{location.hash="#/p:acme";}));
  card.appendChild(foot);
  return card;
}

/* The notices the certificates page can show, in the order they matter. */
export function certificateNotices(){
  return [acmeSetupNotice(), acmeNotice(), adcsNotice()];
}

/* Active Directory Certificate Services needs acme2certifier on the node that
   issues. The image has it; a node installed from a package or install.sh
   fetches it at the first issuance -- or now, from here. */
export function adcsNotice(){
  const a=acmeHealth&&acmeHealth.adcs;
  if(!a||!a.wanted||(a.installed&&a.impacket))return null;
  const card=document.createElement("div");card.className="card";card.style.borderColor="#e3cfa8";
  card.innerHTML='<div class=hd><h2>'+(a.installed?t("Impacket is not installed on this node")
                                                   :t("acme2certifier is not installed on this node"))+'</h2></div>'+
    '<div class=bd><p>'+(a.installed
      ?t("An account enrolls with Active Directory Certificate Services over MS-ICPR, which needs Impacket (python3-impacket), and this node does not have it.")
      :t("An account enrolls with Active Directory Certificate Services through acme2certifier, which this node does not have yet. It is installed at the first issuance, or now."))+"</p>"+
    (a.install_error?'<p class=hint style="margin-top:8px">'+t("The last install failed:")+' <span class=mono>'+
       esc(a.install_error.split("\n").slice(-3).join(" "))+"</span></p>":"")+"</div>";
  if(!a.installed){
    const foot=document.createElement("div");foot.className="bd";foot.style.cssText="border-top:1px solid var(--hair)";
    const b=btn(t("Install acme2certifier now"),"pri",async()=>{
      b.disabled=true;b.textContent=t("Installing -- this can take a few minutes...");
      try{await api("acme/adcs/install","POST",{});await route();}catch(e){b.textContent=e.message;}});
    foot.appendChild(b);card.appendChild(foot);
  }
  return card;
}

export function acmeNotice(){
  const h=acmeHealth;
  if(!h||(h.ok&&!h.warning))return null;
  const card=document.createElement("div");card.className="card";
  card.style.borderColor=h.ok?"#e3cfa8":"var(--down)";
  const bad=!h.ok;
  card.innerHTML='<div class=hd><h2>'+(bad?t("Certificates cannot be issued on this node")
                                         :t("acme.sh warning"))+"</h2></div>"+
    '<div class=bd><p>'+esc(h.problem||h.warning||"")+"</p>"+
    (h.hint?'<p class=hint style="margin-top:8px">'+esc(h.hint)+"</p>":"")+
    '<p class=hint style="margin-top:8px">'+
      t("Looked for it at <span class=mono>{path}</span>",{path:esc(h.path)})+
      (h.version?", "+t("found {version}",{version:esc(h.version)}):"")+
      ". "+(bad?t("Existing certificates are still served and still sync between nodes; only issuing and renewing are affected.")
               :t("Existing certificates are still served and still sync between nodes."))+"</p></div>";
  return card;
}

/* ---- certificate status ---- */
/* Per-certificate state comes from /api/status, keyed by certificate id. */
export let certStat={};
export async function loadCertStatus(){
  try{const st=await api("status?brief=1");certStat={};(st.certs||[]).forEach(c=>{certStat[c.id]=c;});}
  catch(e){certStat={};}
}
export const CERT_STATUS={
  valid:      ["up",  "valid"],
  expiring:   ["warn","expires soon"],
  expired:    ["down","expired"],
  placeholder:["warn","placeholder"],
  missing:    ["off", "not issued"],
  unreadable: ["down","unreadable"],
  unknown:    ["off", "unknown"],
};
export function certStatusCell(r){
  const s=certStat[r.id];
  if(!s)return '<span class="pill off">'+t("unknown")+'</span>';
  const [cls,label]=CERT_STATUS[s.status]||["off",s.status];
  let h='<span class="pill '+cls+'">'+esc(t(label))+"</span>";
  if(s.status==="placeholder")h+='<div class=sub>'+t("self-signed stand-in — press Issue")+'</div>';
  else if(s.status==="missing")h+='<div class=sub>'+t("no PEM on disk yet")+'</div>';
  if(s.auto_renew===false)h+='<div class=sub>'+t("auto-renew off")+'</div>';
  /* A name added to a certificate is not a name the certificate covers: the
     file on disk still holds whatever was last issued. Until it is issued
     again, that address is served the wrong certificate, which looks to a
     browser like the site being unreachable rather than like a certificate
     problem -- so it is said here plainly. */
  if((s.not_issued_for||[]).length)
    h+='<div class=sub style="color:var(--drift)">'+
       t("not in the issued certificate: {names} — press Issue",{names:s.not_issued_for.map(esc).join(", ")})+"</div>";
  return h;
}
/* Shown in the reader's own timezone; the server only ever speaks UTC. */
export function fmtTime(t){return esc(localTime(t));}
export function certExpiryCell(r){
  const s=certStat[r.id];
  if(!s||!(s.expires_iso||s.expires))return '<span class=sub>—</span>';
  const d=s.days_left;
  let h='<span class=mono>'+fmtTime(s.expires_iso||s.expires)+"</span>";
  if(d!==null&&d!==undefined){
    const n=Math.abs(d);
    h+='<div class=sub>'+(d<0?tn(n,"expired {n} day ago","expired {n} days ago")
                             :tn(n,"in {n} day","in {n} days"))+"</div>";
  }
  return h;
}
export function certLastCell(r){
  if(r.source==="custom")return '<span class="pill off">'+t("uploaded")+'</span><div class=sub>'+t("never renewed here")+"</div>";
  const li=(certStat[r.id]||{}).last_issue;
  if(!li)return '<span class=sub>'+t("never attempted")+'</span>';
  let h='<span class="pill '+(li.ok?"up":"down")+'">'+(li.ok?t("succeeded"):t("failed"))+"</span>"+
        "<div class=sub>"+fmtTime(li.time)+" · "+esc(li.seconds)+"s</div>";
  if(!li.ok&&li.error)h+="<div class=sub>"+esc(li.error)+"</div>";
  return h;
}
export async function issueCert(row,force){
  const pre=document.createElement("pre");
  pre.textContent=t("Requesting a certificate for \"{name}\" ...",{name:row.name})+"\n\n"+
    t("acme.sh usually needs 10-60 seconds for HTTP-01; DNS-01 can take several minutes\n"+
      "while the TXT record propagates. The result and the full log appear here.");
  openDlg(t(force?"Force issue: {name}":"Issue: {name}",{name:row.name}),pre,[btn(t("Close"),"",closeDlg)]);
  try{
    const r=await api("acme/issue/"+row.id,"POST",{force:!!force});
    pre.textContent=(r.ok
        ? t("SUCCESS -- certificate issued and written to the HAProxy certificate directory.\nHAProxy has been reloaded and the certificate pushed to the other nodes.")
        : t("FAILED -- {error}",{error:r.error||t("unknown error")}))+
      "\n\n--- "+t("acme.sh log")+" ---\n"+(r.log||t("(no output)"));
  }catch(e){pre.textContent=t("FAILED -- {error}",{error:e.message});}
  // Only repaint if the Certificates page is still the one on screen: issuing
  // takes tens of seconds (minutes for DNS-01), and landing this on whatever
  // page the person moved to would replace it. route() serializes with any
  // navigation in flight rather than painting straight over it.
  if(location.hash==="#/acme/certificates")route();
  refreshStatus();
}
/* A certificate issued elsewhere: the PEMs pasted or read from files, checked
   on the server (the key must belong to the certificate), stored like an
   issued one and sent to the other nodes. Replacing names the one to replace. */
export function openUpload(row){
  const wrap=document.createElement("div");
  const frm=document.createElement("div");frm.className="frm";
  const field=(id,label,el,hint)=>{
    const lab=document.createElement("label");lab.className="fl";lab.textContent=label;lab.htmlFor=id;
    const cell=document.createElement("div");el.id=id;cell.appendChild(el);
    if(hint){const h=document.createElement("div");h.className="hint";h.textContent=hint;cell.appendChild(h);}
    frm.appendChild(lab);frm.appendChild(cell);return el;
  };
  const pem=(id,label,hint)=>{
    const ta=document.createElement("textarea");ta.className="mono";ta.rows=5;
    const el=field(id,label,ta,hint);
    const file=document.createElement("input");file.type="file";file.accept=".pem,.crt,.cer,.key,.txt";
    file.style.marginTop="6px";file.setAttribute("aria-label",t("Load from file"));
    file.addEventListener("change",()=>{const f=file.files&&file.files[0];if(!f)return;
      const rd=new FileReader();rd.onload=()=>{ta.value=String(rd.result||"");};rd.readAsText(f);});
    el.parentNode.insertBefore(file,el.nextSibling);
    return ta;
  };
  const name=document.createElement("input");name.type="text";
  if(row){name.value=row.name;name.disabled=true;}
  field("f_up_name",t("Name"),name,t("Also the file name in the certificate directory"));
  const cert=pem("f_up_cert",t("Certificate"),t("PEM, -----BEGIN CERTIFICATE----- and all. Intermediates may follow it here or go below."));
  const key=pem("f_up_key",t("Private key"),t("PEM, unencrypted: HAProxy reads it without a passphrase."));
  const chain=pem("f_up_chain",t("Chain (optional)"),t("The intermediate certificates, if not already above."));
  wrap.appendChild(frm);
  const err=document.createElement("div");err.className="err";
  const out=document.createElement("div");out.className="hint";out.style.marginTop="12px";wrap.appendChild(out);
  const closeBtn=btn(t("Close"),"",closeDlg);
  const save=btn(t("Upload"),"pri",async()=>{
    err.textContent="";save.disabled=true;
    try{
      const r=await api("acme/certificates/upload","POST",{id:row?row.id:undefined,name:name.value,
        cert:cert.value,key:key.value,chain:chain.value});
      out.textContent=t("Stored, covering {names}.",{names:(r.names||[]).join(", ")||"—"})+" "+(r.note||"");
      closeBtn.textContent=t("Done");
      if(location.hash==="#/acme/certificates")route();
      refreshStatus();
    }catch(e){err.textContent=e.message;save.disabled=false;}
  });
  openDlg(row?t("Replace: {name}",{name:row.name}):t("Upload a certificate"),wrap,[err,closeBtn,save]);
}
/* The certificate and its chain, or the private key: two files, two
   clicks, so the key is never downloaded by accident. */
export function openDownload(row){
  const wrap=document.createElement("div");
  const p=document.createElement("p");p.className="hint";
  p.textContent=t("The certificate with its chain is safe to share. The private key is not: whoever has it can pose as these names.");
  wrap.appendChild(p);
  const bar=document.createElement("div");bar.style.cssText="display:flex;gap:8px;flex-wrap:wrap";
  bar.appendChild(btn(t("Certificate and chain (.crt)"),"pri",()=>download("acme/certificates/"+row.id+"/download?part=chain")));
  bar.appendChild(btn(t("Private key (.key)"),"dngr",()=>{
    if(confirm(t("Download the private key of {name}?",{name:row.name})))
      download("acme/certificates/"+row.id+"/download?part=key");
  }));
  wrap.appendChild(bar);
  openDlg(t("Download: {name}",{name:row.name}),wrap,[btn(t("Close"),"",closeDlg)]);
}
export async function showCertLog(row){
  try{
    const r=await api("acme/log/"+row.id);
    if(!r.ok){showText(t("Last issuance: {name}",{name:row.name}),r.error);return;}
    const e=r.entry;
    showText(t("Last issuance: {name}",{name:row.name}),
      (e.ok?t("Result: succeeded"):t("Result: FAILED")+(e.error?" -- "+e.error:""))+
      "\n"+t("When:   {when}",{when:String(e.time).replace("T"," ").replace("+00:00"," UTC")})+
      "\n"+t("Took:   {seconds}s",{seconds:e.seconds})+"\n\n--- "+t("acme.sh log")+" ---\n"+(e.log||t("(no output)")));
  }catch(e){showText(t("Last issuance: {name}",{name:row.name}),e.message);}
}
