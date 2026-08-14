import { $, api, btn, closeDlg, esc, fieldRow, list, lists, localTime, openDlg, readForm, showText } from "../core.js";
import { E, renderEntity } from "../entities.js";
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
    (o.optional?" <span class=sub>(optional)</span>":"")+
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
    if(!h){note.innerHTML='<span class=sub>Unknown hook &mdash; it will be passed to acme.sh as typed.</span>';return;}
    let html="<b>"+esc(h.title)+"</b> needs:<br>"+(h.options.length?varList(h.options):"<span class=sub>no credentials</span>");
    if(h.options_alt.length)html+="<br><i>or instead:</i><br>"+varList(h.options_alt);
    if(h.docs)html+='<br><a href="'+esc(h.docs.startsWith("http")?h.docs:"https://"+h.docs)+'" target="_blank" rel="noopener">documentation</a>';
    note.innerHTML=html;
    const need=(h.options.length?h.options:h.options_alt).filter(o=>!o.optional);
    if(need.length){
      const b=btn("Fill in the variable names","sm",()=>{
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
export const CERT_WIZ=[
 {k:"domains",l:"Domain names",t:"textarea",h:"One per line. The first is the certificate's primary name. A wildcard such as *.example.com needs DNS-01."},
 {k:"name",l:"Certificate name",t:"text",h:"Optional -- taken from the first domain when left empty"},
 {k:"account_id",l:"ACME account",t:"select",o:[]},
 {k:"acc_name",l:"New account name",t:"text"},
 {k:"acc_email",l:"E-mail address",t:"text",h:"Where the CA sends expiry warnings"},
 {k:"acc_ca",l:"Certificate authority",t:"select",o:["letsencrypt","letsencrypt_test","zerossl","buypass","google"],d:"letsencrypt",
  h:"letsencrypt_test issues untrusted certificates but has no rate limits -- ideal while setting things up"},
 {k:"acc_eab_kid",l:"EAB key ID",t:"text",h:"Only for ZeroSSL and Google"},
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
    if(f.k==="account_id")return Object.assign({},f,{o:accounts.map(a=>({value:a.id,label:a.name+" ("+(a.ca||"letsencrypt")+")"})).concat([{value:NEWOPT,label:"Create a new account..."}])});
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
  const sync=()=>{
    const newAcc=frm.querySelector("#f_account_id").value===NEWOPT;
    ["acc_name","acc_email","acc_ca","acc_eab_kid","acc_eab_hmac"].forEach(k=>setRow(k,newAcc));
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
      ? {name:d.acc_name||("account-"+(d.acc_ca||"letsencrypt")),email:d.acc_email,ca:d.acc_ca,
         eab_kid:d.acc_eab_kid,eab_hmac:d.acc_eab_hmac}
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
    box.innerHTML='<div class=hd><h2>'+(saved?"Done":"What this will create")+'</h2></div>'+
      '<div class=bd><div class=mono style="margin-bottom:10px">'+esc((r.domains||[]).join(", "))+"</div>"+
      "<table><tbody>"+(r.actions||[]).map(a=>"<tr><td style='width:90px'><span class='pill "+
        (a.action==="created"?"up":a.action==="updated"?"warn":"off")+"'>"+esc(a.action)+"</span></td><td>"+
        esc(a.type)+"</td><td class=mono>"+esc(a.name)+"</td></tr>").join("")+"</tbody></table>"+
      (r.warnings||[]).map(w=>'<div class=hint style="margin-top:10px">! '+esc(w)+"</div>").join("")+
      (r.issued?('<div style="margin-top:12px">'+(r.issued.ok
          ?'<span class="pill up">issued</span> The certificate is deployed.'
          :'<span class="pill down">failed</span> '+esc(r.issued.error||""))+"</div>"):"")+"</div>";
    if(r.issued&&r.issued.log){
      const b=btn("Show the acme.sh log","sm",()=>showText("acme.sh",r.issued.log));
      b.style.margin="0 16px 16px";box.appendChild(b);
    }
    out.appendChild(box);
  };

  const prev=btn("Preview","",async()=>{
    err.textContent="";
    try{show(await api("wizard/certificate","POST",Object.assign(read(),{dry_run:true,issue:false})),false);}
    catch(e){err.textContent=e.message;}
  });
  const go=btn("Create","pri",async()=>{
    err.textContent="";go.disabled=true;prev.disabled=true;
    const body=read();
    if(body.issue)show({domains:(body.domains||"").split(/[\s,]+/).filter(Boolean),actions:[],
                        warnings:["Running acme.sh -- this can take a minute."]},false);
    try{
      const r=await api("wizard/certificate","POST",body);
      show(r,true);
      lists["acme/accounts"]=null;lists["acme/challenges"]=null;
      await route();refreshStatus();
    }catch(e){err.textContent=e.message;go.disabled=false;prev.disabled=false;}
  });
  openDlg("Request a certificate",wrap,[err,btn("Close","",closeDlg),prev,go]);
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
  const missing=[];
  if(!accounts.length)missing.push("an ACME account");
  if(!challenges.length)missing.push("a challenge type");
  const card=document.createElement("div");card.className="card";
  card.style.borderColor="#e3cfa8";
  card.innerHTML='<div class=hd><h2>Set up ACME first</h2></div>'+
    '<div class=bd><p>Issuing a certificate needs '+esc(missing.join(" and "))+
      ', and this node has '+(missing.length===2?"neither":"none")+' yet.</p>'+
    '<p class=hint style="margin-top:8px">An account is who the certificate is '+
      'requested as; a challenge type is how the certificate authority checks you '+
      'control the domain &mdash; HTTP-01 over port 80, or DNS-01 through your DNS '+
      'provider for wildcards.</p></div>';
  const foot=document.createElement("div");foot.className="bd";
  foot.style.cssText="border-top:1px solid var(--hair)";
  foot.appendChild(btn("Open ACME Settings","pri",()=>{location.hash="#/p:acme";}));
  card.appendChild(foot);
  return card;
}

/* Both notices the certificates page can show, in the order they matter. */
export function certificateNotices(){
  return [acmeSetupNotice(), acmeNotice()];
}

export function acmeNotice(){
  const h=acmeHealth;
  if(!h||(h.ok&&!h.warning))return null;
  const card=document.createElement("div");card.className="card";
  card.style.borderColor=h.ok?"#e3cfa8":"var(--down)";
  const bad=!h.ok;
  card.innerHTML='<div class=hd><h2>'+(bad?"Certificates cannot be issued on this node"
                                         :"acme.sh warning")+"</h2></div>"+
    '<div class=bd><p>'+esc(h.problem||h.warning||"")+"</p>"+
    (h.hint?'<p class=hint style="margin-top:8px">'+esc(h.hint)+"</p>":"")+
    '<p class=hint style="margin-top:8px">Looked for it at <span class=mono>'+esc(h.path)+
      "</span>"+(h.version?", found "+esc(h.version):"")+
      ". Existing certificates are still served and still sync between nodes"+
      (bad?"; only issuing and renewing are affected.":".")+"</p></div>";
  return card;
}

/* ---- certificate status ---- */
/* Per-certificate state comes from /api/status, keyed by certificate id. */
export let certStat={};
export async function loadCertStatus(){
  try{const st=await api("status");certStat={};(st.certs||[]).forEach(c=>{certStat[c.id]=c;});}
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
  if(!s)return '<span class="pill off">unknown</span>';
  const [cls,label]=CERT_STATUS[s.status]||["off",s.status];
  let h='<span class="pill '+cls+'">'+esc(label)+"</span>";
  if(s.status==="placeholder")h+='<div class=sub>self-signed stand-in — press Issue</div>';
  else if(s.status==="missing")h+='<div class=sub>no PEM on disk yet</div>';
  if(s.auto_renew===false)h+='<div class=sub>auto-renew off</div>';
  /* A name added to a certificate is not a name the certificate covers: the
     file on disk still holds whatever was last issued. Until it is issued
     again, that address is served the wrong certificate, which looks to a
     browser like the site being unreachable rather than like a certificate
     problem -- so it is said here plainly. */
  if((s.not_issued_for||[]).length)
    h+='<div class=sub style="color:var(--drift)">not in the issued certificate: '+
       s.not_issued_for.map(esc).join(", ")+" — press Issue</div>";
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
    const n=Math.abs(d),unit=" day"+(n===1?"":"s");
    h+='<div class=sub>'+(d<0?("expired "+n+unit+" ago"):("in "+d+unit))+"</div>";
  }
  return h;
}
export function certLastCell(r){
  const li=(certStat[r.id]||{}).last_issue;
  if(!li)return '<span class=sub>never attempted</span>';
  let h='<span class="pill '+(li.ok?"up":"down")+'">'+(li.ok?"succeeded":"failed")+"</span>"+
        "<div class=sub>"+fmtTime(li.time)+" · "+esc(li.seconds)+"s</div>";
  if(!li.ok&&li.error)h+="<div class=sub>"+esc(li.error)+"</div>";
  return h;
}
export async function issueCert(row,force){
  const pre=document.createElement("pre");
  pre.textContent="Requesting a certificate for \""+row.name+"\" ...\n\n"+
    "acme.sh usually needs 10-60 seconds for HTTP-01; DNS-01 can take several minutes\n"+
    "while the TXT record propagates. The result and the full log appear here.";
  openDlg((force?"Force issue: ":"Issue: ")+row.name,pre,[btn("Close","",closeDlg)]);
  try{
    const r=await api("acme/issue/"+row.id,"POST",{force:!!force});
    pre.textContent=(r.ok
        ? "SUCCESS -- certificate issued and written to the HAProxy certificate directory.\nHAProxy has been reloaded and the certificate pushed to the other nodes."
        : "FAILED -- "+(r.error||"unknown error"))+
      "\n\n--- acme.sh log ---\n"+(r.log||"(no output)");
  }catch(e){pre.textContent="FAILED -- "+e.message;}
  if(E[location.hash.replace(/^#\//,"")])await renderEntity("acme/certificates");
  refreshStatus();
}
export async function showCertLog(row){
  try{
    const r=await api("acme/log/"+row.id);
    if(!r.ok){showText("Last issuance: "+row.name,r.error);return;}
    const e=r.entry;
    showText("Last issuance: "+row.name,
      (e.ok?"Result: succeeded":"Result: FAILED"+(e.error?" -- "+e.error:""))+
      "\nWhen:   "+String(e.time).replace("T"," ").replace("+00:00"," UTC")+
      "\nTook:   "+e.seconds+"s\n\n--- acme.sh log ---\n"+(e.log||"(no output)"));
  }catch(e){showText("Last issuance: "+row.name,e.message);}
}
