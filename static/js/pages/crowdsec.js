/* CrowdSec: the bouncer on every node, and what HAProxy does with its answers. */
import { $, api, btn, esc, fieldRow, list, readForm, showText } from "../core.js";
import { t } from "../i18n.js";
import { refreshStatus } from "../shell.js";
import { state } from "../state.js";

export const MODE_LABEL={ban:"ban -- a 403 page",captcha:"captcha first, then a ban for those who fail"};
export const PROVIDER_LABEL={"":"(none)",hcaptcha:"hCaptcha",recaptcha:"reCAPTCHA",turnstile:"Cloudflare Turnstile"};

export async function renderCrowdsec(){
  const c=$("#content");c.innerHTML="";
  let s;
  try{[s]=await Promise.all([api("crowdsec/settings"),list("haproxy/addresslists",true)]);}
  catch(e){c.innerHTML='<div class="card"><div class="bd">'+esc(e.message)+"</div></div>";return;}
  const st=s.status||{};

  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>CrowdSec</h2><div class=sp></div>'+
    '<span class="pill '+(s.enabled?"up":"off")+'">'+(s.enabled?t("on"):t("off"))+"</span></div>";
  const bd=document.createElement("div");bd.className="bd";
  bd.innerHTML='<p class=hint style="margin-bottom:14px">'+
    t("CrowdSec decides who is banned from what its agents see across the fleet; HAProxy asks about "+
      "each visitor through a small local agent, the SPOA bouncer, and answers a banned address with a "+
      "403 page -- or a captcha first. The bouncer runs on every node and polls your CrowdSec LAPI for "+
      "decisions. Fail-open: a bouncer that is down or slow leaves the request alone.")+"</p>";

  /* the node: is the bouncer here, and running */
  const node=document.createElement("div");node.className="hint";node.style.cssText="border:1px solid var(--hair);border-radius:6px;padding:10px 12px;margin-bottom:14px";
  const draw=(x)=>{
    node.innerHTML="<b>"+t("This node")+"</b> &mdash; "+
      (x.installed?t("bouncer {version} installed",{version:esc(x.version||"")}):t("bouncer not installed"))+
      (x.installed?", "+t("service")+" <span class='pill "+(x.service==="active"?"up":"off")+"'>"+esc(t(x.service||"unknown"))+"</span>":"")+
      (x.installed?"":" ");
    if(!x.installed&&!state.readOnly){
      const b=btn(t("Install on this node"),"sm",async()=>{
        b.disabled=true;b.textContent=t("Installing...");
        try{const r=await api("crowdsec/install","POST",{});showText(t("CrowdSec bouncer"),r.message);draw(r.status||x);}
        catch(e){showText(t("Install failed"),e.message);b.disabled=false;b.textContent=t("Install on this node");}
      });
      node.appendChild(b);
    }
  };
  draw(st);
  bd.appendChild(node);

  const FIELDS=[
   {k:"enabled",l:"Enable CrowdSec",t:"bool",h:"HAProxy asks the bouncer about every HTTP request, on every node. Takes effect at the next Apply."},
   {k:"api_url",l:"LAPI URL",t:"text",h:"Your CrowdSec local API, e.g. http://192.168.1.5:8080/ -- the machine running the CrowdSec agent."},
   {k:"api_key",l:"API key",t:"password",
    h:s.has_api_key?"Leave empty to keep the stored one":"On the CrowdSec host: cscli bouncers add haproxy-manager -- the key it prints. One key serves every node."},
   {k:"insecure_skip_verify",l:"Skip TLS verification",t:"bool",h:"For a LAPI on https:// with a certificate this node does not trust"},
   {k:"mode",l:"What a banned visitor gets",t:"select",o:["ban","captcha"],d:"ban",
    h:"The 403 page is the one under Error Pages for 403 when there is one, else the bouncer's own. A captcha asks the visitor to prove they are human before the ban stands."},
   {k:"captcha_provider",l:"Captcha provider",t:"select",o:["","hcaptcha","recaptcha","turnstile"],d:""},
   {k:"captcha_site_key",l:"Captcha site key",t:"text"},
   {k:"captcha_secret_key",l:"Captcha secret key",t:"password",h:s.has_captcha_secret?"Leave empty to keep the stored one":"From the provider's dashboard"},
   {k:"contact_url",l:"Contact URL on the ban page",t:"text",h:"Optional. A page a wrongly banned visitor can reach you through -- a form rather than a mailto:, which crawlers harvest."},
   {k:"skip_lists",l:"Never ask about",t:"refmulti",ref:"haproxy/addresslists",h:"Address lists CrowdSec is not consulted for -- the LAN, typically. Everyone else is."},
  ];
  const frm=document.createElement("div");frm.className="frm";
  FIELDS.forEach(f=>fieldRow(f,s[f.k]).forEach(el=>frm.appendChild(el)));
  const msel=frm.querySelector("#f_mode");
  if(msel)[...msel.options].forEach(o=>{o.textContent=t(MODE_LABEL[o.value]||o.value);});
  const psel=frm.querySelector("#f_captcha_provider");
  if(psel)[...psel.options].forEach(o=>{o.textContent=t(PROVIDER_LABEL[o.value]||o.value);});
  const rows=k=>{const el=frm.querySelector('[data-field="'+k+'"]');return el?[el.parentNode.previousElementSibling,el.parentNode]:[];};
  const syncRows=()=>{
    const captcha=(msel&&(msel.value!==undefined?msel.value:(([...msel.options].find(o=>o.selected)||{}).value)))==="captcha";
    ["captcha_provider","captcha_site_key","captcha_secret_key"].forEach(k=>rows(k).forEach(el=>{el.style.display=captcha?"":"none";}));
  };
  bd.appendChild(frm);

  const foot=document.createElement("div");foot.style.marginTop="16px";
  const msg=document.createElement("span");msg.className="hint";msg.style.marginLeft="10px";
  const save=btn(t("Save"),"pri",async()=>{
    const data=readForm(FIELDS);
    try{
      const r=await api("crowdsec/settings","PUT",data);
      msg.textContent=t("Saved. Apply to make it so on this node; the other nodes follow.");
      if(r.status)draw(r.status);
      refreshStatus();
    }catch(e){
      msg.innerHTML='<span class="pill down">'+t("not saved")+'</span>';
      showText(t("Not saved"),e.message);
    }
  });
  if(state.readOnly){save.disabled=true;msg.textContent=t("Read-only on a passive node.");}
  foot.appendChild(save);
  foot.appendChild(document.createTextNode(" "));
  foot.appendChild(btn(t("Test the LAPI connection"),"",async()=>{
    msg.textContent=t("Asking...");
    const d=readForm(FIELDS);
    try{
      const r=await api("crowdsec/test","POST",{api_url:d.api_url,api_key:d.api_key,insecure_skip_verify:d.insecure_skip_verify});
      msg.innerHTML='<span class="pill '+(r.ok?"up":"down")+'">'+(r.ok?t("reachable"):t("not reachable"))+"</span> "+esc(r.message);
    }catch(e){msg.textContent=e.message;}
  }));
  foot.appendChild(msg);
  bd.appendChild(foot);card.appendChild(bd);c.appendChild(card);
  if(msel){msel.addEventListener("change",syncRows);}
  syncRows();
}
