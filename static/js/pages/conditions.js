import { api, btn, closeDlg, esc, lists, openDlg, selectOption, showText } from "../core.js";
import { t } from "../i18n.js";
import { refreshStatus, route } from "../shell.js";
import { COND_LABEL } from "./rules.js";

/* ---- the condition wizard ----
   One test, asked in words: what to look at, what it should be, and whether
   to turn it around. Then Try it: a sample request -- a host, a path, an
   address, a header value -- answered with "matches" or "does not match"
   before anything is saved, and HAProxy's own verdict on the acl line. */

const PLACEHOLDER={
 host_matches:"app.example.com",host_starts_with:"app.",host_ends_with:".example.com",
 path_matches:"/healthz",path_starts_with:"/api",path_ends_with:".php",path_contains:"/admin/",
 url_parameter:"value",http_header:"value",source_ip:"192.168.1.0/24 203.0.113.7",ssl_sni:"app.example.com",
 custom:"path_beg /admin"};
/* which sample fields a type reads */
const SAMPLE={
 host_matches:["host"],host_starts_with:["host"],host_ends_with:["host"],ssl_sni:["host"],
 path_matches:["path"],path_starts_with:["path"],path_ends_with:["path"],path_contains:["path"],
 url_parameter:["param"],http_header:["header"],source_ip:["src"],source_list:["src"],custom:[]};
const chosen=sel=>sel?(sel.value!==undefined?sel.value:(([...sel.options].find(o=>o.selected)||{}).value||"")):"";
function select(options,value){
  const s=document.createElement("select");
  options.forEach(o=>{const op=document.createElement("option");op.value=o.value;op.textContent=o.label;s.appendChild(op);});
  selectOption(s,value||"");
  return s;
}

export function openConditionWizard(cond){
  const wrap=document.createElement("div");
  const frm=document.createElement("div");frm.className="frm";
  const rows={};
  const add=(k,label,el,hint)=>{
    const lab=document.createElement("label");lab.className="fl";lab.textContent=label;
    const cell=document.createElement("div");cell.appendChild(el);
    if(hint){const h=document.createElement("div");h.className="hint";h.textContent=hint;cell.appendChild(h);}
    frm.appendChild(lab);frm.appendChild(cell);rows[k]=[lab,cell];return el;
  };
  const heading=txt=>{const h=document.createElement("div");h.className="fsec";h.textContent=txt;frm.appendChild(h);};

  heading(t("Test"));
  const type=select(Object.keys(COND_LABEL).map(k=>({value:k,label:t(COND_LABEL[k])})),cond?cond.type:"host_matches");
  type.id="f_cw_type";add("type",t("What to look at"),type);
  const param=document.createElement("input");param.type="text";param.id="f_cw_param";param.value=cond?cond.param||"":"";
  add("param",t("Header / parameter name"),param);
  const value=document.createElement("input");value.type="text";value.id="f_cw_value";value.value=cond?cond.value||"":"";
  add("value",t("Value"),value,t("Several values separated by spaces match any of them -- two host names, two networks. For type custom: a raw ACL expression."));
  const list=select([{value:"",label:t("(none)")}].concat((lists["haproxy/addresslists"]||[]).map(l=>({value:l.id,label:l.name}))),cond?cond.list||"":"");
  list.id="f_cw_list";add("list",t("Address list"),list);
  const neg=document.createElement("input");neg.type="checkbox";neg.id="f_cw_negate";neg.checked=!!(cond&&cond.negate);
  const ck=document.createElement("div");ck.className="ckbox";ck.appendChild(neg);
  add("negate",t("Turn it around"),ck,t("The condition holds when the test does not: not from this network, not this path."));
  const name=document.createElement("input");name.type="text";name.id="f_cw_name";name.value=cond?cond.name||"":"";
  add("name",t("Name"),name,t("Optional -- derived from what it tests when left empty"));

  heading(t("Try it"));
  const samples={};
  [["host",t("Host"),"app.example.com"],["path",t("Path"),"/api/items"],["src",t("Source address"),"192.168.1.20"],
   ["header",t("Header value"),""],["param",t("Parameter value"),""]].forEach(([k,label,ph])=>{
    const i=document.createElement("input");i.type="text";i.id="f_cw_s_"+k;i.placeholder=ph;samples[k]=i;add("s_"+k,label,i);
  });
  const sync=()=>{
    const ty=chosen(type);
    const show=(k,on)=>(rows[k]||[]).forEach(el=>{el.style.display=on?"":"none";});
    show("param",ty==="http_header"||ty==="url_parameter");
    show("value",ty!=="source_list");
    show("list",ty==="source_list");
    value.placeholder=PLACEHOLDER[ty]||"";
    Object.keys(samples).forEach(k=>show("s_"+k,(SAMPLE[ty]||[]).includes(k)));
  };
  type.addEventListener("change",sync);sync();
  wrap.appendChild(frm);
  const out=document.createElement("div");out.style.marginTop="16px";wrap.appendChild(out);
  const err=document.createElement("div");err.className="err";

  const read=()=>({
    id:cond?cond.id:undefined,name:name.value,type:chosen(type),value:value.value,param:param.value,
    list:chosen(list),negate:!!neg.checked,
    sample:Object.fromEntries(Object.entries(samples).map(([k,i])=>[k,i.value])),
  });
  const show=(r,saved)=>{
    out.innerHTML="";
    const box=document.createElement("div");box.className="card";box.style.margin="0";
    box.innerHTML='<div class=hd><h2>'+(saved?t("Saved"):t("What this will create"))+'</h2></div>';
    const bd=document.createElement("div");bd.className="bd";
    const v=r.validation||{};
    const verdict=r.matches===true?'<span class="pill up">'+t("matches the sample")+"</span>"
      :r.matches===false?'<span class="pill off">'+t("does not match the sample")+"</span>"
      :'<span class="pill off">'+t("only HAProxy can judge a raw ACL")+"</span>";
    bd.innerHTML='<div style="margin-bottom:10px">'+verdict+' <span class="pill '+(v.ok?"up":"down")+'">'+
        (v.ok?t("HAProxy accepts it"):t("HAProxy refuses it"))+"</span>"+
        (v.ok?"":"<pre class=mono style='white-space:pre-wrap;margin-top:8px'>"+esc(v.message||"")+"</pre>")+"</div>"+
      "<pre class=mono style='white-space:pre-wrap;margin:0 0 10px'>"+esc(r.preview||"")+"</pre>"+
      "<table><tbody>"+(r.actions||[]).map(a=>"<tr><td style='width:90px'><span class='pill "+
        (a.action==="created"?"up":a.action==="updated"?"warn":"off")+"'>"+esc(t(a.action))+"</span></td><td>"+
        esc(a.type)+"</td><td class=mono>"+esc(a.name)+"</td></tr>").join("")+"</tbody></table>";
    box.appendChild(bd);out.appendChild(box);
  };
  const tryIt=btn(t("Try it"),"",async()=>{
    err.textContent="";
    try{show(await api("wizard/condition","POST",Object.assign(read(),{dry_run:true})),false);}
    catch(e){err.textContent=e.message;}
  });
  const save=btn(t("Save"),"pri",async()=>{
    err.textContent="";save.disabled=true;
    try{
      const r=await api("wizard/condition","POST",read());
      show(r,true);save.disabled=true;tryIt.disabled=true;
      await route();refreshStatus();
    }catch(e){err.textContent=e.message;save.disabled=false;}
  });
  openDlg(cond?t("Edit condition"):t("New condition"),wrap,[err,btn(t("Close"),"",closeDlg),tryIt,save]);
}
