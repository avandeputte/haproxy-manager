import { api, btn, closeDlg, esc, lists, nameOf, openDlg, selectOption, showText, trimHaproxy } from "../core.js";
import { t } from "../i18n.js";
import { refreshStatus, route } from "../shell.js";

/* ---- the rule wizard ----
   A rule read as a sentence: ON these listeners, WHEN these conditions hold,
   THEN do this. The conditions are typed here and made on the way, the rule
   is attached where it applies, and Preview asks HAProxy whether it would
   load the result -- all of which the Rules page used to leave to three
   separate pages and a reload. */

/* English here; translated where drawn. The keys are what HAProxy calls them. */
export const COND_LABEL={
 host_matches:"host is",host_starts_with:"host starts with",host_ends_with:"host ends with",
 path_matches:"path is",path_starts_with:"path starts with",path_ends_with:"path ends with",
 path_contains:"path contains",url_parameter:"URL parameter",http_header:"HTTP header",
 source_ip:"from network",source_list:"from address list",ssl_sni:"SNI is",custom:"raw ACL"};
export const ACTION_LABEL={
 use_backend:"route to a pool",redirect_scheme_https:"redirect to HTTPS",
 redirect_location:"redirect to a URL",http_request_deny:"deny the request",
 http_request_set_header:"set a request header",http_request_del_header:"delete a request header",
 http_response_set_header:"set a response header",tcp_request_content_accept:"accept the connection",
 tcp_request_content_reject:"reject the connection",custom:"a raw line"};
const PLACEHOLDER={
 host_matches:"app.example.com",host_starts_with:"app.",host_ends_with:".example.com",
 path_matches:"/healthz",path_starts_with:"/api",path_ends_with:".php",path_contains:"/admin/",
 url_parameter:"value",http_header:"value",source_ip:"192.168.1.0/24",ssl_sni:"app.example.com",
 custom:"path_beg /admin"};
/* what each action needs typed: [field, label] */
const ACTION_FIELDS={
 use_backend:[["backend","Backend Pool"]],
 redirect_location:[["param1","Location"]],
 http_request_set_header:[["param1","Header name"],["param2","Value"]],
 http_request_del_header:[["param1","Header name"]],
 http_response_set_header:[["param1","Header name"],["param2","Value"]],
 custom:[["param1","Line"]]};

/* a select's value, read off the marked option where .value is not there */
const chosen=sel=>sel?(sel.value!==undefined?sel.value:(([...sel.options].find(o=>o.selected)||{}).value||"")):"";
function select(options,value){
  const s=document.createElement("select");
  options.forEach(o=>{const op=document.createElement("option");op.value=o.value;op.textContent=o.label;s.appendChild(op);});
  selectOption(s,value||"");
  return s;
}
function row(label,hint,forId){
  const lab=document.createElement("label");lab.className="fl";lab.textContent=label;
  if(forId)lab.htmlFor=forId;
  const cell=document.createElement("div");
  if(hint){const h=document.createElement("div");h.className="hint";h.textContent=hint;cell.appendChild(h);}
  return [lab,cell];
}

/* One condition, typed or picked. A picked one is shown by name; a typed one
   is a type, its value, and what the type needs besides. */
function condRow(pre){
  const r=document.createElement("div");r.className="condrow";
  r.style.cssText="display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:6px";
  if(pre&&pre.id){
    r.dataset.id=pre.id;
    const nm=document.createElement("span");nm.className="mono";nm.textContent=nameOf("haproxy/conditions",pre.id);
    const ex=document.createElement("span");ex.className="sub";ex.textContent=t("(existing condition)");
    r.appendChild(nm);r.appendChild(ex);
  }else{
    pre=pre||{};
    const type=select(Object.keys(COND_LABEL).map(k=>({value:k,label:t(COND_LABEL[k])})),pre.type||"host_matches");
    type.dataset.role="type";
    const param=document.createElement("input");param.type="text";param.dataset.role="param";
    param.placeholder=t("name");param.value=pre.param||"";param.style.width="9em";
    const value=document.createElement("input");value.type="text";value.dataset.role="value";
    value.value=pre.value||"";value.style.width="16em";
    const list=select((lists["haproxy/addresslists"]||[]).map(l=>({value:l.id,label:l.name})),pre.list||"");
    list.dataset.role="list";
    const negWrap=document.createElement("label");negWrap.style.cssText="display:inline-flex;gap:4px;align-items:center";
    const neg=document.createElement("input");neg.type="checkbox";neg.dataset.role="negate";neg.checked=!!pre.negate;
    negWrap.appendChild(neg);negWrap.appendChild(document.createTextNode(t("not")));
    const sync=()=>{
      const ty=chosen(type);
      param.style.display=(ty==="http_header"||ty==="url_parameter")?"":"none";
      value.style.display=ty==="source_list"?"none":"";
      list.style.display=ty==="source_list"?"":"none";
      value.placeholder=PLACEHOLDER[ty]||"";
    };
    type.addEventListener("change",sync);sync();
    [type,param,value,list,negWrap].forEach(el=>r.appendChild(el));
  }
  const rm=btn("×","sm",()=>r.remove());rm.setAttribute("aria-label",t("Remove this condition"));
  r.appendChild(rm);
  return r;
}
function readRow(r){
  if(r.dataset.id)return {id:r.dataset.id};
  const q=role=>r.querySelector('[data-role="'+role+'"]');
  return {type:chosen(q("type")),value:q("value").value,param:q("param").value,
          list:chosen(q("list")),negate:!!q("negate").checked};
}

/* a group of conditions: its rows, and the two ways to add one */
function condGroup(id,hint,pre){
  const cell=document.createElement("div");
  const h=document.createElement("div");h.className="hint";h.style.marginBottom="6px";h.textContent=hint;cell.appendChild(h);
  const rows=document.createElement("div");rows.id=id;cell.appendChild(rows);
  (pre||[]).forEach(p=>rows.appendChild(condRow(p)));
  const bar=document.createElement("div");bar.style.cssText="display:flex;gap:8px;align-items:center;flex-wrap:wrap";
  bar.appendChild(btn(t("Add condition"),"sm",()=>rows.appendChild(condRow())));
  const pick=select([{value:"",label:t("or pick an existing one")}].concat(
    (lists["haproxy/conditions"]||[]).map(c=>({value:c.id,label:c.name}))),"");
  pick.id=id+"_pick";
  pick.addEventListener("change",()=>{const v=chosen(pick);if(v){rows.appendChild(condRow({id:v}));selectOption(pick,"");}});
  bar.appendChild(pick);
  cell.appendChild(bar);
  return cell;
}

export function openRuleWizard(rule){
  const wrap=document.createElement("div");
  const frm=document.createElement("div");frm.className="frm";
  const add=(label,cell,hint)=>{const [lab,c]=row(label,null,cell&&cell.id);if(cell)c.insertBefore(cell,c.firstChild);
    if(hint){const h=document.createElement("div");h.className="hint";h.textContent=hint;c.appendChild(h);}
    frm.appendChild(lab);frm.appendChild(c);return c;};
  const heading=txt=>{const h=document.createElement("div");h.className="fsec";h.textContent=txt;frm.appendChild(h);};

  const name=document.createElement("input");name.type="text";name.id="f_rw_name";name.value=rule?rule.name||"":"";
  add(t("Name"),name,t("Optional -- derived from the action and the first condition when left empty"));

  /* ON: the listeners. Editing shows the ones that hold the rule now. */
  heading(t("On"));
  const fes=lists["haproxy/frontends"]||[];
  const lst=document.createElement("div");lst.className="cklist";lst.id="f_rw_listeners";
  if(!fes.length){const d=document.createElement("div");d.className="none";d.textContent=t("Nothing defined yet.");lst.appendChild(d);}
  fes.forEach(f=>{
    const l=document.createElement("label");
    const c=document.createElement("input");c.type="checkbox";c.value=f.id;
    c.checked=rule?(f.rules||[]).includes(rule.id):fes.length===1;
    if(c.checked)c.setAttribute("checked","");
    l.appendChild(c);l.appendChild(document.createTextNode(f.name+" "));
    const m=document.createElement("span");m.className="sub mono";
    m.textContent=(f.binds||"").split("\n").filter(Boolean).join(", ")+(f.mode==="tcp"?" tcp":"");
    l.appendChild(m);lst.appendChild(l);
  });
  add(t("Public Services"),lst,t("Which listeners this rule applies to. Unticked everywhere, it is stored but does nothing."));

  /* WHEN: any of these, and all of these. A rule from before 2.0 with "or"
     over its one list is alternatives alone. */
  heading(t("When"));
  const anyPre=rule?(rule.any_of||[]).concat(rule.operator==="or"?(rule.conditions||[]):[]).map(id=>({id})):[];
  const allPre=rule?(rule.operator==="or"?[]:(rule.conditions||[])).map(id=>({id})):[];
  add(t("Any of these conditions"),condGroup("f_rw_any",t("One of them must match -- several host names, say"),anyPre));
  add(t("All of these conditions"),condGroup("f_rw_all",t("Every one of them must match, together with one of the above. Leave both empty to apply unconditionally."),allPre));

  /* THEN: the action, with only its own fields shown. */
  heading(t("Then"));
  const action=select(Object.keys(ACTION_LABEL).map(k=>({value:k,label:t(ACTION_LABEL[k])})),rule?rule.type:"use_backend");
  action.id="f_rw_action";
  add(t("Action"),action);
  const fields={};
  const backend=select([{value:"",label:t("(none)")}].concat((lists["haproxy/backends"]||[]).map(b=>({value:b.id,label:b.name}))),rule?rule.backend:"");
  backend.id="f_rw_backend";fields.backend=add(t("Backend Pool"),backend);
  const p1=document.createElement("input");p1.type="text";p1.id="f_rw_param1";p1.value=rule?rule.param1||"":"";
  fields.param1=add(t("Location"),p1);
  const p2=document.createElement("input");p2.type="text";p2.id="f_rw_param2";p2.value=rule?rule.param2||"":"";
  fields.param2=add(t("Value"),p2);
  const test=select([{value:"if",label:t("if")},{value:"unless",label:t("unless")}],rule?rule.test||"if":"if");
  test.id="f_rw_test";add(t("Apply when"),test,t("\"unless\" turns the whole test around"));
  const syncAction=()=>{
    const want=Object.fromEntries(ACTION_FIELDS[chosen(action)]||[]);
    Object.keys(fields).forEach(k=>{
      const on=k in want;
      fields[k].style.display=on?"":"none";
      fields[k].previousElementSibling.style.display=on?"":"none";
      if(on)fields[k].previousElementSibling.textContent=t(want[k]);
    });
  };
  action.addEventListener("change",syncAction);syncAction();

  const applyNow=document.createElement("input");applyNow.type="checkbox";applyNow.id="f_rw_apply";applyNow.checked=true;
  const ck=document.createElement("div");ck.className="ckbox";ck.appendChild(applyNow);
  add(t("Apply immediately"),ck,t("Write haproxy.cfg and reload once the rule is saved"));
  wrap.appendChild(frm);

  const out=document.createElement("div");out.style.marginTop="16px";wrap.appendChild(out);
  const err=document.createElement("div");err.className="err";

  const read=()=>({
    id:rule?rule.id:undefined,
    name:name.value,
    listeners:[...lst.querySelectorAll("input:checked")].map(c=>c.value),
    any_of:[...document.querySelectorAll("#f_rw_any .condrow")].map(readRow),
    all_of:[...document.querySelectorAll("#f_rw_all .condrow")].map(readRow),
    action:{type:chosen(action),test:chosen(test),backend:chosen(backend),param1:p1.value,param2:p2.value},
    apply:!!applyNow.checked,
  });
  const show=(r,saved)=>{
    out.innerHTML="";
    const box=document.createElement("div");box.className="card";box.style.margin="0";
    box.innerHTML='<div class=hd><h2>'+(saved?t("Saved"):t("What this will create"))+'</h2></div>';
    const bd=document.createElement("div");bd.className="bd";
    const v=r.validation||{};
    bd.innerHTML='<div style="margin-bottom:10px"><span class="pill '+(v.ok?"up":"down")+'">'+
        (v.ok?t("HAProxy accepts it"):t("HAProxy refuses it"))+"</span>"+
        (v.ok?"":"<pre class=mono style='white-space:pre-wrap;margin-top:8px'>"+esc(trimHaproxy(v.message||""))+"</pre>")+"</div>"+
      "<table><tbody>"+(r.actions||[]).map(a=>"<tr><td style='width:90px'><span class='pill "+
        (a.action==="created"||a.action==="attached"?"up":a.action==="updated"?"warn":"off")+"'>"+esc(t(a.action))+"</span></td><td>"+
        esc(a.type)+"</td><td class=mono>"+esc(a.name)+"</td></tr>").join("")+"</tbody></table>"+
      (r.warnings||[]).map(w=>'<div class=hint style="margin-top:10px">! '+esc(w)+"</div>").join("");
    if(r.preview)bd.appendChild(btn(t("Show the generated lines"),"sm",()=>showText(t("Generated lines"),r.preview)));
    if(saved&&r.applied)bd.appendChild(document.createTextNode(" "+(r.applied.ok?t("Applied."):t("Apply FAILED: {error}",{error:r.applied.error||""}))));
    box.appendChild(bd);out.appendChild(box);
  };
  const preview=btn(t("Preview"),"",async()=>{
    err.textContent="";
    try{show(await api("wizard/rule","POST",Object.assign(read(),{dry_run:true})),false);}
    catch(e){err.textContent=e.message;}
  });
  const save=btn(t("Save"),"pri",async()=>{
    err.textContent="";save.disabled=true;
    try{
      const r=await api("wizard/rule","POST",read());
      show(r,true);
      save.disabled=true;preview.disabled=true;closeBtn.textContent=t("Done");
      await route();refreshStatus();
    }catch(e){err.textContent=trimHaproxy(e.message);save.disabled=false;}
  });
  const closeBtn=btn(t("Close"),"",closeDlg);
  openDlg(rule?t("Edit rule"):t("New rule"),wrap,[err,closeBtn,preview,save]);
}
