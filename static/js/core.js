"use strict";
/* What to do when the server says the session is gone. auth.js registers
   showLogin here; importing it directly would make core and auth depend on
   each other, and core is the module everything else builds on. */
let onUnauthorised = () => {};
export function setUnauthorisedHandler(fn){ onUnauthorised = fn; }

/* ---- plumbing ---- */
export const $=s=>document.querySelector(s);
export const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
/* The session cookie is set by /api/login and travels automatically. */
export async function api(path,method="GET",body){
  const r=await fetch("/api/"+path,{method,headers:{"Content-Type":"application/json"},
    body:body!==undefined?JSON.stringify(body):undefined});
  const data=await r.json().catch(()=>({}));
  if(r.status===401){onUnauthorised();throw new Error(data.error||"Your session has expired -- sign in again.");}
  if(!r.ok)throw new Error(data.error||("HTTP "+r.status));
  return data;
}
export function download(path){                       // let the browser save the response
  const a=document.createElement("a");a.href="/api/"+path;a.download="";
  document.body.appendChild(a);a.click();a.remove();
}
export const lists={};                     // cache: "haproxy/servers" -> [...]
export async function list(path,fresh){ if(fresh||!lists[path])lists[path]=await api(path); return lists[path]; }
export function nameOf(path,id){const it=(lists[path]||[]).find(x=>x.id===id);return it?it.name:"?";}

/* ---- modal ---- */
export function openDlg(title,bodyEl,buttons){
  $("#dlgtitle").textContent=title;
  const b=$("#dlgbody");b.innerHTML="";b.appendChild(bodyEl);
  const f=$("#dlgfoot");f.innerHTML="";
  (buttons||[]).forEach(x=>f.appendChild(x));
  $("#ovl").classList.add("show");
}
export function closeDlg(){$("#ovl").classList.remove("show");}
$("#dlgclose").onclick=closeDlg;   // the markup cannot call into a module
$("#ovl").addEventListener("click",e=>{if(e.target.id==="ovl")closeDlg();});
document.addEventListener("keydown",e=>{if(e.key==="Escape")closeDlg();});
export function btn(label,cls,fn){const b=document.createElement("button");b.className="btn "+(cls||"");b.textContent=label;b.onclick=fn;return b;}
export function showText(title,text){const p=document.createElement("pre");p.textContent=text;openDlg(title,p,[btn("Close","",closeDlg)]);}

/* health check kinds, shared by the wizard and the Health Monitors page */
export const HEALTH_LABEL={
  none:"none -- always considered up",
  tcp:"ping (TCP connect to the port)",
  http:"HTTP request",
  ssl:"TLS handshake",
  pgsql:"PostgreSQL login",
  mysql:"MariaDB / MySQL login",
};

/* ---- form rendering ---- */
/* An open dialog owns the fields it shows. Page forms and dialog forms use the
   same f_<key> ids, and document.getElementById returns whichever comes first
   in the document -- which is the page, not the dialog on top of it. */
export function fieldEl(k){
  const ovl=$("#ovl");
  if(ovl&&ovl.classList.contains("show")){
    const inDlg=$("#dlg").querySelector('[data-field="'+k+'"]');
    if(inDlg)return inDlg;
  }
  return document.querySelector('#content [data-field="'+k+'"]')||document.getElementById("f_"+k);
}
export function fieldRow(f,val){
  const lab=document.createElement("label");lab.className="fl";lab.textContent=f.l;lab.htmlFor="f_"+f.k;
  const cell=document.createElement("div");
  let inp;
  if(f.t==="bool"){
    const wrap=document.createElement("div");wrap.className="ckbox";
    inp=document.createElement("input");inp.type="checkbox";inp.id="f_"+f.k;inp.dataset.field=f.k;
    inp.checked=val!==undefined?!!val:!!f.d;
    wrap.appendChild(inp);cell.appendChild(wrap);
  }else if(f.t==="select"){
    inp=document.createElement("select");inp.id="f_"+f.k;inp.dataset.field=f.k;
    /* options are plain strings, or {value,label} for things with an id */
    const opts=(typeof f.o==="function"?f.o():f.o)||[];
    const valOf=o=>(o&&typeof o==="object")?o.value:o;
    opts.forEach(o=>{
      const op=document.createElement("option");
      op.value=valOf(o);
      op.textContent=(o&&typeof o==="object")?(o.label??o.value):o;
      inp.appendChild(op);
    });
    inp.value=val??f.d??(opts.length?valOf(opts[0]):"");
    cell.appendChild(inp);
  }else if(f.t==="ref"){
    inp=document.createElement("select");inp.id="f_"+f.k;inp.dataset.field=f.k;
    const none=document.createElement("option");none.value="";none.textContent="(none)";inp.appendChild(none);
    (lists[f.ref]||[]).forEach(it=>{const op=document.createElement("option");op.value=it.id;op.textContent=it.name;inp.appendChild(op);});
    inp.value=val||"";cell.appendChild(inp);
  }else if(f.t==="refmulti"){
    inp=document.createElement("div");inp.className="cklist";inp.id="f_"+f.k;inp.dataset.field=f.k;inp.dataset.refmulti="1";
    const items=lists[f.ref]||[];
    if(!items.length){const d=document.createElement("div");d.className="none";d.textContent="Nothing defined yet.";inp.appendChild(d);}
    items.forEach(it=>{
      const l=document.createElement("label");
      const c=document.createElement("input");c.type="checkbox";c.value=it.id;
      c.checked=(val||[]).includes(it.id);
      l.appendChild(c);l.appendChild(document.createTextNode(it.name));inp.appendChild(l);
    });
    cell.appendChild(inp);
  }else if(f.t==="combo"){
    /* a list to pick from that still accepts anything typed */
    inp=document.createElement("input");inp.type="text";inp.id="f_"+f.k;inp.dataset.field=f.k;inp.value=val??"";
    inp.autocomplete="off";inp.setAttribute("list","dl_"+f.k);
    const dl=document.createElement("datalist");dl.id="dl_"+f.k;
    (typeof f.o==="function"?f.o():(f.o||[])).forEach(o=>{
      const op=document.createElement("option");
      op.value=(o&&o.value!==undefined)?o.value:o;
      if(o&&o.label)op.label=o.label;
      dl.appendChild(op);
    });
    cell.appendChild(inp);cell.appendChild(dl);
  }else if(f.t==="textarea"){
    inp=document.createElement("textarea");inp.id="f_"+f.k;inp.dataset.field=f.k;inp.value=val??"";cell.appendChild(inp);
  }else{
    inp=document.createElement("input");inp.type=f.t==="password"?"password":(f.t==="number"?"number":"text");
    inp.id="f_"+f.k;inp.dataset.field=f.k;inp.value=val??(f.d??"");
    if(f.t==="password")inp.autocomplete="new-password";
    cell.appendChild(inp);
    /* Secrets you have to move to another machine need to be readable. */
    if(f.t==="password"&&f.reveal){
      const bar=document.createElement("div");bar.style.marginTop="7px";
      const note=document.createElement("span");note.className="sub";note.style.marginLeft="8px";
      const toggle=btn("Show","sm",()=>{
        const hidden=inp.type==="password";
        inp.type=hidden?"text":"password";
        toggle.textContent=hidden?"Hide":"Show";
      });
      bar.appendChild(toggle);
      bar.appendChild(document.createTextNode(" "));
      bar.appendChild(btn("Copy","sm",async()=>{
        if(!inp.value){note.textContent="nothing to copy";return;}
        try{
          await navigator.clipboard.writeText(inp.value);
          note.textContent="copied";
        }catch(e){
          // clipboard access needs a secure context; fall back to selecting it
          const was=inp.type;inp.type="text";inp.focus();inp.select();
          note.textContent="selected -- press "+(navigator.platform.indexOf("Mac")>=0?"Cmd":"Ctrl")+"+C";
          if(was==="password")toggle.textContent="Hide";
        }
        setTimeout(()=>{note.textContent="";},4000);
      }));
      if(f.generate){
        bar.appendChild(document.createTextNode(" "));
        bar.appendChild(btn("Generate","sm",()=>{
          const a=new Uint8Array(24);crypto.getRandomValues(a);
          inp.value=[...a].map(x=>x.toString(16).padStart(2,"0")).join("");
          inp.type="text";toggle.textContent="Hide";
          inp.dispatchEvent(new Event("input"));
        }));
      }
      // The node still checks the SAVED key, so an edited field is a trap:
      // copy it to another node and that node will present the wrong value.
      const saved=inp.value;
      const warn=document.createElement("div");warn.className="hint";
      warn.style.cssText="margin-top:6px;color:var(--drift)";
      inp.addEventListener("input",()=>{
        warn.textContent=inp.value!==saved
          ? "This key has not been saved yet. Press Save before copying it to another node -- "+
            "until then this node still expects the previous key."
          : "";
      });
      cell.appendChild(warn);
      bar.appendChild(note);
      cell.appendChild(bar);
    }
  }
  if(f.h){const h=document.createElement("div");h.className="hint";h.textContent=f.h;cell.appendChild(h);}
  return [lab,cell];
}
export function readForm(fields){
  const out={};
  fields.forEach(f=>{
    const el=fieldEl(f.k);
    if(f.t==="bool")out[f.k]=el.checked;
    else if(f.t==="refmulti")out[f.k]=[...el.querySelectorAll("input:checked")].map(c=>c.value);
    else if(f.t==="number")out[f.k]=el.value===""?"":Number(el.value);
    else out[f.k]=el.value;
  });
  return out;
}
