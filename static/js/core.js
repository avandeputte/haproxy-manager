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
/* Choose an option by marking it, not by assigning to the select's value.
   Both work in a browser; only this one works everywhere, and it is also the
   thing that actually happens -- a select has no value of its own, it has an
   option that is selected. */
export function selectOption(sel,value){
  const want=String(value==null?"":value);
  let found=false;
  [...(sel.options||[])].forEach(o=>{
    const hit=String(o.value)===want;
    o.selected=hit;
    if(hit)found=true;
  });
  if(!found&&sel.options&&sel.options.length)sel.options[0].selected=true;
  return found;
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
    selectOption(inp,val??f.d??(opts.length?valOf(opts[0]):""));
    cell.appendChild(inp);
  }else if(f.t==="ref"){
    inp=document.createElement("select");inp.id="f_"+f.k;inp.dataset.field=f.k;
    const none=document.createElement("option");none.value="";none.textContent="(none)";inp.appendChild(none);
    (lists[f.ref]||[]).forEach(it=>{const op=document.createElement("option");op.value=it.id;op.textContent=it.name;inp.appendChild(op);});
    selectOption(inp,val||"");cell.appendChild(inp);
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

/* ============================ sortable tables ============================ */
/* Every table in the app is built from HTML, so rather than teach each page to
   sort, tables are upgraded after they are rendered: click a heading to sort by
   it, click again to reverse. The comparison is separated from the DOM work so
   it can be tested on its own. */

/* What a cell is worth when sorting. Numbers sort as numbers even when they
   carry a unit ("1.2 GB", "12/s", "3 days"), because a table of sizes sorted
   as text is worse than not sorting at all. Empty and "—" sort last. */
export function sortValue(text){
  const t=String(text==null?"":text).trim();
  if(!t||t==="—"||t==="-")return {empty:true};
  const m=t.match(/^([<>]?\s*-?\d[\d\s,]*\.?\d*)\s*([a-zA-Z%/]*)/);
  if(m){
    const n=parseFloat(m[1].replace(/[\s,<>]/g,""));
    if(!isNaN(n)){
      const unit=(m[2]||"").toLowerCase();
      const scale={b:1,kb:1e3,mb:1e6,gb:1e9,tb:1e12,
                   ms:1e-3,s:1,sec:1,secs:1,m:60,min:60,mins:60,
                   h:3600,hour:3600,hours:3600,
                   d:86400,day:86400,days:86400}[unit];
      return {num:scale?n*scale:n};
    }
  }
  return {text:t.toLowerCase()};
}

export function compareValues(a,b){
  const x=sortValue(a), y=sortValue(b);
  if(x.empty&&y.empty)return 0;
  if(x.empty)return 1;               /* blanks always at the bottom */
  if(y.empty)return -1;
  if("num" in x&&"num" in y)return x.num-y.num;
  if("num" in x)return -1;           /* numbers before words */
  if("num" in y)return 1;
  return x.text.localeCompare(y.text,undefined,{numeric:true});
}

/* rows: [{key:[cell text,...], el}] -- returns them in the wanted order */
export function sortRows(rows,index,dir){
  const out=rows.slice();
  out.sort((r1,r2)=>{
    const a=r1.key[index], b=r2.key[index];
    const ea=sortValue(a).empty, eb=sortValue(b).empty;
    /* Blank stays at the bottom whichever way the column is sorted: reversing
       the order should not fill the top of the table with nothing. */
    if(ea||eb)return ea&&eb?0:(ea?1:-1);
    return compareValues(a,b)*(dir==="desc"?-1:1);
  });
  return out;
}

/* Remembered per table so a refresh (statistics, logs) does not undo a sort. */
const sorted={};
function tableKey(t){
  const hs=[...t.querySelectorAll("thead th")].map(h=>h.textContent.trim()).join("|");
  return (location.hash||"#/")+"::"+hs;
}

function applySort(t,index,dir){
  const body=t.querySelector("tbody");
  if(!body)return;
  const rows=[...body.querySelectorAll(":scope > tr")].map(tr=>({
    key:[...tr.children].map(td=>td.textContent), el:tr,
  }));
  /* A trailing row that spans the table is a total, not data: leave it last. */
  const data=rows.filter(r=>r.el.children.length>1&&!r.el.querySelector("[colspan]"));
  const rest=rows.filter(r=>!data.includes(r));
  sortRows(data,index,dir).forEach(r=>body.appendChild(r.el));
  rest.forEach(r=>body.appendChild(r.el));
  [...t.querySelectorAll("thead th")].forEach((h,i)=>{
    h.classList.remove("sorted-asc","sorted-desc");
    if(i===index)h.classList.add(dir==="desc"?"sorted-desc":"sorted-asc");
  });
}

export function makeSortable(t){
  if(t.dataset.sortable)return;
  const heads=[...t.querySelectorAll("thead th")];
  if(heads.length<2||!t.querySelector("tbody"))return;
  t.dataset.sortable="1";
  const key=tableKey(t);
  heads.forEach((h,i)=>{
    if(!h.textContent.trim())return;          /* the actions column */
    h.classList.add("sortable");
    h.addEventListener("click",()=>{
      const cur=sorted[key];
      const dir=cur&&cur.index===i&&cur.dir==="asc"?"desc":"asc";
      sorted[key]={index:i,dir};
      applySort(t,i,dir);
    });
  });
  const remembered=sorted[key];
  if(remembered)applySort(t,remembered.index,remembered.dir);
}

/* Every cell carries the name of its column.
   A table of five columns has nowhere to go on a phone: it either overflows the
   screen or squeezes each column to a few characters. On a narrow screen the
   stylesheet lays each row out as a block instead, one line per field, and a
   value with no label in front of it is unreadable -- so the label each cell
   would have had at the top of its column is written onto the cell here, once,
   where the table is already being walked. Nothing changes on a wide screen:
   the attribute is only ever drawn by a media query. */
export function labelCells(t){
  const heads=[...t.querySelectorAll("thead th")].map(h=>h.textContent.trim());
  if(!heads.length)return;
  t.querySelectorAll("tbody tr").forEach(tr=>{
    [...tr.children].forEach((td,i)=>{
      /* A cell spanning the table is a note or a total, not a field. */
      if(td.getAttribute&&td.getAttribute("colspan"))return;
      const label=heads[i]||"";
      if(label&&td.dataset.label!==label)td.dataset.label=label;
      /* The actions column has no heading; marked so it can be laid out as a
         row of buttons rather than as a nameless field. */
      if(!label&&!td.dataset.actions)td.dataset.actions="1";
    });
  });
}

/* A box a table can be wider than.
   Between a phone and a desktop there is a width where a table of eight
   columns still will not fit but laying every row out as a block wastes the
   room there is. There the table scrolls sideways inside its own card --
   which is only possible if something around it can scroll, so it is put
   there. */
export function scrollWrap(t){
  const p=t.parentNode;
  if(!p||(p.classList&&p.classList.contains("tscroll")))return;
  const box=document.createElement("div");
  box.className="tscroll";
  p.insertBefore(box,t);
  box.appendChild(t);
}

export function enhanceTables(root){
  (root||document).querySelectorAll("table").forEach(t=>{
    makeSortable(t);
    /* The log is a fixed three-column stream, already sized for a narrow
       screen and read as a stream rather than as fields. */
    if(t.closest(".logview"))return;
    labelCells(t);
    scrollWrap(t);
  });
}
