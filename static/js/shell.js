/* The application shell: the sidebar, routing, the header status and Apply.
 *
 * The page renderers are handed in by main.js rather than imported here. That
 * is what keeps the graph acyclic: pages import the shell for route() and
 * refreshStatus(), and only main.js knows what all the pages are.
 */
import { $, api, btn, esc, showText } from "./core.js";
import { refreshWho, showLogin } from "./auth.js";
import { state } from "./state.js";

let pages = {};        /* "p:" pages, keyed by name */
let render = {};       /* the generic renderers, and the entity definitions */

/* main.js hands these over at start-up. Importing them here instead would put
   the shell in a cycle with every page, and a cycle is how the first attempt
   at this broke: core.js exports $ as a const, so whichever module evaluated
   first hit its temporal dead zone. */
export function setPages(map){ pages = map; }
export function setRenderers(r){ render = r; }

export const NAV=[
 ["","Overview",null],
 ["p:services","Services"],
 ["p:stats","Statistics"],
 ["p:logs","Logs"],
 ["p:cluster","Cluster"],
 ["acme/certificates","Certificates"],
 ["grp","ADVANCED · HAPROXY","collapse"],
 ["haproxy/frontends","Public Services"],
 ["haproxy/backends","Backend Pools"],
 ["haproxy/servers","Real Servers"],
 ["haproxy/conditions","Conditions"],
 ["haproxy/rules","Rules"],
 ["haproxy/healthchecks","Health Monitors"],
 ["s:haproxy-settings","Settings"],
 /* Who a published service may ask to sign in -- not accounts for this UI,
    which is why they are their own group rather than part of Settings. */
 ["grp","BASIC AUTH","collapse"],
 ["access/users","Users"],
 ["access/groups","Groups"],
 /* Settings last: everything here is something you set once and revisit
    rarely, unlike the pages above that you watch. */
 ["grp","SETTINGS","collapse"],
 ["p:acme","ACME Settings"],
 ["p:webui","Web UI access"],
 ["p:watchdog","Watchdog"],
 ["p:notify","Notifications"],
 ["p:backup","Backup & Export"],
 ["p:history","History"],
 ["p:updates","Updates"],
];
/* pages with a hand-written renderer (neither CRUD nor a settings form) */
export function openGroups(){
  try{return JSON.parse(localStorage.getItem("ham_nav_open")||"[]");}catch(e){return [];}
}
export function setGroupOpen(label,on){
  const cur=openGroups().filter(x=>x!==label);
  if(on)cur.push(label);
  try{localStorage.setItem("ham_nav_open",JSON.stringify(cur));}catch(e){}
}
export function toggleGroup(head,on){
  const body=head.nextElementSibling;
  const open=on!==undefined?on:head.getAttribute("aria-expanded")!=="true";
  head.setAttribute("aria-expanded",open?"true":"false");
  body.hidden=!open;
  setGroupOpen(head.dataset.group,open);
}
export function buildNav(){
  const n=$("#navlinks");
  const remembered=openGroups();
  let bucket=null;                       // where following items go
  NAV.forEach(([key,label,opt])=>{
    if(key==="grp"){
      if(opt!=="collapse"){
        const g=document.createElement("div");g.className="grp";g.textContent=label;
        n.appendChild(g);bucket=null;return;
      }
      const head=document.createElement("button");
      head.className="grp";head.type="button";head.dataset.group=label;
      head.innerHTML='<span class=caret>&#9656;</span><span>'+esc(label)+"</span><span class=count></span>";
      const body=document.createElement("div");body.className="grp-body";
      head.setAttribute("aria-expanded","false");body.hidden=true;
      head.onclick=()=>toggleGroup(head);
      n.appendChild(head);n.appendChild(body);
      bucket=body;
      if(remembered.includes(label))toggleGroup(head,true);
      return;
    }
    const a=document.createElement("a");a.className="item";a.href="#/"+key;a.textContent=label;a.dataset.key=key;
    (bucket||n).appendChild(a);
    if(bucket){
      /* the count badge is decoration; do not take the whole menu down for it */
      const head=bucket.previousElementSibling;
      const c=head&&head.querySelector(".count");
      if(c)c.textContent=bucket.querySelectorAll("a").length;
    }
  });
}
/* ---- the menu on a narrow screen ----
   There it is a drawer over the page rather than a column beside it: a menu of
   twenty entries stacked above the content means scrolling past all of it to
   reach anything, and the page you navigated to starts below the fold. */
export function setNavOpen(on){
  const want=on===undefined?!document.body.classList.contains("navopen"):!!on;
  document.body.classList.toggle("navopen",want);
  const b=$("#navtoggle");
  if(b)b.setAttribute("aria-expanded",want?"true":"false");
}
export function wireNav(){
  const b=$("#navtoggle");
  if(b)b.addEventListener("click",()=>setNavOpen());
  const scrim=$("#scrim");
  if(scrim)scrim.addEventListener("click",()=>setNavOpen(false));
  /* A menu that stays open over the page it just navigated to is a menu in the
     way, so anything that routes closes it. */
  document.addEventListener("keydown",e=>{if(e.key==="Escape")setNavOpen(false);});
}

/* One page is drawn at a time.
   Every renderer empties #content and then waits for what it needs before
   filling it again, so two renders that overlap both empty it and both fill
   it -- the page ends up with two of everything. Renders are therefore run one
   after another, and one that has already been overtaken is dropped rather
   than drawn and immediately replaced. */
let drawing=Promise.resolve(), asked=0;
export function route(){
  const mine=++asked;
  drawing=drawing.then(()=>mine===asked?draw():undefined,()=>{});
  return drawing;
}

async function draw(){
  if(state.pageTimer){clearTimeout(state.pageTimer);state.pageTimer=null;}
  setNavOpen(false);
  const key=location.hash.replace(/^#\//,"");
  document.querySelectorAll("#nav a.item").forEach(a=>{
    const on=a.dataset.key===key;
    a.classList.toggle("on",on);
    // a deep link into a collapsed group should not leave it hidden
    if(on){
      const body=a.closest(".grp-body");
      if(body&&body.hidden)toggleGroup(body.previousElementSibling,true);
    }
  });
  const entry=NAV.find(x=>x[0]===key)||NAV[0];
  $("#pagetitle").textContent=entry[1];
  try{
    if(key.startsWith("s:"))await render.settings(key.slice(2));
    else if(key.startsWith("p:"))await pages[key.slice(2)]();
    else if(render.entities[key])await render.entity(key);
    else await render.overview();
  }catch(e){
    $("#content").innerHTML='<div class="card"><div class="bd">'+esc(e.message)+"</div></div>";
  }
}
export async function refreshStatus(){
  try{
    const st=await api("status");
    $("#brandhost").textContent=st.hostname+(st.version?" · v"+st.version:"");
    const ns=$("#nodestrip");ns.innerHTML="";
    const role=document.createElement("span");
    role.className="chip role-"+st.role;role.textContent=st.role.toUpperCase()+(st.vip_held.length?" · "+st.vip_held[0]:"");
    ns.appendChild(role);
    if(st.dirty){const d=document.createElement("span");d.className="chip drift";d.textContent="unapplied changes";ns.appendChild(d);}
    if(st.update_available){
      const u=document.createElement("a");u.className="chip drift";u.href="#/p:updates";
      u.style.textDecoration="none";u.textContent="v"+st.latest_version+" available";
      ns.appendChild(u);
    }
    renderBanner(st);
    $("#applybtn").classList.toggle("warn",st.dirty);
    $("#applybtn").classList.toggle("pri",!st.dirty);
  }catch(e){/* not fatal */}
}
export async function doApply(){
  const b=$("#applybtn");b.disabled=true;b.textContent="Applying...";
  try{
    const r=await api("apply","POST",{});
    const warn=r.warnings||[];
    let text="";
    if(!r.ok)text+="FAILED: "+(r.error||"")+"\n\n";
    else if(warn.length)text+="HAProxy was applied, but something else needs attention:\n\n";
    else text+="Applied.\n\n";
    if(warn.length)text+=warn.map(w=>"!! "+w).join("\n\n")+"\n\n";
    text+=(r.steps||[]).map(s=>"* "+s).join("\n")+
      "\n\n--- haproxy -c output ---\n"+(r.haproxy_check||"(none)")+
      (r.keepalived_check?"\n\n--- keepalived -t output ---\n"+r.keepalived_check:"");
    showText(!r.ok?"Apply failed":warn.length?"Applied with problems":"Configuration applied",text);
  }catch(e){showText("Apply failed",e.message);}
  b.disabled=false;b.textContent="Apply";
  refreshStatus();
  if(!location.hash||location.hash==="#/")route();
}


export function renderBanner(st){
  const b=$("#banner");
  state.readOnly=!!(st&&st.read_only);
  const unlocked=!!(st&&st.edit_override);
  if(!state.readOnly&&!unlocked){b.innerHTML="";return;}
  b.innerHTML="";
  const box=document.createElement("div");box.className="ro";
  const txt=document.createElement("div");
  txt.innerHTML=state.readOnly
    ? "<b>Read-only: this node is passive</b>"+esc(st.read_only_reason||"")
    : "<b>Editing is unlocked on this passive node</b>Another node holds the virtual IP. "+
      "Anything changed here will be overwritten the next time that node pushes, so make the "+
      "change there once it is reachable again.";
  box.appendChild(txt);
  const act=state.readOnly
    ? btn("Edit here anyway","sm",async()=>{
        if(!confirm("Allow editing the shared configuration on this passive node?\n\n"+
                    "Use this when no node holds the virtual IP, or when you are deliberately "+
                    "working here. Whatever you change must still be pushed to the others, and "+
                    "the active node's copy will overwrite this one if it pushes first.\n\n"+
                    "This lasts for this sign-in only: logging out or back in locks it again."))return;
        try{await api("unlock","POST",{on:true});refreshStatus();route();}
        catch(e){alert(e.message);}
      })
    : btn("Lock again","sm",async()=>{
        try{await api("unlock","POST",{on:false});refreshStatus();route();}
        catch(e){alert(e.message);}
      });
  act.style.marginLeft="auto";act.style.whiteSpace="nowrap";
  box.appendChild(act);b.appendChild(box);
}

export function boot(){
  route();refreshStatus();
  if(!state.ticking){state.ticking=true;setInterval(refreshStatus,10000);}
}
