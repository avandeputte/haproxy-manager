import { $, api, btn, esc, fieldRow, localTime, pageGuard, readForm } from "../core.js";
import { t } from "../i18n.js";
import { state } from "../state.js";

/* ---- watchdog ---- */
export const WD_STATE={ok:["up","is answering"],down:["down","is not running"],
  hung:["down","is not responding"],starting:["warn","is starting"],
  idle:["off","nothing to supervise yet"],disabled:["off","not run on this node"],
  unwatched:["off","not supervised"],unknown:["warn","could not be determined"]};
export async function renderWatchdog(){
  const c=$("#content");
  const fresh=pageGuard();
  let wd;
  try{wd=await api("watchdog");}
  catch(e){if(fresh())c.innerHTML='<div class="card"><div class="bd">'+esc(e.message)+"</div></div>";return;}
  if(!fresh())return;   // navigated away while loading
  c.innerHTML="";

  /* --- what it sees right now --- */
  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>'+t("Watchdog")+'</h2><div class=sp></div>'+
    '<span class="pill '+(wd.settings.enabled?"up":"off")+'">'+
    (wd.settings.enabled?t("on"):t("off"))+"</span></div>";
  const rows=Object.keys(wd.services||{}).map(u=>{
    const s=wd.services[u],m=WD_STATE[s.state]||["warn",s.state];
    return "<tr><td class=mono>"+esc(u)+"</td>"+
      '<td><span class="pill '+m[0]+'">'+esc(t(s.state))+"</span></td>"+
      "<td>"+esc(s.detail||t(m[1]))+
        (s.blocked?'<div class=sub style="color:var(--down)">'+t("not restarted: {why}",{why:esc(s.blocked)})+"</div>":"")+
        (s.restart_error?'<div class=sub style="color:var(--down)">'+esc(s.restart_error)+"</div>":"")+
      "</td>"+
      "<td>"+esc(s.action||"—")+"</td></tr>";
  }).join("");
  card.innerHTML+=(rows?"<table><thead><tr><th>"+t("Service")+"</th><th>"+t("State")+"</th><th>"+t("Detail")+"</th>"+
      "<th>"+t("Last action")+"</th></tr></thead><tbody>"+rows+"</tbody></table>"
    :'<div class=empty>'+t("No round has run yet. It runs every {n}s.",{n:esc(wd.settings.interval||20)})+"</div>");

  const self=document.createElement("div");self.className="bd";
  self.innerHTML='<div class=hint><b>'+t("This process:")+'</b> '+
    (wd.self.ok?t("the UI answered its own request in {ms} ms.",{ms:esc(wd.self.ms)})
              :'<span style="color:var(--down)">'+esc(wd.self.detail)+"</span>")+
    " "+(wd.systemd
      ? t("systemd is watching: if this stops answering, it is restarted.")
      : t("systemd is not watching this process (no WatchdogSec in the unit), so a hang here "+
          "is reported but not repaired."))+"</div>"+
    (wd.last_run?'<div class=hint style="margin-top:4px">'+t("Last round {when}.",{when:esc(localTime(wd.last_run))})+"</div>":"");
  /* Two machines using one address is invisible from every layer above it:
     the address is configured here, the socket is listening here, and a client
     reaches whichever machine won the last ARP exchange. */
  const dupes=wd.duplicate_addresses||[];
  const addr=document.createElement("div");addr.className="bd";
  if(dupes.length)
    addr.innerHTML='<div class=hint style="color:var(--down)"><b>'+
      t("Another machine is using {addresses}.",{addresses:
        dupes.map(d=>'<span class=mono>'+esc(d.address)+"</span> "+t("(on {iface})",{iface:esc(d.interface)})).join(", ")})+
      "</b> "+t("Traffic for that address reaches whichever of the two won the last ARP exchange, so "+
      "this node works from some places and not others, and comes and goes for no visible reason. "+
      "Nothing here can fix it: one of the two has to stop using the address.")+"</div>";
  else if(wd.arping===false)
    addr.innerHTML='<div class=hint>'+t("Duplicate address detection needs <span class=mono>arping</span>, "+
      "which is not installed here, so nothing is being checked.")+"</div>";
  else
    addr.innerHTML='<div class=hint><b>'+t("Addresses:")+'</b> '+
      t("nothing else on the network answers for this node's addresses.")+"</div>";
  card.appendChild(self);
  card.appendChild(addr);
  c.appendChild(card);

  /* --- settings --- */
  const sc=document.createElement("div");sc.className="card";
  sc.innerHTML='<div class=hd><h2>'+t("Settings")+'</h2></div>';
  const sb=document.createElement("div");sb.className="bd";
  const FIELDS=[
   {k:"enabled",l:"Run the watchdog on this node",t:"bool"},
   {k:"haproxy",l:"Supervise HAProxy",t:"bool"},
   {k:"keepalived",l:"Supervise Keepalived",t:"bool"},
   {k:"probe_urls",l:"Probe the published URLs",t:"bool",
    h:"Once a minute, from the node holding the virtual IP, each public name is requested the way a browser would -- DNS, connection, certificate. Failures appear on the Services page and in notifications. Turn off if the names only resolve from outside your network."},
   {k:"interval",l:"Check every (seconds)",t:"text",h:"minimum 5"},
   {k:"max_restarts",l:"Restarts allowed per window",t:"text",
    h:"after this many it stops trying, so a broken service stays visible instead of flapping"},
   {k:"window",l:"Window (seconds)",t:"text",h:"e.g. 900 for fifteen minutes"},
  ];
  const sfrm=document.createElement("div");sfrm.className="frm";
  FIELDS.forEach(f=>fieldRow(f,wd.settings[f.k]).forEach(el=>sfrm.appendChild(el)));
  sb.appendChild(sfrm);
  sc.appendChild(sb);
  const foot=document.createElement("div");foot.className="bd";
  foot.style.cssText="display:flex;gap:8px;align-items:center;border-top:1px solid var(--hair)";
  const note=document.createElement("span");note.className="hint";
  foot.appendChild(btn(t("Save"),"pri",async()=>{
    note.textContent=t("saving...");
    try{await api("watchdog","PUT",readForm(FIELDS));note.textContent=t("Saved.");renderWatchdog();}
    catch(e){note.textContent=e.message;}
  }));
  foot.appendChild(btn(t("Check now"),"",async()=>{
    note.textContent=t("checking...");
    try{await api("watchdog/check","POST",{});renderWatchdog();}
    catch(e){note.textContent=e.message;}
  }));
  foot.appendChild(note);
  sc.appendChild(foot);
  c.appendChild(sc);

  /* --- what it has done --- */
  const ev=document.createElement("div");ev.className="card";
  ev.innerHTML='<div class=hd><h2>'+t("Recent actions")+'</h2></div>'+
    ((wd.events||[]).length
      ? "<table><thead><tr><th>"+t("When")+"</th><th>"+t("Service")+"</th><th>"+t("What happened")+"</th></tr></thead><tbody>"+
        wd.events.map(e=>"<tr><td class=mono style=white-space:nowrap>"+esc(localTime(e.time))+"</td>"+
          "<td class=mono>"+esc(e.unit)+"</td><td"+
          (e.level==="error"?' style="color:var(--down)"':e.level==="warning"?' style="color:var(--drift)"':"")+
          ">"+esc(e.message)+"</td></tr>").join("")+"</tbody></table>"
      : '<div class=empty>'+t("It has not had to do anything.")+'</div>');
  c.appendChild(ev);

  // The refresh rebuilds the Settings form from the server, so a tick mid-edit
  // would wipe what is being typed into "Check every" or "Window". Skip the
  // re-render while a field on the page has focus, but keep the timer alive.
  state.pageTimer=setTimeout(function tick(){
    if(location.hash!=="#/p:watchdog")return;
    const a=document.activeElement;
    if(a&&a.closest("#content")&&/^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName)){
      state.pageTimer=setTimeout(tick,10000);
      return;
    }
    renderWatchdog();
  },10000);
}
