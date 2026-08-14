import { $, api, btn, esc, fieldRow, readForm } from "../core.js";
import { state } from "../state.js";

/* ---- watchdog ---- */
export const WD_STATE={ok:["up","is answering"],down:["down","is not running"],
  hung:["down","is not responding"],starting:["warn","is starting"],
  idle:["off","nothing to supervise yet"],disabled:["off","not run on this node"],
  unwatched:["off","not supervised"],unknown:["warn","could not be determined"]};
export async function renderWatchdog(){
  const c=$("#content");c.innerHTML="";
  let wd;
  try{wd=await api("watchdog");}
  catch(e){c.innerHTML='<div class="card"><div class="bd">'+esc(e.message)+"</div></div>";return;}

  /* --- what it sees right now --- */
  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>Watchdog</h2><div class=sp></div>'+
    '<span class="pill '+(wd.settings.enabled?"up":"off")+'">'+
    (wd.settings.enabled?"on":"off")+"</span></div>";
  const rows=Object.keys(wd.services||{}).map(u=>{
    const s=wd.services[u],m=WD_STATE[s.state]||["warn",s.state];
    return "<tr><td class=mono>"+esc(u)+"</td>"+
      '<td><span class="pill '+m[0]+'">'+esc(s.state)+"</span></td>"+
      "<td>"+esc(s.detail||m[1])+
        (s.blocked?'<div class=sub style="color:var(--down)">not restarted: '+esc(s.blocked)+"</div>":"")+
        (s.restart_error?'<div class=sub style="color:var(--down)">'+esc(s.restart_error)+"</div>":"")+
      "</td>"+
      "<td>"+esc(s.action||"—")+"</td></tr>";
  }).join("");
  card.innerHTML+=(rows?"<table><thead><tr><th>Service</th><th>State</th><th>Detail</th>"+
      "<th>Last action</th></tr></thead><tbody>"+rows+"</tbody></table>"
    :'<div class=empty>No round has run yet. It runs every '+
      esc(wd.settings.interval||20)+"s.</div>");

  const self=document.createElement("div");self.className="bd";
  self.innerHTML='<div class=hint><b>This process:</b> '+
    (wd.self.ok?'the UI answered its own request in '+esc(wd.self.ms)+" ms."
              :'<span style="color:var(--down)">'+esc(wd.self.detail)+"</span>")+
    " "+(wd.systemd
      ? "systemd is watching: if this stops answering, it is restarted."
      : "systemd is not watching this process (no WatchdogSec in the unit), so a hang here "+
        "is reported but not repaired.")+"</div>"+
    (wd.last_run?'<div class=hint style="margin-top:4px">Last round '+esc(wd.last_run)+".</div>":"");
  /* Two machines using one address is invisible from every layer above it:
     the address is configured here, the socket is listening here, and a client
     reaches whichever machine won the last ARP exchange. */
  const dupes=wd.duplicate_addresses||[];
  const addr=document.createElement("div");addr.className="bd";
  if(dupes.length)
    addr.innerHTML='<div class=hint style="color:var(--down)"><b>Another machine is using '+
      dupes.map(d=>'<span class=mono>'+esc(d.address)+"</span> (on "+esc(d.interface)+")").join(", ")+
      ".</b> Traffic for that address reaches whichever of the two won the last ARP exchange, so "+
      "this node works from some places and not others, and comes and goes for no visible reason. "+
      "Nothing here can fix it: one of the two has to stop using the address.</div>";
  else if(wd.arping===false)
    addr.innerHTML='<div class=hint>Duplicate address detection needs <span class=mono>arping</span>, '+
      "which is not installed here, so nothing is being checked.</div>";
  else
    addr.innerHTML='<div class=hint><b>Addresses:</b> nothing else on the network answers for '+
      "this node's addresses.</div>";
  card.appendChild(self);
  card.appendChild(addr);
  c.appendChild(card);

  /* --- settings --- */
  const sc=document.createElement("div");sc.className="card";
  sc.innerHTML='<div class=hd><h2>Settings</h2></div>';
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
  foot.appendChild(btn("Save","primary",async()=>{
    note.textContent="saving...";
    try{await api("watchdog","PUT",readForm(FIELDS));note.textContent="Saved.";renderWatchdog();}
    catch(e){note.textContent=e.message;}
  }));
  foot.appendChild(btn("Check now","",async()=>{
    note.textContent="checking...";
    try{await api("watchdog/check","POST",{});renderWatchdog();}
    catch(e){note.textContent=e.message;}
  }));
  foot.appendChild(note);
  sc.appendChild(foot);
  c.appendChild(sc);

  /* --- what it has done --- */
  const ev=document.createElement("div");ev.className="card";
  ev.innerHTML='<div class=hd><h2>Recent actions</h2></div>'+
    ((wd.events||[]).length
      ? "<table><thead><tr><th>When</th><th>Service</th><th>What happened</th></tr></thead><tbody>"+
        wd.events.map(e=>"<tr><td class=mono style=white-space:nowrap>"+esc(e.time)+"</td>"+
          "<td class=mono>"+esc(e.unit)+"</td><td"+
          (e.level==="error"?' style="color:var(--down)"':e.level==="warning"?' style="color:var(--drift)"':"")+
          ">"+esc(e.message)+"</td></tr>").join("")+"</tbody></table>"
      : '<div class=empty>It has not had to do anything.</div>');
  c.appendChild(ev);

  state.pageTimer=setTimeout(()=>{if(location.hash==="#/p:watchdog")renderWatchdog();},10000);
}
