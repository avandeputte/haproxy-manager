import { $, api, esc } from "../core.js";
import { trafficSpark } from "../sparkline.js";
import { state } from "../state.js";

/* ---- live statistics ---- */
export const ST_PILL={UP:"up",OPEN:"up",DOWN:"down",MAINT:"warn",DRAIN:"warn",NOLB:"warn"};
export function statusPill(v){
  const head=String(v||"").split(" ")[0].replace(/^\d+\//,"");   // "UP 2/3" -> "UP"
  const cls=ST_PILL[head]||"off";
  return '<span class="pill '+cls+'">'+esc(v||"—")+"</span>";
}
export function num(v){const n=Number(v);return isNaN(n)?(v||"0"):n.toLocaleString();}
export function bytes(v){
  let n=Number(v)||0;const u=["B","kB","MB","GB","TB"];let i=0;
  while(n>=1024&&i<u.length-1){n/=1024;i++;}
  return (i?n.toFixed(1):n)+" "+u[i];
}
export function since(sec){
  let n=Number(sec);if(isNaN(n)||n<0)return "—";
  if(n<60)return n+"s";if(n<3600)return Math.floor(n/60)+"m";
  if(n<86400)return Math.floor(n/3600)+"h";return Math.floor(n/86400)+"d";
}
export async function renderStats(){
  const c=$("#content");
  let st;
  try{st=await api("stats");}catch(e){c.innerHTML='<div class="card"><div class="bd">'+esc(e.message)+"</div></div>";return;}
  c.innerHTML="";
  if(!st.ok){
    c.innerHTML='<div class="card"><div class=hd><h2>Statistics</h2></div><div class="bd"><p class=hint>'+esc(st.error)+"</p></div></div>";
    return;
  }

  /* The figures above are what is happening now; this is what happened.
     "When did it start" is not answerable from a live gauge. */
  try{
    const h=await api("traffic");
    if((h.at||[]).length>1)c.appendChild(historyCard(h));
  }catch(e){/* history is a nicety; the live figures are the page */}

  const fe=document.createElement("div");fe.className="card";
  fe.innerHTML='<div class=hd><h2>Listeners</h2><div class=sp></div><span class=hint>refreshes every 5s</span></div>'+
    (st.frontends.length?"<table><thead><tr><th>Name</th><th>Status</th><th>Sessions</th><th>Rate</th>"+
      "<th>In</th><th>Out</th><th>Denied</th><th>Errors</th></tr></thead><tbody>"+
      st.frontends.map(f=>"<tr><td class=mono>"+esc(f.proxy)+"</td><td>"+statusPill(f.status)+"</td>"+
        "<td>"+num(f.scur)+" <span class=sub>max "+num(f.smax)+", total "+num(f.stot)+"</span></td>"+
        "<td>"+num(f.rate)+"/s <span class=sub>max "+num(f.rate_max)+"</span></td>"+
        "<td>"+bytes(f.bin)+"</td><td>"+bytes(f.bout)+"</td>"+
        "<td>"+num(f.dreq)+"</td><td>"+num(f.ereq)+"</td></tr>").join("")+"</tbody></table>"
     :'<div class=empty>No listeners are running. Publish a service and press Apply.</div>');
  c.appendChild(fe);

  st.backends.forEach(be=>{
    const card=document.createElement("div");card.className="card";
    const allUp=be.servers_total&&be.servers_up===be.servers_total;
    card.innerHTML='<div class=hd><h2>'+esc(be.proxy)+'</h2><div class=sp></div>'+
        statusPill(be.status)+' <span class="pill '+(be.servers_total?(allUp?"up":be.servers_up?"warn":"down"):"off")+'">'+
        be.servers_up+"/"+be.servers_total+" up</span></div>"+
      "<table><thead><tr><th>Server</th><th>Status</th><th>Role</th><th>Sessions</th><th>Queue</th>"+
      "<th>In</th><th>Out</th><th>Last check</th><th>Flaps</th><th>Downtime</th></tr></thead><tbody>"+
      (be.servers.length?be.servers.map(s=>"<tr>"+
        "<td class=mono>"+esc(s.name)+(s.addr?"<div class=sub>"+esc(s.addr)+"</div>":"")+"</td>"+
        "<td>"+statusPill(s.status)+"<div class=sub>for "+since(s.lastchg)+"</div></td>"+
        "<td>"+(s.bck==="1"?"backup":"active")+"<div class=sub>weight "+esc(s.weight||"")+"</div></td>"+
        "<td>"+num(s.scur)+" <span class=sub>max "+num(s.smax)+", total "+num(s.stot)+"</span></td>"+
        "<td>"+num(s.qcur)+"</td><td>"+bytes(s.bin)+"</td><td>"+bytes(s.bout)+"</td>"+
        "<td>"+esc(s.check_status||"—")+(s.check_code?" <span class=sub>"+esc(s.check_code)+"</span>":"")+
          (s.check_duration?"<div class=sub>"+esc(s.check_duration)+" ms</div>":"")+"</td>"+
        "<td>"+num(s.chkfail)+" fail <span class=sub>"+num(s.chkdown)+" down</span></td>"+
        "<td>"+since(s.downtime)+"</td></tr>").join("")
        :'<tr><td colspan=10 class=sub style="padding:14px 12px">This pool has no servers.</td></tr>')+
      "<tr><td class=mono><b>total</b></td><td>"+statusPill(be.status)+"</td><td>"+esc(be.algo||"")+"</td>"+
        "<td>"+num(be.scur)+" <span class=sub>total "+num(be.stot)+"</span></td><td>"+num(be.qcur)+"</td>"+
        "<td>"+bytes(be.bin)+"</td><td>"+bytes(be.bout)+"</td><td>—</td>"+
        "<td>"+num(be.econ)+" conn err</td><td>"+since(be.downtime)+"</td></tr>"+
      "</tbody></table>";
    c.appendChild(card);
  });

  state.pageTimer=setTimeout(()=>{if(location.hash==="#/p:stats")renderStats();},5000);
}


/* ---- what happened, a minute at a time ---- */
function historyCard(h){
  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>Traffic</h2><div class=sp></div>'+
    "<span class=hint>"+esc(h.span)+" of history, one point a minute</span></div>";
  const bd=document.createElement("div");bd.className="bd";
  /* Busiest first: a page of flat lines with the interesting one at the
     bottom is a page nobody reads to the bottom of. */
  const rows=Object.keys(h.series||{}).map(name=>{
    const s=h.series[name];
    return {name:name, s:s,
            req:(s.req||[]).reduce((a,b)=>a+b,0),
            err:(s.e5||[]).reduce((a,b)=>a+b,0)};
  }).filter(r=>r.req||r.err).sort((a,b)=>b.req-a.req);
  if(!rows.length){
    bd.innerHTML='<p class=hint>Nothing has been served yet in the recorded window.</p>';
    card.appendChild(bd);return card;
  }
  bd.innerHTML="<table><thead><tr><th>Pool</th><th>Traffic</th><th>Requests</th>"+
    "<th>Server errors</th><th>Busiest minute</th></tr></thead><tbody>"+
    rows.map(r=>{
      const peak=Math.max(0,...(r.s.req||[]));
      return "<tr><td class=mono>"+esc(r.name.replace(/^b[ek]_/,""))+"</td>"+
        "<td>"+trafficSpark(r.s,{width:220,height:28})+"</td>"+
        "<td>"+num(r.req)+"</td>"+
        "<td>"+(r.err?'<span style="color:var(--down)">'+num(r.err)+"</span>":"0")+"</td>"+
        "<td>"+num(peak)+" <span class=sub>req/min</span></td></tr>";
    }).join("")+"</tbody></table>";
  const foot=document.createElement("div");foot.className="hint";
  foot.style.padding="8px 16px";
  foot.textContent="Collected on this node only, and only while it is running -- "+
    "a gap in the line is a gap in the recording, not in the traffic.";
  bd.appendChild(foot);
  card.appendChild(bd);return card;
}
