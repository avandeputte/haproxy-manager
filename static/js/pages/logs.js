import { $, api, download, esc } from "../core.js";
import { state } from "../state.js";

/* ---- logs ---- */
/* Filters live outside the render so a refresh does not wipe what you typed. */
export const logState={sources:{manager:true,haproxy:true,acme:true,keepalived:true},
                level:"DEBUG",q:"",lines:300,follow:true};
export function logParams(){
  const on=Object.keys(logState.sources).filter(k=>logState.sources[k]);
  return "sources="+encodeURIComponent(on.join(","))+"&lines="+logState.lines+
         "&level="+logState.level+"&q="+encodeURIComponent(logState.q);
}
export function logStamp(ts){
  if(!ts)return "--:--:--";
  const d=new Date(ts*1000),p=n=>String(n).padStart(2,"0");
  return p(d.getHours())+":"+p(d.getMinutes())+":"+p(d.getSeconds());
}
export async function refreshLogs(view,note){
  let r;
  try{r=await api("logs?"+logParams());}
  catch(e){note.textContent=e.message;return;}
  const stick=logState.follow||
              view.scrollTop+view.clientHeight>=view.scrollHeight-40;  /* at the bottom */
  if(!r.entries.length){
    view.innerHTML='<div class=logempty>Nothing matches. Widen the filters, or wait for '+
      'something to happen.</div>';
  }else{
    view.innerHTML="<table><tbody>"+r.entries.map(e=>
      "<tr class="+e.level+"><td class=t>"+logStamp(e.ts)+"</td>"+
      "<td class='s src-"+e.source+"'>"+esc(e.source)+"</td>"+
      "<td class=m>"+esc(e.text)+"</td></tr>").join("")+"</tbody></table>";
  }
  if(stick)view.scrollTop=view.scrollHeight;
  note.textContent=r.entries.length+" line"+(r.entries.length===1?"":"s")+
    (r.failed.length?"  ·  unreadable: "+r.failed.join("; "):"");
  note.className=r.failed.length?"err":"hint";
}
export async function renderLogs(){
  const c=$("#content");c.innerHTML="";
  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>Logs</h2><div class=sp></div>'+
    '<button class="btn ghost" id=logdl>Download</button></div>';

  const bar=document.createElement("div");bar.className="logbar";
  bar.innerHTML=[["manager","Web UI"],["haproxy","HAProxy"],["acme","acme.sh"],
                 ["keepalived","Keepalived"]].map(([k,l])=>
      '<label><input type=checkbox data-src="'+k+'"'+(logState.sources[k]?" checked":"")+
      '> <span class="src-'+k+'" style="font-weight:600">'+l+"</span></label>").join("")+
    '<span style="flex:1"></span>'+
    '<label>Level <select id=loglevel><option value=DEBUG>everything</option>'+
      '<option value=INFO>info and above</option><option value=WARNING>warnings and errors</option>'+
      '<option value=ERROR>errors only</option></select></label>'+
    '<label>Lines <select id=loglines><option>100</option><option>300</option>'+
      '<option>1000</option><option>2000</option></select></label>'+
    '<label><input type=search id=logq placeholder="search text" style="width:170px"></label>'+
    '<label><input type=checkbox id=logfollow'+(logState.follow?" checked":"")+"> follow</label>";
  card.appendChild(bar);

  const view=document.createElement("div");view.className="logview";
  view.innerHTML='<div class=logempty>Loading...</div>';
  card.appendChild(view);
  const foot=document.createElement("div");foot.className="bd";
  const note=document.createElement("div");note.className="hint";
  note.textContent="Loading...";
  foot.appendChild(note);
  foot.insertAdjacentHTML("beforeend",
    '<div class=hint style="margin-top:6px">HAProxy and Keepalived are read from the '+
    'system journal, acme.sh from its own log and the record of each issuance. '+
    'Timestamps are this node\'s.</div>');
  card.appendChild(foot);
  c.appendChild(card);

  $("#loglevel").value=logState.level;
  $("#loglines").value=String(logState.lines);
  $("#logq").value=logState.q;
  const again=()=>refreshLogs(view,note);
  bar.querySelectorAll("input[data-src]").forEach(b=>{
    b.onchange=()=>{logState.sources[b.dataset.src]=b.checked;again();};
  });
  $("#loglevel").onchange=e=>{logState.level=e.target.value;again();};
  $("#loglines").onchange=e=>{logState.lines=parseInt(e.target.value,10)||300;again();};
  $("#logfollow").onchange=e=>{logState.follow=e.target.checked;};
  let typing=null;
  $("#logq").oninput=e=>{logState.q=e.target.value;
    clearTimeout(typing);typing=setTimeout(again,300);};
  $("#logdl").onclick=()=>download("logs?format=text&"+logParams());

  await again();
  const tick=async()=>{
    if(location.hash!=="#/p:logs")return;
    if(logState.follow)await again();
    state.pageTimer=setTimeout(tick,5000);
  };
  state.pageTimer=setTimeout(tick,5000);
}
