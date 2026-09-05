import { $, api, btn, closeDlg, esc, localTime, openDlg } from "../core.js";
import { t, tn } from "../i18n.js";
import { refreshStatus, route } from "../shell.js";
import { state } from "../state.js";

/* ---- configuration history ---- */
/* Every state the shared configuration has passed through on this node, and
   the way back to any of them. The one feature that exists for the day
   something went wrong, so the page leads with when and what, not with
   plumbing. */

const STATE_PILL={added:"up",removed:"off",changed:"warn"};

function diffTable(parts){
  const box=document.createElement("div");
  if(!parts.length){
    box.innerHTML='<div class=empty>'+t("No difference -- this is the current configuration.")+'</div>';
    return box;
  }
  const tbl=document.createElement("table");
  const tb=document.createElement("tbody");
  parts.forEach(p=>{
    p.objects.forEach((o,i)=>{
      const tr=document.createElement("tr");
      tr.innerHTML="<td class=mono>"+(i?"":esc(p.part))+"</td>"+
        '<td style="width:90px"><span class="pill '+(STATE_PILL[o.state]||"off")+'">'+
          esc(t(o.state))+"</span></td>"+
        "<td class=mono>"+esc(o.name)+"</td>";
      tb.appendChild(tr);
    });
  });
  tbl.appendChild(tb);box.appendChild(tbl);
  return box;
}

export async function renderHistory(){
  const c=$("#content");c.innerHTML="";
  const r=await api("history");
  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>'+t("Configuration history")+'</h2></div>';
  const bd=document.createElement("div");
  const intro=document.createElement("p");intro.className="hint";
  intro.style.cssText="padding:14px 16px 0";
  intro.textContent=t("Every state the shared configuration has passed through on this node, "+
    "newest first -- including states a peer pushed here. Restore puts one back as a new "+
    "change: nothing is applied or synced until you press Apply.");
  bd.appendChild(intro);
  const snaps=r.snapshots||[];
  if(!snaps.length){
    bd.innerHTML+='<div class=empty>'+t("Nothing recorded yet. A snapshot is kept each time the shared configuration changes.")+'</div>';
  }else{
    const tbl=document.createElement("table");
    tbl.innerHTML="<thead><tr><th>"+t("When")+"</th><th>"+t("Revision")+"</th><th>"+t("What changed")+"</th><th></th></tr></thead>";
    const tb=document.createElement("tbody");
    snaps.forEach(s=>{
      const tr=document.createElement("tr");
      tr.innerHTML="<td class=mono>"+esc(localTime(s.at))+
          (s.current?' <span class="pill up">'+t("current")+'</span>':"")+"</td>"+
        "<td class=mono>"+esc(s.rev)+"</td>"+
        "<td>"+(s.summary?esc(s.summary):'<span class=sub>'+
          (s.current&&snaps.length===1?t("the first recorded state"):t("the oldest recorded state"))+"</span>")+"</td>";
      const act=document.createElement("td");act.style.textAlign="right";act.style.whiteSpace="nowrap";
      act.appendChild(btn(t("Diff vs now"),"sm",async()=>{
        try{
          const d=await api("history/"+encodeURIComponent(s.id)+"/diff");
          const wrap=document.createElement("div");
          const note=document.createElement("p");note.className="hint";note.style.marginBottom="12px";
          note.textContent=t("Against the current configuration. \"added\" exists now and Restore "+
            "would remove it; \"removed\" would come back; \"changed\" would revert.");
          wrap.appendChild(note);wrap.appendChild(diffTable(d.parts||[]));
          openDlg(t("This node at {when}",{when:localTime(s.at)}),wrap,[btn(t("Close"),"",closeDlg)]);
        }catch(e){alert(e.message);}
      }));
      if(!state.readOnly&&!s.current){
        act.appendChild(document.createTextNode(" "));
        act.appendChild(btn(t("Restore"),"sm warn",async()=>{
          if(!confirm(t("Put the configuration of {when} (revision {rev}) back?\n\n"+
                        "It becomes a NEW change: the services, certificates, users and cluster "+
                        "settings return to that state, node-local settings stay as they are, "+
                        "and nothing is applied or synced until you press Apply.",
                        {when:localTime(s.at),rev:s.rev})))return;
          try{
            const res=await api("history/"+encodeURIComponent(s.id)+"/restore","POST",{});
            alert(res.note||t("Restored."));
            await route();refreshStatus();
          }catch(e){alert(e.message);}
        }));
      }
      tr.appendChild(act);tb.appendChild(tr);
    });
    tbl.appendChild(tb);bd.appendChild(tbl);
    const hint=document.createElement("div");hint.className="hint";hint.style.padding="10px 16px";
    hint.textContent=tn(snaps.length,
      "The last {n} state is kept, on this node's own disk. Each node remembers what it saw.",
      "The last {n} states are kept, on this node's own disk. Each node remembers what it saw.");
    bd.appendChild(hint);
  }
  card.appendChild(bd);c.appendChild(card);
}
