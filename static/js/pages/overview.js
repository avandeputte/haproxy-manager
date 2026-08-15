import { $, api, btn, closeDlg, esc, openDlg } from "../core.js";
import { refreshStatus, route } from "../shell.js";
import { certExpiryCell, certLastCell, certStat, certStatusCell } from "../pages/certificates.js";
import { clusterCard } from "../pages/cluster.js";
import { servicesCard } from "../pages/services.js";

/* ---- overview ---- */
export async function renderOverview(){
  const c=$("#content");
  let st;
  try{st=await api("status");}catch(e){c.innerHTML='<div class="card"><div class="bd">'+esc(e.message)+"</div></div>";return;}
  c.innerHTML="";
  const grid=document.createElement("div");grid.className="grid row5";grid.style.marginBottom="18px";
  const pill=(v,goodVals)=>'<span class="pill '+(goodVals.includes(v)?"up":v==="disabled"?"off":"down")+'">'+esc(v)+"</span>";
  grid.innerHTML=
    '<div class=stat><div class=k>HAProxy</div><div class=v>'+pill(st.haproxy,["active"])+"</div></div>"+
    '<div class=stat><div class=k>Keepalived</div><div class=v>'+pill(st.keepalived,["active"])+"</div></div>"+
    '<div class=stat><div class=k>Virtual IPs</div><div class=v style="font-size:13px">'+
      (st.vips.length?st.vips.map(v=>esc(v)+(st.vip_held.includes(v)?" ●":"")).join("<br>"):"—")+"</div></div>"+
    '<div class=stat><div class=k>Configuration</div><div class=v style="font-size:13px">'+
      (st.dirty?'<span class="pill" style="background:#f6ecdd;color:var(--drift)">unapplied changes</span>':'<span class="pill up">applied</span>')+"</div></div>";
  grid.style.gridTemplateColumns="repeat("+grid.children.length+",1fr)";
  c.appendChild(grid);

  c.appendChild(await clusterCard());
  c.appendChild(await servicesCard());

  const cc=document.createElement("div");cc.className="card";
  cc.innerHTML='<div class=hd><h2>Certificates</h2><div class=sp></div></div>';
  if(st.renewal_note){
    const n=document.createElement("span");n.className="hint";n.style.marginRight="10px";
    n.textContent=st.renewal_note;cc.querySelector(".hd").appendChild(n);
  }
  cc.querySelector(".hd").appendChild(btn("Renew all now","sm",async()=>{
    const pre=document.createElement("pre");
    pre.textContent="Running acme.sh for every auto-renew certificate -- this can take a few minutes.";
    openDlg("Renewing certificates",pre,[btn("Close","",closeDlg)]);
    try{
      const r=await api("acme/renew","POST",{});
      const res=r.results||{};
      const names=Object.keys(res);
      pre.textContent=(names.length?names.map(n=>
          (res[n].ok?"OK      ":"FAILED  ")+n+(res[n].ok?"":" -- "+(res[n].error||"unknown error"))).join("\n")
        :"No certificates have auto-renew enabled.")+
        "\n\nOpen a certificate's Log button for the full acme.sh output.";
      // Renewing runs for minutes; only repaint if the Overview is still up,
      // and through route() so it does not stomp a page navigated to since.
      refreshStatus();if(location.hash===""||location.hash==="#/")route();
    }catch(e){pre.textContent="FAILED -- "+e.message;}
  }));
  const cb=document.createElement("div");
  if(!st.certs.length)cb.innerHTML='<div class=empty>No certificates yet. Request one on the Certificates page.</div>';
  else{
    st.certs.forEach(x=>{certStat[x.id]=x;});
    cb.innerHTML="<table><thead><tr><th>Name</th><th>Status</th><th>Expires</th><th>Issuer</th><th>Last issue</th></tr></thead><tbody>"+
      st.certs.map(x=>"<tr><td>"+esc(x.name)+"<div class=sub>"+esc((x.domains||[]).join(", "))+"</div></td>"+
        "<td>"+certStatusCell(x)+"</td>"+
        "<td>"+certExpiryCell(x)+"</td>"+
        "<td class=mono style=font-size:11.5px>"+esc(x.issuer||"—")+"</td>"+
        "<td>"+certLastCell(x)+"</td></tr>").join("")+
      "</tbody></table>"+
      '<div class=hint style="padding:10px 16px">Manage and issue them on the Certificates page.</div>';
  }
  cc.appendChild(cb);c.appendChild(cc);

}
