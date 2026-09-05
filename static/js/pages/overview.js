import { $, api, btn, closeDlg, esc, openDlg } from "../core.js";
import { t } from "../i18n.js";
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
  const pill=(v,goodVals)=>'<span class="pill '+(goodVals.includes(v)?"up":v==="disabled"?"off":"down")+'">'+esc(t(v))+"</span>";
  grid.innerHTML=
    '<div class=stat><div class=k>HAProxy</div><div class=v>'+pill(st.haproxy,["active"])+"</div></div>"+
    '<div class=stat><div class=k>Keepalived</div><div class=v>'+pill(st.keepalived,["active"])+"</div></div>"+
    '<div class=stat><div class=k>'+t("Virtual IPs")+'</div><div class=v style="font-size:13px">'+
      (st.vips.length?st.vips.map(v=>esc(v)+(st.vip_held.includes(v)?" ●":"")).join("<br>"):"—")+"</div></div>"+
    '<div class=stat><div class=k>'+t("Configuration")+'</div><div class=v style="font-size:13px">'+
      (st.dirty?'<span class="pill" style="background:#f6ecdd;color:var(--drift)">'+t("unapplied changes")+'</span>':'<span class="pill up">'+t("applied")+'</span>')+"</div></div>";
  grid.style.gridTemplateColumns="repeat("+grid.children.length+",1fr)";
  c.appendChild(grid);

  c.appendChild(await clusterCard());
  c.appendChild(await servicesCard());

  const cc=document.createElement("div");cc.className="card";
  cc.innerHTML='<div class=hd><h2>'+t("Certificates")+'</h2><div class=sp></div></div>';
  if(st.renewal_note){
    const n=document.createElement("span");n.className="hint";n.style.marginRight="10px";
    n.textContent=st.renewal_note;cc.querySelector(".hd").appendChild(n);
  }
  cc.querySelector(".hd").appendChild(btn(t("Renew all now"),"sm",async()=>{
    const pre=document.createElement("pre");
    pre.textContent=t("Running acme.sh for every auto-renew certificate -- this can take a few minutes.");
    openDlg(t("Renewing certificates"),pre,[btn(t("Close"),"",closeDlg)]);
    try{
      const r=await api("acme/renew","POST",{});
      const res=r.results||{};
      const names=Object.keys(res);
      pre.textContent=(names.length?names.map(n=>
          (res[n].ok?"OK      ":t("FAILED")+"  ")+n+(res[n].ok?"":" -- "+(res[n].error||t("unknown error")))).join("\n")
        :t("No certificates have auto-renew enabled."))+
        "\n\n"+t("Open a certificate's Log button for the full acme.sh output.");
      // Renewing runs for minutes; only repaint if the Overview is still up,
      // and through route() so it does not stomp a page navigated to since.
      refreshStatus();if(location.hash===""||location.hash==="#/")route();
    }catch(e){pre.textContent=t("FAILED -- {error}",{error:e.message});}
  }));
  const cb=document.createElement("div");
  if(!st.certs.length)cb.innerHTML='<div class=empty>'+t("No certificates yet. Request one on the Certificates page.")+'</div>';
  else{
    st.certs.forEach(x=>{certStat[x.id]=x;});
    cb.innerHTML="<table><thead><tr><th>"+t("Name")+"</th><th>"+t("Status")+"</th><th>"+t("Expires")+"</th><th>"+t("Issuer")+"</th><th>"+t("Last issue")+"</th></tr></thead><tbody>"+
      st.certs.map(x=>"<tr><td>"+esc(x.name)+"<div class=sub>"+esc((x.domains||[]).join(", "))+"</div></td>"+
        "<td>"+certStatusCell(x)+"</td>"+
        "<td>"+certExpiryCell(x)+"</td>"+
        "<td class=mono style=font-size:11.5px>"+esc(x.issuer||"—")+"</td>"+
        "<td>"+certLastCell(x)+"</td></tr>").join("")+
      "</tbody></table>"+
      '<div class=hint style="padding:10px 16px">'+t("Manage and issue them on the Certificates page.")+'</div>';
  }
  cc.appendChild(cb);c.appendChild(cc);

}
