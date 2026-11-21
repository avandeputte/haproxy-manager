/* Cloudflare: the tunnel services are published through, and cloudflared on this node. */
import { $, api, btn, esc, fieldRow, readForm, showText } from "../core.js";
import { t } from "../i18n.js";
import { refreshStatus } from "../shell.js";
import { state } from "../state.js";

export async function renderCloudflare(){
  const c=$("#content");c.innerHTML="";
  let s;
  try{s=await api("cloudflare/settings");}
  catch(e){c.innerHTML='<div class="card"><div class="bd">'+esc(e.message)+"</div></div>";return;}

  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>Cloudflare</h2> <span class="pill warn">'+t("beta")+'</span><div class=sp></div>'+
    '<span class="pill '+(s.enabled?"up":"off")+'">'+(s.enabled?t("saved: on"):t("saved: off"))+"</span></div>";
  const bd=document.createElement("div");bd.className="bd";
  bd.innerHTML='<p class=hint style="margin-bottom:14px">'+
    t("Publish HTTP and HTTPS services to the internet through a Cloudflare Tunnel, with no open port "+
      "here: cloudflared on every node holds an outbound connection to Cloudflare, and visitors come "+
      "down it to HAProxy. Tick Publish through Cloudflare on a service, and Apply adds its route, "+
      "its DNS record and, when the service asks for a sign-in, its Cloudflare Access application. "+
      "Only what was made here is ever changed or removed.")+"</p>";

  /* the node and the tunnel: is cloudflared here and running, what is published */
  const node=document.createElement("div");node.className="hint";node.style.cssText="border:1px solid var(--hair);border-radius:6px;padding:10px 12px;margin-bottom:14px";
  const draw=(x)=>{
    node.innerHTML="<b>"+t("This node")+"</b> &mdash; "+
      (x.installed?t("cloudflared {version} installed",{version:esc(x.version||"")})
                  :t("cloudflared not installed -- fetched at the next Apply once Cloudflare is on, or now:"))+
      (x.installed?", "+t("service")+" <span class='pill "+(x.service==="active"?"up":"off")+"'>"+esc(t(x.service||"unknown"))+"</span>":" ");
    if(!x.installed&&!state.readOnly){
      const b=btn(t("Install on this node"),"sm",async()=>{
        b.disabled=true;b.textContent=t("Installing...");
        try{const r=await api("cloudflare/install","POST",{});showText("cloudflared",r.message);draw(r.status||x);}
        catch(e){showText(t("Install failed"),e.message);b.disabled=false;b.textContent=t("Install on this node");}
      });
      node.appendChild(b);
    }
    const tun=document.createElement("div");tun.style.marginTop="6px";
    tun.innerHTML="<b>"+t("Tunnel")+"</b> &mdash; "+
      (x.connected?t("connected, {n} host name(s) published",{n:(x.hosts||[]).length})+
         ((x.hosts||[]).length?": "+esc(x.hosts.join(", ")):"")+
         (x.in_step?"":' <span class="pill warn">'+t("Cloudflare is behind -- Apply, or Sync now")+"</span>")
       :t("not connected -- saved with Enable ticked, a tunnel is made in your account"));
    node.appendChild(tun);
  };
  draw(s.status||{});
  bd.appendChild(node);

  const FIELDS=[
   {k:"api_token",l:"API token",t:"password",
    h:s.has_api_token?"Leave empty to keep the stored one"
      :"From the Cloudflare dashboard: My Profile > API Tokens > Create Token > Custom token, with Account: Cloudflare Tunnel: Edit, Account: Access: Apps and Policies: Edit, Zone: DNS: Edit and Zone: Zone: Read, for the zones your services are in."},
   {k:"account_id",l:"Account ID",t:"text",h:"Optional when the token sees one account. It is on the right of a zone's Overview page."},
   {k:"tunnel_name",l:"Tunnel name",t:"text",d:"haproxy-manager",h:"The tunnel made in your account. One of that name that is already there is used only while it is empty: a tunnel with routes or a connector is somebody's, and is refused. The other nodes of a cluster share this one."},
   {k:"origin_port",l:"First loopback port",t:"text",d:"7811",h:"cloudflared reaches HAProxy on 127.0.0.1, on one port per listener that carries a published service, counted up from this one. Change it only if something else on the node uses these ports."},
   {k:"enabled",l:"Enable Cloudflare",t:"bool",h:"cloudflared runs on every node, and the services ticked for it are published. Test the token first; takes effect at the next Apply."},
  ];
  const frm=document.createElement("div");frm.className="frm";
  FIELDS.forEach(f=>fieldRow(f,s[f.k]).forEach(el=>frm.appendChild(el)));
  bd.appendChild(frm);

  const foot=document.createElement("div");foot.style.marginTop="16px";
  const msg=document.createElement("span");msg.className="hint";msg.style.marginLeft="10px";
  const save=btn(t("Save"),"pri",async()=>{
    const data=readForm(FIELDS);
    msg.textContent=t("Asking...");
    try{
      const r=await api("cloudflare/settings","PUT",data);
      msg.textContent=t("Saved. Apply to make it so; the other nodes follow.");
      if(r.status)draw(r.status);
      refreshStatus();
    }catch(e){
      msg.innerHTML='<span class="pill down">'+t("not saved")+'</span>';
      showText(t("Not saved"),e.message);
    }
  });
  if(state.readOnly){save.disabled=true;msg.textContent=t("Read-only on a passive node.");}
  foot.appendChild(save);
  foot.appendChild(document.createTextNode(" "));
  foot.appendChild(btn(t("Test the token"),"",async()=>{
    msg.textContent=t("Asking...");
    const d=readForm(FIELDS);
    try{
      const r=await api("cloudflare/test","POST",{api_token:d.api_token,account_id:d.account_id});
      msg.innerHTML='<span class="pill '+(r.ok?"up":"down")+'">'+(r.ok?t("reachable"):t("not reachable"))+"</span> "+esc(r.message);
    }catch(e){msg.textContent=e.message;}
  }));
  if(!state.readOnly&&(s.status||{}).connected){
    foot.appendChild(document.createTextNode(" "));
    /* for a record or an application somebody removed in the dashboard */
    foot.appendChild(btn(t("Sync now"),"",async()=>{
      msg.textContent=t("Asking...");
      try{
        const r=await api("cloudflare/sync","POST",{});
        msg.textContent="";showText("Cloudflare",r.message);if(r.status)draw(r.status);
      }catch(e){msg.textContent="";showText("Cloudflare",e.message);}
    }));
    foot.appendChild(document.createTextNode(" "));
    foot.appendChild(btn(t("Disconnect"),"dngr",async()=>{
      if(!confirm(t("Remove every route, DNS record and Access application made here from Cloudflare, and delete the tunnel? Services stay as they are on this node.")))return;
      msg.textContent=t("Asking...");
      try{
        const r=await api("cloudflare/disconnect","POST",{});
        showText("Cloudflare",r.message);renderCloudflare();refreshStatus();
      }catch(e){
        /* Cloudflare would not have it -- the tunnel gone there, the token
           revoked. The way out is to forget it here, said as what it is. */
        msg.textContent="";
        if(!confirm(e.message+"\n\n"+t("Cloudflare could not be cleaned up. Forget the tunnel on this installation anyway? What is left in Cloudflare then has to be removed there by hand."))){renderCloudflare();refreshStatus();return;}
        try{
          const r=await api("cloudflare/disconnect","POST",{forget:true});
          showText("Cloudflare",r.message);
        }catch(e2){showText("Cloudflare",e2.message);}
        renderCloudflare();refreshStatus();
      }
    }));
  }
  foot.appendChild(msg);
  bd.appendChild(foot);card.appendChild(bd);c.appendChild(card);
}
