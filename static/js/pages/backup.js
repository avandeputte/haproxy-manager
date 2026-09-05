import { $, api, btn, download, esc, localTime, showText } from "../core.js";
import { t } from "../i18n.js";
import { refreshStatus } from "../shell.js";

/* ---- backup / export ---- */
export async function renderBackup(){
  const c=$("#content");c.innerHTML="";

  const files=document.createElement("div");files.className="card";
  files.innerHTML='<div class=hd><h2>'+t("Generated configuration files")+'</h2></div>';
  const fb=document.createElement("div");fb.className="bd";
  fb.innerHTML='<p class=hint style="margin-bottom:14px">'+
    t("The files this configuration renders to, exactly as Apply would write them. "+
      "Downloading does not change anything on the node.")+'</p>';
  const row=document.createElement("div");row.style.display="flex";row.style.gap="10px";row.style.flexWrap="wrap";
  row.appendChild(btn(t("Download haproxy.cfg"),"pri",()=>download("export/haproxy.cfg")));
  row.appendChild(btn(t("Download keepalived.conf"),"",()=>download("export/keepalived.conf")));
  row.appendChild(btn(t("View haproxy.cfg"),"",async()=>{const p=await api("preview");showText(t("haproxy.cfg (preview)"),p.haproxy);}));
  fb.appendChild(row);files.appendChild(fb);c.appendChild(files);

  const bk=document.createElement("div");bk.className="card";
  bk.innerHTML='<div class=hd><h2>'+t("Configuration backup")+'</h2></div>';
  const bb=document.createElement("div");bb.className="bd";
  bb.innerHTML='<p class=hint style="margin-bottom:14px">'+
    t("A JSON backup of everything the UI manages: Real Servers, Backend Pools, "+
      "Public Services, Conditions, Rules, Health Monitors, HAProxy Settings, all ACME objects, and the "+
      "users and groups a service can ask visitors to sign in with. "+
      "Node-local settings (Keepalived, Sync, the login and the API key), private keys and those users' "+
      "passwords are <b>not</b> included, so the file is safe to copy between nodes.")+'</p>';
  const brow=document.createElement("div");brow.style.display="flex";brow.style.gap="10px";brow.style.alignItems="center";brow.style.flexWrap="wrap";
  brow.appendChild(btn(t("Download backup"),"pri",()=>download("export/config")));
  const file=document.createElement("input");file.type="file";file.accept=".json,application/json";file.style.fontSize="13px";
  const msg=document.createElement("div");msg.className="hint";msg.style.marginTop="12px";
  brow.appendChild(file);
  brow.appendChild(btn(t("Restore"),"warn",async()=>{
    const f=file.files&&file.files[0];
    if(!f){msg.textContent=t("Choose a backup file first.");return;}
    if(!confirm(t("Restore \"{file}\"?\n\nThis replaces every Real Server, Backend Pool, Public Service, "+
                  "Condition, Rule, Health Monitor, ACME object, service user and group on this node. "+
                  "Keepalived, Sync and the login are kept, and so are the passwords of the service users "+
                  "already here -- a backup carries none.\n\nNothing is applied until you press Apply.",{file:f.name})))return;
    msg.textContent=t("Restoring...");
    try{
      const r=await api("import/config","POST",JSON.parse(await f.text()));
      const parts=[];
      Object.keys(r.restored||{}).forEach(sec=>{
        const counts=r.restored[sec];
        Object.keys(counts).sort().forEach(k=>{if(counts[k])parts.push(counts[k]+" "+k);});
      });
      msg.innerHTML=t("Restored {what}",{what:parts.join(", ")||t("nothing")})+
        (r.source?" ("+t("from {source}",{source:esc(r.source)+(r.exported?", "+esc(localTime(r.exported)):"")})+")":"")+
        ". <b>"+t("Review the objects, then press Apply.")+"</b>";
      refreshStatus();
    }catch(e){msg.textContent=t("Restore failed: {error}",{error:e.message});}
  }));
  bb.appendChild(brow);bb.appendChild(msg);bk.appendChild(bb);c.appendChild(bk);
}
