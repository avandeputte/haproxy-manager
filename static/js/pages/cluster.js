import { $, api, btn, closeDlg, esc, fieldRow, openDlg, readForm, showText } from "../core.js";
import { refreshStatus, route } from "../shell.js";
import { state } from "../state.js";

/* ---- cluster: peers and health ---- */
export const PEER_FIELDS=[
 {k:"name",l:"Name",t:"text",h:"How this node should refer to it"},
 {k:"url",l:"URL",t:"text",h:"e.g. http://10.0.0.2:8080 or https://node2.example.com"},
 {k:"api_key",l:"Its API key",t:"password",reveal:true,h:"The API key configured on THAT node (Cluster > This node there). Leave blank when editing to keep the stored one."},
 {k:"verify_tls",l:"Verify its TLS certificate",t:"bool"},
 {k:"enabled",l:"Enabled",t:"bool",d:true},
];
export function peerEditor(peer,after){
  const frm=document.createElement("div");frm.className="frm";
  PEER_FIELDS.forEach(f=>fieldRow(f,peer?peer[f.k]:undefined).forEach(el=>frm.appendChild(el)));
  const err=document.createElement("div");err.className="err";
  openDlg(peer?"Edit node":"Add a node",frm,[err,btn("Cancel","",closeDlg),
    btn("Save","pri",async()=>{
      const d=readForm(PEER_FIELDS);
      try{
        if(peer)await api("peers/"+peer.id,"PUT",d); else await api("peers","POST",d);
        closeDlg();after();
      }catch(e){err.textContent=e.message;}
    })]);
}
/* Everything about the cluster on one page: what all nodes share, what is
   particular to this one, state.who the others are, and how this node is doing. */
export const CLUSTER_SHARED=[
 {k:"vips",l:"Virtual IP addresses",t:"textarea",h:"One per line with prefix, e.g. 192.0.2.10/24. Bind your Public Services to these."},
 {k:"vrid",l:"Virtual router ID",t:"number",h:"1-255. Must be identical on every node, and unique among other VRRP groups on the same network."},
 {k:"auth_pass",l:"VRRP password",t:"password",reveal:true,h:"Same on every node; only the first 8 characters are used"},
 {k:"state",l:"Initial state",t:"select",o:["MASTER","BACKUP"],d:"BACKUP"},
 {k:"nopreempt",l:"No preempt",t:"bool",d:true,h:"A recovered node does not take the virtual IP back"},
 {k:"advert_int",l:"Advertisement interval (s)",t:"number"},
 {k:"track_haproxy",l:"Track HAProxy",t:"bool",d:true,h:"Give the virtual IP up when HAProxy is not serving on this node"},
 {k:"track_mode",l:"What counts as up",t:"select",d:"responding",o:["responding","process"],
  h:"\"responding\" asks HAProxy through its admin socket, so an instance that is running but wedged "+
    "hands the virtual IP over. \"process\" only checks that a process called haproxy exists, which a "+
    "hung one still does. With no admin socket to ask, \"responding\" behaves as \"process\"."},
 {k:"custom",l:"Extra keepalived directives",t:"textarea",
  h:"Advanced, and rarely needed. Raw lines added inside the vrrp_instance block of the generated "+
    "keepalived.conf, for settings this page does not cover -- for example \"garp_master_delay 5\" or "+
    "\"notify_master /etc/keepalived/on-master.sh\". One per line, exactly as keepalived expects. "+
    "They are validated with keepalived -t before anything is written, so a mistake blocks Apply "+
    "rather than breaking the node. See the keepalived.conf manual (man 5 keepalived.conf)."},
];
export const CLUSTER_LOCAL=[
 {k:"interface",l:"Interface",t:"combo",o:()=>kaIfaceOptions,
  h:"The interface on THIS node that carries the virtual IP"},
 {k:"priority",l:"Priority",t:"number",h:"Higher wins. Give each node a different value, e.g. 150 / 140 / 130."},
];
export async function renderCluster(){
  const c=$("#content");c.innerHTML="";
  await loadKeepalivedDiag();
  const [shared,loc,peers]=await Promise.all([api("cluster/settings"),api("local"),api("peers")]);

  /* --- what every node shares --- */
  const s1=document.createElement("div");s1.className="card";
  s1.innerHTML='<div class=hd><h2>Cluster settings</h2><div class=sp></div><span class=hint>shared by every node</span></div>';
  const b1=document.createElement("div");b1.className="bd";
  b1.innerHTML='<p class=hint style="margin-bottom:14px">These must match on every node. Pushing the configuration '+
    'sends them to the others, so set them here and sync.</p>';
  const f1=document.createElement("div");f1.className="frm";
  CLUSTER_SHARED.forEach(f=>fieldRow(f,shared[f.k]).forEach(el=>f1.appendChild(el)));
  b1.appendChild(f1);
  const m1=document.createElement("span");m1.className="hint";m1.style.marginLeft="10px";
  const ft1=document.createElement("div");ft1.style.marginTop="16px";
  const saveShared=btn("Save","pri",async()=>{
    try{await api("cluster/settings","PUT",readForm(CLUSTER_SHARED));
      m1.textContent="Saved. Apply on this node, then push to the others.";refreshStatus();}
    catch(e){m1.textContent=e.message;}
  });
  if(state.readOnly){saveShared.disabled=true;m1.textContent="Read-only on a passive node -- change these on the active node and push.";}
  ft1.appendChild(saveShared);
  ft1.appendChild(document.createTextNode(" "));
  ft1.appendChild(btn("Validate","",async()=>{
    m1.textContent="Checking...";
    try{
      const r=await api("validate","POST",{section:"cluster",settings:readForm(CLUSTER_SHARED)});
      m1.innerHTML=r.ok?'<span class="pill up">valid</span> '+esc(r.message)
                       :'<span class="pill down">not valid</span>';
      if(!r.ok)showText("These settings would not work",r.message);
    }catch(e){m1.textContent=e.message;}
  }));
  ft1.appendChild(m1);b1.appendChild(ft1);s1.appendChild(b1);c.appendChild(s1);

  /* --- what is particular to this node --- */
  const s2=document.createElement("div");s2.className="card";
  s2.innerHTML='<div class=hd><h2>This node &mdash; <span class=mono>'+esc(state.kaDiag&&state.kaDiag.hostname||location.host)+
    '</span></h2><div class=sp></div><span class=hint>never synced</span></div>';
  const b2=document.createElement("div");b2.className="bd";
  const f2=document.createElement("div");f2.className="frm";
  const localFields=CLUSTER_LOCAL.concat([
    {k:"node_url",l:"This node's URL",t:"text",h:"How the other nodes reach this one, e.g. http://10.0.0.1:8080. Needed to hand them a way back."},
    {k:"api_key",l:"API key",t:"password",reveal:true,generate:true,
     h:"Machines only: the other nodes present this to sync here, and scripts can send it as X-API-Key. Show it to copy it onto another node."},
  ]);
  localFields.forEach(f=>{
    const v=f.k==="node_url"?loc.node_url:f.k==="api_key"?loc.api_key:(loc.keepalived||{})[f.k];
    fieldRow(f,v).forEach(el=>f2.appendChild(el));
  });
  b2.appendChild(f2);
  const ka=document.createElement("div");ka.className="hint";ka.style.marginTop="10px";
  ka.innerHTML=(shared.vips||"").trim()
    ? "Keepalived runs on this node because the cluster has a virtual IP. Its interface and priority "+
      "are set here; everything else follows the cluster settings above."
    : "The cluster has no virtual IP, so Keepalived does not run and this node serves on its own "+
      "addresses. Add one above and the nodes take turns holding it: one active, the rest ready.";
  b2.appendChild(ka);
  const fp=document.createElement("div");fp.className="hint";fp.style.marginTop="8px";
  try{
    const st=await api("status");
    fp.innerHTML=st.api_key_fp
      ? 'This node\'s API key fingerprint: <span class=mono><b>'+esc(st.api_key_fp)+"</b></span>. "+
        "The other nodes must hold a key with this fingerprint for this node."
      : "No API key is set on this node, so no other node can sync to it.";
  }catch(e){}
  b2.appendChild(fp);
  const m2=document.createElement("span");m2.className="hint";m2.style.marginLeft="10px";
  const ft2=document.createElement("div");ft2.style.marginTop="16px";
  ft2.appendChild(btn("Save","pri",async()=>{
    const d=readForm(localFields);
    try{
      await api("local","PUT",{keepalived:readForm(CLUSTER_LOCAL),
                               node_url:d.node_url,api_key:d.api_key});
      m2.textContent="Saved. Press Apply to write keepalived.conf.";
      await loadKeepalivedDiag();refreshStatus();
    }catch(e){m2.textContent=e.message;}
  }));
  ft2.appendChild(m2);b2.appendChild(ft2);s2.appendChild(b2);c.appendChild(s2);

  /* --- the other nodes --- */
  c.appendChild(peersCard(peers,loc));
  c.appendChild(keepalivedDiagCard());
}

export function peersCard(peers,loc){
  const frag=document.createDocumentFragment();
  const card=document.createElement("div");card.className="card";
  const hd=document.createElement("div");hd.className="hd";
  hd.innerHTML="<h2>Other nodes</h2><div class=sp></div>";
  hd.appendChild(btn("Add a node","pri sm",()=>peerEditor(null,()=>route())));
  card.appendChild(hd);
  const bd=document.createElement("div");
  if(!peers.length){
    bd.innerHTML='<div class=empty>No other nodes yet.<br><br>Add every other node, each with the API key '+
      'configured on it. Configuration, cluster settings and certificates are pushed to all of them, and the '+
      'Overview shows their health.</div>';
  }else{
    const t=document.createElement("table");
    t.innerHTML="<thead><tr><th>Name</th><th>URL</th><th>API key</th><th>Enabled</th><th></th></tr></thead>";
    const tb=document.createElement("tbody");
    peers.forEach(p=>{
      const tr=document.createElement("tr");
      tr.innerHTML="<td>"+esc(p.name)+"</td><td class=mono>"+esc(p.url)+byNameHint(p.url)+"</td>"+
        "<td>"+(p.has_key?(p.is_own_key?'<span class="pill down">this node\'s own key</span>'
                                       :'<span class="pill up">set</span>')+
            '<div class=sub>fingerprint <span class=mono>'+esc(p.key_fp)+"</span></div>"
                         :'<span class="pill down">missing</span>')+"</td>"+
        "<td>"+(p.enabled===false?'<span class="pill off">no</span>':"yes")+"</td>";
      const act=document.createElement("td");act.style.textAlign="right";act.style.whiteSpace="nowrap";
      const out=document.createElement("div");out.className="sub";
      out.style.cssText="margin-bottom:6px;text-align:right;max-width:420px;margin-left:auto";
      act.appendChild(out);
      act.appendChild(btn("Test","sm",async()=>{
        out.textContent="testing...";
        try{
          const r=await api("peers/"+p.id+"/test","POST",{});
          out.innerHTML=r.ok?('<span class="pill up">ok</span> '+esc(r.hostname||"")+" v"+esc(r.version||"?")+
                              ", "+esc(r.role||"")+(r.note?" — "+esc(r.note):""))
                            :('<span class="pill down">failed</span> '+esc(r.error||""));
        }catch(e){out.textContent=e.message;}
      }));
      act.appendChild(document.createTextNode(" "));
      act.appendChild(btn("Sync","sm",async()=>{
        out.textContent="pushing...";
        try{const r=await api("sync/push","POST",{peer:p.id,include_peers:true});
          out.textContent=r.ok?"synced":("failed: "+(r.error||""));}
        catch(e){out.textContent=e.message;}
      }));
      act.appendChild(document.createTextNode(" "));
      /* For the case an ordinary Sync cannot handle: the other node was edited
         and holds a newer configuration, so it refuses this one. This discards
         what is there and replaces it with what is here. */
      act.appendChild(btn("Overwrite","sm warn",async()=>{
        if(!confirm("Replace the configuration on "+p.name+" with this node's?\n\n"+
                    "Anything changed on "+p.name+" and not applied from here is discarded."))return;
        out.textContent="overwriting...";
        try{const r=await api("sync/push","POST",{peer:p.id,include_peers:true,overwrite:true});
          out.textContent=r.ok?"overwritten":("failed: "+(r.error||""));
          if(r.ok)route();}   /* the health on screen predates this */
        catch(e){out.textContent=e.message;}
      }));
      act.appendChild(document.createTextNode(" "));
      act.appendChild(btn("Edit","sm",()=>peerEditor(p,()=>route())));
      act.appendChild(document.createTextNode(" "));
      act.appendChild(btn("Remove","sm dngr",async()=>{
        if(!confirm("Stop syncing to "+p.name+"?"))return;
        try{await api("peers/"+p.id,"DELETE");route();}catch(e){alert(e.message);}
      }));
      tr.appendChild(act);tb.appendChild(tr);
    });
    t.appendChild(tb);bd.appendChild(t);
  }
  card.appendChild(bd);frag.appendChild(card);

  const opt=document.createElement("div");opt.className="card";
  opt.innerHTML='<div class=hd><h2>Sync</h2></div>';
  const ob=document.createElement("div");ob.className="bd";
  ob.innerHTML='<p class=hint style="margin-bottom:12px">A push sends the shared configuration (HAProxy, ACME and '+
    'the cluster settings above) and the deployed certificates to every enabled node, which validates, applies and '+
    'reloads. Their own interface, priority, unicast addresses, login and API key are never touched, so there is no '+
    'sync loop. It also hands each node the membership list, including a way back to this one, so you only maintain '+
    'the list here.</p>';
  const f={k:"auto_sync",l:"Keep the nodes in step",t:"bool",
    h:"Pushes after every Apply, brings any node that is behind up to date in the background, "+
      "and takes the newest configuration from the cluster when this node starts. Leave it off "+
      "to move configuration between nodes by hand."};
  const frm=document.createElement("div");frm.className="frm";
  fieldRow(f,(loc.sync||{}).auto_sync).forEach(el=>frm.appendChild(el));
  ob.appendChild(frm);
  const msg=document.createElement("div");msg.className="hint";msg.style.marginTop="12px";
  const foot=document.createElement("div");foot.style.marginTop="14px";
  foot.appendChild(btn("Save","pri",async()=>{
    try{await api("local","PUT",{sync:readForm([f])});msg.textContent="Saved.";}
    catch(e){msg.textContent=e.message;}
  }));
  foot.appendChild(document.createTextNode(" "));
  foot.appendChild(btn("Sync to all nodes now","warn",async()=>{
    msg.textContent="Pushing to every node...";
    try{
      const r=await api("sync/push","POST",{include_peers:true});
      msg.innerHTML=(r.results||[]).map(x=>esc(x.name)+": "+(x.ok?'<span class="pill up">ok</span>'
                                                              :'<span class="pill down">'+esc(x.error||"failed")+"</span>")).join("<br>")
                    ||esc(r.error||"done");
      if(r.warning)msg.innerHTML+='<div style="margin-top:8px">! '+esc(r.warning)+"</div>";
    }catch(e){msg.textContent=e.message;}
  }));
  foot.appendChild(document.createTextNode(" "));
  foot.appendChild(btn("Overwrite every node","dngr",async()=>{
    if(!confirm("Replace the configuration on every other node with this one's?\n\n"+
                "A node that was edited holds a newer configuration and normally refuses "+
                "this push. Overwriting discards those changes."))return;
    msg.textContent="Overwriting every node...";
    try{
      const r=await api("sync/push","POST",{include_peers:true,overwrite:true});
      msg.innerHTML=(r.results||[]).map(x=>esc(x.name)+": "+(x.ok?'<span class="pill up">ok</span>'
                                                              :'<span class="pill down">'+esc(x.error||"failed")+"</span>")).join("<br>")
                    ||esc(r.error||"done");
      if(r.ok)setTimeout(route,900);   /* the health on screen predates this */
    }catch(e){msg.textContent=e.message;}
  }));
  foot.appendChild(msg);
  ob.appendChild(foot);opt.appendChild(ob);frag.appendChild(opt);
  return frag;
}

/* A peer addressed by name costs a DNS lookup on every health check, and
   nothing caches it: glibc queries the resolver each time, and a resolver that
   does not answer costs 10s (timeout 5s, 2 attempts) per query -- with DNS
   often served by the very cluster being checked. */
export function isIpLiteral(host){
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host)||host.includes(":");
}
export function byNameHint(url){
  let host="";
  try{host=new URL(url).hostname;}catch(e){return "";}
  if(!host||isIpLiteral(host.replace(/^\[|\]$/g,"")))return "";
  return '<div class=sub title="DNS is not cached: every health check resolves this name again, '+
         'and an unresponsive resolver costs about 10 seconds each time.">addressed by name &mdash; '+
         'an IP address is steadier here</div>';
}

/* Health of every node, as seen from this one. */
export async function clusterCard(fresh){
  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>Cluster</h2><div class=sp></div></div>';
  const bd=document.createElement("div");
  let cl;
  try{cl=await api("cluster"+(fresh?"?fresh=1":""));}
  catch(e){bd.innerHTML='<div class="bd">'+esc(e.message)+"</div>";card.appendChild(bd);return card;}

  const s=cl.summary;
  const hd=card.querySelector(".hd");
  /* Health is collected in the background, so say how old it is rather than
     let it look live. Asking each node on page load put the slowest node's
     timeout in front of the user. */
  hd.insertAdjacentHTML("beforeend",
    '<span class=hint style="margin-right:10px">'+
      (cl.live?"just now":"as of "+esc(cl.age_seconds)+"s ago")+"</span>");
  const rb=btn("Refresh","sm ghost",async()=>{
    rb.disabled=true;rb.textContent="asking each node...";
    const fresh=await clusterCard(true);
    card.replaceWith(fresh);
  });
  hd.appendChild(rb);
  hd.insertAdjacentHTML("beforeend",
    '<span class="pill '+(s.reachable===s.total?"up":"down")+'">'+s.reachable+"/"+s.total+" reachable</span>");
  /* Reachable is not the same as up to date, and the difference is invisible
     until a node with an older configuration takes the virtual IP. */
  if(s.config_rev!==undefined&&cl.nodes.length>1)
    hd.insertAdjacentHTML("beforeend",
      '<span class="pill '+(s.config_agreed?"up":"warn")+'" title="Revision '+esc(s.config_rev)+
      '">'+(s.config_agreed?"configuration agreed":"configuration differs")+"</span>");
  if(cl.nodes.length===1&&!s.warnings.length){
    bd.innerHTML='<div class=empty>This is the only node. Add the others under '+
      'Advanced &rsaquo; Keepalived &rsaquo; Peer sync to see their health here.</div>';
    card.appendChild(bd);return card;
  }
  const pill=(v,good)=>'<span class="pill '+(good?"up":v==="disabled"?"off":"down")+'">'+esc(v||"—")+"</span>";
  bd.innerHTML="<table><thead><tr><th>Node</th><th>Role</th><th>HAProxy</th><th>Keepalived</th>"+
    "<th>Virtual IP</th><th>Configuration</th><th>Certificates</th><th>Version</th></tr></thead><tbody>"+
    cl.nodes.map(n=>{
      if(!n.reachable)return "<tr><td>"+esc(n.name)+(n.self?" <span class=sub>(this node)</span>":"")+
        '<div class=sub>'+esc(n.url)+"</div></td>"+
        '<td colspan=7><span class="pill down">unreachable</span> <span class=sub>'+esc(n.error||"")+"</span></td></tr>";
      return "<tr><td>"+esc(n.hostname||n.name)+(n.self?" <span class=sub>(this node)</span>":"")+
        (n.url?'<div class=sub>'+esc(n.url)+"</div>":"")+"</td>"+
        "<td>"+pill(n.role,n.role==="active"||n.role==="standalone")+
          (n.dirty?'<div class=sub style="color:var(--drift)">unapplied changes</div>':"")+"</td>"+
        "<td>"+pill(n.haproxy,n.haproxy==="active")+"</td>"+
        "<td>"+pill(n.keepalived,n.keepalived==="active")+"</td>"+
        "<td>"+(n.vip_held.length?'<span class=mono>'+n.vip_held.map(esc).join("<br>")+"</span>"
                                 :'<span class=sub>'+(n.vips.length?"held elsewhere":"none")+"</span>")+"</td>"+
        "<td>"+(n.config_fp
                 ?(n.config_rev<s.config_rev
                    ?'<span class="pill warn">behind</span><div class=sub>revision '+esc(n.config_rev)+
                     " of "+esc(s.config_rev)+"</div>"
                    :(s.config_agreed
                       ?'<span class="pill up">revision '+esc(n.config_rev)+"</span>"
                       :'<span class="pill warn">revision '+esc(n.config_rev)+'</span><div class=sub>'+
                        esc((n.config_fp||"").slice(0,8))+"</div>"))
                 :'<span class=sub>not reported</span>')+"</td>"+
        "<td>"+(n.certs_total?(n.certs_bad?'<span class="pill warn">'+n.certs_bad+" of "+n.certs_total+" need attention</span>"
                                          :'<span class="pill up">'+n.certs_total+" ok</span>")
                             :'<span class=sub>none</span>')+"</td>"+
        "<td class=mono>"+esc(n.version||"?")+(n.update_available?' <span class="pill warn">update</span>':"")+
          (n.ms?'<div class=sub>'+esc(n.ms)+" ms</div>":"")+"</td></tr>";
    }).join("")+"</tbody></table>";
  s.warnings.forEach(w=>{
    const el=document.createElement("div");el.className="hint";el.style.padding="8px 16px";
    el.innerHTML="! "+esc(w);bd.appendChild(el);
  });
  /* A node that took a configuration and then did not match it is the one
     case the comparison cannot explain from the outside, so it is called out
     above the table rather than left among the other warnings. */
  cl.nodes.filter(n=>n.config_leak).forEach(n=>{
    const el=document.createElement("div");el.className="hint";el.style.padding="8px 16px";
    el.innerHTML="! <b>"+esc(n.hostname||n.name)+"</b> took the configuration from "+
      esc(n.config_leak.source||"another node")+" and then did not match it ("+
      esc(n.config_leak.mine)+" here against "+esc(n.config_leak.theirs)+
      "). Something belonging to one node is inside the shared configuration; "+
      "the object named below is the one to look at.";
    bd.appendChild(el);
  });
  if(!s.config_agreed)bd.appendChild(configDiff(cl.nodes));
  card.appendChild(bd);return card;
}

/* What exactly the nodes disagree about.

   "They differ in haproxy.backends" is better than "they differ", and still
   leaves someone comparing two configurations by hand. This names the object:
   what is on one node and missing from another, and what exists everywhere
   under the same identity but with different contents. */
function configDiff(nodes){
  const wrap=document.createElement("div");wrap.style.padding="0 16px 12px";
  const have=nodes.filter(n=>n.reachable&&n.config_objects&&Object.keys(n.config_objects).length);
  if(have.length<2){
    wrap.innerHTML='<div class=sub>Not every node reports its objects in detail, so there is '+
      "nothing to compare one by one. That usually means they are not all on the same version.</div>";
    return wrap;
  }
  const label=n=>n.hostname||n.name;
  const rows=[];
  [...new Set(have.flatMap(n=>Object.keys(n.config_objects)))].sort().forEach(coll=>{
    const seen={};                       /* id -> {node -> [name, contents]} */
    have.forEach(n=>{
      (n.config_objects[coll]||[]).forEach(o=>{
        (seen[o[0]]=seen[o[0]]||{})[label(n)]=[o[1],o[2]];
      });
    });
    Object.keys(seen).forEach(id=>{
      const per=seen[id],on=Object.keys(per);
      const missing=have.map(label).filter(l=>on.indexOf(l)<0);
      const name=per[on[0]][0];
      if(missing.length){
        rows.push([coll,name,"only on "+on.join(", "),"missing from "+missing.join(", ")]);
      }else if(new Set(on.map(l=>per[l][1])).size>1){
        const groups={};
        on.forEach(l=>{(groups[per[l][1]]=groups[per[l][1]]||[]).push(l);});
        rows.push([coll,name,"different contents",
                   Object.keys(groups).map(k=>groups[k].join(" + ")).join("  vs  ")]);
      }
    });
  });
  /* Settings have no id, so they are compared whole rather than object by object. */
  const parts=have.filter(n=>n.config_parts&&Object.keys(n.config_parts).length);
  if(parts.length>1){
    [...new Set(parts.flatMap(n=>Object.keys(n.config_parts)))].sort()
      .filter(k=>k.indexOf(".settings")>0&&new Set(parts.map(n=>n.config_parts[k])).size>1)
      .forEach(k=>{
        const groups={};
        parts.forEach(n=>{(groups[n.config_parts[k]]=groups[n.config_parts[k]]||[]).push(label(n));});
        rows.push([k,"settings","different contents",
                   Object.keys(groups).map(x=>groups[x].join(" + ")).join("  vs  ")]);
      });
  }
  if(!rows.length){
    wrap.innerHTML='<div class=sub>Every shared object matches on every node. The health here is '+
      "collected in the background, so press Refresh; if it still says they differ, the nodes are "+
      "at different revisions rather than holding different things.</div>";
    return wrap;
  }
  wrap.innerHTML="<div class=fl style='margin-bottom:6px'>What differs</div>"+
    "<table><thead><tr><th>Where</th><th>Object</th><th>Problem</th><th>Nodes</th></tr></thead><tbody>"+
    rows.map(r=>"<tr><td class=mono>"+esc(r[0])+"</td><td>"+esc(r[1])+"</td><td>"+esc(r[2])+
                "</td><td class=sub>"+esc(r[3])+"</td></tr>").join("")+
    "</tbody></table><div class=sub style='margin-top:6px'>Apply from the node that is right, "+
    "or use Overwrite under Nodes to replace what is on the others.</div>";
  return wrap;
}

/* ---- keepalived diagnostics ---- */

export let kaIfaceOptions=[];
export async function loadKeepalivedDiag(){
  try{
    state.kaDiag=await api("keepalived/status");
    kaIfaceOptions=(state.kaDiag.interfaces||[]).filter(i=>i.name!=="lo")
      .map(i=>({value:i.name,label:i.name+(i.addresses.length?" ("+i.addresses.join(", ")+")":" (no address)")}));
  }catch(e){state.kaDiag=null;kaIfaceOptions=[];}
  return state.kaDiag;
}
export function keepalivedDiagCard(){
  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>This node right now</h2></div>';
  const bd=document.createElement("div");bd.className="bd";
  const d=state.kaDiag;
  /* The endpoint answers {ok:false,error} when it cannot inspect the node, and
     a card that assumes the full shape takes the whole Cluster page down with
     it. Say what went wrong instead. */
  if(!d||d.ok===false||!Array.isArray(d.vips)){
    bd.innerHTML='<p class=hint>Diagnostics are unavailable'+
      (d&&d.error?": "+esc(d.error):".")+'</p>';
    card.appendChild(bd);return card;
  }

  /* Name the fault outright rather than making it a reading exercise. */
  const problems=[];
  if(d.enabled){
    if(!d.interface_exists)
      problems.push("Interface <span class=mono>"+esc(d.interface||"(unset)")+"</span> does not exist on this node. "+
        "Available: <span class=mono>"+esc((d.interfaces||[]).map(i=>i.name).filter(n=>n!=="lo").join(", ")||"none")+
        "</span>. Keepalived exits with a config error when the interface is wrong, so no node takes the VIP.");
    if(d.validation&&d.validation.ran&&d.validation.ok===false)
      problems.push("Keepalived rejects the configuration this node would write, so Apply leaves "+
        "<span class=mono>"+esc(d.config_path)+"</span> untouched. See the output below.");
    if(!d.config_present)
      problems.push("<span class=mono>"+esc(d.config_path)+"</span> does not exist, so keepalived.service "+
        "never starts (its unit has ConditionFileNotEmpty). Fix the configuration above, then press Apply.");
    if(d.service!=="active"&&d.config_present)
      problems.push("keepalived.service is <b>"+esc(d.service)+"</b>.");
    if(!d.vips.length)
      problems.push("No virtual IP is configured, so there is nothing to take over.");
    if(d.service==="active"&&d.interface_exists&&d.vips.length&&!d.vip_held.length)
      problems.push("Keepalived is running but this node holds no VIP. If the peer holds it, this node is "+
        "correctly passive. If <b>neither</b> node holds it, the two are not seeing each other's VRRP: "+
        "check that every node uses the same virtual router ID, and that they list each other under "+
        "Other nodes -- unicast addresses are derived from that list.");
  }
  const pill=(v,good)=>'<span class="pill '+(good?"up":v==="disabled"?"off":"down")+'">'+esc(v)+"</span>";
  bd.innerHTML='<div class=grid style="margin-bottom:14px">'+
    '<div class=stat><div class=k>Keepalived</div><div class="v" style="font-size:13px">'+pill(d.service,d.service==="active")+"</div></div>"+
    '<div class=stat><div class=k>Interface</div><div class="v" style="font-size:13px">'+
      (d.interface?pill(d.interface,d.interface_exists):'<span class="pill off">unset</span>')+"</div></div>"+
    '<div class=stat><div class=k>VRRP state</div><div class="v" style="font-size:13px">'+
      (d.vrrp_state?pill(d.vrrp_state,d.vrrp_state==="MASTER"):'<span class="pill off">unknown</span>')+
      /* Where the state came from: read from the log, or worked out from what
         the node is actually doing. Worth showing, because only the log can
         tell FAULT apart from BACKUP. */
      (d.vrrp_state_source&&d.vrrp_state_source!=="journal"
        ?'<div class=sub style="margin-top:3px">'+esc(d.vrrp_state_source)+"</div>":"")+
      "</div></div>"+
    '<div class=stat><div class=k>Virtual IPs held</div><div class="v" style="font-size:13px">'+
      (d.vips.length?d.vips.map(v=>esc(v)+(d.vip_held.includes(v)?' <span class="pill up">here</span>'
                                                                 :' <span class="pill off">elsewhere</span>')).join("<br>")
                    :'<span class=sub>none configured</span>')+"</div></div>"+
    '<div class=stat><div class=k>Config file</div><div class="v" style="font-size:13px">'+
      (d.config_present?'<span class="pill up">written</span>':'<span class="pill down">missing</span>')+"</div></div>"+
    '<div class=stat><div class=k>VRID / priority</div><div class=v style="font-size:13px">'+
      esc(d.vrid)+" / "+esc(d.priority)+"</div></div></div>";
  problems.forEach(p=>{
    const el=document.createElement("div");el.className="hint";el.style.marginBottom="8px";
    el.innerHTML="! "+p;bd.appendChild(el);
  });
  if(!problems.length&&d.enabled){
    const el=document.createElement("div");el.className="hint";
    el.textContent=d.vip_held.length?"This node holds the virtual IP: it is the active one."
                                    :"Nothing looks wrong here.";
    bd.appendChild(el);
  }
  const uni=document.createElement("div");uni.className="hint";uni.style.marginBottom="10px";
  uni.innerHTML=(d.unicast_peer&&d.unicast_peer.length)
    ? "VRRP transport: <b>unicast</b> from <span class=mono>"+esc(d.unicast_src||"the interface address")+
      "</span> to <span class=mono>"+d.unicast_peer.map(esc).join("</span>, <span class=mono>")+
      "</span>. Managed automatically from the node list -- there is nothing to set."
    : "VRRP transport: <b>multicast</b>. Add the other nodes under Other nodes and press Apply, and "+
      "this node switches to unicast automatically, which is what most networks need.";
  bd.appendChild(uni);
  const row=document.createElement("div");row.style.marginTop="14px";
  row.appendChild(btn("Refresh addresses from the other nodes","sm",async()=>{
    uni.textContent="Asking each node for the address on its VRRP interface...";
    try{
      const r=await api("cluster/unicast/apply","POST",{});
      uni.innerHTML=(r.steps||[]).map(x=>"&#10003; "+esc(x)).join("<br>")+
        (r.warnings||[]).map(w=>'<div style="margin-top:6px">! '+esc(w)+"</div>").join("")+
        (r.error?'<div style="margin-top:6px">! '+esc(r.error)+"</div>":"")+
        (r.note?'<div style="margin-top:6px">'+esc(r.note)+"</div>":"");
    }catch(e){uni.textContent=e.message;}
  }));
  row.appendChild(document.createTextNode(" "));
  if(d.validation&&d.validation.output)
    row.appendChild(btn("Show keepalived -t output","sm",()=>showText("keepalived -t",d.validation.output)));
  if(d.log){
    row.appendChild(document.createTextNode(" "));
    row.appendChild(btn("Show the keepalived log","sm",()=>showText("journalctl -u keepalived",d.log)));
  }
  row.appendChild(document.createTextNode(" "));
  row.appendChild(btn("Refresh","sm",async()=>{await loadKeepalivedDiag();route();}));
  bd.appendChild(row);card.appendChild(bd);return card;
}
