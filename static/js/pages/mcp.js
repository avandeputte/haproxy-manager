import { $, api, btn, esc, fieldRow, localTime, pageGuard, readForm } from "../core.js";
import { t } from "../i18n.js";

/* ---- MCP server ----
   An assistant (Claude Code, Claude Desktop, any MCP client) gets this node's
   tools at /mcp with a token of its own. Off, and read-only, until turned on
   here. The token is shown once, when it is made: only its hash is kept. */
const FIELDS=[
 {k:"enabled",l:"Answer MCP clients at /mcp",t:"bool"},
 {k:"allow_writes",l:"Allow changes",t:"bool",
  h:"Off: an assistant can read everything and try changes as a dry run. On: it can also publish, edit and delete services, rules and objects, and Apply. Each change is in the log under the client's name."},
];

function pushNote(pushed){
  const bad=(pushed||[]).filter(p=>!p.ok);
  if(!(pushed||[]).length)return "";
  return bad.length
    ? t("Not copied to {nodes}: change it there too, or save again once they answer.",
        {nodes:bad.map(p=>p.name+" ("+p.error+")").join(", ")})
    : t("Copied to the other nodes.");
}

export async function renderMcp(){
  const c=$("#content");
  const fresh=pageGuard();
  let s;
  try{s=await api("mcp");}
  catch(e){if(fresh())c.innerHTML='<div class="card"><div class="bd">'+esc(e.message)+"</div></div>";return;}
  if(!fresh())return;
  c.innerHTML="";
  const endpoint=location.origin+"/mcp";

  /* --- on, off, read-only --- */
  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>'+t("MCP server")+'</h2><div class=sp></div>'+
    '<span class="pill '+(s.enabled?"up":"off")+'">'+(s.enabled?(s.allow_writes?t("on, changes allowed"):t("on, read-only")):t("off"))+"</span></div>"+
    '<div class=bd><div class=hint>'+
    t("Lets an AI assistant -- Claude Code, Claude Desktop or any MCP client -- read this node and, when allowed, change it, through the same checks as this UI: nothing is stored that HAProxy would not load, and nothing goes live until Apply.")+
    "</div><div class=hint style=margin-top:6px>"+
    t("In a cluster these settings and the token are the same on every node. Point the client at the virtual IP or this UI's public name, so it reaches whichever node is active; a change asked of a passive node is made on the active one.")+
    "</div></div>";
  const b=document.createElement("div");b.className="bd";
  const frm=document.createElement("div");frm.className="frm";
  FIELDS.forEach(f=>fieldRow(f,s[f.k]).forEach(el=>frm.appendChild(el)));
  b.appendChild(frm);card.appendChild(b);
  const foot=document.createElement("div");foot.className="bd";
  foot.style.cssText="display:flex;gap:8px;align-items:center;border-top:1px solid var(--hair)";
  const note=document.createElement("span");note.className="hint";
  foot.appendChild(btn(t("Save"),"pri",async()=>{
    note.textContent=t("saving...");
    try{const r=await api("mcp","PUT",readForm(FIELDS));await renderMcp();
        const n=$("#mcp_note");if(n)n.textContent=t("Saved.")+" "+pushNote(r.pushed);}
    catch(e){note.textContent=e.message;}
  }));
  note.id="mcp_note";
  foot.appendChild(note);card.appendChild(foot);
  c.appendChild(card);

  /* --- the token, and how to connect --- */
  const tc=document.createElement("div");tc.className="card";
  tc.innerHTML='<div class=hd><h2>'+t("Token")+"</h2></div>";
  const tb=document.createElement("div");tb.className="bd";
  tb.innerHTML='<div class=hint>'+(s.has_token
    ? t("A token is set (fingerprint {fp}, made {when}). It is not shown again; replace it if it is lost.",
        {fp:'<span class=mono>'+esc(s.token_fp)+"</span>",when:esc(localTime(s.token_created))})
    : t("No token yet. Make one, then give it to the client."))+"</div>";
  const out=document.createElement("div");out.id="mcp_token";
  const bar=document.createElement("div");bar.style.marginTop="10px";
  bar.appendChild(btn(s.has_token?t("Replace the token"):t("Make a token"),"",async()=>{
    if(s.has_token&&!confirm(t("Replace the token?\n\nEvery client using the current one stops working until it is given the new one.")))return;
    try{
      const r=await api("mcp/token","POST",{});
      const cmd='claude mcp add --transport http haproxy-manager '+endpoint+' --header "Authorization: Bearer '+r.token+'"';
      out.innerHTML='<div class=hint style="margin-top:12px"><b>'+t("Copy it now: it is not shown again.")+"</b> "+esc(pushNote(r.pushed))+"</div>"+
        '<div class=fl style=margin-top:8px>'+t("Token")+'</div><pre class=mono id=mcp_tok>'+esc(r.token)+"</pre>"+
        '<div class=fl style=margin-top:8px>'+t("Claude Code")+'</div><pre class=mono id=mcp_cmd>'+esc(cmd)+"</pre>"+
        '<div class=hint>'+t("Any other client: the address {url}, with the header Authorization: Bearer and the token.",
          {url:'<span class=mono>'+esc(endpoint)+"</span>"})+"</div>";
    }catch(e){out.textContent=e.message;}
  }));
  tb.appendChild(bar);tb.appendChild(out);tc.appendChild(tb);
  c.appendChild(tc);

  /* --- what it offers --- */
  const tl=document.createElement("div");tl.className="card";
  tl.innerHTML='<div class=hd><h2>'+t("Tools")+"</h2></div>"+
    "<table><thead><tr><th>"+t("Tool")+"</th><th>"+t("What it does")+"</th><th>"+t("Kind")+"</th></tr></thead><tbody>"+
    (s.tools||[]).map(x=>"<tr><td class=mono>"+esc(x.name)+"</td><td>"+esc(x.title)+"</td><td>"+
      '<span class="pill '+(x.write?"warn":"up")+'">'+(x.write?t("changes"):t("reads"))+"</span></td></tr>").join("")+
    "</tbody></table>";
  c.appendChild(tl);
}
