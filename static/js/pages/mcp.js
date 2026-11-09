import { $, api, btn, esc, fieldRow, localTime, pageGuard, readForm, selectOption } from "../core.js";
import { t } from "../i18n.js";

/* ---- MCP server ----
   An assistant (Claude Code, Codex, Antigravity, any MCP client) gets this
   node's tools at /mcp with a token of its own. Off, and read-only, until
   turned on here. The token can be shown again to set up the next client;
   the tools themselves are described on the documentation site. */
const FIELDS=[
 {k:"enabled",l:"Answer MCP clients at /mcp",t:"bool"},
 {k:"allow_writes",l:"Allow changes",t:"bool",
  h:"Off: an assistant can read everything and try changes as a dry run. On: it can also publish, edit and delete services, rules and objects, and Apply. Each change is in the log under the client's name."},
];
const DOCS="https://ham.iothing.net/docs/mcp/";
const NAME="haproxy-manager";
const HIDDEN="<token>";

/* How each client is given the address and the token, as its own
   documentation has it. run: a command; file: where the text goes and the
   program to restart after. */
const json=o=>JSON.stringify(o,null,2);
const servers=(key,entry)=>json({[key]:{[NAME]:entry}});
export const CLIENTS=[
 {id:"claude-code",name:"Claude Code",run:true,
  h:"Every Claude Code session started after this has the tools, whatever folder it starts in.",
  text:(u,k)=>`claude mcp add --scope user --transport http ${NAME} ${u} --header "Authorization: Bearer ${k}"`},
 {id:"claude-desktop",name:"Claude Desktop",
  file:"claude_desktop_config.json (Settings › Developer › Edit Config)",app:"Claude Desktop",
  h:"It connects through mcp-remote, a small bridge run with npx, so Node.js 18 or later is needed.",
  text:(u,k)=>servers("mcpServers",{command:"npx",
    args:"-y mcp-remote".split(" ").concat(u,"--header","Authorization:${AUTH_HEADER}"),
    env:{AUTH_HEADER:"Bearer "+k}})},
 {id:"codex",name:"OpenAI Codex",file:"~/.codex/config.toml",app:"Codex",
  h:"The CLI, the IDE extension and the app all read this file.",
  text:(u,k)=>`[mcp_servers.${NAME}]\nurl = "${u}"\nhttp_headers = { "Authorization" = "Bearer ${k}" }`},
 {id:"antigravity",name:"Google Antigravity",
  file:"~/.gemini/config/mcp_config.json (MCP Servers › Manage MCP Servers › View raw config)",app:"Antigravity",
  text:(u,k)=>servers("mcpServers",{serverUrl:u,headers:{Authorization:"Bearer "+k}})},
 {id:"gemini",name:"Gemini CLI",run:true,
  text:(u,k)=>`gemini mcp add -s user --transport http --header "Authorization: Bearer ${k}" ${NAME} ${u}`},
 {id:"openclaw",name:"OpenClaw",file:"~/.openclaw/openclaw.json",app:"the OpenClaw gateway",
  text:(u,k)=>json({mcp:{servers:{[NAME]:{url:u,transport:"streamable-http",headers:{Authorization:"Bearer "+k}}}}})},
 {id:"cursor",name:"Cursor",file:"~/.cursor/mcp.json",app:"Cursor",
  text:(u,k)=>servers("mcpServers",{url:u,headers:{Authorization:"Bearer "+k}})},
 {id:"vscode",name:"VS Code (Copilot)",file:"mcp.json (MCP: Open User Configuration)",app:"VS Code",
  text:(u,k)=>servers("servers",{type:"http",url:u,headers:{Authorization:"Bearer "+k}})},
 {id:"copilot-cli",name:"GitHub Copilot CLI",run:true,
  text:(u,k)=>`copilot mcp add --transport http --header "Authorization: Bearer ${k}" ${NAME} ${u}`},
 {id:"devin",name:"Devin Desktop (Windsurf)",file:"~/.config/devin/mcp_config.json",app:"Devin Desktop",
  text:(u,k)=>servers("mcpServers",{url:u,headers:{Authorization:"Bearer "+k}})},
 {id:"zed",name:"Zed",file:"settings.json (zed: open settings)",app:"Zed",
  text:(u,k)=>servers("context_servers",{url:u,headers:{Authorization:"Bearer "+k}})},
 {id:"cline",name:"Cline",run:true,
  text:(u,k)=>`cline mcp add ${NAME} ${u} --transport http --header "Authorization: Bearer ${k}" --yes`},
 {id:"opencode",name:"opencode",run:true,
  text:(u,k)=>`opencode mcp add ${NAME} --global --url ${u} --header 'Authorization=Bearer ${k}'`},
 {id:"other",name:"Another client",
  h:"Any client that can send a header with a streamable HTTP server. ChatGPT and claude.ai's connectors sign in with OAuth only, which this server does not offer.",
  text:(u,k)=>`URL:     ${u}\nHeader:  Authorization: Bearer ${k}`},
];

function pushNote(pushed){
  const bad=(pushed||[]).filter(p=>!p.ok);
  if(!(pushed||[]).length)return "";
  return bad.length
    ? t("Not copied to {nodes}: change it there too, or save again once they answer.",
        {nodes:bad.map(p=>p.name+" ("+p.error+")").join(", ")})
    : t("Copied to the other nodes.");
}

/* the clipboard needs a secure context; without one, select the text */
async function copyText(text,pre,note){
  try{await navigator.clipboard.writeText(text);note.textContent=t("copied");}
  catch(e){
    const r=document.createRange();r.selectNodeContents(pre);
    const s=window.getSelection();s.removeAllRanges();s.addRange(r);
    note.textContent=t("selected -- press {key}+C",{key:navigator.platform.indexOf("Mac")>=0?"Cmd":"Ctrl"});
  }
  setTimeout(()=>{note.textContent="";},4000);
}

let lastClient="claude-code";

export async function renderMcp(fresh_token){
  const c=$("#content");
  const fresh=pageGuard();
  let s;
  try{s=await api("mcp");}
  catch(e){if(fresh())c.innerHTML='<div class="card"><div class="bd">'+esc(e.message)+"</div></div>";return;}
  if(!fresh())return;
  c.innerHTML="";
  const endpoint=location.origin+"/mcp";
  let token=fresh_token||"";          // filled in once shown, until the page is left

  /* --- on, off, read-only --- */
  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>'+t("MCP server")+'</h2><div class=sp></div>'+
    '<span class="pill '+(s.enabled?"up":"off")+'">'+(s.enabled?(s.allow_writes?t("on, changes allowed"):t("on, read-only")):t("off"))+"</span></div>"+
    '<div class=bd><div class=hint>'+
    t("Lets an AI assistant -- Claude Code, Codex, Antigravity or any MCP client -- read this node and, when allowed, change it, through the same checks as this UI: nothing is stored that HAProxy would not load, and nothing goes live until Apply.")+
    "</div><div class=hint style=margin-top:6px>"+
    t("In a cluster these settings and the token are the same on every node. Point the client at the virtual IP or this UI's public name, so it reaches whichever node is active; a change asked of a passive node is made on the active one.")+
    "</div><div class=hint style=margin-top:6px>"+
    t("What the tools do, and examples of asking for them: {link}.",
      {link:'<a href="'+DOCS+'" target=_blank rel=noopener>'+t("MCP server in the documentation")+"</a>"})+
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
    try{const r=await api("mcp","PUT",readForm(FIELDS));await renderMcp(token);
        const n=$("#mcp_note");if(n)n.textContent=t("Saved.")+" "+pushNote(r.pushed);}
    catch(e){note.textContent=e.message;}
  }));
  note.id="mcp_note";
  foot.appendChild(note);card.appendChild(foot);
  c.appendChild(card);

  /* --- the token --- */
  const tc=document.createElement("div");tc.className="card";
  tc.innerHTML='<div class=hd><h2>'+t("Token")+"</h2></div>";
  const tb=document.createElement("div");tb.className="bd";
  const status=document.createElement("div");status.className="hint";
  status.innerHTML=!s.has_token
    ? t("No token yet. Make one, then give it to the client.")
    : t("A token is set (fingerprint {fp}, made {when}).",
        {fp:'<span class=mono>'+esc(s.token_fp)+"</span>",when:esc(localTime(s.token_created))})+
      (s.token_shown?"":" "+t("It was made before tokens were kept, so it cannot be shown. Replace it to get one that can."));
  tb.appendChild(status);
  const tokPre=document.createElement("pre");tokPre.className="mono";tokPre.id="mcp_tok";
  tokPre.style.display=token?"":"none";tokPre.textContent=token;
  const bar=document.createElement("div");bar.style.cssText="margin-top:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap";
  const tnote=document.createElement("span");tnote.className="hint";
  const show=async()=>{
    if(!token){const r=await api("mcp/token");token=r.token;}
    return token;
  };
  if(s.has_token&&s.token_shown){
    const toggle=btn(token?t("Hide the token"):t("Show the token"),"",async()=>{
      try{
        if(tokPre.style.display==="none"){await show();tokPre.textContent=token;tokPre.style.display="";toggle.textContent=t("Hide the token");}
        else{tokPre.style.display="none";toggle.textContent=t("Show the token");}
        drawClient();
      }catch(e){tnote.textContent=e.message;}
    });
    bar.appendChild(toggle);
    bar.appendChild(btn(t("Copy"),"",async()=>{
      try{await show();await copyText(token,tokPre,tnote);}catch(e){tnote.textContent=e.message;}
    }));
  }
  bar.appendChild(btn(s.has_token?t("Replace the token"):t("Make a token"),"",async()=>{
    if(s.has_token&&!confirm(t("Replace the token?\n\nEvery client using the current one stops working until it is given the new one.")))return;
    try{
      const r=await api("mcp/token","POST",{});
      await renderMcp(r.token);
      const n=$("#mcp_tnote");if(n)n.textContent=pushNote(r.pushed);
    }catch(e){tnote.textContent=e.message;}
  }));
  tnote.id="mcp_tnote";
  bar.appendChild(tnote);
  tb.appendChild(bar);tb.appendChild(tokPre);tc.appendChild(tb);
  c.appendChild(tc);

  /* --- connecting a client --- */
  const cc=document.createElement("div");cc.className="card";
  cc.innerHTML='<div class=hd><h2>'+t("Connect a client")+"</h2></div>";
  const cb=document.createElement("div");cb.className="bd";
  const pick=document.createElement("select");pick.id="mcp_client";
  CLIENTS.forEach(x=>{const o=document.createElement("option");o.value=x.id;o.textContent=x.name;pick.appendChild(o);});
  selectOption(pick,lastClient);
  const how=document.createElement("div");how.className="hint";how.style.margin="10px 0 6px";
  const pre=document.createElement("pre");pre.className="mono";pre.id="mcp_cmd";pre.style.whiteSpace="pre-wrap";
  const cbar=document.createElement("div");cbar.style.cssText="display:flex;gap:8px;align-items:center";
  const cnote=document.createElement("span");cnote.className="hint";
  const warn=document.createElement("div");warn.className="hint";warn.style.marginTop="8px";
  const client=()=>CLIENTS.find(x=>x.id===(([...pick.options].find(o=>o.selected)||{}).value))||CLIENTS[0];
  function drawClient(){
    const x=client();lastClient=x.id;
    const shown=tokPre.style.display!=="none"&&token;
    how.innerHTML=(x.run?t("Run this in a terminal."):x.file
        ?t("Add this to {file}, merged with what is already there, then restart {app}.",
           {file:'<span class=mono>'+esc(x.file)+"</span>",app:esc(x.app)}):"")+
      (x.h?" "+t(x.h):"");
    pre.textContent=x.text(endpoint,shown?token:HIDDEN);
    warn.textContent=!s.has_token?t("Make a token first."):
      shown?t("The token is in this text: keep it out of repositories, screenshots and shared files.")
           :t("Show the token to fill it in, or copy: the copy has the token in it.");
  }
  pick.onchange=drawClient;
  if(s.has_token&&s.token_shown)
    cbar.appendChild(btn(t("Copy"),"",async()=>{
      try{await show();await copyText(client().text(endpoint,token),pre,cnote);}catch(e){cnote.textContent=e.message;}
    }));
  cbar.appendChild(cnote);
  cb.appendChild(pick);cb.appendChild(how);cb.appendChild(pre);cb.appendChild(cbar);cb.appendChild(warn);
  cc.appendChild(cb);c.appendChild(cc);
  drawClient();
}
