import { $, api, btn, closeDlg, esc, fieldRow, openDlg, readForm } from "../core.js";

/* ---- notifications ---- */
export const NOTIFY_TYPES={
  smtp:{label:"Email (SMTP)",fields:[
    {k:"host",l:"Server",t:"text",h:"e.g. smtp.gmail.com"},
    {k:"port",l:"Port",t:"text",h:"587 for STARTTLS, 465 for SSL, 25 for none"},
    {k:"security",l:"Encryption",t:"select",d:"starttls",o:["starttls","ssl","none"]},
    {k:"username",l:"Username",t:"text",h:"leave empty if the server needs no login"},
    {k:"password",l:"Password",t:"password",h:"leave blank to keep the stored one"},
    {k:"from",l:"From",t:"text",h:"e.g. haproxy@example.com"},
    {k:"to",l:"To",t:"text",h:"one or more addresses, separated by commas"}]},
  pushover:{label:"Pushover",fields:[
    {k:"token",l:"Application token",t:"password",h:"from your Pushover application -- blank keeps the stored one"},
    {k:"user",l:"User or group key",t:"password",h:"blank keeps the stored one"},
    {k:"device",l:"Device",t:"text",h:"optional -- leave empty for all your devices"}]},
  webhook:{label:"Webhook (JSON POST)",fields:[
    {k:"url",l:"URL",t:"text",h:"receives {subject, message, severity, event, node, time}"},
    {k:"headers",l:"Extra headers",t:"textarea",h:"one per line, e.g. Authorization: Bearer xyz"},
    {k:"verify_tls",l:"Verify TLS",t:"bool",d:true}]},
};
export async function renderNotify(){
  const c=$("#content");c.innerHTML="";
  let n;
  try{n=await api("notify");}
  catch(e){c.innerHTML='<div class="card"><div class="bd">'+esc(e.message)+"</div></div>";return;}
  const st=n.settings||{};
  let dests=(st.destinations||[]).map(d=>Object.assign({},d));

  /* --- when to send --- */
  const w=document.createElement("div");w.className="card";
  w.innerHTML='<div class=hd><h2>Notifications</h2><div class=sp></div>'+
    '<span class="pill '+(st.enabled?"up":"off")+'">'+(st.enabled?"on":"off")+"</span></div>";
  const wb=document.createElement("div");wb.className="bd";
  const WHEN=[
   {k:"enabled",l:"Send notifications",t:"bool"},
   {k:"min_severity",l:"Only at or above",t:"select",d:"warning",
    o:[{value:"info",label:"info -- including recoveries and new versions"},
       {value:"warning",label:"warning -- something was repaired"},
       {value:"error",label:"error -- something is broken"}]},
   {k:"repeat_hours",l:"Repeat an unresolved problem after (hours)",t:"text",
    h:"a problem is announced when it starts, then repeated this often until it clears. "+
      "The message saying it has cleared is always sent, whatever the severity above says -- "+
      "being told what broke and never that it came back is worse than not being told."},
  ];
  const wfrm=document.createElement("div");wfrm.className="frm";
  WHEN.forEach(f=>fieldRow(f,st[f.k]).forEach(el=>wfrm.appendChild(el)));
  wb.appendChild(wfrm);
  const ev=st.events||{};
  const EVENTS=[["certificates","Certificates issued, renewed or failed"],
                ["service","A published service loses servers, or gets them back"],
                ["watchdog","Services restarted, or beyond repair"],
                ["apply","Apply refused, or HAProxy did not reload"],
                ["cluster","A node stops answering, or split brain"],
                ["updates","A new version is published"]];
  const evWrap=document.createElement("div");
  evWrap.innerHTML='<div class=fl style="margin-top:6px">Tell me about</div>';
  EVENTS.forEach(([k,l])=>{
    const row=document.createElement("label");
    row.className="ckbox";row.style.cssText="display:flex;gap:8px;align-items:center;margin:3px 0";
    row.innerHTML='<input type=checkbox data-event="'+k+'"'+(ev[k]!==false?" checked":"")+
      "><span>"+esc(l)+"</span>";
    evWrap.appendChild(row);
  });
  wb.appendChild(evWrap);
  w.appendChild(wb);
  const wf=document.createElement("div");wf.className="bd";
  wf.style.cssText="border-top:1px solid var(--hair);display:flex;gap:8px;align-items:center";
  const wnote=document.createElement("span");wnote.className="hint";
  const save=async(extra,msg)=>{
    const body=readForm(WHEN);
    body.events={};
    evWrap.querySelectorAll("input[data-event]").forEach(b=>{body.events[b.dataset.event]=b.checked;});
    body.destinations=dests;
    Object.assign(body,extra||{});
    await api("notify","PUT",body);
    wnote.textContent=msg||"Saved.";
  };
  wf.appendChild(btn("Save","primary",async()=>{
    wnote.textContent="saving...";
    try{await save();renderNotify();}catch(e){wnote.textContent=e.message;}
  }));
  wf.appendChild(wnote);
  w.appendChild(wf);
  c.appendChild(w);

  /* --- where to send --- */
  const dc=document.createElement("div");dc.className="card";
  dc.innerHTML='<div class=hd><h2>Destinations</h2><div class=sp></div></div>';
  const tbl=document.createElement("div");
  const draw=()=>{
    tbl.innerHTML="";
    if(!dests.length){
      tbl.innerHTML='<div class=empty>Nowhere to send yet. Add a destination below, '+
        "then use Test to prove it works before you need it.</div>";
      return;
    }
    const t=document.createElement("table");
    t.innerHTML="<thead><tr><th>Name</th><th>Type</th><th>Where</th><th>On</th><th></th></tr></thead>";
    const tb=document.createElement("tbody");
    dests.forEach((d,i)=>{
      const tr=document.createElement("tr");
      const where=d.type==="smtp"?(d.to||"")+" via "+(d.host||"")
        :d.type==="webhook"?(d.url||"")
        :(d.has_token?"token set":"no token")+", "+(d.has_user?"user key set":"no user key");
      tr.innerHTML="<td>"+esc(d.name||"—")+"</td><td>"+esc((NOTIFY_TYPES[d.type]||{}).label||d.type)+"</td>"+
        "<td class=mono style=font-size:12px>"+esc(where)+"</td>"+
        "<td>"+(d.enabled===false?'<span class="pill off">no</span>':"yes")+"</td>";
      const act=document.createElement("td");act.style.cssText="text-align:right;white-space:nowrap";
      const out=document.createElement("div");out.className="sub";
      out.style.cssText="text-align:right;margin-bottom:4px";
      act.appendChild(out);
      act.appendChild(btn("Test","sm",async()=>{
        if(!d.id){out.textContent="save it first";return;}
        out.textContent="sending...";
        try{const r=await api("notify/test","POST",{id:d.id});
          out.innerHTML=r.ok?'<span style="color:var(--up)">'+esc(r.message)+"</span>"
                            :'<span style="color:var(--down)">'+esc(r.error)+"</span>";}
        catch(e){out.innerHTML='<span style="color:var(--down)">'+esc(e.message)+"</span>";}
      }));
      act.appendChild(btn("Edit","sm",()=>editDest(i)));
      act.appendChild(btn("Remove","sm danger",async()=>{
        dests.splice(i,1);await save(null,"Removed.");renderNotify();
      }));
      tr.appendChild(act);tb.appendChild(tr);
    });
    t.appendChild(tb);tbl.appendChild(t);
  };
  const editDest=(idx)=>{
    const d=idx===null?{type:"smtp",enabled:true,security:"starttls",port:"587"}:dests[idx];
    const body=document.createElement("div");
    const common=[{k:"name",l:"Name",t:"text",h:"how it appears in this list"},
                  {k:"enabled",l:"Enabled",t:"bool",d:true}];
    body.className="frm";
    common.forEach(f=>fieldRow(f,d[f.k]).forEach(el=>body.appendChild(el)));
    /* Keep the element rather than looking it up later: nothing here is in the
       document until openDlg runs, so a lookup by id finds nothing. */
    const typeCells=fieldRow({k:"type",l:"Type",t:"select",d:d.type,
              o:Object.keys(NOTIFY_TYPES).map(k=>({value:k,label:NOTIFY_TYPES[k].label}))},
             d.type);
    typeCells.forEach(el=>body.appendChild(el));
    const typeSel=typeCells[1].querySelector("select");
    // The type-specific fields are replaced when the type changes, so they get
    // their own grid rather than being spliced into this one.
    const holder=document.createElement("div");holder.className="frm";
    holder.style.gridColumn="1 / -1";
    body.appendChild(holder);
    const paint=(type)=>{
      holder.innerHTML="";
      (NOTIFY_TYPES[type]||{fields:[]}).fields
        .forEach(f=>fieldRow(f,d[f.k]).forEach(el=>holder.appendChild(el)));
    };
    paint(d.type);
    typeSel.onchange=e=>paint(e.target.value);
    const err=document.createElement("span");err.className="err";
    openDlg(idx===null?"Add a destination":"Edit destination",body,[err,
      btn("Cancel","",closeDlg),
      btn("Save","primary",async()=>{
        try{
          const vals=readForm(common.concat([{k:"type",t:"select"}])
                              .concat(NOTIFY_TYPES[typeSel.value].fields));
          const merged=Object.assign({},d,vals);
          if(idx===null)dests.push(merged); else dests[idx]=merged;
          await save(null,"Saved.");
          closeDlg();renderNotify();
        }catch(e){err.textContent=e.message;}
      })]);
  };
  draw();
  dc.appendChild(tbl);
  const df=document.createElement("div");df.className="bd";
  df.style.cssText="border-top:1px solid var(--hair)";
  df.appendChild(btn("Add a destination","primary",()=>editDest(null)));
  dc.appendChild(df);
  c.appendChild(dc);

  /* --- what has been sent --- */
  const rc=document.createElement("div");rc.className="card";
  rc.innerHTML='<div class=hd><h2>Recent attempts</h2></div>'+
    ((n.recent||[]).length
      ? "<table><thead><tr><th>When</th><th>Destination</th><th>Result</th></tr></thead><tbody>"+
        n.recent.map(r=>"<tr><td class=mono style=white-space:nowrap>"+esc(r.time)+"</td>"+
          "<td>"+esc(r.destination)+"</td><td"+(r.ok?"":' style="color:var(--down)"')+">"+
          esc(r.ok?"sent":r.detail)+"</td></tr>").join("")+"</tbody></table>"
      : '<div class=empty>Nothing has been sent yet.</div>');
  c.appendChild(rc);
}
