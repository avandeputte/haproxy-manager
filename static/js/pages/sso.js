/* Single sign-on: the OIDC provider services can send their visitors to. */
import { $, api, btn, esc, fieldRow, readForm } from "../core.js";

export async function renderSso(){
  const c=$("#content");c.innerHTML="";
  let s;
  try{s=await api("access/oauth");}
  catch(e){c.innerHTML='<div class="card"><div class="bd">'+esc(e.message)+"</div></div>";return;}

  const card=document.createElement("div");card.className="card";
  card.innerHTML='<div class=hd><h2>Single sign-on (OIDC)</h2><div class=sp></div>'+
    '<span class="pill '+(s.enabled?"up":"off")+'">'+(s.enabled?"on":"off")+"</span></div>";
  const bd=document.createElement("div");bd.className="bd";
  bd.innerHTML='<p class=hint style="margin-bottom:14px">Services can require a sign-in through '+
    "an OpenID Connect provider -- Authentik, Keycloak, Authelia, Pocket ID, Google, Entra. "+
    "One sign-in covers every protected service: HAProxy itself verifies the session cookie and "+
    "each service's allow-list on every request, on whichever node is active. Turn it on per "+
    "service in the publish wizard.</p>"+
    (s.redirect_uri?'<p class=hint style="margin-bottom:14px">Register this redirect URI at the '+
    'provider: <span class=mono>'+esc(s.redirect_uri)+"</span></p>":"");
  const FIELDS=[
   {k:"enabled",l:"Enable single sign-on",t:"bool"},
   {k:"issuer",l:"Issuer URL",t:"text",
    h:"The provider's issuer, e.g. https://auth.example.net/application/o/services/ for "+
      "Authentik. Its /.well-known/openid-configuration is read from here."},
   {k:"client_id",l:"Client ID",t:"text"},
   {k:"client_secret",l:"Client secret",t:"password",
    h:s.has_client_secret?"Leave empty to keep the stored one":"From the provider's client registration"},
   {k:"auth_host",l:"Sign-in host",t:"text",
    h:"A name for the sign-in itself, e.g. auth.example.com. Point its DNS at the virtual IP; "+
      "HAProxy routes it to this app. It needs a certificate on the HTTPS listener -- "+
      "a wildcard that covers it is enough."},
   {k:"cookie_domain",l:"Cookie domain",t:"text",
    h:"The domain the session covers, e.g. example.com -- every protected service and the "+
      "sign-in host must sit under it. Never a public suffix like com or co.uk: browsers "+
      "refuse such cookies outright."},
   {k:"scopes",l:"Scopes",t:"text",d:"openid email profile"},
   {k:"session_hours",l:"Session length (hours)",t:"number",d:12,
    h:"How long a sign-in lasts. There is no revocation for a single session -- "+
      "rotating the secret below is the kill switch, and it signs everyone out."},
  ];
  const frm=document.createElement("div");frm.className="frm";
  FIELDS.forEach(f=>fieldRow(f,s[f.k]).forEach(el=>frm.appendChild(el)));
  bd.appendChild(frm);
  const note=document.createElement("span");note.className="hint";note.style.marginLeft="10px";
  const foot=document.createElement("div");foot.style.marginTop="16px";
  foot.appendChild(btn("Save","pri",async()=>{
    note.textContent="saving...";
    try{
      await api("access/oauth","PUT",readForm(FIELDS));
      note.textContent="Saved.";
      renderSso();
    }catch(e){note.textContent=e.message;}
  }));
  foot.appendChild(document.createTextNode(" "));
  foot.appendChild(btn("Test","",async()=>{
    note.textContent="asking the provider...";
    try{
      const r=await api("access/oauth/test","POST",{issuer:readForm(FIELDS).issuer});
      note.textContent=r.ok?r.message:(r.error||"failed");
    }catch(e){note.textContent=e.message;}
  }));
  foot.appendChild(document.createTextNode(" "));
  foot.appendChild(btn("Rotate secret","dngr",async()=>{
    if(!confirm("Rotate the signing secret?\n\nEvery signed-in session on every service stops "+
                "verifying immediately -- everyone signs in again. This is the kill switch "+
                "for a leaked session."))return;
    note.textContent="rotating...";
    try{
      const r=await api("access/oauth/rotate","POST",{});
      note.textContent=r.ok?"Rotated: everyone is signed out.":(r.error||"failed");
    }catch(e){note.textContent=e.message;}
  }));
  foot.appendChild(note);
  bd.appendChild(foot);
  card.appendChild(bd);
  c.appendChild(card);
}
