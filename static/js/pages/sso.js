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

  /* --- how to set up the common providers --- */
  /* Every URL below is a real one, built from what is saved above: the
     reader should be able to paste, not translate placeholders. Until the
     hosts are saved, sensible guesses on the same domain stand in. */
  const dom=s.cookie_domain||(s.auth_host?s.auth_host.split(".").slice(1).join("."):"")||"example.com";
  const ah=s.auth_host||"auth."+dom;
  const ru=s.redirect_uri||"https://"+ah+"/.ham-sso/callback";
  const cid=s.client_id||"haproxy-manager";
  const akIssuer=(s.issuer&&s.issuer.includes("/application/o/"))?s.issuer
    :"https://authentik."+dom+"/application/o/"+cid+"/";
  const aeIssuer=(s.issuer&&!s.issuer.includes("/application/o/")
                  &&s.issuer!=="https://accounts.google.com")?s.issuer
    :"https://authelia."+dom;
  const mono=t=>'<span class=mono>'+esc(t)+"</span>";
  const pre=t=>'<pre class=mono style="margin:8px 0;padding:10px;border:1px solid '+
    'var(--line,#8884);border-radius:6px;overflow-x:auto;line-height:1.5">'+esc(t)+"</pre>";
  const guide=document.createElement("div");guide.className="card";
  guide.innerHTML='<div class=hd><h2>Provider setup</h2></div>';
  const gb=document.createElement("div");gb.className="bd";
  gb.innerHTML=
    '<p class=hint style="margin-bottom:12px">Every provider needs the same three things: a '+
    "confidential OAuth2/OIDC client, the redirect URI "+mono(ru)+", and the "+
    mono("openid email profile")+" scopes. The URLs below are built from the settings above"+
    (s.auth_host&&s.cookie_domain?"":" -- save the sign-in host and cookie domain first and "+
    "they become exact")+". Where to click differs:</p>"+

    "<details style='margin-bottom:10px'><summary style='cursor:pointer;font-weight:600'>authentik</summary>"+
    '<ol class=hint style="margin:8px 0 0 18px;line-height:1.7">'+
    "<li><b>Applications &rsaquo; Providers &rsaquo; Create</b>: an <b>OAuth2/OpenID Provider</b> "+
    "named "+mono(cid)+". Client type <b>Confidential</b>; under <b>Redirect URIs</b> add a "+
    "<b>Strict</b> entry:"+pre(ru)+
    "Pick an authorization flow (implicit consent is the usual choice) and a signing key, and "+
    "copy the client ID and secret it generates into the form above.</li>"+
    "<li><b>Applications &rsaquo; Applications &rsaquo; Create</b>: an application named "+
    mono(cid)+" with slug "+mono(cid)+", bound to that provider.</li>"+
    "<li>Issuer URL"+((s.issuer&&s.issuer===akIssuer)?" (your saved issuer):"
      :", assuming authentik answers at "+mono("authentik."+dom)+" and the slug above:")+
    pre(akIssuer)+
    "authentik gives every application its own issuer -- your authentik's hostname, the "+
    "application's slug, and the trailing slash all matter.</li>"+
    "<li>Who may sign in at all is authentik's side (application bindings); who may reach each "+
    "service is the allow-list here. Both apply.</li></ol></details>"+

    "<details style='margin-bottom:10px'><summary style='cursor:pointer;font-weight:600'>Authelia</summary>"+
    '<ol class=hint style="margin:8px 0 0 18px;line-height:1.7">'+
    "<li>Authelia 4.38 or later, with its OIDC provider enabled: "+
    mono("identity_providers.oidc")+" needs signing keys ("+mono("jwks")+") -- Authelia's own "+
    "documentation covers generating them.</li>"+
    "<li>Generate the client secret pair: "+mono("authelia crypto hash generate pbkdf2 --random")+
    ". The <b>plain</b> half goes in the form above; the <b>digest</b> goes in Authelia's "+
    "configuration, in this client entry:"+
    pre("identity_providers:\n  oidc:\n    clients:\n      - client_id: "+cid+
        "\n        client_secret: '$pbkdf2-sha512$...'   # the digest half"+
        "\n        redirect_uris:\n          - "+ru+
        "\n        scopes: [openid, email, profile]"+
        "\n        token_endpoint_auth_method: client_secret_post")+"</li>"+
    "<li>Issuer URL"+((s.issuer&&s.issuer===aeIssuer)?" (your saved issuer):"
      :", assuming Authelia answers at "+mono("authelia."+dom)+":")+pre(aeIssuer)+
    "the root it is served on -- no path.</li></ol></details>"+

    "<details><summary style='cursor:pointer;font-weight:600'>Google</summary>"+
    '<ol class=hint style="margin:8px 0 0 18px;line-height:1.7">'+
    "<li>In <b>console.cloud.google.com</b>: <b>APIs &amp; Services &rsaquo; OAuth consent "+
    "screen</b> first (External is fine; publish it, or list your accounts as test users), "+
    "then <b>Credentials &rsaquo; Create credentials &rsaquo; OAuth client ID</b>, type "+
    "<b>Web application</b>, name "+mono(cid)+".</li>"+
    "<li>Under <b>Authorized redirect URIs</b> add:"+pre(ru)+"</li>"+
    "<li>Issuer URL, always the same for Google:"+pre("https://accounts.google.com")+"</li>"+
    "<li>Never use "+mono("*")+" on a service's allow-list with Google -- that is every Google "+
    "account there is. List emails, or your workspace domain as "+mono("@"+dom)+".</li>"+
    "</ol></details>";
  guide.appendChild(gb);
  c.appendChild(guide);
}
