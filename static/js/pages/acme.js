import { $ } from "../core.js";
import { renderEntity, renderSettings } from "../entities.js";

/* Everything ACME is configured with, on one page: the accounts certificates
   are issued under, the challenge types that prove the domains, and the
   protocol settings. They were three separate places, which meant setting up
   a certificate started with a tour of the menu. */
export async function renderAcmeSettings(){
  const c=$("#content");c.innerHTML="";
  await renderEntity("acme/accounts",c);
  await renderEntity("acme/challenges",c);
  await renderSettings("acme-settings",c);
}
