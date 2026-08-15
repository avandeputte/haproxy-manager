/* Entry point. Imports every page, tells the shell about them, and starts. */
import { refreshWho, showLogin } from "./auth.js";
import { $, enhanceTables } from "./core.js";
import { E, renderEntity, renderSettings } from "./entities.js";
import { renderAcmeSettings } from "./pages/acme.js";
import { renderBackup } from "./pages/backup.js";
import { renderCluster } from "./pages/cluster.js";
import { renderHistory } from "./pages/history.js";
import { renderLogs } from "./pages/logs.js";
import { renderNotify } from "./pages/notify.js";
import { renderOverview } from "./pages/overview.js";
import { renderServices } from "./pages/services.js";
import { maybeSetupWizard } from "./pages/setup.js";
import { renderSso } from "./pages/sso.js";
import { renderStats } from "./pages/stats.js";
import { renderUpdates } from "./pages/updates.js";
import { renderWatchdog } from "./pages/watchdog.js";
import { renderWebui } from "./pages/webui.js";
import { state } from "./state.js";
import { boot, buildNav, doApply, route, setPages, setRenderers, wireNav } from "./shell.js";

const P={acme:renderAcmeSettings,services:renderServices,stats:renderStats,backup:renderBackup,
         updates:renderUpdates,webui:renderWebui,cluster:renderCluster,logs:renderLogs,history:renderHistory,
         watchdog:renderWatchdog,notify:renderNotify,sso:renderSso};

/* Collapsed groups are remembered, so the nav stays how you left it. */

/* Any table that appears becomes sortable, including the ones the statistics
   and log pages replace every few seconds -- which is also why the sort is
   remembered rather than reset on each refresh. */
const content=$("#content");
let upgrading=false;
const upgrade=()=>{
  if(upgrading)return;
  upgrading=true;
  try{enhanceTables(content);}finally{upgrading=false;}
};
new MutationObserver(upgrade).observe(content,{childList:true,subtree:true});

setPages(P);
setRenderers({entities:E, entity:renderEntity, settings:renderSettings,
              overview:renderOverview});
buildNav();
wireNav();
$("#applybtn").onclick=doApply;
window.addEventListener("hashchange",route);

(async function start(){
  await refreshWho();
  if(state.who.needs_setup){showLogin(true);return;}      // first run: create an administrator
  if(!state.who.authenticated){showLogin(false);return;}
  boot();                                           // no hash => Overview
  maybeSetupWizard();                               // fresh install => offer the setup wizard
})();
