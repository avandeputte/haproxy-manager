/* Entry point. Imports every page, tells the shell about them, and starts. */
import { refreshWho, showLogin } from "./auth.js";
import { $, api, btn, esc, showText } from "./core.js";
import { E, renderEntity, renderSettings } from "./entities.js";
import { renderAdmin } from "./pages/admin.js";
import { renderBackup } from "./pages/backup.js";
import { renderCluster } from "./pages/cluster.js";
import { renderLogs } from "./pages/logs.js";
import { renderNotify } from "./pages/notify.js";
import { renderOverview } from "./pages/overview.js";
import { renderServices } from "./pages/services.js";
import { maybeSetupWizard } from "./pages/setup.js";
import { renderStats } from "./pages/stats.js";
import { renderUpdates } from "./pages/updates.js";
import { renderWatchdog } from "./pages/watchdog.js";
import { renderWebui } from "./pages/webui.js";
import { state } from "./state.js";
import { boot, buildNav, doApply, route, setPages } from "./shell.js";

const P={services:renderServices,stats:renderStats,backup:renderBackup,admin:renderAdmin,
         updates:renderUpdates,webui:renderWebui,cluster:renderCluster,logs:renderLogs,
         watchdog:renderWatchdog,notify:renderNotify};

/* Collapsed groups are remembered, so the nav stays how you left it. */

setPages(P);
buildNav();
$("#applybtn").onclick=doApply;
window.addEventListener("hashchange",route);

(async function start(){
  await refreshWho();
  if(state.who.needs_setup){showLogin(true);return;}      // first run: create an administrator
  if(!state.who.authenticated){showLogin(false);return;}
  boot();                                           // no hash => Overview
  maybeSetupWizard();                               // fresh install => offer the setup wizard
})();
