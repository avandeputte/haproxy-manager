// Choosing a recipe must fill the wizard in. A picker that looks right and
// changes nothing would be worse than no picker.
import "./stub-dom.mjs";

const RECIPES = [
  {id:"galera", name:"MariaDB — Galera", category:"Databases",
   summary:"TCP 3306 with every client pinned to one node.", notes:"Stickiness by source.",
   fields:{url:"tcp://0.0.0.0:3306", balance:"source", persistence:"source",
           health:"mysql", health_user:"haproxy", check_port:"", log_health_checks:true,
           timeout_server:"30m"}},
  {id:"web", name:"Web application", category:"Web", summary:"HTTP with a check on /.",
   notes:"The default.", fields:{url:"https://app.example.com", balance:"roundrobin",
           health:"http", health_uri:"/", health_status:"200"}},
];
globalThis.fetch = async (url) => {
  const path = String(url).replace(/^\/api\//,"").split("?")[0];
  const body = path === "recipes" ? {ok:true, recipes:RECIPES}
             : /^[a-z]+\/[a-z]+$/.test(path) ? [] : {};
  return { ok:true, status:200, json: async()=>body, text: async()=>"" };
};
const root = process.cwd() + "/static/js/";
const { openWizard, loadRecipes } = await import(root + "pages/services.js");

let fail = 0;
const ok = (c,m) => { console.log((c?"  PASS  ":"  FAIL  ")+m); if(!c) fail++; };

await loadRecipes();
openWizard();
await new Promise(r => setImmediate(r));       // the picker fills in after its fetch

const body = document.querySelector("#dlgbody").children[0];
const sel = body.querySelector("#f_recipe");
ok(!!sel, "the wizard offers a recipe picker");
ok(body.querySelectorAll("optgroup").length >= 2, "recipes are grouped by category");

const val = k => {
  const el = document.getElementById("f_" + k);
  return el ? (el.type === "checkbox" ? el.checked : el.value) : null;
};
sel.value = "galera";
sel.onchange();
ok(val("url") === "tcp://0.0.0.0:3306", "it sets the port: " + val("url"));
ok(val("balance") === "source", "and the balancing: " + val("balance"));
ok(val("health") === "mysql", "and the health check: " + val("health"));
ok(val("health_user") === "haproxy", "and its user: " + val("health_user"));
ok(val("timeout_server") === "30m", "and the timeout: " + val("timeout_server"));
ok(val("log_health_checks") === true, "booleans are set too");

sel.value = "web";
sel.onchange();
ok(val("url") === "https://app.example.com" && val("health") === "http",
   "choosing another recipe replaces the values");

sel.value = "";
sel.onchange();
ok(val("url") === "https://app.example.com", "choosing nothing leaves what is there");

console.log(fail ? "\n"+fail+" FAILED" : "\nrecipes fill the wizard in");
process.exit(fail?1:0);
