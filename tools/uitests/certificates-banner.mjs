import "./stub-dom.mjs";
import fs from "node:fs";
const src = fs.readFileSync("tools/uitests/navigate.mjs","utf8");
eval(src.slice(src.indexOf("const FIXTURES"), src.indexOf("globalThis.fetch")).replace("const FIXTURES","globalThis.FIXTURES"));
let ACCOUNTS = [], CHALLENGES = [];
globalThis.fetch = async (url) => {
  const path = String(url).replace(/^\/api\//,"").split("?")[0];
  let body;
  if (path === "acme/accounts") body = ACCOUNTS;
  else if (path === "acme/challenges") body = CHALLENGES;
  else if (path === "acme/certificates") body = [];
  else body = path in FIXTURES ? FIXTURES[path] : /^[a-z]+\/[a-z]+$/.test(path) ? [] : {};
  return { ok:true, status:200, json: async()=>body, text: async()=>"" };
};
const root = process.cwd() + "/static/js/";
const { renderEntity } = await import(root + "entities.js");
const c = document.querySelector("#content");
const render = async () => { c.children.length = 0; c.innerHTML = "";
  await renderEntity("acme/certificates");
  return c.children.map(x => x.text).join(""); };

let fail = 0;
const ok = (cond,m) => { console.log((cond?"  PASS  ":"  FAIL  ")+m); if(!cond) fail++; };

let html = await render();
ok(html.includes("Set up ACME first"), "banner shown when nothing is configured");
ok(html.includes("an ACME account and a challenge type"), "it names both missing pieces");
ok(html.includes("Open ACME Settings"), "it offers a way to fix it");

ACCOUNTS = [{id:"1",name:"le"}];
html = await render();
ok(html.includes("Set up ACME first"), "banner still shown with an account but no challenge type");
ok(html.includes("a challenge type") && !html.includes("an ACME account and"),
   "it names only what is missing");

CHALLENGES = [{id:"2",name:"http"}];
html = await render();
ok(!html.includes("Set up ACME first"), "banner gone once both exist");

console.log(fail ? "\n"+fail+" FAILED" : "\nthe certificates banner behaves");
process.exit(fail?1:0);
