// Load the real module graph under a stub DOM. Linking catches every
// import/export mismatch; evaluating catches anything missing at module top
// level. This is what "it still loads" means without a browser.
import fs from "node:fs";
import "./stub-dom.mjs";

const files = [];
(function walk(d){ for (const e of fs.readdirSync(d, {withFileTypes:true})) {
  const p = d + "/" + e.name;
  if (e.isDirectory()) walk(p);
  else if (e.name.endsWith(".js") && e.name !== "app.js") files.push(p);
}})("static/js");

let bad = 0;
for (const f of files.sort()) {
  try {
    const m = await import(process.cwd() + "/" + f);
    console.log("  ok    %s  (%d exports)", f.replace("static/js/",""), Object.keys(m).length);
  } catch (e) {
    bad++;
    console.log("  FAIL  %s\n        %s", f.replace("static/js/",""), String(e).split("\n")[0]);
  }
}
console.log(bad ? "\n" + bad + " module(s) failed to load" : "\nthe whole module graph loads");
process.exit(bad ? 1 : 0);
