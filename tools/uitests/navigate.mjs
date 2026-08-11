// Visit every entry in the navigation and fail if a page reports a name it
// does not have.
//
// route() catches whatever a renderer throws and prints the message into the
// page, which is why a missing import showed up as "E is not defined" on screen
// rather than as a crash. So this looks at what was rendered, and only treats
// ReferenceErrors as failures: thin stub data legitimately produces TypeErrors.
import "./stub-dom.mjs";

const root = process.cwd() + "/static/js/";
const { NAV, route } = await import(root + "shell.js");
await import(root + "main.js");          // wires the pages and renderers

let bad = 0, visited = 0;
for (const [key, label] of NAV) {
  if (key === "grp") continue;
  visited++;
  globalThis.location.hash = "#/" + key;
  const content = document.querySelector("#content");
  content.innerHTML = ""; content.children.length = 0;
  try { await route(); } catch (e) { /* route() catches its own */ }
  const shown = content.innerHTML + content.children.map(c => c.text || "").join("");
  const m = shown.match(/([A-Za-z_$][\w$]*) is not defined|([A-Za-z_$][\w$.]*) is not a function/);
  if (m) {
    bad++;
    console.log("  FAIL  " + (key || "(overview)").padEnd(26) + " " + m[0]);
  } else {
    console.log("  ok    " + (key || "(overview)").padEnd(26) + " " + label);
  }
}
console.log(bad ? "\n" + bad + " of " + visited + " pages reference something they do not have"
                : "\nall " + visited + " pages resolved every name they use");
process.exit(bad ? 1 : 0);
