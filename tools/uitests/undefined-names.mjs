// Every name a module uses must be declared in it, imported, or a real global.
// A missing import is silent until the page runs, so this is the check that
// replaces "it looked right".
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const root = "static/js";
const files = [];
(function walk(d){ for (const e of fs.readdirSync(d, {withFileTypes:true})) {
  const p = path.join(d, e.name);
  if (e.isDirectory()) walk(p);
  else if (e.name.endsWith(".js") && e.name !== "app.js") files.push(p);
}})(root);

const GLOBALS = new Set([
  ...Object.getOwnPropertyNames(globalThis), ...Object.getOwnPropertyNames(vm.constants||{}),
  "window","document","location","navigator","fetch","alert","confirm","prompt","history",
  "setTimeout","clearTimeout","setInterval","clearInterval","requestAnimationFrame",
  "localStorage","sessionStorage","crypto","URL","URLSearchParams","Event","CustomEvent",
  "FormData","Blob","FileReader","TextEncoder","TextDecoder","AbortController","console",
  "Math","JSON","Object","Array","String","Number","Boolean","Date","Promise","Set","Map",
  "RegExp","Error","TypeError","parseInt","parseFloat","isNaN","isFinite","encodeURIComponent",
  "decodeURIComponent","btoa","atob","Intl","Symbol","WeakMap","Uint8Array","structuredClone",
  "undefined","NaN","Infinity","globalThis","arguments","this","null","true","false",
]);
const KEYWORDS = new Set(["break","case","catch","class","const","continue","debugger","default",
  "delete","do","else","export","extends","finally","for","function","if","import","in",
  "instanceof","let","new","of","return","static","super","switch","throw","try","typeof",
  "var","void","while","with","yield","async","await","from","as","get","set"]);

const strip = s => s
  .replace(/\/\*[\s\S]*?\*\//g, " ")
  .replace(/(^|[^:])\/\/[^\n]*/g, "$1 ")
  .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
  .replace(/'(?:[^'\\\n]|\\.)*'/g, "''")
  .replace(/`(?:[^`\\]|\\.)*`/gs, "``");

let problems = 0;
for (const f of files) {
  const src = fs.readFileSync(f, "utf8");
  const code = strip(src);
  const declared = new Set();
  // imports
  for (const m of src.matchAll(/import\s*\{([^}]*)\}\s*from/g))
    m[1].split(",").forEach(n => declared.add(n.trim().split(/\s+as\s+/).pop()));
  // every binding introduced anywhere in the file (top level, nested, params)
  for (const m of code.matchAll(/(?:function\s+|class\s+)([A-Za-z_$][\w$]*)/g)) declared.add(m[1]);
  for (const m of code.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)/g)) declared.add(m[1]);
  for (const m of code.matchAll(/(?:const|let|var)\s*\{([^}]*)\}/g))
    m[1].split(",").forEach(n => declared.add(n.trim().split(":").pop().trim()));
  for (const m of code.matchAll(/(?:const|let|var)\s*\[([^\]]*)\]/g))
    m[1].split(",").forEach(n => declared.add(n.trim()));
  for (const m of code.matchAll(/\(([^()]*)\)\s*=>/g))
    m[1].split(",").forEach(n => declared.add(n.trim().split("=")[0].trim()));
  for (const m of code.matchAll(/function\s*[A-Za-z_$\w]*\s*\(([^()]*)\)/g))
    m[1].split(",").forEach(n => declared.add(n.trim().split("=")[0].trim()));
  for (const m of code.matchAll(/([A-Za-z_$][\w$]*)\s*=>/g)) declared.add(m[1]);
  for (const m of code.matchAll(/catch\s*\(\s*([A-Za-z_$][\w$]*)/g)) declared.add(m[1]);
  for (const m of code.matchAll(/for\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)/g)) declared.add(m[1]);

  const missing = new Set();
  for (const m of code.matchAll(/(?<![.\w$])([A-Za-z_$][\w$]*)/g)) {
    const n = m[1];
    if (KEYWORDS.has(n) || GLOBALS.has(n) || declared.has(n)) continue;
    // an object key ("name:") is not a reference -- but a ternary ("x ? a : b")
    // is, so only skip when the colon follows immediately.
    const after = code.slice(m.index + n.length);
    if (/^\s*:/.test(after) && !/^\s*:\s*$/.test(after)) {
      const before = code.slice(Math.max(0, m.index - 40), m.index);
      if (!/\?[^:]*$/.test(before)) continue;   // not the middle of a ternary
    }
    missing.add(n);
  }
  if (missing.size) {
    problems++;
    console.log("  " + f + "  ->  " + [...missing].sort().join(", "));
  }
}
console.log(problems ? "\n" + problems + " module(s) reference names they do not have"
                     : "every module has every name it uses");
process.exit(problems ? 1 : 0);
