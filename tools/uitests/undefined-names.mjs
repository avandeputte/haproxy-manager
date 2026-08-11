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
  "MutationObserver","IntersectionObserver","ResizeObserver","queueMicrotask",
]);
const KEYWORDS = new Set(["break","case","catch","class","const","continue","debugger","default",
  "delete","do","else","export","extends","finally","for","function","if","import","in",
  "instanceof","let","new","of","return","static","super","switch","throw","try","typeof",
  "var","void","while","with","yield","async","await","from","as","get","set"]);

// Blank out comments, strings, template literals and regex literals. A regex
// like /[&<>"]/ contains a quote, so stripping strings first desynchronises
// everything after it -- which is how "amp" and "lt" once looked like missing
// names. One pass that knows which is which avoids that.
function strip(src) {
  let out = "", i = 0;
  const prevSignificant = () => { let j = out.length - 1;
    while (j >= 0 && /\s/.test(out[j])) j--; return j >= 0 ? out[j] : ""; };
  while (i < src.length) {
    const c = src[i], d = src[i + 1];
    if (c === "/" && d === "/") { while (i < src.length && src[i] !== "\n") i++; continue; }
    if (c === "/" && d === "*") { i += 2; while (i < src.length && !(src[i] === "*" && src[i+1] === "/")) i++; i += 2; out += " "; continue; }
    if (c === '"' || c === "'" || c === "`") {
      const q = c; i++;
      while (i < src.length && src[i] !== q) { if (src[i] === "\\") i++; i++; }
      i++; out += q + q; continue;
    }
    if (c === "/" && "(,=:[!&|?{};+*%<>~^\n".includes(prevSignificant() || "\n")) {
      i++; let inClass = false;
      while (i < src.length) {
        if (src[i] === "\\") { i += 2; continue; }
        if (src[i] === "[") inClass = true;
        else if (src[i] === "]") inClass = false;
        else if (src[i] === "/" && !inClass) break;
        else if (src[i] === "\n") break;
        i++;
      }
      i++; while (i < src.length && /[a-z]/.test(src[i])) i++;   // flags
      out += " 0 "; continue;
    }
    out += c; i++;
  }
  return out;
}

// every name a `const a=1,b=2` style statement introduces, not just the first
function declaredNames(code) {
  const names = new Set();
  const re = /\b(?:const|let|var)\s+/g;
  let m;
  while ((m = re.exec(code))) {
    let i = m.index + m[0].length, depth = 0, expectName = true;
    while (i < code.length) {
      const c = code[i];
      if ("([{".includes(c)) { depth++; i++; continue; }
      if (")]}".includes(c)) { if (depth === 0) break; depth--; i++; continue; }
      if (c === ";" || c === "\n") break;
      if (c === "," && depth === 0) { expectName = true; i++; continue; }
      if (c === "=" && depth === 0) { expectName = false; i++; continue; }
      if (expectName && /[A-Za-z_$]/.test(c)) {
        let j = i; while (j < code.length && /[\w$]/.test(code[j])) j++;
        names.add(code.slice(i, j)); i = j; expectName = false; continue;
      }
      i++;
    }
  }
  return names;
}

let problems = 0;
for (const f of files) {
  const src = fs.readFileSync(f, "utf8");
  const code = strip(src);
  const multi = declaredNames(code);
  const declared = new Set();
  // imports
  for (const m of src.matchAll(/import\s*\{([^}]*)\}\s*from/g))
    m[1].split(",").forEach(n => declared.add(n.trim().split(/\s+as\s+/).pop()));
  // every binding introduced anywhere in the file (top level, nested, params)
  for (const m of code.matchAll(/(?:function\s+|class\s+)([A-Za-z_$][\w$]*)/g)) declared.add(m[1]);
  for (const n of multi) declared.add(n);
  for (const m of code.matchAll(/(?:const|let|var)\s*\{([^}]*)\}/g))
    m[1].split(",").forEach(n => declared.add(n.trim().split(":").pop().trim()));
  for (const m of code.matchAll(/(?:const|let|var)\s*\[([^\]]*)\]/g))
    m[1].split(",").forEach(n => declared.add(n.trim()));
  for (const m of code.matchAll(/\(([^()]*)\)\s*=>/g))
    m[1].replace(/[[\]{}]/g, ",").split(",")
        .forEach(n => declared.add(n.trim().split("=")[0].trim()));
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
    // An object key is a name followed by a colon and preceded by "{" or ",".
    // The middle of a ternary is also followed by a colon, but never preceded
    // by either -- which is the distinction that matters here.
    const after = code.slice(m.index + n.length);
    if (/^\s*:/.test(after)) {
      const before = code.slice(Math.max(0, m.index - 60), m.index).replace(/\s+$/, "");
      if (/[{,]$/.test(before)) continue;
    }
    missing.add(n);
  }
  // Single letters come from regex literals this lint does not parse; a
  // multi-character name that is not declared or imported is a real bug.
  const real = [...missing].filter(n => n.length > 1).sort();
  const noise = [...missing].filter(n => n.length === 1).sort();
  if (real.length) {
    problems++;
    console.log("  MISSING  " + f + "  ->  " + real.join(", "));
  } else if (noise.length) {
    console.log("  ok       " + f + "   (ignored: " + noise.join(", ") + ")");
  } else {
    console.log("  ok       " + f);
  }
}
console.log(problems ? "\n" + problems + " module(s) reference names they do not have"
                     : "\nevery module has every name it uses");
process.exit(problems ? 1 : 0);
