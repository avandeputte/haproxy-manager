#!/usr/bin/env node
// Every string the UI shows has a translation in every language, or this
// fails. The dictionaries are keyed by the English, so a string added to the
// source is shown in English until each dictionary learns it -- silently,
// which is what this exists to prevent.
//
//   node tools/i18n-check.mjs            # check every dictionary
//   node tools/i18n-check.mjs --keys     # list the keys the source uses
//   node tools/i18n-check.mjs --missing de   # print a skeleton of what de lacks
//
// Where the keys come from, in order of how much of the UI they carry:
//   * t("...") and tn(n, "...", "...") calls, with literals joined by +;
//     a ternary of two literals counts as both
//   * the data the pages are drawn from: l:, h:, title:, add:, intro:, one:
//     and label: properties, the [key, "Label"] pairs of nav entries, table
//     columns and state maps, the values of any *_LABEL object, and th([...])
//   * index.html: the text of every data-i18n element and the attribute of
//     every data-i18n-<attr> one
//   * ham/*.py: the fixed "error", "note" and "message" strings the API
//     answers with, which core.js translates on the way in
//   * the words the server sends as values and the pages show through t():
//     roles, service states, what a wizard did
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const JS_DIR = path.join(ROOT, "static/js");
const DICT_DIR = path.join(JS_DIR, "i18n");

/* Values the server sends that a page shows through t(): a role, a unit's
   state, what the wizard did to an object. They are data on the server's
   side, so no t("...") in the source names them. */
const VOCABULARY = {
  "the node's role (status.role)": ["active", "passive", "standalone"],
  "a systemd unit's state": ["active", "inactive", "failed", "activating", "deactivating",
                             "unknown", "disabled"],
  "what a wizard did to an object": ["created", "updated", "reused", "removed", "renamed"],
  "history: how an object differs": ["added", "removed", "changed"],
  "watchdog: a service's state": ["ok", "down", "hung", "starting", "idle", "disabled",
                                  "unwatched", "unknown"],
};

/* ---- reading string literals out of source ---- */

/* Source with every string literal replaced by "N" (an index into lits) and
   every comment blanked. The rules below then see code structure only: a
   colon inside a sentence is not a property, and an example in a comment is
   not a call. Newlines are kept, so line numbers still mean something. */
function mask(src, python){
  const lits = [];
  let code = "", i = 0;
  const blank = s => s.replace(/[^\n]/g, " ");
  while (i < src.length) {
    const c = src[i], d = src[i + 1];
    if (python ? c === "#" : (c === "/" && d === "/")) {
      let j = i; while (j < src.length && src[j] !== "\n") j++;
      code += blank(src.slice(i, j)); i = j; continue;
    }
    if (!python && c === "/" && d === "*") {
      let j = src.indexOf("*/", i + 2); j = j < 0 ? src.length : j + 2;
      code += blank(src.slice(i, j)); i = j; continue;
    }
    /* A regex literal can hold a quote (/[&<>"]/), which would otherwise
       open a string that never closes. It is a regex, not a division, when
       what precedes it cannot end an expression. */
    if (!python && c === "/") {
      const prev = code.replace(/\s+$/, "").slice(-1);
      if (!prev || "(,=:[!&|?{};+*%<>~^".includes(prev)) {
        let j = i + 1, inClass = false;
        while (j < src.length) {
          if (src[j] === "\\") { j += 2; continue; }
          if (src[j] === "[") inClass = true;
          else if (src[j] === "]") inClass = false;
          else if (src[j] === "/" && !inClass) break;
          else if (src[j] === "\n") break;
          j++;
        }
        j++; while (j < src.length && /[a-z]/.test(src[j])) j++;
        code += blank(src.slice(i, j)); i = j; continue;
      }
    }
    if (c === '"' || c === "'" || (c === "`" && !python)) {
      const triple = python && src.slice(i, i + 3) === c + c + c;
      const q = triple ? c + c + c : c;
      /* a Python prefix (f, r, b) sits just before the quote */
      let prefix = "";
      if (python) { const m = code.match(/[fFrRbBuU]{1,2}$/); if (m) { prefix = m[0].toLowerCase(); code = code.slice(0, -m[0].length) + " ".repeat(m[0].length); } }
      let j = i + q.length, out = "";
      while (j < src.length && src.slice(j, j + q.length) !== q) {
        if (src[j] === "\\" && !prefix.includes("r")) {
          const e = src[j + 1];
          if (e === "n") out += "\n";
          else if (e === "t") out += "\t";
          else if (e === "\n") { /* a continued line */ }
          else if (e === "u") { out += String.fromCharCode(parseInt(src.slice(j + 2, j + 6), 16)); j += 4; }
          else out += e;
          j += 2; continue;
        }
        out += src[j++];
      }
      lits.push({ value: out, prefix: prefix, at: i });
      code += '"' + (lits.length - 1) + '"' + blank(src.slice(i, j + q.length)).slice(("" + (lits.length - 1)).length + 2);
      i = j + q.length; continue;
    }
    code += c; i++;
  }
  return { code, lits };
}
/* A literal or a run of them joined by + (or, in Python, by whitespace),
   starting at code[i] (a quote). Returns [value, end, pure]: pure is false
   when the run ends in +something that is not a literal, i.e. the key is
   built at run time and could never be looked up. */
function readSequence(code, lits, i, python){
  let value = "", j = i, pure = true, fstring = false;
  const join = python ? /^(?:\s*\+\s*|\s+)/ : /^\s*\+\s*/;
  for(;;){
    const m = code.slice(j).match(/^"(\d+)"/);
    if (!m) break;
    const lit = lits[+m[1]];
    value += lit.value; j += m[0].length;
    if (lit.prefix.includes("f")) fstring = true;
    const jm = code.slice(j).match(join);
    if (!jm) break;
    const k = j + jm[0].length;
    if (code[k] === '"') { j = k; continue; }
    if (jm[0].trim() === "+") pure = false;
    break;
  }
  return [value, j, pure && !fstring];
}
const isQuote = c => c === '"';

/* Every key a JS module uses. */
function keysOfModule(file){
  const { code, lits } = mask(fs.readFileSync(file, "utf8"), false);
  const keys = new Map();          /* key -> where */
  const problems = [];
  const add = (k, where) => { if (k) keys.set(k, where); };
  const where = (i) => path.relative(ROOT, file) + ":" + (code.slice(0, i).split("\n").length);
  const seq = (i) => readSequence(code, lits, i, false);

  /* t( and tn( */
  const call = /(?<![\w.$])(tn?)\(/g;
  let m;
  while ((m = call.exec(code))) {
    let i = m.index + m[0].length;
    /* the arguments, up to the closing paren, tracking nesting */
    let depth = 0, args = [], cur = i;
    for (let j = i; j < code.length; j++) {
      const c = code[j];
      if ("([{".includes(c)) depth++;
      else if (")]}".includes(c)) { if (depth === 0) { args.push(code.slice(cur, j)); break; } depth--; }
      else if (c === "," && depth === 0) { args.push(code.slice(cur, j)); cur = j + 1; }
    }
    const first = m[1] === "tn" ? args.slice(1, 3) : args.slice(0, 1);
    first.forEach(arg => {
      const a = arg.trim();
      if (!a) return;
      if (isQuote(a[0])) {
        const [v, end, pure] = readSequence(a, lits, 0, false);
        if (!pure || a.slice(end).trim()) problems.push(where(m.index) + ": key is built at run time");
        add(v, where(m.index));
        return;
      }
      /* not a literal: a ternary of literals counts as each; anything else
         is data, covered by the rules below or the vocabulary */
      for (let j = 0; j < a.length; j++) {
        if (isQuote(a[j])) { const [v, end] = readSequence(a, lits, j, false); add(v, where(m.index)); j = end - 1; }
      }
    });
    if (m[1] === "tn" && args.length < 3) problems.push(where(m.index) + ": tn() needs a count and two forms");
  }

  /* data properties whose values are shown: l, h, title, add, intro, one, label */
  const prop = /(?<![\w$.])(l|h|title|add|intro|one|label)\s*:\s*(?=")/g;
  while ((m = prop.exec(code))) {
    const [v, , pure] = seq(m.index + m[0].length);
    if (pure) add(v, where(m.index));
    else problems.push(where(m.index) + ": " + m[1] + ": is built at run time");
  }

  /* [key, "Label"] pairs: the start of an array literal whose first two
     elements are strings, sitting inside another array or as a property
     value -- a nav entry, a table column, a state map. Option lists (o:) and
     reference lists (refs:) have the same shape and are values, not words;
     so is a list of field keys, which is what an underscore gives away. */
  const pair = /(\[|,|(\w+)\s*:)\s*\[\s*"\d+"\s*,\s*(?=")/g;
  while ((m = pair.exec(code))) {
    if (m[2] === "o" || m[2] === "refs") continue;
    const [v] = seq(m.index + m[0].length);
    if (/^[a-z0-9]+_[a-z0-9_]+$/.test(v)) continue;
    add(v, where(m.index));
  }

  /* every string value of a *_LABEL object */
  const labels = /const\s+\w+_LABEL\s*=\s*\{/g;
  while ((m = labels.exec(code))) {
    let j = m.index + m[0].length, depth = 1;
    while (j < code.length && depth) {
      const c = code[j];
      if (c === ":" ) { const k = code.slice(j + 1).match(/^\s*"/); if (k) { const [v, end] = seq(j + k[0].length); add(v, where(j)); j = end; continue; } }
      if (c === "{") depth++; else if (c === "}") depth--;
      j++;
    }
  }

  /* th(["Name", ...]) -- a row of table headings */
  const th = /\bth\(\[([^\]]*)\]\)/g;
  while ((m = th.exec(code))) {
    for (const s of m[1].matchAll(/"(\d+)"/g)) add(lits[+s[1]].value, where(m.index));
  }
  return { keys, problems };
}

/* index.html: data-i18n takes the element's text, data-i18n-<attr> that attribute. */
function keysOfHtml(file){
  const src = fs.readFileSync(file, "utf8");
  const keys = new Map();
  const tag = /<(\w+)([^>]*)>/g;
  let m;
  while ((m = tag.exec(src))) {
    const attrs = m[2];
    if (/\sdata-i18n(?=[\s>]|$)/.test(attrs)) {
      const text = src.slice(m.index + m[0].length).split("<")[0].trim();
      keys.set(text, "index.html");
    }
    for (const a of attrs.matchAll(/\sdata-i18n-([\w-]+)/g)) {
      const v = attrs.match(new RegExp("\\s" + a[1] + '="([^"]*)"'));
      if (v) keys.set(v[1], "index.html");
    }
  }
  return keys;
}

/* ham/*.py: the fixed phrases the API answers with. Anything with a %s, an
   f-string or a value added on is assembled around a value and falls through
   untranslated, so it is not a key. */
function keysOfPython(){
  const keys = new Map();
  const files = fs.readdirSync(path.join(ROOT, "ham")).filter(f => f.endsWith(".py"));
  for (const f of files) {
    const { code, lits } = mask(fs.readFileSync(path.join(ROOT, "ham", f), "utf8"), true);
    const re = /(?:"(\d+)"\s*:|(?<![\w])(error|note|message)\s*=)\s*(?=")/g;
    let m;
    while ((m = re.exec(code))) {
      if (m[1] !== undefined && !["error", "note", "message"].includes(lits[+m[1]].value)) continue;
      const [v, end, pure] = readSequence(code, lits, m.index + m[0].length, true);
      const after = code.slice(end, end + 12);
      if (!pure || /[%{]/.test(v) || /^\s*%/.test(after) || /^\s*\.format/.test(after)) continue;
      if (v.length < 4 || !/[a-z]/.test(v)) continue;
      keys.set(v.replace(/\s+$/, ""), "ham/" + f + ":" + code.slice(0, m.index).split("\n").length);
    }
  }
  return keys;
}

/* ---- the keys, from everywhere ---- */
function walk(d, out){
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) { if (p !== DICT_DIR) walk(p, out); }
    else if (e.name.endsWith(".js")) out.push(p);
  }
  return out;
}
const problems = [];
const keys = new Map();
const groups = [];
for (const f of walk(JS_DIR, []).sort()) {
  const r = keysOfModule(f);
  problems.push(...r.problems);
  groups.push([path.relative(ROOT, f), [...r.keys.keys()]]);
  r.keys.forEach((w, k) => { if (!keys.has(k)) keys.set(k, w); });
}
{
  const h = keysOfHtml(path.join(ROOT, "static/index.html"));
  groups.push(["static/index.html", [...h.keys()]]);
  h.forEach((w, k) => { if (!keys.has(k)) keys.set(k, w); });
  const p = keysOfPython();
  groups.push(["ham/*.py (what the API answers with)", [...p.keys()]]);
  p.forEach((w, k) => { if (!keys.has(k)) keys.set(k, w); });
  for (const [what, words] of Object.entries(VOCABULARY)) {
    groups.push(["vocabulary: " + what, words]);
    words.forEach(k => { if (!keys.has(k)) keys.set(k, what); });
  }
}
/* HTML entities and tags inside a key must survive translation; a
   placeholder must too, or the value it carries is lost. */
const placeholders = s => [...s.matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort().join(",");
const tags = s => [...s.matchAll(/<\/?[a-z][^>]*>/g)].map(m => m[0].replace(/\s+/g, " ")).sort().join(" ");

const mode = process.argv[2];
if (mode === "--keys") {
  for (const [name, ks] of groups) {
    if (!ks.length) continue;
    console.log("\n/* ---- " + name + " ---- */");
    ks.forEach(k => console.log(JSON.stringify(k)));
  }
  console.log("\n// " + keys.size + " keys");
  process.exit(0);
}

const langs = fs.readdirSync(DICT_DIR).filter(f => f.endsWith(".js")).map(f => f.slice(0, -3)).sort();
let failed = 0;
if (problems.length) {
  failed++;
  console.log("keys that cannot be looked up:");
  problems.forEach(p => console.log("  " + p));
}
for (const lang of langs) {
  const dict = (await import(pathToFileURL(path.join(DICT_DIR, lang + ".js")).href)).default || {};
  const have = new Set(Object.keys(dict));
  const missing = [...keys.keys()].filter(k => !have.has(k));
  const extra = [...have].filter(k => !keys.has(k));
  const bad = [];
  for (const [k, v] of Object.entries(dict)) {
    if (typeof v !== "string" || !v.trim()) { bad.push(k + "  ->  empty"); continue; }
    if (placeholders(k) !== placeholders(v)) bad.push(k + "  ->  placeholders differ: " + JSON.stringify(v));
    else if (tags(k) !== tags(v)) bad.push(k + "  ->  markup differs: " + JSON.stringify(v));
  }
  const same = Object.entries(dict).filter(([k, v]) => k === v).length;
  if (mode === "--missing" && process.argv[3] === lang) {
    missing.forEach(k => console.log("  " + JSON.stringify(k) + ": " + JSON.stringify(k) + ","));
    continue;
  }
  const ok = !missing.length && !extra.length && !bad.length;
  if (!ok) failed++;
  console.log((ok ? "  ok    " : "  FAIL  ") + lang.padEnd(4) + " " + have.size + " entries" +
              (same ? " (" + same + " unchanged)" : "") +
              (missing.length ? ", " + missing.length + " missing" : "") +
              (extra.length ? ", " + extra.length + " unused" : "") +
              (bad.length ? ", " + bad.length + " broken" : ""));
  missing.slice(0, 40).forEach(k => console.log("          missing  " + JSON.stringify(k)));
  if (missing.length > 40) console.log("          ... and " + (missing.length - 40) + " more");
  extra.forEach(k => console.log("          unused   " + JSON.stringify(k)));
  bad.forEach(b => console.log("          broken   " + b));
}
if (mode === "--missing") process.exit(0);
console.log(failed ? "\n" + failed + " problem(s): the UI would show English somewhere"
                   : "\n" + keys.size + " strings, every one translated into " + langs.length + " language(s)");
process.exit(failed ? 1 : 0);
