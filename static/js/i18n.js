/* The language the page speaks.

   Chosen from the browser's own preference list, the way the browser chooses
   for every other site: the first language on it that this UI has is the one
   used, and English is what remains when none matches. That is the default,
   and for most people the end of it -- but the browser's list is not always
   the person's: an iPad takes it from the system language, and someone who
   reads the documentation in English wants the field names it uses. So the
   account dialog can pin a language, and that choice wins over the browser.

   The dictionaries live in ./i18n/<code>.js, one per language, keyed by the
   English string exactly as it appears in the source. That is what makes the
   English the fallback rather than a language of its own: a key with no entry
   is shown as it is, so a string added to the source is never invisible, only
   untranslated until each dictionary catches up -- which tools/i18n-check.mjs
   refuses to let a release forget. */

export const LANGUAGES = {
  en: "English",
  de: "Deutsch",
  fr: "Français",
  es: "Español",
  it: "Italiano",
  pt: "Português",
  nl: "Nederlands",
  sv: "Svenska",
  da: "Dansk",
  nb: "Norsk",
  fi: "Suomi",
};
/* Tags a browser sends that name the same dictionary under another code. */
const ALIASES = { no: "nb", nn: "nb" };
/* Which of the two forms "one" and "other" a count takes. Every language here
   has two, but French puts zero with the singular. */
const ONE = { fr: n => n <= 1 };

let dict = {};
let lang = "en";

/* A language pinned on the account dialog, or "" for the browser's. The
   account holds the real choice; it is mirrored here because the dictionary
   has to be loaded before the first frame, before the API could be asked --
   the same reason the theme is. */
const STORE = "ham_lang";
export function chosenLanguage(){
  try{
    const code = localStorage.getItem(STORE) || "";
    return LANGUAGES[code] ? code : "";
  }catch(e){ return ""; }
}
/* Remember a choice, "" for the browser's. True when it was remembered: a
   browser that refuses to store anything says so here. */
export function rememberLanguage(code){
  const want = LANGUAGES[code] ? code : "";
  try{
    if(want)localStorage.setItem(STORE, want);
    else localStorage.removeItem(STORE);
    return chosenLanguage() === want;
  }catch(e){ return false; }
}
/* The language a choice comes to: itself, or the browser's when it is "". */
export function resolveLanguage(choice){
  return LANGUAGES[choice] ? choice : detectLanguage();
}

/* The first entry on the browser's list that has a dictionary, or English.
   "pt-BR" finds pt, "no" finds nb; "en-GB" finds nothing and that is right. */
export function pickLanguage(wanted){
  for(const tag of wanted || []){
    const base = String(tag || "").toLowerCase().split(/[-_]/)[0];
    const code = ALIASES[base] || base;
    if(code === "en")return "en";
    if(LANGUAGES[code])return code;
  }
  return "en";
}
export function detectLanguage(){
  const nav = typeof navigator !== "undefined" ? navigator : null;
  if(!nav)return "en";
  const list = nav.languages && nav.languages.length ? nav.languages
             : nav.language ? [nav.language] : [];
  return pickLanguage(list);
}

/* Load the dictionary, before anything is painted. A dictionary that fails to
   load -- a broken deploy, a network that dropped the request -- costs the
   translation, not the page. */
export async function initLanguage(code){
  lang = code || chosenLanguage() || detectLanguage();
  dict = {};
  if(lang !== "en"){
    try{
      const m = await import("./i18n/" + lang + ".js");
      dict = m.default || {};
    }catch(e){
      lang = "en";
    }
  }
  if(typeof document !== "undefined" && document.documentElement)
    document.documentElement.lang = lang;
  return lang;
}
export function currentLanguage(){ return lang; }
/* For tests, and for anything that wants to speak a language without loading
   it from disk. */
export function setDictionary(code, entries){ lang = code; dict = entries || {}; }

function fill(s, vars){
  return String(s).replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
}
/* The string in the reader's language, with {name} placeholders filled in.
   Values are put in as given: where the result is markup, escape them first. */
export function t(key, vars){
  const s = Object.prototype.hasOwnProperty.call(dict, key) ? dict[key] : key;
  return vars ? fill(s, vars) : s;
}
/* One of two forms by count, {n} filled in: tn(3, "{n} node", "{n} nodes"). */
export function tn(n, one, other, vars){
  const single = (ONE[lang] || (x => x === 1))(Number(n));
  return t(single ? one : other, Object.assign({ n: n }, vars || {}));
}

/* The few strings that are written in index.html rather than by a module.
   An element marked data-i18n is translated in place; its English is kept on
   the attribute so a second pass knows what to look up. The same for the
   attributes people see or hear: a title, a placeholder, an aria-label. */
export function translateStatic(root){
  const r = root || (typeof document !== "undefined" ? document : null);
  if(!r || !r.querySelectorAll)return;
  r.querySelectorAll("[data-i18n]").forEach(el => {
    const key = el.getAttribute("data-i18n") || el.textContent.trim();
    if(!key)return;
    el.setAttribute("data-i18n", key);
    el.textContent = t(key);
  });
  ["title", "placeholder", "aria-label"].forEach(a => {
    r.querySelectorAll("[data-i18n-" + a + "]").forEach(el => {
      const key = el.getAttribute("data-i18n-" + a) || el.getAttribute(a);
      if(!key)return;
      el.setAttribute("data-i18n-" + a, key);
      el.setAttribute(a, t(key));
    });
  });
}
