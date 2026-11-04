/* A language pinned on the account, over the browser's.
 *
 * The browser here asks for Dutch. The mechanism: a remembered choice wins
 * over that list, an unknown one is ignored, and "" means the list again. The
 * dialog: every language is offered in its own name, Automatic says what it
 * comes to, and saving one sends it. Then the part that could go wrong
 * quietly: a different language reloads the page once and only once, a new
 * browser picks the account's choice up after sign-in, and a browser that
 * stores nothing is left in its own language rather than reloaded forever.
 */
let parseHTML;
for (const where of ["linkedom", process.env.LINKEDOM]) {
  if (!where) continue;
  try { ({ parseHTML } = await import(where)); break; } catch { /* try the next */ }
}
if (!parseHTML) {
  console.log("  skipped: no DOM available (npm i linkedom, or set LINKEDOM)");
  process.exit(0);
}
const REPO = process.cwd();
const { document, window } = parseHTML(`<!doctype html><html><body>
<div id="ovl"><div id="dlg" role="dialog" aria-modal="true">
<div class="hd"><h3 id="dlgtitle"></h3><button id="dlgclose"></button></div>
<div class="bd" id="dlgbody"></div><div class="ft" id="dlgfoot"></div></div></div>
<aside id="nav"><div class="foot" id="whofoot"></div></aside>
<div id="login"><form id="loginbox"><input id="lu"><input id="lp">
<div id="lp2wrap" hidden><input id="lp2"></div><div id="lerr"></div>
<button id="lbtn"></button><h2 id="logintitle"></h2><p id="loginintro"></p></form></div>
<div id="content"></div></body></html>`);
globalThis.document = document; globalThis.window = window;
globalThis.MutationObserver = class { observe(){} };
Object.defineProperty(globalThis, "navigator", { configurable: true,
  value: { languages: ["nl-NL", "en"], language: "nl-NL" } });
let reloads = 0;
globalThis.location = { hash: "#/p:stats", host: "node1", reload(){ reloads++; } };
let stored = {};
const memory = {
  getItem: k => (k in stored ? stored[k] : null),
  setItem: (k, v) => { stored[k] = String(v); },
  removeItem: k => { delete stored[k]; },
};
globalThis.localStorage = memory;

let who = { authenticated: true, username: "admin", language: "" };
let sent = null;
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  let body = who;
  if (path === "password") {
    sent = JSON.parse(o.body);
    who = Object.assign({}, who, { language: sent.language });
    body = { ok: true, language: sent.language };
  }
  return { ok: true, status: 200, json: async () => body, text: async () => "" };
};

/* linkedom (0.18) gets selects wrong in two ways; see proxy-protocol.mjs. */
const optProto = Object.getPrototypeOf(document.createElement("option"));
Object.defineProperty(optProto, "selected", {
  configurable: true,
  get() { return this.hasAttribute("selected"); },
  set(v) {
    if (v) {
      const prev = this.parentElement && this.parentElement.querySelector("option[selected]");
      if (prev && prev !== this) prev.removeAttribute("selected");
      this.setAttribute("selected", "");
    } else this.removeAttribute("selected");
  },
});
const selProto = Object.getPrototypeOf(document.createElement("select"));
Object.defineProperty(selProto, "value", {
  configurable: true,
  get() { const o = this.querySelector("option[selected]") || this.querySelector("option"); return o ? o.value : ""; },
  set(v) { const o = [...this.querySelectorAll("option")].find(x => x.value === String(v)); if (o) o.selected = true; },
});

const { chosenLanguage, currentLanguage, initLanguage, rememberLanguage, resolveLanguage, LANGUAGES } =
  await import(REPO + "/static/js/i18n.js");
const { refreshWho, openAccount } = await import(REPO + "/static/js/auth.js");
let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };

// -- the mechanism -------------------------------------------------------------
ok(chosenLanguage() === "" && await initLanguage() === "nl",
   "with nothing chosen, the browser's Dutch is used");
stored.ham_lang = "en";
ok(chosenLanguage() === "en" && await initLanguage() === "en",
   "a language chosen for the account wins over the browser's");
stored.ham_lang = "xx";
ok(chosenLanguage() === "" && await initLanguage() === "nl",
   "one this UI does not have is ignored, not tried");
ok(rememberLanguage("de") === true && stored.ham_lang === "de", "a choice is remembered");
ok(rememberLanguage("") === true && !("ham_lang" in stored), "and Automatic forgets it");
ok(rememberLanguage("zz") === true && !("ham_lang" in stored), "an unknown one is remembered as Automatic");
ok(resolveLanguage("") === "nl" && resolveLanguage("fi") === "fi" && resolveLanguage("zz") === "nl",
   "a choice comes to itself, or to the browser's");

// -- the dialog ----------------------------------------------------------------
stored = {};
await initLanguage();
await refreshWho();
ok(reloads === 0, "an account that follows the browser, in the browser's language, does not reload");
openAccount();
const sel = document.querySelector("#f_language");
ok(!!sel, "the account dialog has a language select");
const opts = [...sel.options];
ok(opts.length === Object.keys(LANGUAGES).length + 1, "Automatic and every language: " + opts.length);
ok(opts[0].value === "" && opts[0].textContent === "Automatisch (Nederlands)",
   "Automatic comes first and says what it comes to here: " + opts[0].textContent);
ok(opts.slice(1).every(o => o.textContent === LANGUAGES[o.value]) &&
   opts.some(o => o.value === "en" && o.textContent === "English"),
   "each language is offered in its own name, so it can be found from any other");
ok(sel.value === "", "it opens on what the account has");
ok([...document.querySelectorAll("#dlgbody label")].some(l => l.textContent === "Taal"),
   "the label itself is in the page's language");

sel.value = "en";
await document.querySelector("#dlgfoot button.pri").onclick();
ok(sent && sent.language === "en", "saving sends the language chosen");
ok(stored.ham_lang === "en" && reloads === 1,
   "and the page is drawn again in it, once: " + reloads + " reload(s)");

// what the reload comes back to
ok(await initLanguage() === "en", "the reload paints in English before asking the server");
await refreshWho();
ok(reloads === 1, "and does not reload again");
openAccount();
ok(document.querySelector("#f_language").value === "en", "the dialog opens on English now");
document.querySelector("#dlgclose").click?.();

// a browser that has never seen this account
stored = {};
ok(await initLanguage() === "nl", "a new browser starts in its own language");
await refreshWho();
ok(stored.ham_lang === "en" && reloads === 2, "and switches to the account's once signed in");
await initLanguage();

// back to Automatic
who.language = "";
await refreshWho();
ok(!("ham_lang" in stored) && reloads === 3, "going back to Automatic forgets the choice and redraws");

// a browser that will not remember anything
globalThis.localStorage = {
  getItem(){ throw new Error("private browsing"); },
  setItem(){ throw new Error("private browsing"); },
  removeItem(){ throw new Error("private browsing"); },
};
ok(await initLanguage() === "nl", "a browser that stores nothing still gets a language");
who.language = "en";
await refreshWho();
ok(reloads === 3, "and is not reloaded over and over trying to keep a choice it cannot");
globalThis.localStorage = memory;

// signed out, the login screen keeps whatever this browser last had
stored = { ham_lang: "de" };
who = { authenticated: false, needs_setup: false };
await refreshWho();
ok(stored.ham_lang === "de" && reloads === 3, "signing out leaves the last language for the login screen");

console.log(fail ? `\n${fail} failed` : "\nthe account's language wins over the browser's");
process.exit(fail ? 1 : 0);
