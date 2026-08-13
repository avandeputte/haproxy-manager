/* Light, dark, or whichever the machine is set to.

   The preference belongs to the account, so it follows the person to another
   browser -- but the page has to be painted before the API can answer, so it
   is also mirrored locally. What is checked here is that those two never
   disagree in a way anyone would notice. */
import "./stub-dom.mjs";

let stored = {};
globalThis.localStorage = {
  getItem: k => (k in stored ? stored[k] : null),
  setItem: (k, v) => { stored[k] = String(v); },
  removeItem: k => { delete stored[k]; },
};
let systemDark = false, listeners = [];
globalThis.window.matchMedia = () => ({
  get matches(){ return systemDark; },
  addEventListener: (_, fn) => listeners.push(fn),
  addListener: fn => listeners.push(fn),
});
const root = { dataset: {} };
globalThis.document.documentElement = root;

const { applyTheme, currentTheme, THEMES } = await import("../../static/js/theme.js");
let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };

ok(THEMES.join(",") === "system,light,dark", "three choices, system first");

applyTheme("dark");
ok(root.dataset.theme === "dark", "dark is dark");
ok(stored.ham_theme === "dark", "and is remembered for the next first paint");

applyTheme("light");
ok(root.dataset.theme === "light", "light is light");

systemDark = true;
applyTheme("system");
ok(root.dataset.theme === "dark", "system follows the machine when it is dark");
systemDark = false;
applyTheme("system");
ok(root.dataset.theme === "light", "and when it is light");

// following the machine means following it as it changes
systemDark = true;
listeners.forEach(fn => fn());
ok(root.dataset.theme === "dark", "a machine that changes its mind is followed");

applyTheme("light");
systemDark = false;
listeners.forEach(fn => fn());
ok(root.dataset.theme === "light",
   "but not once someone has chosen for themselves");

applyTheme("nonsense");
ok(currentTheme() === "system" && root.dataset.theme !== undefined,
   "an unknown preference falls back to system rather than breaking the page");

stored = {};
ok(currentTheme() === "system", "with nothing remembered, system is the default");

globalThis.localStorage = {
  getItem(){ throw new Error("private browsing"); },
  setItem(){ throw new Error("private browsing"); },
  removeItem(){},
};
applyTheme("dark");
ok(root.dataset.theme === "dark",
   "a browser that refuses to remember anything still gets the theme applied");

console.log(fail ? `\n${fail} failed` : "\nthe theme follows the account and the machine");
process.exit(fail ? 1 : 0);
