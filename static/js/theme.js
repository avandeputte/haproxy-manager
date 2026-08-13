/* Light or dark, or whichever the machine is set to.

   The choice belongs to the account, so it follows the person between
   browsers; it is also mirrored into localStorage, because the page has to be
   painted before the API can answer. */
export const THEMES = ["system", "light", "dark"];

let watching = null;

export function applyTheme(pref){
  const want = THEMES.indexOf(pref) < 0 ? "system" : pref;
  try{ localStorage.setItem("ham_theme", want); }catch(e){ /* private browsing */ }
  const media = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)");
  const dark = want === "dark" || (want === "system" && media && media.matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  /* Following the machine means following it as it changes, not only as it was
     when the page loaded. */
  if(media && !watching){
    watching = () => {
      if((localStorage.getItem("ham_theme") || "system") === "system")
        applyTheme("system");
    };
    if(media.addEventListener)media.addEventListener("change", watching);
    else if(media.addListener)media.addListener(watching);
  }
  return want;
}

export function currentTheme(){
  try{ return localStorage.getItem("ham_theme") || "system"; }catch(e){ return "system"; }
}
