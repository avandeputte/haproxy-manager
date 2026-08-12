// A DOM stub good enough to render this UI in node. It grows when the app
// uses something it does not have yet -- that is the stub catching up, not a
// bug in the app.
class El {
  constructor(t){ this.tagName=t; this.children=[]; this.style={cssText:""}; this.dataset={};
    this._html=""; this.className=""; this.textContent=""; this.value=""; this.checked=false;
    this.classList={add(){},remove(){},contains(){return false;},toggle(){}}; }
  /* Most of this UI builds markup as a string and then queries it, so the
     setter parses that string into children. Without it every
     card.querySelector(".hd") returns null here and works in a browser --
     the stub would be failing tests the product passes. Deliberately small:
     tags, attributes and text, which is all this app writes. */
  set innerHTML(v){
    this._html = v;
    this.children.length = 0;
    parseInto(this, String(v == null ? "" : v));
  }
  get innerHTML(){ return this._html; }
  appendChild(c){ if(!(c instanceof El)) throw new TypeError("appendChild got a non-Node");
    c._parent = this; this.children.push(c); return c; }
  insertAdjacentHTML(){} addEventListener(){} removeEventListener(){} dispatchEvent(){return true;}
  /* Search the children for real. Returning a fresh element for any selector
     -- which this used to do -- makes every lookup succeed, including the ones
     that return null in a browser. */
  matches(sel){
    /* "input,select,textarea" is one selector to a browser; treat any of the
       alternatives matching as a match. */
    if (sel.includes(",")) return sel.split(",").some(part => this.matches(part));
    sel = sel.trim();
    if (sel.startsWith("#")) return this.id === sel.slice(1);
    if (sel.startsWith(".")) return (this.className||"").split(/\s+/).includes(sel.slice(1));
    const attr = sel.match(/^\[([\w-]+)="?([^"\]]*)"?\]$/);
    if (attr) {
      const key = attr[1].startsWith("data-") ? attr[1].slice(5).replace(/-(\w)/g,(m,c)=>c.toUpperCase()) : attr[1];
      const have = attr[1].startsWith("data-") ? this.dataset[key] : this[key];
      return String(have == null ? "" : have) === attr[2];
    }
    return this.tagName === sel;
  }
  querySelector(sel){
    for (const c of this.children) {
      if (c.matches(sel)) return c;
      const deeper = c.querySelector(sel);
      if (deeper) return deeper;
    }
    return null;
  }
  querySelectorAll(sel){
    const out = [];
    for (const c of this.children) {
      if (c.matches(sel)) out.push(c);
      out.push(...c.querySelectorAll(sel));
    }
    return out;
  }
  /* Siblings come from the parent's child list, as in a document. Handing back
     a fresh element made every sibling lookup succeed. */
  get nextElementSibling(){
    const k = this._parent ? this._parent.children.indexOf(this) : -1;
    return k >= 0 ? (this._parent.children[k+1] || null) : null;
  }
  get previousElementSibling(){
    const k = this._parent ? this._parent.children.indexOf(this) : -1;
    return k > 0 ? this._parent.children[k-1] : null;
  }
  get parentNode(){ return this._parent || null; }
  insertBefore(c){ return this.appendChild(c); }
  /* a <select> exposes its <option>s, and code iterates them to relabel */
  get options(){ return this.querySelectorAll("option"); }
  /* everything a person would see: markup, text nodes and children */
  get text(){ return this._html + (this.textContent||"") + this.children.map(c=>c.text).join(""); }
  get firstChild(){ return this.children[0] || null; }
  removeChild(){} contains(){ return false; }
  setAttribute(){} getAttribute(){ return null; } removeAttribute(){} remove(){}
  replaceWith(){} focus(){} click(){} closest(){ return null; }
}
/* The ids the real page actually contains. Anything else must come back null,
   exactly as a browser would: a stub that conjures elements on demand hides
   every lookup that happens before its element is in the document. */
const PAGE_IDS = new Set(["applybtn", "banner", "brandhost", "content", "dlg", "dlgbody", "dlgclose", "dlgfoot", "dlgtitle", "lbtn", "lerr", "login", "loginbox", "loginintro", "logintitle", "lp", "lp2", "lp2wrap", "lu", "main", "nav", "navlinks", "nodestrip", "ovl", "pagetitle", "topbar", "whofoot"]);
const VOID = new Set(["br","hr","img","input","meta","link","source","path","circle","rect","use"]);
function parseInto(parent, html){
  const stack = [parent];
  const re = /<\/?([a-zA-Z][\w-]*)((?:\s+[^>]*?)?)\/?>|([^<]+)/g;
  let m;
  while ((m = re.exec(html))) {
    const [raw, tag, attrs, text] = m;
    const top = stack[stack.length - 1];
    if (text !== undefined) {
      if (text.trim()) top.textContent = (top.textContent || "") + text;
      continue;
    }
    if (raw.startsWith("</")) {
      if (stack.length > 1 && stack[stack.length-1].tagName === tag) stack.pop();
      continue;
    }
    const el = new El(tag);
    for (const a of (attrs || "").matchAll(/([\w-]+)(?:=("[^"]*"|'[^']*'|[^\s>]+))?/g)) {
      const name = a[1];
      const val = (a[2] || "").replace(/^["']|["']$/g, "");
      if (name === "class") el.className = val;
      else if (name === "id") el.id = val;
      else if (name.startsWith("data-"))
        el.dataset[name.slice(5).replace(/-(\w)/g, (x,c)=>c.toUpperCase())] = val;
      else el[name] = val;
    }
    top.children.push(el); el._parent = top;
    if (!VOID.has(tag) && !raw.endsWith("/>")) stack.push(el);
  }
}

const reg = new Map();
globalThis.document = {
  createElement: t => new El(t),
  createTextNode: () => new El("#text"),
  createDocumentFragment: () => new El("#fragment"),
  /* Only what is actually in the document, as a browser does. An id map that
     also holds detached elements makes a lookup succeed before its element has
     been attached -- which is exactly the bug this suite is meant to catch. */
  getElementById: id => {
    if (reg.has(id)) return reg.get(id);
    const seen = new Set();
    for (const root of reg.values()) {
      const hit = (function find(n){
        if (seen.has(n)) return null;
        seen.add(n);
        for (const c of n.children) {
          if (c.id === id) return c;
          const deeper = find(c);
          if (deeper) return deeper;
        }
        return null;
      })(root);
      if (hit) return hit;
    }
    return null;
  },
  querySelector: sel => {
    if (!sel.startsWith("#")) return null;
    const id = sel.slice(1);
    if (reg.has(id)) return reg.get(id);
    if (!PAGE_IDS.has(id)) return null;     /* not in index.html, so not there */
    const el = new El("div"); el.id = id; reg.set(id, el); return el;
  },
  querySelectorAll: () => [],
  createComment: () => new El("#comment"),
  addEventListener(){}, body: new El("body"), documentElement: new El("html"),
};
globalThis.window = { addEventListener(){},
  location: { hash: "", host: "localhost:8080", protocol: "http:" } };
globalThis.location = globalThis.window.location;
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({}), text: async () => "" });
globalThis.Event = class {};
globalThis.setTimeout = () => 0;
globalThis.setInterval = () => 0;

/* The app upgrades tables as they appear; under the stub nothing mutates,
   so observing is a no-op that still has to exist. */
globalThis.MutationObserver = class { observe(){} disconnect(){} takeRecords(){return [];} };
