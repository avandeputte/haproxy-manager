// A DOM stub good enough to render this UI in node. It grows when the app
// uses something it does not have yet -- that is the stub catching up, not a
// bug in the app.
class El {
  constructor(t){ this.tagName=t; this.children=[]; this.style={cssText:""}; this.dataset={};
    this._html=""; this.className=""; this.textContent=""; this.value=""; this.checked=false;
    this.classList={add(){},remove(){},contains(){return false;},toggle(){}}; }
  set innerHTML(v){ this._html=v; } get innerHTML(){ return this._html; }
  appendChild(c){ if(!(c instanceof El)) throw new TypeError("appendChild got a non-Node"); this.children.push(c); return c; }
  insertAdjacentHTML(){} addEventListener(){} removeEventListener(){} dispatchEvent(){return true;}
  querySelector(){ return new El("div"); } querySelectorAll(){ return []; }
  get nextElementSibling(){ return this._next || (this._next = new El("div")); }
  get previousElementSibling(){ return this._prev || (this._prev = new El("div")); }
  get parentNode(){ return this._parent || (this._parent = new El("div")); }
  insertBefore(c){ return this.appendChild(c); }
  get firstChild(){ return this.children[0] || null; }
  removeChild(){} contains(){ return false; }
  setAttribute(){} getAttribute(){ return null; } removeAttribute(){} remove(){}
  replaceWith(){} focus(){} click(){} closest(){ return null; }
}
const reg = new Map();
globalThis.document = {
  createElement: t => new El(t),
  createTextNode: () => new El("#text"),
  createDocumentFragment: () => new El("#fragment"),
  getElementById: id => reg.get(id) || null,
  querySelector: sel => { const id = sel.replace("#",""); if(!reg.has(id)) reg.set(id, new El("div")); return reg.get(id); },
  querySelectorAll: () => [],
  createComment: () => new El("#comment"),
  addEventListener(){}, body: new El("body"), documentElement: new El("html"),
};
globalThis.window = { addEventListener(){}, location: { hash: "", host: "localhost:8080" } };
globalThis.location = globalThis.window.location;
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({}), text: async () => "" });
globalThis.Event = class {};
globalThis.setTimeout = () => 0;
globalThis.setInterval = () => 0;
