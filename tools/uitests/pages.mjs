// The page harnesses, now importing the real modules instead of slicing text
// out of index.html and eval-ing it. Same assertions as before.
import fs from "node:fs";

class El {
  constructor(t){ this.tagName=t; this.children=[]; this.style={cssText:""}; this.dataset={};
    this._html=""; this.className=""; this.textContent=""; this.value=""; this.checked=false;
    this.id=""; this.type=""; this.disabled=false;
    this.classList={_s:new Set(),add(x){this._s.add(x);},remove(x){this._s.delete(x);},
                    contains(x){return this._s.has(x);},toggle(){}}; }
  set innerHTML(v){ this._html=v; } get innerHTML(){ return this._html; }
  appendChild(c){
    if(!(c instanceof El))
      throw new TypeError("Failed to execute 'appendChild' on 'Node': parameter 1 is not of type 'Node'.");
    this.children.push(c); if(c.id) reg.set(c.id, c); return c; }
  insertAdjacentHTML(_,h){ this._html+=h; }
  addEventListener(){} removeEventListener(){} dispatchEvent(){return true;}
  querySelector(){ return new El("div"); }
  querySelectorAll(sel){
    const out=[];
    if(/data-event/.test(sel))
      for(const m of this._html.matchAll(/data-event="([a-z]+)"/g)){
        const e=new El("input"); e.dataset.event=m[1]; e.checked=true; out.push(e); }
    if(/data-src/.test(sel))
      for(const m of this._html.matchAll(/data-src="([a-z]+)"/g)){
        const e=new El("input"); e.dataset.src=m[1]; e.checked=true; out.push(e); }
    return out; }
  setAttribute(){} getAttribute(){return null;} remove(){} replaceWith(){} focus(){} closest(){return null;}
  get nextElementSibling(){ return this._n || (this._n=new El("div")); }
  get previousElementSibling(){ return this._p || (this._p=new El("div")); }
  get parentNode(){ return this._pa || (this._pa=new El("div")); }
  insertBefore(c){ return this.appendChild(c); }
  get text(){ return this._html + this.children.map(c=>c.text).join(""); }
}
const reg = new Map();
globalThis.document = {
  createElement: t => new El(t), createTextNode: () => new El("#text"),
  createDocumentFragment: () => new El("#fragment"),
  getElementById: id => reg.get(id) || null,
  querySelector: sel => { const id=sel.replace("#",""); if(!reg.has(id)) reg.set(id,new El("div")); return reg.get(id); },
  querySelectorAll: () => [], addEventListener(){}, body: new El("body"),
};
globalThis.window = { addEventListener(){}, location:{hash:"",host:"h:8080"} };
globalThis.location = globalThis.window.location;
globalThis.localStorage = { getItem:()=>null, setItem(){}, removeItem(){} };
globalThis.Event = class {};
globalThis.setTimeout = () => 0;
globalThis.setInterval = () => 0;
let feed = null, lastPath = null;
globalThis.fetch = async (p) => { lastPath = p;
  return { ok:true, status:200, json: async () => feed, text: async () => "" }; };

const root = process.cwd() + "/static/js/";
const { renderWatchdog } = await import(root + "pages/watchdog.js");
const { renderNotify }   = await import(root + "pages/notify.js");
const { renderLogs }     = await import(root + "pages/logs.js");
const content = document.querySelector("#content");

let fail = 0;
const ok = (c,m) => { console.log((c?"  PASS  ":"  FAIL  ")+m); if(!c) fail++; };
const html = () => content.children.map(c=>c.text).join("") + content.innerHTML;
const reset = () => { content.children.length = 0; content.innerHTML = ""; };

/* ---- watchdog ---- */
feed = { settings:{enabled:true,haproxy:true,keepalived:true,interval:20,max_restarts:3,window:900},
         systemd:true, last_run:"2026-08-11T00:00:00+00:00", self:{ok:true,detail:"",ms:4},
         services:{haproxy:{state:"ok",detail:"answered in 2 ms"},
                   keepalived:{state:"down",detail:"the service is failed",action:"restarted"}},
         events:[{time:"t",unit:"keepalived",level:"warning",message:"is not running -- restarting it"}] };
reset(); await renderWatchdog();
ok(html().includes("haproxy") && html().includes("keepalived"), "watchdog: both services listed");
ok(html().includes("answered in 2 ms"), "watchdog: liveness detail shown");
ok(html().includes("systemd is watching"), "watchdog: says systemd supervises the process");
ok(!html().includes("[object Object]"), "watchdog: nothing renders as [object Object]");

/* ---- notifications ---- */
feed = { ok:true, settings:{enabled:true,min_severity:"warning",repeat_hours:6,
          events:{certificates:true,watchdog:true,apply:true,cluster:true,updates:false},
          destinations:[{id:"1",name:"ops mailbox",type:"smtp",enabled:true,host:"smtp.example.com",to:"ops@example.com"},
                        {id:"2",name:"my phone",type:"pushover",enabled:true,has_token:true,has_user:true}]},
         recent:[{time:"t",destination:"ops mailbox",ok:true,detail:"sent"}] };
reset(); await renderNotify();
ok(html().includes("ops mailbox") && html().includes("my phone"), "notify: destinations listed");
ok(html().includes("token set"), "notify: a stored secret is shown as set, not revealed");
ok(!html().includes("[object Object]"), "notify: nothing renders as [object Object]");

/* ---- logs ---- */
const now = Math.floor(Date.now()/1000);
feed = { ok:true, failed:[], entries:[
  {ts:now-2,source:"manager",level:"INFO",text:"admin POST /api/apply -> 200"},
  {ts:now-1,source:"haproxy",level:"WARNING",text:"backend pg has no server available!"},
  {ts:now,  source:"acme",level:"ERROR",text:"certificate wild: failed"} ] };
reset(); await renderLogs();
ok(html().includes("src-haproxy") && html().includes("src-acme"), "logs: sources are tagged");
ok(html().includes("<tr class=ERROR>"), "logs: level drives the row class");
feed.entries = [{ts:now,source:"haproxy",level:"INFO",text:'<img src=x onerror="alert(1)">'}];
reset(); await renderLogs();
ok(html().includes("&lt;img") && !html().includes("<img"), "logs: text is escaped");

console.log(fail ? "\n"+fail+" FAILED" : "\nevery page renders from its own module");
process.exit(fail?1:0);
