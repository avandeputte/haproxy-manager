/* The Web UI access page opens by telling you what it is for. That sentence
   used to say "instead of http://<the host you are on>", which is wrong the
   moment the page has worked: you are then reading it through the published
   address, and it offered to replace that address with itself. */
import "./stub-dom.mjs";
const { blurb } = await import("../../static/js/pages/webui.js");

let fails = 0;
const ok = (cond, msg) => { console.log((cond ? "  PASS  " : "  FAIL  ") + msg); if (!cond) fails++; };
const at = (proto, host) => { location.protocol = proto; location.host = host; };

at("http:", "10.0.0.1:8080");
let t = blurb({ enabled: false, url: "", shared_url: "" });
ok(/Publish this management UI/.test(t), "unpublished: it offers to publish");
ok(t.includes("http://10.0.0.1:8080"), "and names the raw address you are on");

at("https:", "proxy.example.com");
t = blurb({ enabled: true, url: "https://proxy1.example.com",
            shared_url: "https://proxy.example.com" });
ok(!/instead of/.test(t), "on the shared address: it does not offer to replace it");
ok(/shared address/.test(t) && t.includes("https://proxy.example.com"),
   "it says you came in on the shared address");
ok(/virtual IP/.test(t), "and explains what that address means");

at("https:", "proxy1.example.com");
t = blurb({ enabled: true, url: "https://proxy1.example.com",
            shared_url: "https://proxy.example.com" });
ok(/this node specifically/.test(t) && t.includes("https://proxy1.example.com"),
   "on a node address: it says this node specifically");
ok(!/shared address/.test(t), "and does not confuse it with the shared one");

at("https:", "proxy1.example.com/");
t = blurb({ enabled: true, url: "https://proxy1.example.com/", shared_url: "" });
ok(/this node specifically/.test(t), "a trailing slash still matches");

at("https:", "PROXY1.example.com");
t = blurb({ enabled: true, url: "https://proxy1.example.com", shared_url: "" });
ok(/this node specifically/.test(t), "so does a difference in case");

at("http:", "10.0.0.1:8080");
t = blurb({ enabled: true, url: "https://proxy1.example.com",
            shared_url: "https://proxy.example.com" });
ok(/reached it directly/.test(t), "published but reached on the raw port: it says so");
ok(!/Publish this management UI/.test(t),
   "and does not offer to do what it has already done");

console.log(fails ? `\n${fails} failed` : "\nthe opening line matches how you got here");
process.exit(fails ? 1 : 0);
