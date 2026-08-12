/* Overwriting another node's configuration.

   This is the destructive one: it throws away whatever is on the other node.
   So it has to ask first, it has to send the flag that actually does it, and
   saying no has to leave the other node alone. */
import "./stub-dom.mjs";

let sent = null, asked = [], answer = true;
globalThis.confirm = (q) => { asked.push(q); return answer; };
globalThis.fetch = async (u, o) => {
  const path = String(u).replace(/^\/api\//, "").split("?")[0];
  if (o && o.body && path === "sync/push") sent = JSON.parse(o.body);
  const bodies = {
    "local": { sync: { auto_sync: true, peers: [
      { id: "p1", name: "proxy2", url: "http://proxy2.invalid:8080", enabled: true },
    ] } },
    "sync/push": { ok: true, results: [{ name: "proxy2", ok: true }] },
  };
  return { ok: true, status: 200, json: async () => bodies[path] || {},
           text: async () => "" };
};

const mod = await import("../../static/js/pages/cluster.js");
let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };

const peers = [{ id: "p1", name: "proxy2", url: "http://proxy2.invalid:8080",
                 enabled: true, api_key: "k" }];
const frag = mod.peersCard(peers, { sync: { auto_sync: true, peers } });
const el = document.createElement("div");
el.appendChild(frag);
const buttons = [...el.querySelectorAll("button")].map(b => b.textContent);
ok(buttons.includes("Overwrite"), "each node offers Overwrite: " + buttons.join(", "));
ok(buttons.includes("Overwrite every node"), "and there is one for all of them");
ok(buttons.includes("Sync"), "the ordinary Sync is still there beside it");

const press = async (label) => {
  sent = null; asked = [];
  const b = [...el.querySelectorAll("button")].find(x => x.textContent === label);
  await b.onclick();
};

answer = true;
await press("Overwrite");
ok(asked.length === 1, "it asks before overwriting one node");
ok(/discarded/.test(asked[0]), "and says what is lost: " + JSON.stringify(asked[0].slice(-60)));
ok(sent && sent.overwrite === true, "then sends overwrite");
ok(sent && sent.peer === "p1", "for that node only");

await press("Overwrite every node");
ok(sent && sent.overwrite === true && !sent.peer, "the other one sends it for every node");
ok(/every other node/.test(asked[0]), "and asks about all of them");

answer = false;
await press("Overwrite");
ok(sent === null, "answering no sends nothing at all");

answer = true;
await press("Sync");
ok(sent && !sent.overwrite, "an ordinary Sync never overwrites");
ok(asked.length === 0, "and does not ask, because it cannot destroy anything");

console.log(fail ? `\n${fail} failed` : "\noverwriting asks first and does what it says");
process.exit(fail ? 1 : 0);
