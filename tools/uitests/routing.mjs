// One page is drawn at a time.
//
// Every renderer empties #content and then waits -- for /api/status, for the
// services, for the traffic history -- before filling it again. Two renders
// that overlap therefore both empty it and both fill it, and the page ends up
// with two of everything. That is not hypothetical: opening the app and
// clicking a menu entry while it is still loading did it, and the Overview
// came up with the cluster listed twice.
import { setTimeout as sleep } from "node:timers/promises";
import "./stub-dom.mjs";   // which replaces setTimeout with a no-op

const { setPages, setRenderers, route } = await import(process.cwd() + "/static/js/shell.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };

const content = document.querySelector("#content");
const drawn = [];
let running = 0, overlapped = false;

/* A renderer shaped like the real ones: clear, wait, fill. */
const slow = (name, ms) => async () => {
  running++;
  if (running > 1) overlapped = true;
  content.children.length = 0;
  await sleep(ms);
  const card = document.createElement("div");
  card.className = "card";
  card.textContent = name;
  content.appendChild(card);
  drawn.push(name);
  running--;
};

setPages({ services: slow("services", 20), stats: slow("stats", 5) });
setRenderers({ entities: {}, entity: slow("entity", 5), settings: slow("settings", 5),
               overview: slow("overview", 30) });

location.hash = "#/";
const first = route();
location.hash = "#/p:services";
const second = route();
location.hash = "#/p:stats";
const third = route();
await Promise.all([first, second, third]);

ok(!overlapped, "two renders never run at the same time");
ok(content.children.length === 1, "so the page holds one copy of what was drawn, not several");
ok(drawn[drawn.length - 1] === "stats", "and it is the page asked for last: " + drawn.join(" -> "));
ok(drawn.length <= 2, "the ones overtaken on the way are dropped rather than drawn: " +
   drawn.join(" -> "));

// A renderer that throws must not wedge the queue behind it.
setPages({ services: async () => { throw new Error("boom"); }, stats: slow("stats", 5) });
location.hash = "#/p:services";
await route();
location.hash = "#/p:stats";
await route();
ok(drawn[drawn.length - 1] === "stats", "a page that fails does not stop the next one drawing");

console.log(fail ? `\n${fail} failed` : "\nrendering is one page at a time");
process.exit(fail ? 1 : 0);
