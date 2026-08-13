/* Screenshots of the running app, for the documentation.

   Drives a real browser against a real node holding made-up data, rather than
   mocking anything: a picture of a page that cannot happen is worse than no
   picture. */
const puppeteer = require("puppeteer");
const path = require("path");
const fs = require("fs");

const BASE = process.env.BASE || "http://127.0.0.1:15901";
const OUT = process.env.OUT || "/tmp/shots";
const USER = "admin", PASS = "demo-password-1";

const SHOTS = [
  { file: "overview",     hash: "#/",                 wait: ".card" },
  { file: "services",     hash: "#/p:services",       wait: "table" },
  { file: "statistics",   hash: "#/p:stats",          wait: "svg.spark" },
  { file: "certificates", hash: "#/acme/certificates", wait: "table" },
  { file: "cluster",      hash: "#/p:cluster",        wait: "table" },
  { file: "logs",         hash: "#/p:logs",           wait: ".card" },
  { file: "watchdog",     hash: "#/p:watchdog",       wait: ".card" },
  { file: "webui",        hash: "#/p:webui",          wait: ".frm" },
  { file: "notifications", hash: "#/p:notify",        wait: ".card" },
  { file: "backends",     hash: "#/haproxy/backends", wait: "table" },
];

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox", "--force-device-scale-factor=2"],
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 900, deviceScaleFactor: 2 });

  await page.goto(BASE + "/", { waitUntil: "networkidle2" });
  await page.waitForSelector("#lu");
  await page.type("#lu", USER);
  await page.type("#lp", PASS);
  await Promise.all([
    page.click("#lbtn"),
    page.waitForFunction(() => !document.querySelector("#login").classList.contains("show"),
                         { timeout: 15000 }),
  ]);
  console.log("signed in");

  for (const shot of SHOTS) {
    await page.evaluate(h => { location.hash = h; }, shot.hash);
    await new Promise(r => setTimeout(r, 1200));
    try {
      await page.waitForSelector(shot.wait, { timeout: 8000 });
    } catch (e) {
      console.log("  " + shot.file + ": " + shot.wait + " never appeared, shooting anyway");
    }
    await new Promise(r => setTimeout(r, 600));
    const file = path.join(OUT, shot.file + ".png");
    await page.screenshot({ path: file, fullPage: false });
    console.log("  " + shot.file + " -> " + (fs.statSync(file).size / 1024).toFixed(0) + " KB");
  }

  // The publish wizard, which is the thing people actually do
  await page.evaluate(() => { location.hash = "#/p:services"; });
  await new Promise(r => setTimeout(r, 1000));
  const clicked = await page.evaluate(() => {
    const b = [...document.querySelectorAll("button")]
      .find(x => /Publish a service/.test(x.textContent));
    if (!b) return false;
    b.click(); return true;
  });
  if (clicked) {
    await new Promise(r => setTimeout(r, 800));
    await page.screenshot({ path: path.join(OUT, "wizard.png") });
    console.log("  wizard");
    // and the recipe picker open, since that is what makes it quick
    await page.select("#f_recipe", "jellyfin").catch(() => {});
    await new Promise(r => setTimeout(r, 600));
    await page.screenshot({ path: path.join(OUT, "wizard-recipe.png") });
    console.log("  wizard-recipe");
  }

  await browser.close();
})().catch(e => { console.error("FAILED:", e.message); process.exit(1); });
