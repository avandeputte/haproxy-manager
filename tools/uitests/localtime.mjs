/* Timestamps are shown on the reader's clock, not the server's.
 *
 * The server speaks UTC everywhere; the browser is the only place that knows
 * where the reader is. This suite re-runs itself pinned to UTC+13 (a fixed
 * offset, so no daylight-saving date can bend the expected values) -- run in
 * the machine's own zone it could pass by coincidence on any machine sitting
 * at UTC.
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ZONE = "Etc/GMT-13";           /* POSIX sign: GMT-13 means UTC+13 */
if (process.env.TZ !== ZONE) {
  const r = spawnSync(process.execPath, [fileURLToPath(import.meta.url)],
                      { env: { ...process.env, TZ: ZONE }, encoding: "utf8" });
  process.stdout.write(r.stdout || "");
  process.stderr.write(r.stderr || "");
  process.exit(r.status ?? 1);
}

import "./stub-dom.mjs";
const { localTime } = await import(process.cwd() + "/static/js/core.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };

ok(localTime("2026-08-14T02:07:02+00:00") === "2026-08-14 15:07:02",
   "a UTC timestamp reads as the reader's own clock");
ok(localTime("2026-08-14T22:30:00+00:00") === "2026-08-15 11:30:00",
   "and crosses into the reader's tomorrow when it should");
ok(localTime("2026-08-14T02:07:02Z") === "2026-08-14 15:07:02",
   "the Z spelling of UTC reads the same");
ok(localTime("2026-08-14T02:07:02") === "2026-08-14 15:07:02",
   "a timestamp with no zone on it is the server forgetting to say UTC, not local time");
ok(localTime("Aug 14 02:07:02 2026 GMT") === "2026-08-14 15:07:02",
   "openssl's notAfter spelling converts too");
ok(localTime("") === "" && localTime(null) === "" && localTime(undefined) === "",
   "nothing in, nothing out");
ok(localTime("never") === "never",
   "what is not a date is shown as it was sent rather than as garbage");

console.log(fail ? `\n${fail} failed` : "\ntimestamps read on the reader's clock");
process.exit(fail ? 1 : 0);
