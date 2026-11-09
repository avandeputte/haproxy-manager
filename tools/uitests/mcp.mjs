/* Settings > MCP server: on and off, read-only or changes allowed, a token
 * shown once with the line to paste into Claude Code, and the tools listed. */
let parseHTML;
for (const where of ["linkedom", process.env.LINKEDOM]) {
  if (!where) continue;
  try { ({ parseHTML } = await import(where)); break; } catch { /* try the next */ }
}
if (!parseHTML) {
  console.log("  skipped: no DOM available (npm i linkedom, or set LINKEDOM)");
  process.exit(0);
}
const REPO = process.cwd();
const { document, window } = parseHTML(`<!doctype html><html><body>
<div id="ovl"><div id="dlg"><div class="hd"><h3 id="dlgtitle"></h3>
<button id="dlgclose"></button></div><div class="bd" id="dlgbody"></div>
<div class="ft" id="dlgfoot"></div></div></div>
<aside id="nav"><div class="foot" id="whofoot"></div></aside>
<div id="content"></div></body></html>`);
globalThis.document = document; globalThis.window = window;
globalThis.location = { hash: "#/p:mcp", origin: "https://ham.example.com" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = () => 0;
let asked = 0;
globalThis.confirm = () => { asked++; return true; };

let state = { enabled: false, allow_writes: false, has_token: false, token_fp: "", token_created: "",
  tools: [{ name: "get_status", title: "Node status", write: false },
          { name: "apply_changes", title: "Apply", write: true }] };
let sent = [];
globalThis.fetch = async (u, o) => {
  const p = String(u).replace(/^\/api\//, "");
  const method = (o && o.method) || "GET";
  const body = o && o.body ? JSON.parse(o.body) : null;
  sent.push({ p, method, body });
  let out = state;
  if (p === "mcp" && method === "PUT") { Object.assign(state, body); out = { ok: true, pushed: [{ ok: false, name: "node-b", error: "timed out" }] }; }
  if (p === "mcp/token") { state = { ...state, has_token: true, token_fp: "abcd1234", token_created: "2026-11-08T10:00:00+00:00" };
                           out = { ok: true, token: "ham_mcp_SECRET", token_fp: "abcd1234", pushed: [] }; }
  return { ok: true, status: 200, json: async () => out, text: async () => "" };
};

const { renderMcp } = await import(REPO + "/static/js/pages/mcp.js");
let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const $ = s => document.querySelector(s);
const findButton = label => [...document.querySelectorAll("button")].find(b => b.textContent === label) || null;

await renderMcp();
const text = () => $("#content").textContent;
ok(text().includes("off") && !$("#f_enabled").checked && !$("#f_allow_writes").checked,
   "off and read-only to begin with");
ok(text().includes("virtual IP"), "and says to point a client at the virtual IP");
ok(text().includes("get_status") && text().includes("apply_changes") && text().includes("changes") && text().includes("reads"),
   "the tools are listed, reading and changing ones told apart");
ok(!!findButton("Make a token") && !findButton("Replace the token"), "no token yet: one can be made");

$("#f_enabled").checked = true;
await findButton("Save").onclick();
const put = sent.find(s => s.p === "mcp" && s.method === "PUT");
ok(put && put.body.enabled === true && put.body.allow_writes === false, "saving sends the switches");
ok(text().includes("on, read-only"), "then shows it on, read-only");
ok(text().includes("node-b"), "and names a node the settings did not reach");

await findButton("Make a token").onclick();
ok(asked === 0, "making the first token asks nothing");
ok($("#mcp_tok").textContent === "ham_mcp_SECRET", "the token is shown");
ok($("#mcp_cmd").textContent ===
   'claude mcp add --transport http haproxy-manager https://ham.example.com/mcp --header "Authorization: Bearer ham_mcp_SECRET"',
   "with the line to paste into Claude Code");

await renderMcp();
ok(!text().includes("ham_mcp_SECRET") && text().includes("abcd1234"),
   "shown again, the page has only its fingerprint");
await findButton("Replace the token").onclick();
ok(asked === 1, "replacing a token asks first: clients using it stop working");

console.log(fail ? `\n${fail} failed` : "\nan MCP server you can turn on, and off");
process.exit(fail ? 1 : 0);
