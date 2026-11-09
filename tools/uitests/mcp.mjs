/* Settings > MCP server: on and off, read-only or changes allowed, a token
 * that can be shown again, and what to give each client, with the token in
 * it once shown. The tools are on the documentation site, linked. */
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
/* linkedom (0.18) clears the selected option when any other is unselected,
   and has no select.value setter: put both right, as proxy-protocol.mjs does. */
const optProto = Object.getPrototypeOf(document.createElement("option"));
Object.defineProperty(optProto, "selected", {
  configurable: true,
  get() { return this.hasAttribute("selected"); },
  set(v) {
    if (v) {
      const prev = this.parentElement && this.parentElement.querySelector("option[selected]");
      if (prev && prev !== this) prev.removeAttribute("selected");
      this.setAttribute("selected", "");
    } else this.removeAttribute("selected");
  },
});
globalThis.location = { hash: "#/p:mcp", origin: "https://ham.example.com" };
globalThis.MutationObserver = class { observe(){} };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.setTimeout = () => 0;
let asked = 0;
globalThis.confirm = () => { asked++; return true; };
let clip = null;
Object.defineProperty(globalThis, "navigator", { configurable: true,
  value: { platform: "MacIntel", clipboard: { writeText: async s => { clip = s; } } } });

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
  if (p === "mcp/token" && method === "POST") {
    state = { ...state, has_token: true, token_shown: true, token_fp: "abcd1234", token_created: "2026-11-08T10:00:00+00:00" };
    out = { ok: true, token: "ham_mcp_SECRET", token_fp: "abcd1234", pushed: [] }; }
  if (p === "mcp/token" && method === "GET") out = { ok: true, token: "ham_mcp_SECRET", token_fp: "abcd1234" };
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
ok(!text().includes("get_status") && !!document.querySelector('a[href="https://ham.iothing.net/docs/mcp/"]'),
   "the tools are not listed here: the page links to them on the documentation site");
ok(!!findButton("Make a token") && !findButton("Replace the token"), "no token yet: one can be made");

$("#f_enabled").checked = true;
await findButton("Save").onclick();
const put = sent.find(s => s.p === "mcp" && s.method === "PUT");
ok(put && put.body.enabled === true && put.body.allow_writes === false, "saving sends the switches");
ok(text().includes("on, read-only"), "then shows it on, read-only");
ok(text().includes("node-b"), "and names a node the settings did not reach");

ok($("#mcp_cmd").textContent.includes("Bearer <token>") && text().includes("Make a token first"),
   "with no token, the client text has a placeholder and says to make one");
await findButton("Make a token").onclick();
ok(asked === 0, "making the first token asks nothing");
ok($("#mcp_tok").textContent === "ham_mcp_SECRET" && $("#mcp_tok").style.display !== "none", "the new token is shown");
ok($("#mcp_cmd").textContent ===
   'claude mcp add --scope user --transport http haproxy-manager https://ham.example.com/mcp --header "Authorization: Bearer ham_mcp_SECRET"',
   "with the Claude Code line, for every project (--scope user)");

await renderMcp();
ok(!text().includes("ham_mcp_SECRET") && text().includes("abcd1234") && $("#mcp_cmd").textContent.includes("<token>"),
   "opened again, the token is hidden behind its fingerprint");
await findButton("Show the token").onclick();
ok($("#mcp_tok").textContent === "ham_mcp_SECRET" && $("#mcp_cmd").textContent.includes("Bearer ham_mcp_SECRET")
   && !!findButton("Hide the token"), "and can be shown again, filling in the client's text");
await findButton("Hide the token").onclick();
ok($("#mcp_tok").style.display === "none" && $("#mcp_cmd").textContent.includes("<token>"), "and hidden again");

const pick = $("#mcp_client");
const choose = id => { [...pick.options].forEach(o => { o.selected = o.value === id; }); pick.onchange(); };
const want = { codex: 'http_headers = { "Authorization" = "Bearer <token>" }',
               antigravity: '"serverUrl": "https://ham.example.com/mcp"',
               openclaw: '"transport": "streamable-http"',
               vscode: '"type": "http"',
               "claude-desktop": '"mcp-remote"',
               zed: '"context_servers"' };
for (const [id, frag] of Object.entries(want)) {
  choose(id);
  ok($("#mcp_cmd").textContent.includes(frag), id + ": " + frag);
}
ok(text().includes("~/.codex/config.toml") || (choose("codex"), text().includes("~/.codex/config.toml")),
   "and where it goes");
choose("cursor");
JSON.parse($("#mcp_cmd").textContent);
ok(true, "a JSON snippet is valid JSON");
const copyBtn = [...document.querySelectorAll("button")].filter(b => b.textContent === "Copy").pop();
await copyBtn.onclick();
ok(clip && clip.includes("Bearer ham_mcp_SECRET") && $("#mcp_cmd").textContent.includes("<token>"),
   "Copy copies the text with the token in it, without showing it");

state.token_shown = false;
await renderMcp();
ok(!findButton("Show the token") && text().includes("made before tokens were kept")
   && text().includes("Replace the token, above") && !text().includes("Show the token to fill it in"),
   "a token made before they were kept cannot be shown, and both cards say to replace it");
await findButton("Replace the token").onclick();
ok(asked === 1, "replacing a token asks first: clients using it stop working");

console.log(fail ? `\n${fail} failed` : "\nan MCP server you can turn on, and off");
process.exit(fail ? 1 : 0);
