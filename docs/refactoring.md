# A plan for splitting up the two big files

`static/index.html` is 2,632 lines and `app.py` is 5,724. This is a plan to
make them navigable, in steps that can each be shipped and verified on their
own.

- [What is actually wrong](#what-is-actually-wrong)
- [What is not wrong](#what-is-not-wrong)
- [Constraints](#constraints)
- [Stage 1 — split the front end](#stage-1--split-the-front-end)
- [Stage 2 — split the back end](#stage-2--split-the-back-end)
- [Stage 3 — the long functions](#stage-3--the-long-functions)
- [How each stage is verified](#how-each-stage-is-verified)
- [What I would not do](#what-i-would-not-do)
- [Order and effort](#order-and-effort)

## What is actually wrong

Measured, not guessed:

| | |
| --- | --- |
| `static/index.html` | 202 lines of markup, 155 of CSS, **2,427 of JavaScript** in one `<script>`, 75 functions, 24 commented sections |
| `app.py` | 5,724 lines, 209 functions, 24 commented sections |

The concrete costs:

- **Finding things.** "Where is the certificate wizard" is answered by scrolling
  or grepping, not by opening a file. Twenty-four sections in one file is a
  table of contents pretending to be a directory.
- **Name collisions.** Everything shares one scope. This has already produced a
  real bug: two pages both used `id="f_api_key"`, and `getElementById` returned
  the wrong one, so saving a peer stored this node's own key. A module boundary
  makes that class of mistake visible.
- **Merge friction.** Every change touches one of two files.
- **Tests reach in by slicing text.** The DOM harnesses locate code with
  `indexOf("const WD_STATE=")` and `eval` it. That works, but it means the
  tests know where code *sits*, not what it *exports*.

## What is not wrong

Worth saying, because it changes what the refactor should be:

- **The functions are small.** The median function in `app.py` is 13 lines.
  This is a big file of small, mostly independent pieces — not a tangle.
- **There is very little shared mutable state.** Six module-level variables in
  the whole front end (`who`, `readOnly`, `pageTimer`, `dnsApis`, `kaDiag`,
  `setupIfaceOptions`). That is what makes splitting cheap.
- **The sections are already the seams.** Both files carry section comments
  that map almost one-to-one onto the modules proposed below.

So this is a **move, don't rewrite** exercise. Behaviour should not change, and
every stage should be provable by tests that existed before it started.

## Constraints

These shape the design more than taste does:

1. **No build step.** Installing is copying files. There is no npm, no bundler,
   and adding one would mean a build artefact in git or a toolchain on every
   machine that packages a release. Browsers have supported ES modules for
   years; use them and keep the source as the deployed thing.
2. **Three deployment paths already exist.** The container copies `static/`
   whole and the packages ship it whole, so both handle a directory today. Only
   the installer's raw-file fallback names files individually — it fetches
   `app.py`, `static/index.html`, `VERSION`, `install.sh` and the icons — and
   that list would have to grow, or move to a manifest.
3. **The asset route is an allow-list.** `STATIC_ASSETS` names each servable
   file. Splitting the front end means either listing every module or serving
   `static/js/*.js` by extension.
4. **`app.py` is the entry point** named by the systemd unit, the packages, the
   Dockerfile and the docs. It should keep that name whatever moves out of it.

## Stage 1 — split the front end — **done**

Landed in 1.50.0. `index.html` went from 2,632 lines to 56: markup, a
stylesheet link and one `<script type="module">`. The JavaScript is 19 modules
under `static/js/`, the largest 393 lines.

What the plan did not anticipate, and what it cost:

- **Three files were needed that were not in the plan.** `state.js`, because a
  module cannot assign to a binding it imported, so the six shared variables had
  to become properties of one object. `shell.js`, because every page wanted
  `route()` and `refreshStatus()` from `main.js` while `main.js` imports every
  page — the shell now takes the page registry from `main.js` instead of
  importing it. And `static/FILES`, a manifest, because the installer's offline
  fallback fetches files by name and a list buried in a shell script would rot.
- **An import cycle is not automatically harmless.** The plan said cycles are
  fine for hoisted functions. True, but `core.js` exports `$` as a `const`, and
  a cycle meant `main.js` evaluated first and hit the temporal dead zone. The
  graph is acyclic now: `core.js` takes a handler from `auth.js` rather than
  importing it.
- **Two bugs the move exposed.** An inline `onclick="closeDlg()"` in the markup,
  which module scope cannot see, and three `let a=1,b=2` statements whose extra
  declarators my splitting script silently dropped.

The tooling is in `tools/uitests/`; `module-graph.mjs` is what makes stage 2
safe to attempt.

The rest of this section is the plan as written.

The bigger win, and the lower risk.

```
static/
  index.html          markup + <link> to the stylesheet + one <script type="module">
  css/app.css         the 155 lines of CSS, unchanged
  js/
    main.js           boot: routing, nav, first render
    api.js            fetch wrapper, session handling, the lists cache
    dom.js            $, esc, btn, openDlg/closeDlg, fieldRow, readForm, fieldEl
    entities.js       the E registry and the generic CRUD views
    pages/
      overview.js  services.js  stats.js  cluster.js  certificates.js
      acme.js      webui.js     backup.js admin.js    updates.js
      watchdog.js  notify.js    logs.js   setup.js    keepalived.js
```

Roughly 18 files, none much over 250 lines.

**Mechanics.** `index.html` keeps the markup and loads one module:

```html
<link rel="stylesheet" href="/static/css/app.css">
<script type="module" src="/static/js/main.js"></script>
```

Each page module exports its renderer; `main.js` holds the `NAV` table and the
page registry and imports them. The six shared mutable variables move into
`state.js` as an object (`state.who`, `state.readOnly`), because a module's
exported binding cannot be reassigned from outside it.

**Cost to be honest about.** The page goes from one request to about twenty.
On a LAN admin UI that is not worth a bundler, but it is not nothing: the
modules should be served with the `max_age` the icons already use.

**The one code change worth making at the same time**: give each dialog its own
field ids (`dlg_api_key` vs `page_api_key`) or scope lookups to the form
element. That is the duplicate-id bug at its root, and splitting the files is
when it is cheapest to fix.

## Stage 2 — split the back end

`app.py` becomes a thin entry point beside a package:

```
app.py                CLI, thread startup, _serve() -- 100 lines or so
ham/
  __init__.py         create_app(): builds the Flask app, registers blueprints
  config.py           DEFAULT_CONFIG, load/save, migrations, config_hash
  auth.py             sessions, passwords, the API key, _auth, the audit line
  crud.py             the generic collection/item routes
  render/
    haproxy.py        render_haproxy and its helpers
    keepalived.py     render_keepalived, derive_unicast
  apply.py            do_apply, check_rendered, validation
  acme.py             issuance, deployment, renewal, the DNS hook catalogue
  cluster.py          peers, sync push/receive, membership, snapshots
  watchdog.py         probes, restart policy, sd_notify
  notify.py           SMTP, Pushover, webhook, transitions
  logs.py             the four log readers and the merge
  stats.py            the admin socket
  updates.py          version check and one-click update
  wizard.py           wizard_publish and the service view
```

Each of those is an existing section of `app.py`, moved. Flask blueprints keep
the routes where their logic is.

**The ordering problem.** `_lock`, `log`, `load_config` and `save_config` are
used everywhere. They go in `config.py` and `logging.py`, imported by the rest —
no circular imports, because nothing in those two needs anything above them.

**Deployment changes**: the packages and the container already copy
directories; `install.sh` needs `ham/` added to both the copy step and the raw
fallback list.

## Stage 3 — the long functions

Only after the moves, and only these:

| Function | Lines | Why it is long |
| --- | --- | --- |
| `wizard_publish` | 382 | creates or updates six object types in sequence |
| `render_haproxy` | 220 | one long emit; genuinely linear |
| `api_setup_join` | 166 | joining does a lot, in order |

`render_haproxy` is fine as it is — a renderer that emits sections in order is
easier to read long than split. `wizard_publish` is the one worth breaking up,
into one function per object type it reconciles (`_reconcile_servers`,
`_reconcile_backend`, `_reconcile_frontend`, …), each returning what it made or
reused. That is also where the "editing must update, never duplicate" rules
live, so smaller pieces make those rules testable one at a time.

## How each stage is verified

The safety net already exists, which is what makes this worth doing now:

- **`regress.py`** — 32 end-to-end checks against a running container. Entirely
  API-level, so it does not care how the code is arranged. It must pass
  unchanged after every stage.
- **The DOM harnesses** (`wd_dom.js`, `notify_dom.js`, `logs_dom.js`) get
  *simpler*: instead of slicing text out of `index.html` and `eval`-ing it, they
  `import` the module under test. Rewriting them is part of stage 1, not extra.
- **`authcheck.py`** — walks every route and checks the rest refuse an anonymous
  caller. Route counts must not change during a move.
- **`tools/check-docs.py`** — the documented route count is checked against the
  code, so an accidentally dropped route fails the build.
- **A rendering diff**: capture `/api/preview` output for a fixed config before
  and after each stage; the generated `haproxy.cfg` must be byte-identical.

That last one is the strongest check for stage 2 and costs about ten lines.

## What I would not do

- **No bundler, no framework.** The UI is hand-written DOM code that a person
  can read. Rewriting it in a framework would be a different application, and
  would trade a build step for the thing that makes this installable by copying
  two files.
- **No rewrite of working logic.** Moving code and changing it in the same
  commit makes a bisect useless.
- **No splitting for its own sake.** `render_keepalived` and the settings
  validators are short and cohesive; leave them.
- **Not all at once.** Each stage lands separately, with the suites green in
  between.

## Order and effort

| Stage | Effort | Risk | Why in this order |
| --- | --- | --- | --- |
| 1. Front end | one sitting | low | biggest daily pain, and the DOM harnesses make it provable |
| 2. Back end | one or two | medium | more files, but blueprints are mechanical and the API tests are strict |
| 3. `wizard_publish` | half | medium | genuinely changes structure, so it goes last and alone |

A reasonable first commit is smaller than all of stage 1: move the CSS to
`css/app.css` and the plumbing (`dom.js`, `api.js`) out, leaving the pages in
place. That exercises the module loading, the asset route and all three
deployment paths with about 300 lines moved instead of 2,400 — and if something
about the deployment is wrong, it is found cheaply.
