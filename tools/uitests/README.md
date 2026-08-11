# Front-end checks

No browser here, so these run the real modules under a stub DOM in node.

```bash
node tools/uitests/module-graph.mjs      # every module links and evaluates
node tools/uitests/pages.mjs             # the pages render from their modules
node tools/uitests/undefined-names.mjs   # a module uses no name it does not have
```

`module-graph.mjs` is the one that matters most after moving code: it imports
every module, so a wrong import name or a missing export fails immediately
rather than when someone opens that page. It also boots `main.js`, which is why
the stub grows an occasional `previousElementSibling` -- those additions are
the stub catching up with the app, not the app misbehaving.

`table-sorting-dom.mjs` needs a real DOM and skips itself without one. The stub
here is deliberately thin, and reordering rows is exactly the kind of thing it
cannot model honestly:

```bash
npm i linkedom            # anywhere
LINKEDOM=/path/to/node_modules/linkedom/esm/index.js \
  node tools/uitests/table-sorting-dom.mjs
```

`undefined-names.mjs` is a lint, not a parser: it reports a few names that come
from regex literals. Treat multi-character names as real and single letters
with suspicion.
