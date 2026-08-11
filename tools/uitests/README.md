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

`undefined-names.mjs` is a lint, not a parser: it reports a few names that come
from regex literals. Treat multi-character names as real and single letters
with suspicion.
