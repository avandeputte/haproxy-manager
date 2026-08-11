# Looking at it

Some things only a picture shows. The account gear was on its own line in a
dark box, and no assertion about the DOM would have said so.

`build.py` writes an HTML page using the real stylesheet and the real markup;
render it with a headless browser and look:

```bash
python3 tools/uitests/screenshot/build.py            # writes nav.html
docker run --rm -v "$PWD/tools/uitests/screenshot":/w -w /w \
  zenika/alpine-chrome --no-sandbox --headless --disable-gpu \
  --screenshot=/w/wide.png --window-size=1100,520 --hide-scrollbars file:///w/nav.html
```

Render at 1100 **and** at 760: the layout changes below 840px, and the first
attempt at a sticky sidebar would have taken over the whole screen on a phone.
