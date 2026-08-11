#!/usr/bin/env python3
"""Write a page that uses the real stylesheet and the real sidebar markup."""
import pathlib, re, shutil

root = pathlib.Path(__file__).resolve().parents[3]
here = pathlib.Path(__file__).resolve().parent
css = (root / "static/css/app.css").read_text()
auth = (root / "static/js/auth.js").read_text()
m = re.search(r"g\.innerHTML=(.*?);\n", auth, re.S)
gear = "".join(re.findall(r"'([^']*)'", m.group(1))) if m else ""
items = "".join('<a class="item" href="#">Item %d</a>' % i for i in range(1, 19))

(here / "nav.html").write_text("""<!doctype html><html><head><meta charset=utf-8>
<style>%s</style></head><body>
<aside id="nav">
  <div class="brand"><img src="icon.svg" width="26" height="26">
    <span>haproxy<br><span class=brand2>cluster manager</span><small>node1 · v0</small></span></div>
  <div id="navlinks">%s</div>
  <div class="foot">
    <div class="whorow">
      <div class="who"><small>Signed in as</small>admin</div>
      <button class="lo gear" title="Account">%s</button>
    </div>
    <button class="lo">Sign out</button>
  </div>
</aside>
<div id="main"><div id="content" style="padding:20px"><h2>A long page</h2>%s</div></div>
</body></html>""" % (css, items, gear, "<p>content line</p>" * 40))
shutil.copy(root / "static/icon.svg", here / "icon.svg")
print("wrote %s" % (here / "nav.html"))
