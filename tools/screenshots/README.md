# Regenerating the screenshots in `docs/img/`

They are photographs of the real application, driven by a real browser against
a real three-node cluster holding made-up data. Nothing is mocked: a picture of
a page that cannot happen is worse than no picture.

## The cluster

The whole rig is a script. It builds three containers on one Docker network,
so Keepalived runs actual VRRP and one node genuinely holds the virtual IP;
publishes services whose health checks pass against listeners that exist;
creates users, groups and a sign-in; issues certificates from a throwaway CA
that the node trusts, so they verify; and seeds a day of plausible traffic
with one incident, so the error line has something to show.

```bash
docker build -t ham-shot .
docker network create --subnet 172.28.0.0/24 shotnet
for n in 1 2 3; do
  docker run -d --name proxy$n --hostname proxy$n --network shotnet \
    --ip 172.28.0.1$n --cap-add NET_ADMIN --cap-add NET_BROADCAST \
    --cap-add NET_RAW -p 1590$n:8080 ham-shot
done
bash tools/screenshots/demo-cluster.sh
```

If a passive node is holding the virtual IP afterwards (nopreempt: whoever
took it first keeps it), restart Keepalived on that node and proxy1 -- the
highest priority -- takes over:

```bash
docker exec proxy2 supervisorctl restart keepalived
```

## Taking them

```bash
npm i puppeteer
OUT=/tmp/shots BASE=http://127.0.0.1:15901 node tools/screenshots/shoot.js
```

Then scale to 1600px wide and quantise to a 256-colour palette before
committing -- the interface is flat colour and text, so a palette holds it
exactly at about a fifth of the bytes. With Pillow:

```python
im = Image.open(f).convert("RGB")
im = im.resize((1600, round(im.height * 1600 / im.width)), Image.LANCZOS)
im.convert("P", palette=Image.ADAPTIVE, colors=256).save(out, optimize=True)
```

`tools/check-docs.py` holds the guards: every committed screenshot is
referenced, every referenced one is committed, and none is over 400 KB.
