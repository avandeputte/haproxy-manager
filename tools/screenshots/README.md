# Regenerating the screenshots in `docs/img/`

They are photographs of the real application, driven by a real browser against
a real three-node cluster holding made-up data. Nothing is mocked: a picture of
a page that cannot happen is worse than no picture.

## The cluster

Three containers on one Docker network, so Keepalived runs actual VRRP between
them and one of them genuinely holds the virtual IP:

```bash
docker build -t ham-shot .
docker network create shotnet
for n in 1 2 3; do
  docker run -d --name shot$n --network shotnet --cap-add NET_ADMIN -p 1590$n:8080 \
    -e HAM_ADMIN_USER=admin -e HAM_ADMIN_PASSWORD=demo-password-1 ham-shot
done
```

`NET_ADMIN` is what lets Keepalived move the address. Give nodes 2 and 3 an API
key (`app.py set-api-key`), add them as peers on node 1, set the cluster's
virtual IP, and publish a handful of services with `example.com` names. Set
node 1's Keepalived priority highest and restart whichever node currently holds
the address: with `nopreempt` on, the highest-priority node takes it only once
the current holder lets go.

Two things make the pages look like a working installation rather than a fresh
one:

- **Certificates.** Issue them from a throwaway CA (`openssl req -x509` for the
  CA, then sign one per service) into `/etc/haproxy/certs`. A self-signed file
  is reported as the stand-in it is, which is honest but makes a dull picture.
- **Traffic.** Write a day of plausible per-minute counts into
  `$HAM_DATA_DIR/traffic.json` and restart the node so it reads them. Include
  an incident on one pool -- a run of server errors with a server down -- or
  the error line has nothing to show.

## Taking them

```bash
npm i puppeteer
OUT=/tmp/shots BASE=http://127.0.0.1:15901 node tools/screenshots/shoot.js
```

Then scale to 1600px wide and quantise to a palette before committing. The
interface is flat colour and text, so a palette holds it exactly and costs
about a fifth of the bytes.
