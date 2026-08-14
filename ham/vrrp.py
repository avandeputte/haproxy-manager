"""Which addresses Keepalived should use for unicast VRRP."""

from flask import jsonify
from urllib.parse import urlsplit
import socket

from .base import PEER_TIMEOUT, _lock, _requests, app
from .config import load_config, save_config
from . import apply

def keepalived_wanted(cfg):
    """Keepalived runs wherever the cluster has a virtual IP.

    It used to be a per-node checkbox, which let a node sit in a cluster with
    VRRP quietly switched off, never taking the address.
    """
    return bool(cluster_vips(cfg))


def cluster_vips(cfg):
    return [v.strip().split("/")[0] for v in (cfg["cluster"].get("vips") or "").splitlines() if v.strip()]


def resolve_host(host):
    """Every IPv4 address a name resolves to, in a stable order."""
    if not host:
        return []
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
    except OSError:
        return []


def own_addresses():
    return {a.split("/")[0] for i in apply.node_interfaces() for a in i["addresses"]}


def check_node_url(url, vips):
    """A node's URL must reach that node, not the address that moves."""
    host = urlsplit(url).hostname or ""
    ips = resolve_host(host)
    if not ips:
        return "warn", "%s does not resolve here; the other nodes may still be able to reach it." % host
    hit = [ip for ip in ips if ip in (vips or [])]
    if hit:
        return "error", ("%s resolves to the virtual IP (%s). That address moves between nodes, so "
                         "the others would reach whichever node currently holds it -- and this node "
                         "would never receive anything. Use this node's own address or a name that "
                         "resolves to it." % (host, ", ".join(hit)))
    mine = own_addresses()
    if not (set(ips) & mine):
        return "warn", ("%s resolves to %s, which is not an address on this node. Make sure it "
                        "reaches this node and not another." % (host, ", ".join(ips)))
    return "ok", ""


def local_vrrp_address(cfg):
    """This node's own address on the interface that carries the virtual IP."""
    iface = cfg["local"]["keepalived"].get("interface") or ""
    vips = cluster_vips(cfg)
    for i in apply.node_interfaces():
        if i["name"] != iface:
            continue
        for a in i["addresses"]:
            ip = a.split("/")[0]
            if ip not in vips:               # never advertise from the shared address
                return ip
    return ""


def peer_vrrp_address(peer, vips, verify=None):
    """The address to send this peer's VRRP to: (address, how, warning)."""
    url = (peer.get("url") or "").rstrip("/")
    host = urlsplit(url).hostname or ""

    # Best source is the node itself: it knows which address its own VRRP
    # interface carries. A name can point at the virtual IP, which moves.
    if _requests is not None and peer.get("api_key"):
        try:
            r = _requests.get(url + "/api/keepalived/status",
                              headers={"X-API-Key": (peer.get("api_key") or "").strip()},
                              timeout=PEER_TIMEOUT, verify=bool(peer.get("verify_tls")))
            if r.status_code == 200:
                d = r.json()
                for i in d.get("interfaces", []):
                    if i.get("name") != d.get("interface"):
                        continue
                    for a in i.get("addresses", []):
                        ip = a.split("/")[0]
                        if ip not in vips:
                            return ip, "%s reports it on %s" % (peer.get("name"), i["name"]), ""
        except Exception:
            pass

    ips = resolve_host(host)
    usable = [ip for ip in ips if ip not in vips]
    if usable:
        warn = ""
        if len(ips) != len(usable):
            warn = ("%s also resolves to the virtual IP, which moves between nodes -- "
                    "using %s instead." % (host, usable[0]))
        return usable[0], "%s resolves to it" % host, warn
    if ips:
        return "", "", ("%s resolves only to the virtual IP (%s), which cannot be a unicast peer. "
                        "Give this node's own address." % (host, ", ".join(ips)))
    return "", "", "could not resolve %s" % (host or url)


def unicast_plan(cfg):
    """Which address every node should use, and who each should talk to."""
    vips = cluster_vips(cfg)
    nodes = []
    me = local_vrrp_address(cfg)
    nodes.append({"self": True, "name": socket.gethostname(), "address": me,
                  "how": "this node's %s" % (cfg["local"]["keepalived"].get("interface") or "?"),
                  "warning": "" if me else
                             "this node has no usable address on %s"
                             % (cfg["local"]["keepalived"].get("interface") or "(no interface set)"),
                  "peer": None})
    for p in cfg["local"]["sync"].get("peers") or []:
        if not p.get("enabled", True):
            continue
        addr, how, warn = peer_vrrp_address(p, vips)
        nodes.append({"self": False, "name": p.get("name"), "address": addr,
                      "how": how, "warning": warn, "peer": p})
    return nodes


@app.get("/api/cluster/unicast")
def api_cluster_unicast():
    nodes = unicast_plan(load_config())
    return jsonify({"ok": True,
                    "nodes": [{k: v for k, v in n.items() if k != "peer"} for n in nodes],
                    "addresses": [n["address"] for n in nodes if n["address"] and not n["self"]]})


def derive_unicast(cfg):
    """This node's own unicast addresses, worked out from the membership.

    Cheap enough for every Apply: local interfaces and name resolution only,
    no calls to the other nodes. Each node derives its own, so the cluster
    stays correct as members come and go.
    """
    k = cfg["local"]["keepalived"]
    if not keepalived_wanted(cfg):
        return False
    vips = cluster_vips(cfg)
    addrs = []
    for p in cfg["local"]["sync"].get("peers") or []:
        if not p.get("enabled", True):
            continue
        for ip in resolve_host(urlsplit(p.get("url") or "").hostname or ""):
            if ip not in vips and ip not in addrs:
                addrs.append(ip)
                break                        # one address per node
    new_peer = "\n".join(addrs) if addrs else ""
    new_src = local_vrrp_address(cfg) if addrs else ""
    if (k.get("unicast_peer") or "") == new_peer and (k.get("unicast_src") or "") == new_src:
        return False
    k["unicast_peer"], k["unicast_src"] = new_peer, new_src
    return True


def apply_unicast_plan():
    """Give every node its own source address and the list of the others.

    Unicast addresses are node-local, so they cannot ride along with a
    configuration push -- each node has to be told its own.
    """
    cfg = load_config()
    nodes = unicast_plan(cfg)
    steps, warnings = [], [n["warning"] for n in nodes if n["warning"]]
    known = {n["name"]: n["address"] for n in nodes if n["address"]}
    if len(known) < 2:
        return {"ok": False, "error":
                "at least two nodes need a usable address; found %s"
                % (", ".join("%s=%s" % kv for kv in known.items()) or "none"),
                "warnings": warnings, "steps": []}

    def others(name):
        return "\n".join(a for n, a in known.items() if n != name)

    with _lock:
        cur = load_config()
        mine = next((n for n in nodes if n["self"]), None)
        if mine and mine["address"]:
            cur["local"]["keepalived"]["unicast_src"] = mine["address"]
            cur["local"]["keepalived"]["unicast_peer"] = others(mine["name"])
            save_config(cur)
            steps.append("this node: source %s, peers %s"
                         % (mine["address"], others(mine["name"]).replace("\n", ", ") or "(none)"))

    for n in nodes:
        if n["self"] or not n["address"]:
            continue
        p = n["peer"]
        try:
            r = _requests.put((p["url"].rstrip("/")) + "/api/local",
                              json={"keepalived": {"unicast_src": n["address"],
                                                   "unicast_peer": others(n["name"])}},
                              headers={"X-API-Key": (p.get("api_key") or "").strip()},
                              timeout=PEER_TIMEOUT, verify=bool(p.get("verify_tls")))
            if r.status_code == 200:
                steps.append("%s: source %s, peers %s"
                             % (n["name"], n["address"], others(n["name"]).replace("\n", ", ")))
            else:
                warnings.append("%s did not accept its unicast settings (HTTP %s)"
                                % (n["name"], r.status_code))
        except Exception as e:
            warnings.append("%s could not be updated: %s" % (n["name"], e))

    return {"ok": True, "steps": steps, "warnings": warnings,
            "note": "Press Apply on each node to write keepalived.conf."}


@app.post("/api/cluster/unicast/apply")
def api_cluster_unicast_apply():
    res = apply_unicast_plan()
    return jsonify(res), (200 if res.get("ok") else 400)
