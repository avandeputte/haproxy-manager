"""Home Assistant, by MQTT discovery.

Retained discovery messages make the entities appear in Home Assistant by
themselves -- no YAML, no polling. Each node publishes a device of its own
(is HAProxy serving, does it hold the virtual IP), and the node holding the
virtual IP publishes the cluster's view: one problem sensor per service, one
connectivity sensor per published URL, days-to-expiry per certificate,
whether the configuration is agreed. On failover the new active node simply
continues publishing the same topics.

The connection is held open for the sake of the will: the broker publishes
"offline" on this node's availability topic the moment the process vanishes,
and Home Assistant greys the entities out -- the one state a dead process
cannot report for itself, and the reason MQTT beats polling here.
"""

from flask import jsonify, request
import json
import re
import socket
import time

from .base import VERSION, app, log
from .config import merged
from .util import _sec, cert_details, cert_path, parse_domains
from . import auth, cluster, mqtt, stats, traffic

FULL_REFRESH = 600            # rediscover and republish everything this often
RECONNECT_WAIT = 30

_state = {"pub": None, "fp": "", "last_try": 0.0, "last_full": 0.0,
          "published": {}, "uids": set(), "ctl": False}


def settings_of(cfg):
    return (cfg.get("notify") or {}).get("mqtt") or {}


def _node():
    return socket.gethostname()


def _slug(text):
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-") or "x"


def _device_node(base):
    return {"identifiers": ["haproxy-manager-" + _node()],
            "name": "haproxy-manager " + _node(),
            "manufacturer": "haproxy-manager", "sw_version": VERSION}


def _device_cluster():
    return {"identifiers": ["haproxy-manager-cluster"],
            "name": "haproxy-manager cluster",
            "manufacturer": "haproxy-manager", "sw_version": VERSION}


def availability_topic(base):
    return "%s/%s/availability" % (base, _node())


def _entities(cfg, s):
    """Every entity and its current state: {uid: (component, config, state, attrs)}.

    Computed fresh each round from what the app already knows; what changed
    is worked out afterwards by comparing payloads, so this stays a plain
    description of the present.
    """
    base = s.get("base_topic") or "haproxy-manager"
    node = _node()
    avail = availability_topic(base)
    out = {}

    def add(uid, component, name, state, device, device_class=None, unit=None,
            attrs=None, availability=avail):
        topic = "%s/state/%s" % (base, uid)
        conf = {"name": name, "unique_id": uid, "state_topic": topic,
                "availability_topic": availability, "device": device}
        if component == "binary_sensor":
            conf["payload_on"] = "on"
            conf["payload_off"] = "off"
        if device_class:
            conf["device_class"] = device_class
        if unit:
            conf["unit_of_measurement"] = unit
            conf["state_class"] = "measurement"
        if attrs is not None:
            conf["json_attributes_topic"] = topic + "/attrs"
        out[uid] = (component, conf, state, attrs)

    # -- this node -----------------------------------------------------------
    role, _held = auth.node_role(cfg)
    dev = _device_node(base)
    add("ham-%s-active" % _slug(node), "binary_sensor", "Holds the virtual IP",
        "on" if role in ("active", "standalone") else "off", dev)
    st = stats.haproxy_stats()
    add("ham-%s-haproxy" % _slug(node), "binary_sensor", "HAProxy down",
        "off" if st.get("ok") else "on", dev, device_class="problem")

    # -- the cluster's view, from whoever is serving it ----------------------
    if role == "passive":
        return out
    cdev = _device_cluster()
    cavail = "%s/cluster/availability" % base

    modes = traffic.notify_modes(cfg)
    for be in (st.get("backends") or []) if st.get("ok") else []:
        name = be.get("proxy") or ""
        if name in traffic.INTERNAL_POOLS:
            continue
        total = int(be.get("servers_total") or 0)
        if not total:
            continue
        up = int(be.get("servers_up") or 0)
        mode = modes.get(name, "servers")
        problem = up == 0 or (mode == "servers" and up < total)
        add("ham-svc-" + _slug(traffic._pool_label(name)), "binary_sensor",
            traffic._pool_label(name), "on" if problem else "off", cdev,
            device_class="problem", availability=cavail,
            attrs={"servers_up": up, "servers_total": total, "alert_when": mode})

    from . import probe
    with probe._state_lock:
        results = list(probe._state["results"])
    for r in results:
        add("ham-url-" + _slug(r["url"]), "binary_sensor", r["url"],
            "on" if r["state"] != "down" else "off", cdev,
            device_class="connectivity", availability=cavail,
            attrs={"note": r.get("note") or "", "ms": r.get("ms") or 0})

    for c in merged(cfg)["acme"]["certificates"]:
        info = cert_details(cert_path(c))
        days = info.get("days_left")
        add("ham-cert-" + _slug(c.get("name") or "x"), "sensor",
            "Certificate %s" % (c.get("name") or "?"),
            days if days is not None else 0, cdev, unit="d",
            availability=cavail,
            attrs={"domains": " ".join(parse_domains(c)),
                   "placeholder": bool(info.get("self_signed"))})

    snap = cluster._cluster_cache.get("value")
    if snap and snap["summary"]["total"] > 1:
        s2 = snap["summary"]
        add("ham-cluster-agreed", "binary_sensor", "Configuration drift",
            "off" if s2.get("config_agreed") else "on", cdev,
            device_class="problem", availability=cavail)
        add("ham-cluster-reachable", "sensor", "Nodes reachable",
            s2["reachable"], cdev, availability=cavail,
            attrs={"total": s2["total"]})

    if s.get("allow_control"):
        # One switch per service: on = paused, answering a clean 503. The
        # commands only work because this node subscribed to the command
        # topics -- and it only does that when control is allowed.
        pools = {"be_" + _sec(b.get("name") or ""): b
                 for b in merged(cfg)["haproxy"]["backends"]}
        for be in (st.get("backends") or []) if st.get("ok") else []:
            name = be.get("proxy") or ""
            if name in traffic.INTERNAL_POOLS or not int(be.get("servers_total") or 0):
                continue
            pool = pools.get(name)
            label = traffic._pool_label(name)
            paused = bool((pool or {}).get("maintenance"))
            uid = "ham-maint-" + _slug(label)
            topic = "%s/state/%s" % (base, uid)
            out[uid] = ("switch", {
                "name": "%s maintenance" % label, "unique_id": uid,
                "state_topic": topic,
                "command_topic": "%s/cmd/maint/%s" % (base, _slug(label)),
                "payload_on": "ON", "payload_off": "OFF",
                "availability_topic": cavail, "device": cdev,
            }, "ON" if paused else "OFF", None)

    for pool, req in traffic.latest_per_pool().items():
        if pool in traffic.INTERNAL_POOLS:
            continue
        add("ham-traffic-" + _slug(traffic._pool_label(pool)), "sensor",
            "%s requests" % traffic._pool_label(pool),
            req, cdev, unit="req/min", availability=cavail)
    return out


def _publish_all(pub, cfg, s, discover):
    base = s.get("base_topic") or "haproxy-manager"
    disc = s.get("discovery_prefix") or "homeassistant"
    entities = _entities(cfg, s)

    if discover:
        pub.publish(availability_topic(base), "online")
        role, _held = auth.node_role(cfg)
        if role != "passive":
            pub.publish("%s/cluster/availability" % base, "online")
        # Entities that existed last time and are gone now -- a deleted
        # service, a removed certificate -- are removed from Home Assistant by
        # publishing an empty config, or they would linger forever. A PASSIVE
        # node removes nothing: the cluster entities it just stopped
        # publishing did not go away, they moved to whichever node took the
        # virtual IP, which is now keeping them current on the same shared
        # topics. Sweeping here would delete the entities the new active node
        # just published -- every failover would blank the dashboards for a
        # refresh cycle. Its own node-device entities never disappear, and a
        # genuine deletion is always seen by the active node, which still
        # sweeps.
        if role != "passive":
            for uid, comp in list(_state["uids"] - {(u, e[0]) for u, e in entities.items()}):
                pub.publish("%s/%s/%s/config" % (disc, comp, uid), "")
                pub.publish("%s/state/%s" % (base, uid), "")
        _state["uids"] = {(u, e[0]) for u, e in entities.items()}

    for uid, (component, conf, state, attrs) in entities.items():
        topic = conf["state_topic"]
        # A brand-new entity -- the first probe round finishing, a service
        # published a minute ago -- announces itself now rather than waiting
        # for the next full refresh: an entity that exists but was never
        # discovered is invisible for up to ten minutes.
        new = (uid, component) not in _state["uids"]
        if new:
            _state["uids"].add((uid, component))
        if discover or new:
            pub.publish("%s/%s/%s/config" % (disc, component, uid),
                        json.dumps(conf, sort_keys=True, separators=(",", ":")))
        payload = str(state)
        if _state["published"].get(topic) != payload or discover:
            pub.publish(topic, payload)
            _state["published"][topic] = payload
        if attrs is not None:
            ap = json.dumps(attrs, sort_keys=True, separators=(",", ":"))
            if _state["published"].get(topic + "/attrs") != ap or discover:
                pub.publish(topic + "/attrs", ap)
                _state["published"][topic + "/attrs"] = ap


def _reader(pub, cfg_base, allow_control):
    """Consume everything the broker sends: PINGRESPs, SUBACKs, and -- when
    control is on -- the commands Home Assistant publishes."""
    from .config import load_config
    from . import apply
    from .base import _lock
    while _state.get("pub") is pub and pub:
        try:
            frame = pub.read_frame(1.0)
        except (OSError, ConnectionError, AttributeError):
            return                        # closed under us; poll() reconnects
        if not frame or frame[0] & 0xF0 != 0x30:
            continue
        topic, message = pub.parse_publish(frame[1])
        prefix = cfg_base + "/cmd/maint/"
        if not (allow_control and topic.startswith(prefix)):
            continue
        slug = topic[len(prefix):]
        want = message.strip().upper() == "ON"
        try:
            cfg = load_config()
            role, _held = auth.node_role(cfg)
            if role == "passive":
                continue                  # not this node's call to make
            with _lock:
                cfg = load_config()
                pool = next((b for b in cfg["haproxy"]["backends"]
                             if _slug(traffic._pool_label("be_" + b.get("name", ""))) == slug),
                            None)
                if pool is None or bool(pool.get("maintenance")) == want:
                    continue
                pool["maintenance"] = want
                from .config import save_config
                save_config(cfg)
                name = pool.get("name")
            log.warning("home assistant %s %s", "paused" if want else "resumed", name)
            apply.do_apply()
            # Say it back straight away, so the switch in HA settles instead
            # of bouncing until the next round.
            uid = "ham-maint-" + slug
            topic_out = "%s/state/%s" % (cfg_base, uid)
            pub.publish(topic_out, "ON" if want else "OFF")
            _state["published"][topic_out] = "ON" if want else "OFF"
        except Exception:
            log.exception("mqtt: acting on a command failed")


def _fp(s):
    return json.dumps({k: s.get(k) for k in
                       ("enabled", "host", "port", "username", "password",
                        "tls", "base_topic", "discovery_prefix",
                        "allow_control")}, sort_keys=True)


@app.post("/api/hass/test")
def api_hass_test():
    """Connect to the broker and publish one test message, so the settings
    are proven before anything depends on them. Blank password: the stored one."""
    from .config import load_config
    body = request.get_json(force=True, silent=True) or {}
    stored = settings_of(load_config())
    s = dict(stored, **{k: v for k, v in body.items() if str(v or "").strip() or k in ("tls",)})
    if not str(body.get("password") or "").strip():
        s["password"] = stored.get("password") or ""
    if not s.get("host"):
        return jsonify({"ok": False, "error": "a broker host is required"}), 400
    pub, why = mqtt.try_connect(s, client_id="haproxy-manager-test-" + _node())
    if not pub:
        return jsonify({"ok": False, "error": why})
    try:
        pub.publish((s.get("base_topic") or "haproxy-manager") + "/test",
                    "hello from %s" % _node(), retain=False)
    finally:
        pub.close()
    return jsonify({"ok": True, "message":
                    "Connected and published. Save, and the entities appear in "
                    "Home Assistant within a watchdog round."})


def poll(cfg):
    """Called every watchdog round. Connects, discovers, publishes changes.

    Errors close the connection and back off; the broker being down must
    cost this node nothing but a log line every reconnect attempt.
    """
    s = settings_of(cfg)
    if not (s.get("enabled") and s.get("host")):
        if _state["pub"]:
            _state["pub"].close()
            _state["pub"] = None
        return
    if _fp(s) != _state["fp"]:
        if _state["pub"]:
            _state["pub"].close()
        _state["pub"] = None
        _state["fp"] = _fp(s)
        _state["published"] = {}
    base = s.get("base_topic") or "haproxy-manager"

    try:
        if not _state["pub"]:
            if time.time() - _state["last_try"] < RECONNECT_WAIT:
                return
            _state["last_try"] = time.time()
            pub, why = mqtt.try_connect(
                s, will_topic=availability_topic(base),
                client_id="haproxy-manager-" + _node())
            if not pub:
                log.warning("mqtt: cannot reach %s: %s", s.get("host"), why)
                return
            _state["pub"] = pub
            _state["published"] = {}
            _state["last_full"] = time.time()
            role, _held = auth.node_role(cfg)
            allow = bool(s.get("allow_control")) and role != "passive"
            _state["ctl"] = allow
            if allow:
                pub.subscribe(base + "/cmd/#")
            import threading
            threading.Thread(target=_reader, args=(pub, base, allow),
                             daemon=True, name="mqtt-reader").start()
            _publish_all(pub, cfg, s, discover=True)
            log.info("mqtt: connected to %s, entities published for Home Assistant%s",
                     s.get("host"), " (control enabled)" if allow else "")
            return
        # Failover moves the cluster device here, and with it the duty to
        # listen for commands -- which was decided at connect time. A changed
        # answer means reconnecting, so the subscription follows the role.
        role, _held = auth.node_role(cfg)
        if bool(s.get("allow_control")) and (role != "passive") != _state.get("ctl", False):
            _state["pub"].close()
            _state["pub"] = None
            _state["last_try"] = 0.0
            return
        full = time.time() - _state["last_full"] >= FULL_REFRESH
        if full:
            _state["last_full"] = time.time()
        _publish_all(_state["pub"], cfg, s, discover=full)
        _state["pub"].ping_if_idle()
    except (OSError, ConnectionError) as e:
        log.warning("mqtt: lost the broker at %s (%s); reconnecting", s.get("host"), e)
        if _state["pub"]:
            _state["pub"].close(say_goodbye=False)
        _state["pub"] = None
    except Exception:
        log.exception("mqtt: publishing failed")
        if _state["pub"]:
            _state["pub"].close(say_goodbye=False)
        _state["pub"] = None
