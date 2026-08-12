"""Settings validation."""

import re


#
# `haproxy -c` is the authority on whether a configuration works, but it is
# lenient about types: `maxconn not-a-number` parses as zero and validates
# clean, silently capping the proxy at nothing. So the obviously-typed fields
# are checked here first, before anything is written.
# --------------------------------------------------------------------------

NUMERIC_SETTINGS = {
    "haproxy": {"maxconn": (1, 2000000), "nbthread": (1, 256), "retries": (0, 100)},
    "acme": {"challenge_port": (1, 65535), "renew_hours": (1, 8760)},
}
TIME_SETTINGS = {"haproxy": ["timeout_client", "timeout_connect", "timeout_server",
                             "hard_stop_after"]}
TIME_RE = re.compile(r"^\d+(us|ms|s|m|h|d)?$")


def check_setting_types(sec, proposed):
    """Return a human-readable complaint, or "" when the values make sense."""
    problems = []
    for key, (lo, hi) in NUMERIC_SETTINGS.get(sec, {}).items():
        if key not in proposed:
            continue
        raw = proposed[key]
        if raw in ("", None):                  # empty means "use the default"
            continue
        try:
            val = int(str(raw).strip())
        except (TypeError, ValueError):
            problems.append("%s must be a whole number, not %r." % (key, raw))
            continue
        if not lo <= val <= hi:
            problems.append("%s must be between %d and %d." % (key, lo, hi))
    for key in TIME_SETTINGS.get(sec, []):
        raw = proposed.get(key)
        if raw in ("", None):
            continue
        if not TIME_RE.match(str(raw).strip()):
            problems.append("%s must be a time such as 50s, 5000 or 1m -- not %r." % (key, raw))
    return "\n".join(problems)


# --------------------------------------------------------------------------
# generic CRUD
