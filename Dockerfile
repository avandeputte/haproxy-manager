# haproxy-manager -- all-in-one image.
#
# The app is a control plane for HAProxy + Keepalived + acme.sh, so the image
# ships those alongside it. There is no systemd in a container, so supervisord
# runs the processes and a small `systemctl` shim (docker/systemctl) translates
# the handful of calls app.py makes into supervisorctl commands.
FROM debian:bookworm-slim

ARG ACME_VERSION=3.1.4

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-flask \
        python3-requests \
        haproxy \
        keepalived \
        openssl \
        ca-certificates \
        curl \
        socat \
        iproute2 \
        procps \
        supervisor \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

# acme.sh is installed into an image-only directory. The entrypoint seeds
# $HAM_ACME_HOME (a volume) from it, so account keys and issued certificates
# survive upgrades while the program files are refreshed on every start.
RUN curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACME_VERSION}.tar.gz" \
        -o /tmp/acme.tar.gz \
    && mkdir -p /tmp/acme \
    && tar -xzf /tmp/acme.tar.gz -C /tmp/acme --strip-components=1 \
    && cd /tmp/acme \
    && ./acme.sh --install --nocron --noprofile \
        --home /opt/acme.sh --config-home /opt/acme.sh \
    && rm -rf /tmp/acme /tmp/acme.tar.gz

WORKDIR /opt/haproxy-manager
COPY app.py ./app.py
COPY static/ ./static/

COPY docker/systemctl /usr/local/bin/systemctl
COPY docker/haproxy-run /usr/local/bin/haproxy-run
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/supervisord.conf /etc/supervisor/supervisord.conf
RUN chmod 0755 /usr/local/bin/systemctl /usr/local/bin/haproxy-run /usr/local/bin/entrypoint.sh

ENV HAM_DATA_DIR=/var/lib/haproxy-manager \
    HAM_CERT_DIR=/etc/haproxy/certs \
    HAM_HAPROXY_CFG=/etc/haproxy/haproxy.cfg \
    HAM_KEEPALIVED_CFG=/etc/keepalived/keepalived.conf \
    HAM_ACME_HOME=/var/lib/acme.sh \
    HAM_ACME_SH=/var/lib/acme.sh/acme.sh \
    HAM_LISTEN=0.0.0.0 \
    HAM_PORT=8080

# 8080 UI/API, 9080 acme.sh HTTP-01 standalone listener. Whatever ports your
# Public Services bind to (80/443/...) must be published separately.
EXPOSE 8080 9080

VOLUME ["/var/lib/haproxy-manager", "/var/lib/acme.sh", "/etc/haproxy"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${HAM_PORT}/" >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
