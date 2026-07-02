# syntax=docker/dockerfile:1
#
# Parameterized osquery agent for the Fleet osquery-in-a-box lab.
#
# Builds a self-contained osquery agent on a chosen Ubuntu base, installing
# osquery from the official GitHub release .deb (multi-arch: amd64 / arm64).
#
#   docker build --build-arg UBUNTU_VERSION=24.04 -t fleet-osquery-agent:ubuntu24.04 agent/
#
ARG UBUNTU_VERSION=24.04
FROM ubuntu:${UBUNTU_VERSION}

# Re-declare after FROM so it is available for the LABEL below (an ARG declared
# before FROM is only in scope for the FROM line itself).
ARG UBUNTU_VERSION
# osquery version to install (from github.com/osquery/osquery releases).
ARG OSQUERY_VERSION=5.23.0
# TARGETARCH is set automatically by buildx (amd64 / arm64). When building with
# a plain `docker build` it may be empty, in which case we fall back to the
# host architecture reported by dpkg.
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive

# --- osquery (its own layer so a base-package hiccup doesn't invalidate it) ---
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
        amd64|x86_64) deb_arch=amd64 ;; \
        arm64|aarch64) deb_arch=arm64 ;; \
        *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/osquery_${OSQUERY_VERSION}-1.linux_${deb_arch}.deb"; \
    echo "Downloading osquery from ${url}"; \
    curl -fSL "$url" -o /tmp/osquery.deb; \
    apt-get install -y --no-install-recommends /tmp/osquery.deb; \
    rm -f /tmp/osquery.deb; \
    rm -rf /var/lib/apt/lists/*

# --- teaching-lab extras + tools needed by scenario seeding ---------------
# Kept lean and in its own layer; --no-install-recommends keeps it small.
# If a package is missing on a newer base (e.g. 26.04) this layer can be
# adjusted without rebuilding the osquery layer above.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        sudo \
        cron \
        openssh-server \
        procps \
        iproute2 \
        net-tools \
        python3 \
        python3-pip; \
    rm -rf /var/lib/apt/lists/*

# Agent config + entrypoint. The Fleet TLS cert is NOT baked in; it is mounted
# at runtime at /etc/osquery/fleet.crt (see osquery/docker-compose.yml).
COPY osquery.flags /etc/osquery/osquery.flags
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
# Vulnerability-seeding script for the deliberately-vulnerable demo host. It is
# baked into every agent image but only executed at runtime when SEED_VULNS is
# truthy (see entrypoint.sh + the vuln-agent service in docker-compose.yml).
COPY seed-vulnerabilities.sh /usr/local/bin/seed-vulnerabilities.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/seed-vulnerabilities.sh

LABEL org.opencontainers.image.source="https://github.com/fleetdm/osquery-in-a-box" \
      org.opencontainers.image.description="osquery ${OSQUERY_VERSION} agent (Ubuntu ${UBUNTU_VERSION}) for the Fleet osquery-in-a-box teaching lab" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
