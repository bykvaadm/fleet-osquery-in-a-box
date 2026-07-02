# syntax=docker/dockerfile:1
#
# Parameterized osquery agent for the Enterprise Linux (RPM) family — used for
# the Oracle Linux bases. The Ubuntu bases use ./Dockerfile (apt/.deb); this one
# installs osquery from the official GitHub release .rpm via dnf.
#
#   docker build -f agent/Dockerfile.el --build-arg EL_IMAGE=oraclelinux:8 \
#     -t fleet-osquery-agent:ol8 agent/
#
ARG EL_IMAGE=oraclelinux:8
FROM ${EL_IMAGE}

# Re-declare after FROM so it is available for the LABEL below.
ARG EL_IMAGE
# osquery version to install (from github.com/osquery/osquery releases).
ARG OSQUERY_VERSION=5.23.0
# TARGETARCH is set automatically by buildx (amd64 / arm64). For a plain
# `docker build` it may be empty, in which case we fall back to `uname -m`.
ARG TARGETARCH

ENV LANG=C.UTF-8

# --- osquery from the official .rpm (its own layer) -----------------------
# dnf can install straight from the release URL and resolve any deps.
RUN set -eux; \
    arch="${TARGETARCH:-$(uname -m)}"; \
    case "$arch" in \
        amd64|x86_64) rpm_arch=x86_64 ;; \
        arm64|aarch64) rpm_arch=aarch64 ;; \
        *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/osquery-${OSQUERY_VERSION}-1.linux.${rpm_arch}.rpm"; \
    echo "Installing osquery from ${url}"; \
    dnf -y install "$url"; \
    dnf clean all

# --- teaching-lab extras + tools needed by scenario seeding ---------------
# EL package names differ from Debian: cron->cronie, procps->procps-ng,
# iproute2->iproute. --allowerasing lets curl replace curl-minimal on OL9/10.
RUN set -eux; \
    dnf -y --allowerasing --setopt=install_weak_deps=False install \
        ca-certificates \
        curl \
        sudo \
        cronie \
        openssh-server \
        procps-ng \
        iproute \
        net-tools \
        shadow-utils \
        hostname \
        python3 \
        python3-pip; \
    dnf clean all

# Agent config + entrypoint. The Fleet TLS cert is NOT baked in; it is mounted
# at runtime at /etc/osquery/fleet.crt (see osquery/docker-compose.yml).
COPY osquery.flags /etc/osquery/osquery.flags
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
# Vulnerability-seeding script for the deliberately-vulnerable demo host. Baked
# into every agent image but only executed when SEED_VULNS is truthy.
COPY seed-vulnerabilities.sh /usr/local/bin/seed-vulnerabilities.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/seed-vulnerabilities.sh

LABEL org.opencontainers.image.source="https://github.com/bykvaadm/fleet-osquery-in-a-box" \
      org.opencontainers.image.description="osquery ${OSQUERY_VERSION} agent (${EL_IMAGE}) for the Fleet osquery-in-a-box teaching lab" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
