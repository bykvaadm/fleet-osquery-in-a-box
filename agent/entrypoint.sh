#!/usr/bin/env bash
#
# Entrypoint for the Fleet osquery-in-a-box agent.
#
# Responsibilities:
#   1. Require an ENROLL_SECRET (passed through to osquery via the flags file's
#      --enroll_secret_env=ENROLL_SECRET).
#   2. Optionally run a vulnerability-seeding script (authored elsewhere) when
#      SEED_VULNS is truthy and the script is present.
#   3. exec osqueryd against the Fleet TLS server.
#
set -e

FLEET_SERVER="${FLEET_SERVER:-host.docker.internal:8412}"
SEED_SCRIPT="/usr/local/bin/seed-vulnerabilities.sh"

if [ -z "${ENROLL_SECRET:-}" ]; then
    echo "[entrypoint] ERROR: ENROLL_SECRET is not set. The agent cannot enroll." >&2
    echo "[entrypoint] Set ENROLL_SECRET in the environment (see osquery/docker-compose.yml)." >&2
    exit 1
fi

echo "[entrypoint] Fleet server: ${FLEET_SERVER}"

# --- optional vulnerability seeding (script owned by another author) ------
case "${SEED_VULNS:-}" in
    true|TRUE|True|1|yes|YES)
        if [ -x "${SEED_SCRIPT}" ]; then
            echo "[entrypoint] SEED_VULNS is set; running ${SEED_SCRIPT} as root..."
            "${SEED_SCRIPT}"
            echo "[entrypoint] Vulnerability seeding complete."
        elif [ -f "${SEED_SCRIPT}" ]; then
            echo "[entrypoint] SEED_VULNS is set; running ${SEED_SCRIPT} via bash (not executable)..."
            bash "${SEED_SCRIPT}"
            echo "[entrypoint] Vulnerability seeding complete."
        else
            echo "[entrypoint] SEED_VULNS is set but ${SEED_SCRIPT} was not found; skipping seeding."
        fi
        ;;
    *)
        echo "[entrypoint] SEED_VULNS not set/truthy; skipping vulnerability seeding."
        ;;
esac

echo "[entrypoint] Starting osqueryd against ${FLEET_SERVER}..."
exec osqueryd \
    --flagfile=/etc/osquery/osquery.flags \
    --tls_hostname="${FLEET_SERVER}" \
    --verbose
