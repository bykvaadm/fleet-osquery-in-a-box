#!/usr/bin/env bash
###############################################################################
#  run-lab.sh — bring the whole Fleet + osquery lab up and verify every
#  security-audit scenario is executable/detectable.
#
#  Usage:
#     tests/run-lab.sh            # up + test  (default; leaves the lab running)
#     tests/run-lab.sh up         # bring the stack up + enroll the vuln-agent
#     tests/run-lab.sh test       # run the pytest scenario suite (lab must be up)
#     tests/run-lab.sh down       # tear the whole lab down
#     tests/run-lab.sh all        # up + test + down
#
#  Env knobs:
#     AGENTS=all        also start ubuntu20/22/24/26 agents (default: vuln-agent only)
#     PIP_INDEX_URL=…   custom PyPI index for the test venv (behind a mirror/proxy)
#     ADMIN_EMAIL / ADMIN_PASSWORD / ORG_NAME   override the seeded admin
#
#  Requires: docker (with compose v2+), python3. The script provisions its own
#  venv for pytest, so nothing needs to be pre-installed beyond those two.
###############################################################################
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
STATE="$HERE/.lab-state"
VENV="$HERE/.venv"

FLEET_UI="${FLEET_UI:-http://localhost:1337}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Admin123#pass}"
ORG_NAME="${ORG_NAME:-Demo Lab}"
SERVER_URL="${SERVER_URL:-https://localhost:8412}"

# curl that always bypasses any ambient HTTP proxy for localhost.
# Exported so it is also available inside the `bash -c` subshells used by wait_for.
lcurl() { env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
              no_proxy=localhost,127.0.0.1 curl "$@"; }
export -f lcurl

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

dc_server() { docker compose -f "$ROOT/docker-compose.yml" "$@"; }
dc_agents() { docker compose -f "$ROOT/osquery/docker-compose.yml" "$@"; }

vuln_container() { docker ps --filter "name=vuln-agent" --format '{{.Names}}' | head -1; }

wait_for() {  # <desc> <retries> <sleep> <cmd...>
    local desc="$1" tries="$2" nap="$3"; shift 3
    local i=0
    until "$@" >/dev/null 2>&1; do
        i=$((i+1))
        [ "$i" -ge "$tries" ] && die "timed out waiting for: $desc"
        sleep "$nap"
    done
}

lab_up() {
    command -v docker >/dev/null || die "docker not found"

    log "Starting server stack (mysql01 + redis01 + fleet01 + fleet02)"
    dc_server up -d

    log "Waiting for fleet01 to be healthy (DB migration + serve)"
    wait_for "fleet01 /healthz" 60 5 \
        bash -c 'lcurl -sf --max-time 5 -k https://localhost:8412/healthz' \
        || true
    # The healthcheck above uses lcurl defined in this shell; fall back to the
    # container health status which is the authoritative signal.
    wait_for "fleet01 healthy" 60 5 bash -c \
        'test "$(docker inspect -f "{{.State.Health.Status}}" fleet-preview-server-fleet01-1 2>/dev/null)" = healthy'

    log "Creating admin (idempotent) + fetching enroll secret via ${FLEET_UI}"
    lcurl -s -X POST "$FLEET_UI/api/v1/setup" -H 'Content-Type: application/json' -d "{
        \"admin\":{\"admin\":true,\"email\":\"$ADMIN_EMAIL\",\"name\":\"Admin\",
                   \"password\":\"$ADMIN_PASSWORD\",\"password_confirmation\":\"$ADMIN_PASSWORD\"},
        \"org_info\":{\"org_name\":\"$ORG_NAME\"},
        \"server_url\":\"$SERVER_URL\"}" >/dev/null || true

    local token secret
    token="$(lcurl -s -X POST "$FLEET_UI/api/v1/fleet/login" -H 'Content-Type: application/json' \
        -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" \
        | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')"
    [ -n "$token" ] || die "could not log in to Fleet (bad admin creds?)"
    secret="$(lcurl -s "$FLEET_UI/api/latest/fleet/spec/enroll_secret" \
        -H "Authorization: Bearer $token" \
        | sed -n 's/.*"secret": *"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$secret" ] || die "could not read enroll secret"

    { echo "ENROLL_SECRET=$secret"; echo "FLEET_TOKEN=$token"; } > "$STATE"
    log "Enroll secret obtained (saved to $STATE)"

    log "Building + starting the vulnerable demo agent"
    export ENROLL_SECRET="$secret"
    if [ "${AGENTS:-}" = "all" ]; then
        dc_agents up -d --build
    else
        dc_agents up -d --build vuln-agent
    fi

    local c; c="$(vuln_container)"
    [ -n "$c" ] || die "vuln-agent container not found after start"

    log "Waiting for scenario seeding to complete in $c"
    wait_for "seed complete" 40 3 bash -c \
        "docker logs '$c' 2>&1 | grep -q 'Vulnerability seeding complete'"

    log "Waiting for the host to enroll and go online in Fleet"
    wait_for "host online" 40 3 bash -c \
        "lcurl -s '$FLEET_UI/api/latest/fleet/hosts' -H 'Authorization: Bearer $token' | grep -q '\"status\":\"online\"'"

    log "Lab is up. vuln-agent=$c  UI=$FLEET_UI (login: $ADMIN_EMAIL / $ADMIN_PASSWORD)"
}

lab_test() {
    local c; c="$(vuln_container)"
    [ -n "$c" ] || die "vuln-agent not running — run 'tests/run-lab.sh up' first"

    log "Provisioning test venv"
    if [ ! -x "$VENV/bin/pytest" ]; then
        if command -v uv >/dev/null 2>&1; then
            # uv is self-contained (no ensurepip needed) and fast.
            uv venv "$VENV"
            uv pip install --python "$VENV/bin/python" --quiet \
                ${PIP_INDEX_URL:+--index-url "$PIP_INDEX_URL"} \
                -r "$HERE/requirements.txt"
        elif python3 -m venv "$VENV" 2>/dev/null; then
            "$VENV/bin/pip" install --quiet --upgrade pip
            "$VENV/bin/pip" install --quiet \
                ${PIP_INDEX_URL:+--index-url "$PIP_INDEX_URL"} \
                -r "$HERE/requirements.txt"
        else
            die "could not create a venv. Install 'uv' (https://docs.astral.sh/uv/) \
or the python3-venv package (e.g. 'apt install python3-venv'), then retry."
        fi
    fi

    log "Running scenario suite against $c"
    # Export state so pytest can reach Fleet + the container.
    [ -f "$STATE" ] && set -a && . "$STATE" && set +a
    VULN_CONTAINER="$c" FLEET_UI="$FLEET_UI" \
        "$VENV/bin/pytest" -v "$HERE/test_scenarios.py"
}

lab_down() {
    log "Tearing down agent stack"
    dc_agents down -v 2>/dev/null || true
    log "Tearing down server stack"
    dc_server down -v 2>/dev/null || true
    rm -f "$STATE"
    log "Lab is down."
}

case "${1:-default}" in
    up)      lab_up ;;
    test)    lab_test ;;
    down)    lab_down ;;
    all)     lab_up; lab_test; lab_down ;;
    default) lab_up; lab_test ;;
    *)       die "unknown command '$1' (use: up | test | down | all)" ;;
esac
