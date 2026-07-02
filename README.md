# Fleet + osquery in a box — security-audit teaching lab

A self-contained [**Fleet**](https://fleetdm.com) + [**osquery**](https://osquery.io)
lab you can run locally with Docker Compose. It brings up a Fleet server (MySQL +
Redis backing store) and a set of **self-built** Ubuntu osquery agents, including a
deliberately-**vulnerable demo host** you can hunt across from Fleet.

It started life as the FleetDM `osquery-in-a-box` (the stack behind
`fleetctl preview`) and has been **modernized**: current component versions,
self-buildable multi-arch agent images (no more stale Docker Hub pulls), CI to
publish them to Docker Hub, and **10 hands-on security-audit scenarios** with real,
osquery-detectable vulnerabilities for classroom demos.

> ⚠️ **The vulnerable agent deliberately weakens itself** (backdoor accounts, SUID
> root shell, rogue services, SSH/cron persistence, known-vulnerable software, a C2
> beacon). Run this **only** in an isolated lab — never on a real host or network.

## What's inside

| Component      | Version                                   | Notes |
|----------------|-------------------------------------------|-------|
| Fleet server   | `fleetdm/fleet:v4.87.0`                    | Override with `FLEET_VERSION`. |
| MySQL          | `mysql:8.4` (LTS)                          | **Do not use MySQL 9.x** — it breaks Fleet's schema migrations (`prepare db`). 8.4 is the newest Fleet-tested line. |
| Redis          | `redis:7`                                 | |
| osquery agent  | `5.23.0`                                   | Installed from the official GitHub release package (amd64 + arm64). |
| Agent OS bases | Ubuntu `20.04`/`22.04`/`24.04`/`26.04`, Oracle Linux `8`/`10` | 6 self-built images: Ubuntu via `agent/Dockerfile` (apt/`.deb`), Oracle Linux via `agent/Dockerfile.el` (dnf/`.rpm`). |

## Architecture

```
Browser -> http://localhost:1337  (Fleet UI)

┌──────────────────────────────────────────────┐
│  SERVER stack        docker-compose.yml      │
│                                              │
│  fleet02   HTTP  :1337   UI / API            │
│  fleet01   TLS   :8412   osquery enrollment  │
│  mysql01 (8.4)     redis01 (7)               │
└──────────────────────────────────────────────┘
                    ^
                    |  osquery agents enroll over TLS :8412
                    |
┌────────────────────────────────────────────────────────────┐
│  AGENT stack         osquery/docker-compose.yml            │
│                                                            │
│  ubuntu       20.04 / 22.04 / 24.04 / 26.04  agents        │
│  oraclelinux  8 / 10                         agents        │
│  vuln-agent   (24.04, SEED_VULNS=true)  -> seeds 10 vulns  │
└────────────────────────────────────────────────────────────┘
```

Two Fleet servers share the same MySQL/Redis (upstream design): `fleet01` serves
TLS on **8412** for osquery agents; `fleet02` serves plain HTTP on **1337** for the
UI/API.

## Quick start

**1. Start the server stack** (from the repo root):

```bash
docker compose up -d
```

Compose waits for MySQL to be healthy, then starts `fleet01`; `fleet02` waits for
`fleet01` to finish the DB migration (so the two don't race `prepare db`).

- Fleet UI/API → **http://localhost:1337**
- Agent enrollment endpoint → **https://localhost:8412** (self-signed cert in `osquery/fleet.crt`)

**2. Create the admin and capture the enroll secret** (headless, via the API —
run these in the same terminal so `$ENROLL_SECRET` carries into step 3):

```bash
# Create the initial admin (no-op if already set up)
curl -s -X POST http://localhost:1337/api/v1/setup -H 'Content-Type: application/json' -d '{
  "admin":{"admin":true,"email":"admin@example.com","name":"Admin",
           "password":"Admin123#pass","password_confirmation":"Admin123#pass"},
  "org_info":{"org_name":"Demo Lab"},
  "server_url":"https://localhost:8412"}' >/dev/null

# Log in and capture an API token
TOKEN=$(curl -s -X POST http://localhost:1337/api/v1/fleet/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"Admin123#pass"}' \
  | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')

# Fetch the enroll secret straight into an env var (parsed from the JSON)
export ENROLL_SECRET=$(curl -s http://localhost:1337/api/latest/fleet/spec/enroll_secret \
  -H "Authorization: Bearer $TOKEN" \
  | sed -n 's/.*"secret": *"\([^"]*\)".*/\1/p' | head -1)

echo "ENROLL_SECRET=$ENROLL_SECRET"   # sanity check — must be non-empty
```

(Or log into the UI at http://localhost:1337 and read the enroll secret there.)

**3. Start the agents** (from `osquery/`, same terminal — uses `$ENROLL_SECRET`):

```bash
cd osquery
docker compose up -d --build          # builds the agent images on first run
```

This starts one agent per Ubuntu base plus the **`vuln-agent`** demo host. Within a
minute the hosts appear in Fleet (**Hosts** page) as `online`.

**4. Run the security audit.** Open **Fleet → Queries → Live query**, target the
`vuln-agent` host, and work through [**SCENARIOS.md**](SCENARIOS.md) — 10 realistic
findings, each with the exact osquery SQL to surface it.

**Tear down:**

```bash
cd osquery && docker compose down
cd ..      && docker compose down
```

## The 10 security-audit scenarios

The `vuln-agent` runs [`agent/seed-vulnerabilities.sh`](agent/seed-vulnerabilities.sh)
at start (because `SEED_VULNS=true`), planting ten distinct issues — each detected by
a **different osquery table**, so the demo teaches breadth. Full write-ups (framing,
ATT&CK/CVE, seed commands, detection SQL, expected rows, remediation) are in
[**SCENARIOS.md**](SCENARIOS.md).

| # | Scenario | ATT&CK | osquery table |
|---|----------|--------|---------------|
| 1 | SUID backdoor shell | T1548.001 | `suid_bin` |
| 2 | Extra UID 0 / passwordless account | T1136.001 | `users`, `shadow` |
| 3 | Weak SSHD config | T1098 / T1556 | `augeas` |
| 4 | Rogue SSH `authorized_keys` | T1098.004 | `authorized_keys` |
| 5 | Cron persistence beacon | T1053.003 | `crontab` |
| 6 | Rogue bind-shell port | T1571 | `listening_ports` + `processes` |
| 7 | Process executing from `/tmp` | T1036.005 | `processes` |
| 8 | NOPASSWD sudoers + weak `/etc/shadow` | T1548.003 / T1222.002 | `sudoers`, `file` |
| 9 | Known-vulnerable software (CVE) | — | `python_packages` |
| 10 | Reverse-shell / C2 beacon | T1571 / T1059.004 | `process_open_sockets` |

All queries are validated against the osquery **5.23.0** schema and return rows
**only when the vulnerability is present** (empty result = clean).

## Building images / CI / Docker Hub

The agent image is fully self-buildable (`agent/Dockerfile`, parameterized by
`UBUNTU_VERSION` / `OSQUERY_VERSION` / `TARGETARCH`). A GitHub Actions workflow
(`.github/workflows/build-images.yml`) builds the matrix of Ubuntu bases as
multi-arch (`linux/amd64,linux/arm64`) and pushes them to Docker Hub as
[`bykva/osquery`](https://hub.docker.com/r/bykva/osquery) (one tag per base, e.g.
`bykva/osquery:5.23.0-ubuntu24.04`). Build details, single-image build commands,
the required `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` secrets, and how to run against
pre-built images are in [**docs/INFRA.md**](docs/INFRA.md).

## Automated tests

`tests/run-lab.sh` brings the whole lab up and runs a pytest suite
(`tests/test_scenarios.py`) that asserts every one of the 10 scenarios is seeded and
detectable, plus that the host enrolled/online in Fleet:

```bash
tests/run-lab.sh          # up + test (leaves the lab running)
tests/run-lab.sh all      # up + test + tear down
tests/run-lab.sh down     # tear down
```

It provisions its own venv (via `uv` or `python3-venv`), so only Docker + Python 3
are required.

## Verified

Built and run end-to-end locally: all agent images build; the server stack comes up
healthy on **MySQL 8.4** + **Fleet v4.87.0**; the `vuln-agent` seeds all 10
scenarios, enrolls over TLS, shows **online** in Fleet (osquery 5.23.0); and every
one of the 10 detection queries returns its finding.

## Credits & license

Modernized fork of FleetDM's
[`fleetdm/osquery-in-a-box`](https://github.com/fleetdm/osquery-in-a-box). Fleet and
osquery are trademarks of their respective projects. See [LICENSE](LICENSE).
