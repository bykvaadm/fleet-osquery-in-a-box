# Infrastructure notes — osquery-in-a-box

This document covers the infrastructure/plumbing of the lab: component versions,
how to build the agent images, how to bring the stack up, how the CI works, and
how to run against pre-built images from GHCR. (The end-user "try it out" story
lives in the top-level `README.md`.)

## Component versions

| Component      | Version / image                          | Notes |
|----------------|------------------------------------------|-------|
| Fleet server   | `fleetdm/fleet:v4.87.0`                   | Default via `FLEET_VERSION` (`${FLEET_VERSION:-v4.87.0}`). |
| MySQL          | `mysql:8.4`                              | 8.4 LTS — the newest line Fleet is tested against. **Do NOT use MySQL 9.x**: it breaks Fleet's schema migrations (`prepare db`). |
| Redis          | `redis:7`                                | |
| osquery        | `5.23.0`                                | Installed in the agent image from the official GitHub release `.deb` (amd64 + arm64). |
| Agent OS bases | Ubuntu `20.04`, `22.04`, `24.04`, `26.04` | Built from `agent/Dockerfile`. (centos / ubuntu 14/16/18 were dropped.) |

## Repository layout

```
docker-compose.yml            # SERVER stack: mysql01 + redis01 + fleet01 (TLS 8412) + fleet02 (HTTP 1337)
osquery/docker-compose.yml    # AGENT stack: one service per Ubuntu base + a vuln-agent
osquery/fleet.crt / fleet.key # self-signed TLS cert the agents trust (mounted at runtime)
agent/                        # self-buildable osquery agent image
  Dockerfile                  #   parameterized by UBUNTU_VERSION / OSQUERY_VERSION / TARGETARCH
  entrypoint.sh               #   requires ENROLL_SECRET; optional SEED_VULNS hook; exec osqueryd
  osquery.flags               #   TLS config/distributed/logger/carver flags
.github/workflows/build-images.yml  # CI: build + push multi-arch agent images to GHCR
docs/INFRA.md                 # this file
```

## Building the agent images locally

The agent image is fully self-buildable — no more pulling stale `osquery/osquery`
images from Docker Hub.

Build one base directly:

```bash
docker build --build-arg UBUNTU_VERSION=24.04 -t fleet-osquery-agent:ubuntu24.04 agent/
```

Build args:

- `UBUNTU_VERSION` (default `24.04`) — the `ubuntu:<ver>` base.
- `OSQUERY_VERSION` (default `5.23.0`) — the osquery release to install.
- `TARGETARCH` — set automatically by buildx (`amd64`/`arm64`); falls back to
  `dpkg --print-architecture` for a plain `docker build`.

Multi-arch build (needs buildx + QEMU), same as CI:

```bash
docker buildx build \
  --build-arg UBUNTU_VERSION=24.04 \
  --platform linux/amd64,linux/arm64 \
  -t fleet-osquery-agent:ubuntu24.04 agent/
```

The osquery `.deb` is fetched from:
`https://github.com/osquery/osquery/releases/download/5.23.0/osquery_5.23.0-1.linux_<arch>.deb`

## Bringing the lab up

1. Start the server stack (from the repo root):

   ```bash
   docker compose up -d
   ```

   Compose waits for MySQL to be healthy before starting Fleet, and fleet02 waits
   for fleet01 to be healthy so the two servers do not race the DB migration.

   - `fleet01` — TLS on `https://localhost:8412` (the endpoint agents enroll to).
   - `fleet02` — plain HTTP on `http://localhost:1337` (UI / API only).

2. Create the initial admin and grab the enroll secret (headless, via fleet02):

   ```bash
   curl -s -X POST http://localhost:1337/api/v1/setup -H 'Content-Type: application/json' -d '{
     "admin":{"admin":true,"email":"admin@example.com","name":"Admin",
              "password":"Admin123#pass","password_confirmation":"Admin123#pass"},
     "org_info":{"org_name":"Demo Lab"},
     "server_url":"https://localhost:8412"}'

   TOKEN=$(curl -s -X POST http://localhost:1337/api/v1/fleet/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"admin@example.com","password":"Admin123#pass"}' \
     | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')

   curl -s http://localhost:1337/api/latest/fleet/spec/enroll_secret \
     -H "Authorization: Bearer $TOKEN"
   ```

3. Start the agents (from `osquery/`, the external `fleet-preview` network is
   created by the server stack):

   ```bash
   cd osquery
   export ENROLL_SECRET=<secret-from-step-2>
   docker compose up -d --build          # builds the images if not present
   ```

   Agent services: `ubuntu2004-agent`, `ubuntu2204-agent`, `ubuntu2404-agent`,
   `ubuntu2604-agent`, and `vuln-agent` (Ubuntu 24.04 with `SEED_VULNS=true` — the
   deliberately-vulnerable demo host the scenarios target; its seed script is
   authored/mounted separately and run by the entrypoint when present).

   Each agent mounts `osquery/fleet.crt` at `/etc/osquery/fleet.crt` (read-only),
   passes `ENROLL_SECRET` (osquery reads it via `--enroll_secret_env`), and talks
   to `FLEET_SERVER` (default `host.docker.internal:8412`).

4. Tear down:

   ```bash
   cd osquery && docker compose down
   cd ..      && docker compose down
   ```

## Running against pre-built (Docker Hub) images

`osquery/docker-compose.yml` sets both `build:` and `image:` on every agent
service, so Compose builds locally when the image is absent but will use/pull a
published image if present. To pull instead of build:

```bash
cd osquery
export ENROLL_SECRET=<secret>
docker compose pull      # pulls bykva/osquery:5.23.0-ubuntu<ver>
docker compose up -d --no-build
```

## CI flow

Two workflows implement **test-on-MR, publish-on-master**:

```
 MR (pull_request ─► production)         merge/push ─► production  (or a v* tag)
 ┌───────────────────────────┐          ┌────────────────────────────────────┐
 │ test.yml                   │          │ build-images.yml                    │
 │  scenario-tests            │          │  test  (reuses test.yml) ──┐        │
 │  = tests/run-lab.sh all    │          │                            ▼        │
 └───────────────────────────┘          │  build (needs: test) ─► Docker Hub  │
   no images published                   │   only runs if tests pass           │
                                         └────────────────────────────────────┘
```

**`test.yml`** (`.github/workflows/test.yml`)
- Triggers: `pull_request` (every MR), `workflow_call` (reused by build-images),
  `workflow_dispatch`.
- One job: spins the whole lab up on the runner and runs the scenario suite
  (`tests/run-lab.sh all`). Publishes nothing.

**`build-images.yml`** (`.github/workflows/build-images.yml`)
- Triggers: push to `production`, version tags (`v*`), manual `workflow_dispatch`.
- Job `test` reuses `test.yml`; job `build` has `needs: test`, so **images are
  only published if the lab tests pass**.
- `build` matrixes Ubuntu `20.04 / 22.04 / 24.04 / 26.04`, builds
  `linux/amd64,linux/arm64` (QEMU + Buildx) and pushes to **Docker Hub**.
- Requires two repo secrets (Settings → Secrets and variables → Actions):
  - `DOCKERHUB_USERNAME` — the Docker Hub account (e.g. `bykva`)
  - `DOCKERHUB_TOKEN` — a Docker Hub access token with write scope
- Pushes two tags per base into the single `bykva/osquery` repo:
  - pinned: `bykva/osquery:5.23.0-ubuntu<ver>`
  - moving: `bykva/osquery:ubuntu<ver>`
- Forking to a different account: change `env.IMAGE` in the workflow and the
  `image:` names in `osquery/docker-compose.yml`.

## Automated scenario tests

`tests/run-lab.sh` orchestrates the whole lab and runs a pytest suite that asserts
every scenario is seeded and detectable:

- `tests/run-lab.sh up` — start the server stack, create the admin, fetch the
  enroll secret, build + start the `vuln-agent`, wait for seeding + enrollment.
- `tests/run-lab.sh test` — provision a venv (via `uv` or `python3-venv`) and run
  `tests/test_scenarios.py` (12 detection checks + seed-log coverage + Fleet
  enrollment). Set `AGENTS=all` to also start the four clean Ubuntu agents.
- `tests/run-lab.sh down` — tear everything down. `all` = up + test + down.

## What was verified locally

- Agent image builds clean: Ubuntu **24.04** and **26.04** bases, osquery
  **5.23.0** installed from the GitHub `.deb` (`osqueryd version 5.23.0`).
- Server stack healthy on **mysql:8.4** (`SELECT VERSION()` → `8.4.x`) +
  **fleet v4.87.0** (`/version` → `4.87.0`, `/healthz` → 200 on both fleet01 TLS
  and fleet02 HTTP). No MySQL-8.4 migration/compatibility errors.
- End-to-end enrollment: admin created via API, enroll secret fetched, the
  Ubuntu 24.04 agent enrolled over TLS to fleet01 (node key issued, config +
  distributed read/write + log forwarding), and the host shows in Fleet as
  `online`, platform `ubuntu`, `osquery_version 5.23.0`.
