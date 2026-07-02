"""Shared fixtures for the Fleet + osquery lab scenario tests.

The lab must already be running (``tests/run-lab.sh up``). These fixtures locate
the vulnerable agent container, run osquery queries inside it, and talk to the
Fleet API.
"""
from __future__ import annotations

import json
import os
import subprocess
import time

import pytest


def _run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _discover_vuln_container() -> str:
    """Container name of the running vuln-agent (env override wins)."""
    env = os.environ.get("VULN_CONTAINER")
    if env:
        return env
    out = _run(
        ["docker", "ps", "--filter", "name=vuln-agent", "--format", "{{.Names}}"]
    ).stdout.strip()
    return out.splitlines()[0] if out else ""


@pytest.fixture(scope="session")
def vuln_container() -> str:
    name = _discover_vuln_container()
    if not name:
        pytest.skip("vuln-agent container not running — run tests/run-lab.sh up first")
    return name


@pytest.fixture(scope="session")
def osqueryi(vuln_container):
    """Return a callable that runs an osquery SQL string inside the vuln-agent
    and returns the parsed JSON rows. Retries a few times because a couple of
    osquery tables (e.g. augeas) can occasionally return empty on first eval.
    """

    def _query(sql: str, retries: int = 4, delay: float = 1.5) -> list[dict]:
        last = []
        for _ in range(retries):
            proc = _run(
                ["docker", "exec", vuln_container, "osqueryi", "--json", sql],
                timeout=60,
            )
            try:
                rows = json.loads(proc.stdout or "[]")
            except json.JSONDecodeError:
                rows = []
            if rows:
                return rows
            last = rows
            time.sleep(delay)
        return last

    return _query


@pytest.fixture(scope="session")
def fleet():
    """Minimal Fleet API client (base URL + admin token from run-lab state)."""
    import requests

    base = os.environ.get("FLEET_UI", "http://localhost:1337")
    token = os.environ.get("FLEET_TOKEN", "")
    sess = requests.Session()
    sess.trust_env = False  # ignore ambient HTTP proxy for localhost
    if not token:
        email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
        pw = os.environ.get("ADMIN_PASSWORD", "Admin123#pass")
        r = sess.post(f"{base}/api/v1/fleet/login",
                      json={"email": email, "password": pw}, timeout=15)
        token = r.json().get("token", "") if r.ok else ""
    if not token:
        pytest.skip("no Fleet API token available")
    sess.headers["Authorization"] = f"Bearer {token}"

    class _Fleet:
        def get(self, path):
            return sess.get(f"{base}{path}", timeout=15)

    return _Fleet()
