"""End-to-end checks that every security-audit scenario is executable and
detectable.

For each of the 10 scenarios in ``SCENARIOS.md`` we run its detection osquery
SQL inside the seeded ``vuln-agent`` container and assert the finding shows up.
We also assert the host enrolled/online in Fleet and that the seed script logged
every scenario.

Run via ``tests/run-lab.sh test`` (which provisions the venv + env), or directly
with ``pytest`` once the lab is up and ``VULN_CONTAINER`` / ``FLEET_TOKEN`` are set.
"""
from __future__ import annotations

import pytest

# (id, human name, detection SQL, predicate on returned rows)
# SQL mirrors SCENARIOS.md; each returns rows only when the vuln is present.
SCENARIOS = [
    (
        "01-suid-backdoor",
        "SUID backdoor shell (suid_bin)",
        "SELECT path, username, permissions FROM suid_bin "
        "WHERE path LIKE '/usr/local/%' AND username = 'root';",
        lambda r: any(row["path"] == "/usr/local/bin/rootbash" for row in r),
    ),
    (
        "02-extra-uid0",
        "Extra UID 0 account (users)",
        "SELECT uid, username, shell FROM users "
        "WHERE uid = 0 AND username != 'root';",
        lambda r: any(row["username"] == "sysbackup" for row in r),
    ),
    (
        "02b-passwordless",
        "Passwordless account (shadow)",
        "SELECT username, password_status FROM shadow "
        "WHERE password_status = 'empty';",
        lambda r: any(row["username"] == "sysbackup" for row in r),
    ),
    (
        "03-weak-sshd",
        "Weak sshd_config (augeas)",
        "SELECT node, value FROM augeas WHERE path = '/etc/ssh/sshd_config' "
        "AND ((node LIKE '%PermitRootLogin' AND value = 'yes') "
        " OR (node LIKE '%PasswordAuthentication' AND value = 'yes') "
        " OR (node LIKE '%PermitEmptyPasswords' AND value = 'yes'));",
        # >=1 risky directive is a finding. (On EL, a duplicated default
        # PasswordAuthentication line gets an augeas [n] index that the
        # end-anchored LIKE skips, so the count varies by distro; Ubuntu = 3.)
        lambda r: len(r) >= 1,
    ),
    (
        "04-authorized-keys",
        "Rogue authorized_keys (authorized_keys)",
        "SELECT u.username, ak.algorithm, ak.comment "
        "FROM authorized_keys ak JOIN users u ON ak.uid = u.uid;",
        lambda r: any(row.get("comment") == "attacker@evil" for row in r),
    ),
    (
        "05-cron-beacon",
        "Cron persistence beacon (crontab)",
        "SELECT path, command FROM crontab "
        "WHERE command LIKE '%curl%' OR command LIKE '%| bash%' "
        "OR command LIKE '%wget%' OR command LIKE '%/dev/tcp%';",
        lambda r: any("apache-backup" in row.get("path", "") for row in r),
    ),
    (
        "06-bind-shell",
        "Rogue bind-shell port (listening_ports + processes)",
        "SELECT lp.address, lp.port, p.name, p.path "
        "FROM listening_ports lp JOIN processes p ON lp.pid = p.pid "
        "WHERE lp.port = 4444;",
        lambda r: len(r) >= 1,
    ),
    (
        "07-tmp-process",
        "Process executing from /tmp (processes)",
        "SELECT pid, name, path FROM processes "
        "WHERE path LIKE '/tmp/%' OR path LIKE '/dev/shm/%' "
        "OR path LIKE '/var/tmp/%';",
        lambda r: any(row.get("path", "").startswith("/tmp/") for row in r),
    ),
    (
        "08-sudoers-nopasswd",
        "NOPASSWD sudoers backdoor (sudoers)",
        "SELECT source, header, rule_details FROM sudoers "
        "WHERE rule_details LIKE '%NOPASSWD%';",
        lambda r: any("99-backdoor" in row.get("source", "") for row in r),
    ),
    (
        "08b-weak-shadow-perms",
        "World-writable /etc/shadow (file)",
        "SELECT path, mode FROM file WHERE path = '/etc/shadow' "
        "AND mode NOT IN ('0640', '0600', '0400', '0000');",
        lambda r: any(row.get("mode") == "0666" for row in r),
    ),
    (
        "09-vulnerable-django",
        "Known-vulnerable Django (python_packages)",
        "SELECT name, version FROM python_packages "
        "WHERE name = 'Django' AND version LIKE '2.2%';",
        lambda r: len(r) >= 1,
    ),
    (
        "10-c2-beacon",
        "Reverse-shell / C2 beacon (process_open_sockets)",
        "SELECT p.name, pos.remote_port, pos.state "
        "FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid "
        "WHERE pos.state = 'ESTABLISHED' AND pos.remote_port = 9001;",
        lambda r: len(r) >= 1,
    ),
]

SEED_LOG_MARKERS = [f"scenario {n}:" for n in range(1, 11)]


@pytest.mark.parametrize(
    "sid,name,sql,predicate",
    SCENARIOS,
    ids=[s[0] for s in SCENARIOS],
)
def test_scenario_detectable(osqueryi, sid, name, sql, predicate):
    """The scenario's detection query runs and returns the expected finding."""
    rows = osqueryi(sql)
    assert rows, f"{name}: query returned no rows (scenario not seeded / SQL broke)"
    assert predicate(rows), f"{name}: rows returned but finding not present: {rows}"


def test_seed_log_covers_all_scenarios(vuln_container):
    """The seed script logged all 10 scenarios and finished cleanly."""
    import subprocess

    logs = subprocess.run(
        ["docker", "logs", vuln_container],
        capture_output=True, text=True, timeout=30,
    )
    combined = logs.stdout + logs.stderr
    missing = [m for m in SEED_LOG_MARKERS if m not in combined]
    assert not missing, f"seed log missing scenarios: {missing}"
    assert "Vulnerability seeding complete" in combined


def test_host_enrolled_and_online(fleet):
    """The vuln host enrolled and is online in Fleet with osquery 5.23.0."""
    r = fleet.get("/api/latest/fleet/hosts")
    assert r.ok, f"Fleet /hosts returned {r.status_code}"
    hosts = r.json().get("hosts", [])
    assert hosts, "no hosts enrolled in Fleet"
    online = [h for h in hosts if h.get("status") == "online"]
    assert online, f"no online hosts: {[(h['hostname'], h['status']) for h in hosts]}"
    assert any(h.get("osquery_version", "").startswith("5.23")
               for h in online), "expected an osquery 5.23.x host"
