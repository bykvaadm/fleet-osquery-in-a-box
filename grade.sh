#!/usr/bin/env bash
###############################################################################
#  grade.sh — scorecard for the security-audit lab.
#
#  Runs every one of the 15 detection queries (SCENARIOS.md / CHALLENGES.md)
#  directly against the seeded host with osqueryi and reports, per scenario,
#  whether the finding is present. Each detection returns rows ONLY when the
#  vulnerability exists, so "rows > 0" == finding present == host still vulnerable.
#
#  Modes:
#     ./grade.sh                 audit:       FOUND (green) when detectable
#                                             — a fresh vuln-agent scores 15/15 FOUND
#     ./grade.sh --remediation   remediation: CLEAN (green) when the finding is GONE
#                                             — fix the host, re-run, aim for 15/15 CLEAN
#
#  Target host: the running `vuln-agent` container (override with VULN_CONTAINER).
#  Requires: docker + python3 (stdlib only). Runs osqueryi inside the container,
#  so it works fully offline and doesn't touch the Fleet API.
#
#  Exit code: 0 if the run met its goal (audit: all found; remediation: all
#  clean), else 1 — handy in CI or a grading pipeline.
###############################################################################
set -euo pipefail
exec python3 - "$@" <<'PY'
import json, os, subprocess, sys

REMEDIATION = "--remediation" in sys.argv[1:]

# (id, human title, detection SQL). SQL mirrors SCENARIOS.md; rows => finding present.
CHECKS = [
    ("01", "SUID backdoor shell",
     "SELECT path FROM suid_bin WHERE path LIKE '/usr/local/%' AND username='root';"),
    ("02", "Extra UID 0 account",
     "SELECT username FROM users WHERE uid=0 AND username!='root';"),
    ("03", "Weak SSHD config",
     "SELECT node FROM augeas WHERE path='/etc/ssh/sshd_config' AND "
     "((node LIKE '%PermitRootLogin' AND value='yes') OR "
     "(node LIKE '%PasswordAuthentication' AND value='yes') OR "
     "(node LIKE '%PermitEmptyPasswords' AND value='yes'));"),
    ("04", "Rogue authorized_keys",
     "SELECT ak.comment FROM authorized_keys ak JOIN users u ON ak.uid=u.uid;"),
    ("05", "Cron persistence beacon",
     "SELECT path FROM crontab WHERE command LIKE '%curl%' OR command LIKE '%wget%' "
     "OR command LIKE '%| bash%' OR command LIKE '%/dev/tcp%';"),
    ("06", "Rogue bind-shell port",
     "SELECT lp.port FROM listening_ports lp JOIN processes p ON lp.pid=p.pid WHERE lp.port=4444;"),
    ("07", "Process from world-writable dir",
     "SELECT pid FROM processes WHERE path LIKE '/tmp/%' OR path LIKE '/dev/shm/%' "
     "OR path LIKE '/var/tmp/%';"),
    ("08", "NOPASSWD sudoers backdoor",
     "SELECT source FROM sudoers WHERE rule_details LIKE '%NOPASSWD%';"),
    ("09", "Known-vulnerable Django",
     "SELECT name FROM python_packages WHERE name='Django' AND version LIKE '2.2%';"),
    ("10", "Reverse-shell / C2 beacon",
     "SELECT pos.remote_port FROM process_open_sockets pos JOIN processes p ON pos.pid=p.pid "
     "WHERE pos.state='ESTABLISHED' AND pos.remote_port=9001;"),
    ("11", "LD_PRELOAD library injection",
     "SELECT pe.pid FROM process_envs pe JOIN processes p ON pe.pid=p.pid "
     "WHERE pe.key IN ('LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT') AND pe.value!='';"),
    ("12", "Attacker traces in shell history",
     "SELECT sh.command FROM shell_history sh JOIN users u ON sh.uid = u.uid "
     "WHERE sh.command LIKE '%curl%| bash%' OR sh.command LIKE '%wget %' "
     "OR sh.command LIKE '%base64 -d%' OR sh.command LIKE '%history -c%' "
     "OR sh.command LIKE '%/dev/tcp/%';"),
    ("13", "Fileless deleted-binary process",
     "SELECT pid FROM processes WHERE on_disk = 0 AND path != '';"),
    ("14", "/etc/hosts hijack",
     "SELECT address FROM etc_hosts WHERE address NOT LIKE '127.%' AND address NOT LIKE '::%' "
     "AND address NOT LIKE 'fe00%' AND address NOT LIKE 'ff0%' AND "
     "(hostnames LIKE '%.com%' OR hostnames LIKE '%.org%' OR hostnames LIKE '%.net%');"),
    ("15", "Backdoor user in a privileged group",
     "SELECT u.username FROM user_groups ug JOIN users u ON ug.uid=u.uid "
     "JOIN groups g ON ug.gid=g.gid WHERE g.groupname IN "
     "('docker','lxd','disk','shadow') AND u.username!='root';"),
]

def discover():
    c = os.environ.get("VULN_CONTAINER")
    if c:
        return c
    out = subprocess.run(
        ["docker", "ps", "--filter", "name=vuln-agent", "--format", "{{.Names}}"],
        capture_output=True, text=True).stdout.strip()
    return out.splitlines()[0] if out else ""

CONTAINER = discover()
if not CONTAINER:
    sys.exit("ERROR: no running vuln-agent container found. Bring the lab up first "
             "(tests/run-lab.sh up), or set VULN_CONTAINER.")

def rows(sql):
    p = subprocess.run(["docker", "exec", CONTAINER, "osqueryi", "--json", sql],
                       capture_output=True, text=True, timeout=60)
    try:
        return json.loads(p.stdout or "[]")
    except json.JSONDecodeError:
        return []

use_color = sys.stdout.isatty()
def c(code, s):
    return f"\033[{code}m{s}\033[0m" if use_color else s
GREEN, RED, YELLOW, DIM = "32", "31", "33", "2"

mode = "remediation" if REMEDIATION else "audit"
print(f"Grading '{CONTAINER}'  —  {mode} mode\n")
goal_met = 0
for cid, title, sql in CHECKS:
    present = len(rows(sql)) > 0
    if REMEDIATION:
        ok = not present
        label = c(GREEN, "CLEAN           ") if ok else c(RED, "STILL VULNERABLE")
    else:
        ok = present
        label = c(GREEN, "FOUND  ") if ok else c(YELLOW, "MISSING")
    goal_met += 1 if ok else 0
    print(f"  {c(DIM, cid)}  {label}  {title}")

total = len(CHECKS)
noun = "remediated" if REMEDIATION else "findings detected"
tail = "  (fix them and re-run)" if REMEDIATION and goal_met < total else ""
color = GREEN if goal_met == total else (YELLOW if not REMEDIATION else RED)
print("\n" + c(color, f"Score: {goal_met}/{total} {noun}.") + tail)
sys.exit(0 if goal_met == total else 1)
PY
