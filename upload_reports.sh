#!/usr/bin/env bash
###############################################################################
#  upload_reports.sh — create all lab security-audit queries ("reports") in
#  Fleet via the API, so they appear in the UI ready to run — no manual entry.
#
#  Each of the 10 SCENARIOS.md detections becomes a saved query named
#  "[audit] NN <title>", scheduled (interval) with snapshot logging so Fleet's
#  per-query Report tab populates automatically.
#
#  Usage:
#     ./upload_reports.sh                 # create the audit queries; skip any that exist
#     ./upload_reports.sh --force         # on name conflict, delete the old one and recreate
#     ./upload_reports.sh --wipe          # first delete every hand-created query, then upload
#     ./upload_reports.sh --wipe --force  # clean slate: drop hand-made + replace ours
#     ./upload_reports.sh --policies      # ALSO create Fleet Policies (compliance dashboard)
#
#  Policies (--policies) are the inverse of the detection queries: each policy
#  passes (compliant) when the host is CLEAN and fails when the vulnerability is
#  present, so Fleet's Policies page shows the vuln-agent failing while the clean
#  agents pass — a live compliance scorecard for the whole fleet.
#
#  Env knobs:
#     FLEET_UI        Fleet base URL         (default http://localhost:1337)
#     ADMIN_EMAIL     admin login            (default admin@example.com)
#     ADMIN_PASSWORD  admin password         (default Admin123#pass)
#     INTERVAL        schedule seconds       (default 3600; 0 = on-demand only)
#     PLATFORM        target platform        (default linux)
#
#  Requires: python3 (stdlib only) — no pip installs.
###############################################################################
set -euo pipefail
exec python3 - "$@" <<'PY'
import os, sys, json, argparse, urllib.request, urllib.error

FLEET    = os.environ.get("FLEET_UI", "http://localhost:1337").rstrip("/")
EMAIL    = os.environ.get("ADMIN_EMAIL", "admin@example.com")
PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin123#pass")
INTERVAL = int(os.environ.get("INTERVAL", "3600"))
PLATFORM = os.environ.get("PLATFORM", "linux")
PREFIX   = "[audit] "   # marks queries managed by this script

ap = argparse.ArgumentParser(description="Upload the lab security-audit queries to Fleet.")
ap.add_argument("--force", action="store_true",
                help="on name conflict, delete the existing query and recreate it (default: skip)")
ap.add_argument("--wipe", action="store_true",
                help="delete ALL queries NOT managed by this script (hand-created) before uploading")
ap.add_argument("--interval", type=int, default=INTERVAL,
                help="schedule interval in seconds (default %(default)s; 0 = on-demand)")
ap.add_argument("--policies", action="store_true",
                help="also create Fleet Policies (inverted queries: pass = clean) for a compliance dashboard")
args = ap.parse_args()

# --- the 10 reports (mirror SCENARIOS.md). (title, description, sql) ----------
REPORTS = [
    ("01 SUID backdoor shell",
     "[T1548.001] setuid-root shell planted under /usr/local. Fix: rm it; audit `find / -perm -4000`.",
     "SELECT path, username, groupname, permissions FROM suid_bin "
     "WHERE path LIKE '/usr/local/%' AND username = 'root';"),
    ("02 Extra UID 0 account",
     "[T1136.001] a second uid-0 (hidden root) account. Fix: remove it; only root may have uid 0.",
     "SELECT uid, username, description, directory, shell FROM users "
     "WHERE uid = 0 AND username != 'root';"),
    ("03 Weak SSHD config",
     "[T1098/T1556] PermitRootLogin / PasswordAuthentication / PermitEmptyPasswords = yes. Fix: set them no.",
     "SELECT node, value FROM augeas WHERE path = '/etc/ssh/sshd_config' "
     "AND ((node LIKE '%PermitRootLogin' AND value = 'yes') "
     " OR (node LIKE '%PasswordAuthentication' AND value = 'yes') "
     " OR (node LIKE '%PermitEmptyPasswords' AND value = 'yes'));"),
    ("04 Rogue authorized_keys",
     "[T1098.004] attacker SSH key in a user's authorized_keys. Fix: remove unknown keys; monitor the files.",
     "SELECT u.username, ak.algorithm, ak.key_file, ak.comment "
     "FROM authorized_keys ak JOIN users u ON ak.uid = u.uid;"),
    ("05 Cron persistence beacon",
     "[T1053.003] cron entry that pipes a downloader into a shell. Fix: remove it; alert on curl|bash in cron.",
     "SELECT path, minute, hour, command FROM crontab "
     "WHERE command LIKE '%curl%' OR command LIKE '%wget%' "
     "OR command LIKE '%| bash%' OR command LIKE '%/dev/tcp%';"),
    ("06 Rogue bind-shell port",
     "[T1571] unexpected listener (e.g. :4444). Fix: kill it; restrict ingress; allow-list services.",
     "SELECT lp.address, lp.port, lp.protocol, p.pid, p.name, p.path, p.cmdline "
     "FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.port = 4444;"),
    ("07 Process from world-writable dir",
     "[T1036.005] a process running from /tmp, /dev/shm or /var/tmp. Fix: kill it; mount noexec.",
     "SELECT pid, name, path, cmdline, uid, start_time FROM processes "
     "WHERE path LIKE '/tmp/%' OR path LIKE '/dev/shm/%' OR path LIKE '/var/tmp/%';"),
    ("08 NOPASSWD sudoers backdoor",
     "[T1548.003] a NOPASSWD:ALL sudoers rule. Fix: remove the drop-in; run visudo -c; audit /etc/sudoers.d.",
     "SELECT source, header, rule_details FROM sudoers WHERE rule_details LIKE '%NOPASSWD%';"),
    ("09 Known-vulnerable software",
     "Vulnerable Django 2.2.x (CVE-2020-7471 et al.) in the Python inventory. Fix: upgrade; watch the Vulns page.",
     "SELECT name, version, path FROM python_packages "
     "WHERE name = 'Django' AND version LIKE '2.2%';"),
    ("10 Reverse-shell / C2 beacon",
     "[T1571/T1059.004] established outbound connection to a C2 (e.g. :9001). Fix: kill it; egress-filter.",
     "SELECT p.pid, p.name, p.cmdline, pos.remote_address, pos.remote_port, pos.state "
     "FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid "
     "WHERE pos.state = 'ESTABLISHED' AND pos.remote_port = 9001;"),
    ("11 LD_PRELOAD library injection",
     "[T1574.006] a process with LD_PRELOAD/LD_AUDIT injected (userland rootkit). Fix: kill it; remove the .so.",
     "SELECT pe.pid, p.name, pe.key, pe.value "
     "FROM process_envs pe JOIN processes p ON pe.pid = p.pid "
     "WHERE pe.key IN ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT') AND pe.value != '';"),
    ("12 Attacker traces in shell history",
     "[T1552.003/T1070.003] download-and-run / decoded payloads / history -c in shell history. Fix: investigate; central append-only logs.",
     "SELECT u.username, sh.command FROM shell_history sh JOIN users u ON sh.uid = u.uid "
     "WHERE sh.command LIKE '%curl%| bash%' OR sh.command LIKE '%wget %' "
     "OR sh.command LIKE '%base64 -d%' OR sh.command LIKE '%history -c%' OR sh.command LIKE '%/dev/tcp/%';"),
    ("13 Fileless deleted-binary process",
     "[T1070.004] a running process whose on-disk binary was unlinked (on_disk=0). Fix: kill it; mount noexec.",
     "SELECT pid, name, path, cmdline, uid FROM processes WHERE on_disk = 0 AND path != '';"),
    ("14 /etc/hosts hijack",
     "[T1565.001/T1556] update/security domains pinned to an attacker IP in /etc/hosts. Fix: remove lines; FIM /etc/hosts.",
     "SELECT address, hostnames FROM etc_hosts "
     "WHERE address NOT LIKE '127.%' AND address NOT LIKE '::%' "
     "AND address NOT LIKE 'fe00%' AND address NOT LIKE 'ff0%' "
     "AND (hostnames LIKE '%.com%' OR hostnames LIKE '%.org%' OR hostnames LIKE '%.net%');"),
    ("15 Backdoor user in a privileged group",
     "[T1098/T1548] a non-root account in docker/lxd/disk/shadow (root-equivalent, normally empty). Fix: remove it; audit power-group members.",
     "SELECT u.username, u.uid, g.groupname FROM user_groups ug "
     "JOIN users u ON ug.uid = u.uid JOIN groups g ON ug.gid = g.gid "
     "WHERE g.groupname IN ('docker', 'lxd', 'disk', 'shadow') "
     "AND u.username != 'root';"),
]
MANAGED = {PREFIX + t for (t, _, _) in REPORTS}

# --- tiny API client (stdlib; ignores any ambient HTTP proxy for localhost) ---
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def api(method, path, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(FLEET + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with opener.open(req, timeout=20) as r:
            txt = r.read().decode()
            return r.status, (json.loads(txt) if txt.strip() else {})
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()[:300]}
    except urllib.error.URLError as e:
        sys.exit(f"ERROR: cannot reach Fleet at {FLEET} ({e.reason}). Is the lab up?")

# --- login --------------------------------------------------------------------
st, res = api("POST", "/api/v1/fleet/login", body={"email": EMAIL, "password": PASSWORD})
token = res.get("token")
if not token:
    sys.exit(f"ERROR: Fleet login failed ({st}): {res}. Set ADMIN_EMAIL/ADMIN_PASSWORD?")

st, res = api("GET", "/api/latest/fleet/queries", token)
existing = {q["name"]: q["id"] for q in res.get("queries", [])}

def delete(name, qid):
    st, _ = api("DELETE", f"/api/latest/fleet/queries/id/{qid}", token)
    print(f"  - deleted '{name}'" + ("" if st < 300 else f" (HTTP {st})"))
    return st < 300

# --- wipe hand-created queries -------------------------------------------------
if args.wipe:
    victims = {n: i for n, i in existing.items() if n not in MANAGED}
    print(f"[wipe] {len(victims)} hand-created quer{'y' if len(victims)==1 else 'ies'} to remove")
    for n, i in victims.items():
        delete(n, i)
    st, res = api("GET", "/api/latest/fleet/queries", token)
    existing = {q["name"]: q["id"] for q in res.get("queries", [])}

# --- upload our reports -------------------------------------------------------
created = replaced = skipped = failed = 0
for title, desc, sql in REPORTS:
    name = PREFIX + title
    is_conflict = name in existing
    if is_conflict and not args.force:
        print(f"  = skip (exists): {name}   (use --force to replace)")
        skipped += 1
        continue
    if is_conflict and args.force:
        delete(name, existing[name])
    body = {
        "name": name, "description": desc, "query": sql,
        "interval": args.interval, "platform": PLATFORM,
        "observer_can_run": True, "logging": "snapshot",
        "automations_enabled": False, "discard_data": False,
    }
    st, res = api("POST", "/api/latest/fleet/queries", token, body)
    if st < 300:
        if is_conflict:
            print(f"  ~ replaced: {name}"); replaced += 1
        else:
            print(f"  + created:  {name}"); created += 1
    else:
        print(f"  ! FAILED:   {name} -> HTTP {st}: {res.get('error')}"); failed += 1

print(f"\nDone: {created} created, {replaced} replaced, {skipped} skipped, {failed} failed. "
      f"Open Fleet -> Queries (schedule interval={args.interval}s).")

# --- optional: Fleet Policies (inverted detections: pass = clean) -------------
if args.policies:
    print("\n[policies] creating compliance policies (pass = clean, fail = vulnerable)...")
    st, res = api("GET", "/api/latest/fleet/policies", token)
    if st >= 300:  # legacy Fleet exposed global policies under /global
        st, res = api("GET", "/api/latest/fleet/global/policies", token)
    have = {p["name"] for p in (res.get("policies") or [])}
    p_created = p_skipped = p_failed = 0
    for title, desc, sql in REPORTS:
        name = PREFIX + title
        if name in have:
            print(f"  = skip (exists): {name}")
            p_skipped += 1
            continue
        # A policy is compliant when its query returns a row. Invert the detection
        # (which returns rows only when vulnerable) so the policy PASSES when clean.
        policy_sql = f"SELECT 1 WHERE NOT EXISTS ( {sql.rstrip().rstrip(';')} );"
        body = {
            "name": name,
            "query": policy_sql,
            "description": desc,
            "resolution": desc.split("Fix:", 1)[-1].strip() if "Fix:" in desc else "",
            "platform": PLATFORM,
        }
        st, res = api("POST", "/api/latest/fleet/policies", token, body)
        if st >= 300:  # legacy Fleet created global policies under /global
            st, res = api("POST", "/api/latest/fleet/global/policies", token, body)
        if st < 300:
            print(f"  + policy:   {name}")
            p_created += 1
        else:
            print(f"  ! FAILED:   {name} -> HTTP {st}: {res.get('error')}")
            p_failed += 1
    print(f"[policies] {p_created} created, {p_skipped} skipped, {p_failed} failed. "
          f"Open Fleet -> Policies.")
    failed += p_failed

sys.exit(1 if failed else 0)
PY
