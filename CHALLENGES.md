# Challenge mode — hunt the 15 findings yourself

> **CTF-style companion to [`SCENARIOS.md`](SCENARIOS.md).** Same seeded
> `vuln-agent`, but here you get only the **story and the ATT&CK technique** —
> *no table name, no SQL*. Your job is to pick the right osquery table and write
> the query that surfaces each finding. The full answer key (exact SQL, expected
> rows, remediation) is in `SCENARIOS.md` — peek only after you've tried.

## How to play

1. Bring the lab up and target the `vuln-agent` host in **Fleet → Queries → Live
   query** (or run `osqueryi` inside the container).
2. For each challenge below, decide **which osquery table** answers the question,
   write a query that returns **rows only when the problem is present**, and run it.
3. Score yourself with the autograder: `./grade.sh` prints how many of the 15
   findings are still detectable (see [Scoring](#scoring)).
4. **Bonus — think in schema.** Browse the osquery schema
   (<https://osquery.io/schema/5.23.0/>) and, before writing each query, name the
   table you expect to use and one column you'll filter on.

Difficulty: ⭐ warm-up · ⭐⭐ standard · ⭐⭐⭐ needs a less-obvious table or a join.

---

### C1 — The instant root shell ⭐
Someone left a way to become root with no password and no exploit — a single
executable under `/usr/local` that a real admin would never put there.
**Technique:** T1548.001 (Setuid/Setgid). *Hint:* osquery has a table
dedicated to files carrying the setuid/setgid bit.

### C2 — The second king ⭐
There is more than one all-powerful account on this box, even though only one is
named after the throne. **Technique:** T1136.001 (Create Account). *Hint:* a
numeric identity, not a name, defines "root". Then check whether it even needs a
password.

### C3 — The wide-open front door ⭐⭐
Remote login has been configured about as dangerously as possible. Three specific
directives, all switched on, would let an attacker walk in. **Technique:** T1098 /
T1556. *Hint:* osquery has no `sshd_config` table — but it *can* parse config
files structurally with a lens.

### C4 — The uninvited key ⭐⭐
An attacker doesn't need a password if the door already recognizes their key.
**Technique:** T1098.004 (SSH Authorized Keys). *Hint:* one table walks every
user's home directory for you; join it to attribute the key to an account.

### C5 — The 5-minute phone-home ⭐⭐
Something on this host reaches out to the internet on a schedule and runs whatever
it's told. **Technique:** T1053.003 (Cron). *Hint:* one table unifies
`/etc/crontab`, `/etc/cron.d/*` and per-user crontabs — look for a downloader
piped into a shell.

### C6 — The open back door ⭐⭐
A service is listening on a port famous for backdoors, and it's nothing this host
should be running. **Technique:** T1571 (Non-Standard Port). *Hint:* find the
listener, then join to the process table to learn *which binary* owns the socket.

### C7 — The impostor in the scratch space ⭐⭐
A running program lives somewhere no real daemon would — a world-writable
directory — under a system-looking name. **Technique:** T1036.005 (Masquerading).
*Hint:* the process table tells you *where* each running binary lives.

### C8 — The password-free superpower ⭐⭐
A rule grants a specific account the ability to run anything as root without ever
typing a password. (And while you're here — check the permissions on the file that
stores password hashes.) **Technique:** T1548.003 / T1222.002. *Hint:* one table
parses `/etc/sudoers` and its drop-ins; another reports file mode.

### C9 — The rotten dependency ⭐
A well-known web framework is installed at a version riddled with published CVEs.
**Technique:** unpatched software. *Hint:* one table inventories installed Python
distributions; Fleet's **Vulnerabilities** page will also name the CVEs.

### C10 — The quiet outbound call ⭐⭐⭐
Nothing is *listening*, but something is *talking* — a long-lived connection out to
an unusual port. A reverse shell hides its destination in shell redirections, not
in its command line, so don't trust `cmdline`. **Technique:** T1571 / T1059.004.
*Hint:* look at per-process sockets and their connection state, not listeners.

### C11 — The library that shouldn't be there ⭐⭐⭐
A process has been told to load an extra library before everything else — the
userland-rootkit trick for hooking libc and hiding activity. **Technique:**
T1574.006 (Dynamic Linker Hijacking). *Hint:* the tell is in the process's
*environment*, not on disk. Which `LD_*` variables would an attacker set?

### C12 — The confession left behind ⭐⭐
The intruder typed their way through this host and tried to wipe the record —
but the on-disk trail survived the clean-up. **Technique:** T1552.003 / T1070.003.
*Hint:* one table reads users' shell history files; hunt for download-and-run,
decoded payloads, and the clean-up command itself.

### C13 — The ghost process ⭐⭐⭐
A program is running, but its executable is gone from disk — deleted to defeat
file scanners while the process lives on. **Technique:** T1070.004 (File
Deletion). *Hint:* the kernel still knows where the binary *was*, and marks the
path in a very specific way. The process table shows it.

### C14 — The redirected mirror ⭐⭐⭐
Package updates on this host would quietly go to an attacker's server — no DNS
query required, because the answer is pinned locally. **Technique:** T1565.001 /
T1556. *Hint:* a small table parses the file that resolvers consult *before* DNS.
A public domain pinned to a routable IP is the finding.

### C15 — The unassuming insider ⭐⭐⭐
An ordinary-looking service account is secretly a member of a group that is, in
effect, root. **Technique:** T1098 / T1548. *Hint:* which Linux groups grant
host-root by design? Join user↔group membership and list unexpected members.

---

## Scoring

The autograder runs every detection directly against the seeded host and reports
which findings are still present:

```bash
./grade.sh                    # audit scorecard: 15/15 findings present on a fresh vuln-agent
./grade.sh --remediation      # remediation mode: pass = finding is GONE (fix them, re-run)
```

Two ways to use it:

- **Audit exercise (default).** On a freshly-seeded host all 15 findings are
  detectable — a green `FOUND` for each means your mental model matches the lab.
  Compare your hand-written queries against the exact ones in `SCENARIOS.md`.
- **Remediation exercise (`--remediation`).** Now *fix* the host — remove the
  backdoor account, delete the SUID shell, kill the beacons, correct the configs —
  and re-run. Each finding you've cleaned flips to a green `CLEAN`. Goal: **15/15
  remediated.**

For the Fleet-native version of the scorecard, load the checks as **Policies**
(`./upload_reports.sh --policies`) and watch the **Policies** page: the vuln-agent
fails every policy it hasn't been remediated against, the clean agents pass.
