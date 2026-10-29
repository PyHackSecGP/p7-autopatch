# p7-autopatch — Autonomous CVE remediation (DefectDojo -> ZFS -> patch -> verify -> rollback)

![tests](https://img.shields.io/badge/tests-40%20passing-brightgreen)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![deps](https://img.shields.io/badge/cloud%20deps-none-success)
![backends](https://img.shields.io/badge/backends-apt%20%7C%20apk-informational)
![verify](https://img.shields.io/badge/verify-Trivy%20rescan-orange)

Closed-loop CVE patching for Debian/Alpine LXC containers on a Proxmox + ZFS
homelab. Reads findings from DefectDojo, snapshots the target via `pct
snapshot` (ZFS-backed on a zpool), installs the fix version with `apt` or
`apk`, verifies `systemctl is-active` for the services that matter, rescans
the rootfs with Trivy, writes the mitigation back to DefectDojo on success —
and `pct rollback` + `pct reboot` the moment anything fails.

---

## 60-Second Overview

**What it does.** One command, one container ID, one patch cycle:

1. Pull High/Critical, non-mitigated, non-duplicate findings from a
   DefectDojo instance that already aggregates Greenbone / Trivy / Semgrep /
   Wazuh results.
2. For every finding with a `component_name`, `component_version`, and
   `fix_available`, classify the semver jump — only `patch` level (1.2.3 ->
   1.2.4) is auto-applied by default.
3. Snapshot the target container via `pct snapshot <ctid> p7-pre-<ts>-<id>`
   (ZFS-backed on a `local-zfs` storage pool).
4. Patch: `apt-get install pkg=version` or `apk add pkg=version`, both
   routed through `pct exec`, with `DEBIAN_FRONTEND=noninteractive` +
   `--force-confold` so unattended runs do not stall on conffile prompts.
5. Verify: `systemctl is-active` for a per-container service list; then,
   optionally, `trivy rootfs --severity HIGH,CRITICAL /` and grep the JSON
   for the original CVE ID.
6. On any failure (snapshot, patch, healthcheck, Trivy rescan): `pct
   rollback` + `pct reboot` + Telegram/n8n alert. On success:
   `PATCH /api/v2/findings/<id>/` with `is_mitigated=true` and a note.

**Why it matters.** Patch Tuesday is still manual for most teams. CVE feeds
pile up in DefectDojo. Nobody has time to click through 400 findings a month
to run `apt install libxml2=2.9.14-1ubuntu0.4`. Scanners find; humans ignore;
breaches follow. This project is the small, boring, auditable thing that
closes the loop: detect -> remediate -> verify -> write back — with a
cheap rollback path when the patch breaks `sshd`.

---

## For Interviewers

### Problem Statement

**Patch pipelines are the weak point in SMB and homelab security.** The
industry has invested heavily in CVE *detection* (Greenbone, Trivy, Wazuh,
Snyk) and *aggregation* (DefectDojo, Vulners, DeepfenceSecretScanner). The
*remediation* step is still a human running `apt upgrade` on a Monday
morning. The gap:

- Scanners emit 50-500 findings per host per month.
- SMB ops teams have 0.1-0.5 FTE for patching.
- Fix versions are already in the finding — they just do not get applied.
- Patching without a rollback plan is a career-ending change window; so
  people do not patch.

`p7-autopatch` is the opinionated glue. Not an EDR, not a scanner, not
yet-another-config-management-tool. Just: *given a DefectDojo finding with a
fix version and a safe snapshot target, apply the fix and prove it worked —
or revert in under 90 seconds.*

### Skills Demonstrated

- **DefectDojo REST API** — paginated `/api/v2/findings/` consumer with
  product scoping (`test__engagement__product`), severity filter, and
  `PATCH` write-back of `is_mitigated` + notes (`src/p7/dojo.py`).
- **ZFS / Proxmox snapshot & rollback** — `pct snapshot`, `pct rollback`,
  `pct reboot` via a typed wrapper with dry-run mode and 10-minute
  timeout (`src/p7/pct.py`).
- **Multi-backend package orchestration** — `apt-get install pkg=version`
  with locked conffile answers for Debian/Ubuntu; `apk add pkg=version`
  for Alpine; `Patcher` Protocol keeps backends swappable
  (`src/p7/patcher.py`).
- **systemd state verification** — `systemctl is-active` per
  per-container service list, parsed from a `HEALTHCHECKS` env var in
  `209:ssh;205:docker,uwsgi` shape (`src/p7/healthcheck.py`).
- **Trivy post-patch rescan** — `trivy rootfs --format json
  --severity HIGH,CRITICAL /` inside the CT, with JSON walked for the
  specific `VulnerabilityID` (`src/p7/trivy.py`).
- **Exception + rollback flow** — fail-closed state machine; any single
  stage failure (snapshot / patch / healthcheck / Trivy) triggers
  `pct rollback` + `pct reboot` and a per-finding `PatchOutcome` with
  `rolled_back=True` (`src/p7/orchestrator.py`).
- **Zero cloud deps** — only `requests` + `python-dotenv` in
  `pyproject.toml`. DefectDojo, Telegram Bot API, and n8n webhooks are
  the only outbound network targets, all optional, all on-prem.
- **40 pytest tests, zero network** — `classifier` (8), `healthcheck`
  (5), `patcher` (7), `trivy` (6), `notify` (4), `orchestrator` (10).
  Everything that shells out is mocked at the `Pct` wrapper boundary.

### ASCII Pipeline Diagram

```
+--------------------+
|  DefectDojo API    |   /api/v2/findings/?severity=High,Critical
|  (on-prem)         |     &active=true&is_mitigated=false
+---------+----------+
          |
          | iter_high_findings()
          v
+--------------------+
|  detect / filter   |   Finding.is_patchable == True
|  (dojo.py)         |     requires component_name + version + fix
+---------+----------+
          |
          v
+--------------------+
|  classify          |   semver _parse(current) vs _parse(fix)
|  (classifier.py)   |     patch | minor | major | unknown
+---------+----------+
          |
          | allowed(level, --max-change)?
          v
+--------------------+
|  snapshot          |   pct snapshot <ct> p7-pre-<ts>-<id>
|  (pct.py)          |     ZFS-backed on local-zfs pool
+---------+----------+
          |
          v
+--------------------+
|  patch             |   apt-get install pkg=ver  (Debian/Ubuntu)
|  (patcher.py)      |   apk add pkg=ver          (Alpine)
+---------+----------+
          |
          v
+--------------------+
|  verify            |   systemctl is-active <svc1> <svc2> ...
|  (healthcheck.py)  |   trivy rootfs --severity HIGH,CRITICAL /
|  (trivy.py)        |     + JSON scan for original CVE id
+---------+----------+
          |
   +------+-------+
   |              |
  OK          FAIL (any stage)
   |              |
   v              v
+------+     +--------------------+
|write |     |  rollback          |
|-back |     |  pct rollback <ct> |
|dojo  |     |  pct reboot <ct>   |
+---+--+     +---------+----------+
    |                  |
    v                  v
+-----------------------------+
|  notify (Telegram / n8n)    |
|  "P7 ct205 done: 3 applied, |
|   1 rolled back, 2 skipped" |
+-----------------------------+
```

### Design Decisions

**Why ZFS/`pct snapshot`, not LVM-thin.** LVM-thin snapshots are
copy-on-write but single-tier and painful to rollback atomically from
userland. `pct snapshot` on a ZFS-backed storage pool is one syscall away
from `zfs rollback`, is already Proxmox-native, has zero config surface,
and ships with the hypervisor. Snapshot + rollback is O(seconds),
regardless of CT size. LVM-thin rollback typically costs a dismount + fsck.

**Why DefectDojo as truth source, not scanner output directly.** Trivy /
Greenbone / Wazuh / Semgrep each have their own schema. DefectDojo
normalises them into one `Finding` type with `component_name`,
`component_version`, `mitigation`, `vulnerability_ids`, `severity`,
`is_mitigated`. One API, one deduplicated feed, one `active=true` filter.
Changing scanners later does not touch `p7-autopatch`.

**Why Trivy for post-verify, not re-running Greenbone.** Greenbone takes
minutes-to-hours per CT and needs a target definition. Trivy `rootfs` runs
inside the container in seconds, needs no network, and emits JSON. The
semantics match: we are asking "is this specific CVE still present in the
package database after the patch?" — exactly what Trivy answers.

**Why `patch`-level auto-apply, with `--max-change` as the knob.** 1.2.3
-> 1.2.4 is API-compatible by semver contract; the overwhelming majority
of OS security advisories are packaged as patch bumps precisely because
backports preserve ABI. Auto-applying `minor` would occasionally break
dependents; auto-applying `major` would require a human. The CLI exposes
`--max-change {patch,minor,major}` so the operator picks the ceiling, and
the orchestrator refuses anything above it (`src/p7/classifier.py:allowed`).

**Why fail-closed with auto-rollback, no retry.** Retrying a failed `apt
install` on a broken dpkg state is how you turn a one-package problem
into a dead container. The faster, safer action is: rollback, reboot,
emit an alert, let the operator decide. The rollback window is the
snapshot-to-reboot time — single-digit seconds on ZFS. Retry can live in
a future state machine; the MVP is a straight line.

### Metrics

| Metric | Value |
| --- | --- |
| Tests | 40 (`pytest`) |
| Test files | 6 (`tests/test_*.py`) |
| Source files | 8 (`src/p7/*.py`) |
| Pipeline stages | 7 (detect / classify / snapshot / patch / healthcheck / verify / writeback) |
| Backends | 2 (`apt`, `apk`) |
| Cloud deps | 0 |
| Python runtime deps | 2 (`requests`, `python-dotenv`) |
| Rollback trigger paths | 3 (patcher-fail, healthcheck-fail, trivy-still-present) |
| Snapshot naming | `p7-pre-<unix_ts>-<finding_id>` |

---

## Quick Start

```bash
# clone + install
cd ~/projects/p7-autopatch
pip install -e .
cp .env.example .env
$EDITOR .env            # fill DOJO_URL + DOJO_TOKEN

# browse DefectDojo first (zero side-effects)
PYTHONPATH=src python -m p7 list
PYTHONPATH=src python -m p7 list --product-id 2 --limit 2000 --patchable-only

# dry-run a single CT — classify + plan, no pct actions, no writes
PYTHONPATH=src python -m p7 run --target 209 --dry-run

# first real patch cycle: apt backend, no Trivy verify, no writeback
PYTHONPATH=src python -m p7 run --target 209 --backend apt

# full belt-and-braces: apk backend, Trivy rescan verify, DefectDojo write-back
PYTHONPATH=src python -m p7 run --target 205 --backend apk \
    --product-id 2 --verify-cves --writeback

# lift the ceiling to minor-level changes (still refuses major)
PYTHONPATH=src python -m p7 run --target 209 --max-change minor
```

Exit code `0` on clean run, `1` if any finding rolled back, `2` on
missing config.

---

## Pipeline Stages

| Stage | Input | Tool | Failure mode |
| --- | --- | --- | --- |
| `detect` | DefectDojo `/api/v2/findings/` | `requests` session w/ Token auth | HTTP error -> raise, no snapshot taken |
| `classify` | `current_version`, `fix_available` | `_SEMVER_RE` + `_parse` tuple compare | `UNKNOWN` -> skipped; above `--max-change` -> skipped |
| `snapshot` | ctid, `p7-pre-<ts>-<id>` | `pct snapshot` (ZFS CoW) | non-zero rc -> `PatchOutcome(note="snapshot failed")`, no patch attempted |
| `patch` | ctid, `pkg`, `fix_version` | `pct exec` -> `apt-get` / `apk add` | non-zero rc -> `pct rollback`, notifier fired, `rolled_back=True` |
| `healthcheck` | ctid, `HEALTHCHECKS` service list | `pct exec systemctl is-active` | any svc != "active" -> `pct rollback` + `pct reboot` + alert |
| `trivy verify` *(opt)* | ctid, cve id | `pct exec trivy rootfs --format json` | CVE still present -> `pct rollback` + `pct reboot` + alert |
| `writeback` *(opt)* | finding id, note text | `PATCH /api/v2/findings/<id>/` + `POST /notes/` | logged + swallowed (non-fatal); patch is already applied |
| `notify` | summary string | Telegram Bot API *or* n8n webhook *or* NullNotifier | logged + swallowed (fire-and-forget) |

---

## Examples

### 1) Dry-run cycle on CT 209 — classify + plan only

```bash
PYTHONPATH=src python -m p7 run --target 209 --dry-run
```

Expected: every `pct` call becomes `<dry-run>` (`src/p7/pct.py:33`),
the orchestrator still walks findings, classifies versions, and prints a
summary. No snapshot taken. No DefectDojo write.

```
== P7 run summary ==
  [SKIP    ] openssl 3.0.2-0ubuntu1.10 -> 3.0.2-0ubuntu1.12 (patch) -- allowed, dry-run
  [SKIP    ] libxml2 2.9.13+dfsg-1ubuntu0.3 -> 2.9.13+dfsg-1ubuntu0.4 (patch) -- allowed, dry-run
  [SKIP    ] curl 7.81.0-1ubuntu1.14 -> 8.5.0 (minor) -- skipped: minor > max patch
```

### 2) Real patch run — apt + healthcheck, no Trivy

```bash
PYTHONPATH=src python -m p7 run --target 209 --backend apt
```

What happens on CT 209 for every High/Critical finding tagged `ct209`:

1. `pct snapshot 209 p7-pre-1730180000-4421`
2. `pct exec 209 -- env DEBIAN_FRONTEND=noninteractive apt-get install -y
    --no-install-recommends -o Dpkg::Options::=--force-confdef -o
    Dpkg::Options::=--force-confold openssl=3.0.2-0ubuntu1.12`
3. `pct exec 209 -- systemctl is-active ssh`
4. If `ssh` is still `active` -> outcome `APPLIED`.
5. If not -> `pct rollback 209 p7-pre-1730180000-4421` + `pct reboot 209`
    + Telegram alert `P7 ROLLBACK: ct209 openssl healthcheck failed ['ssh']`.

### 3) Induced failure + rollback — bad fix version

Simulate: edit a finding's `mitigation` field in DefectDojo to a nonexistent
version `9.9.9-nope`, then:

```bash
PYTHONPATH=src python -m p7 run --target 209 --backend apt --verify-cves
```

Flow:

1. Snapshot `p7-pre-1730181111-4422` is taken.
2. `apt-get install openssl=9.9.9-nope` exits non-zero (`E: Version
    '9.9.9-nope' for 'openssl' was not found`).
3. Orchestrator calls `pct rollback 209 p7-pre-1730181111-4422`.
4. Notifier fires: `P7 ROLLBACK: ct209 openssl apt-install failed`.
5. Exit code `1`. CT state is bitwise identical to pre-run (ZFS CoW).

### 4) Full prod-grade run — Trivy verify + DefectDojo write-back

```bash
PYTHONPATH=src python -m p7 run --target 205 --backend apk \
    --product-id 2 --verify-cves --writeback
```

Every successful finding gets:

- `PATCH /api/v2/findings/<id>/` with `{"is_mitigated": true,
    "active": false, "verified": true}`.
- `POST /api/v2/findings/<id>/notes/` with
    `"P7 autopatched libssl 3.0.12-r0 -> 3.0.12-r1 (patch);
     snapshot=p7-pre-1730182222-5503; healthcheck OK"`.

A Trivy rescan showing the CVE *still present* reverses this: rollback,
reboot, alert, exit code `1`. No DefectDojo write happens on failure.

---

## Technical Reference

### Install

```bash
cd ~/projects/p7-autopatch
pip install -e .              # or: pip install -r requirements.txt
cp .env.example .env
```

Runtime deps are only `requests>=2.31` and `python-dotenv>=1.0`
(`pyproject.toml`). Python 3.11+ required for `str | None` type syntax.

### Configuration (`.env`)

| Key | Required | Example | Notes |
| --- | --- | --- | --- |
| `DOJO_URL` | yes | `https://defectdojo.example.com` | DefectDojo base URL, no trailing slash |
| `DOJO_TOKEN` | yes | *API token* | Generate under *API v2 Key* in DefectDojo profile |
| `SKIP_HOSTS` | no | `100,101` | Comma-sep CT IDs that are never patched (hypervisor, data) |
| `HEALTHCHECKS` | no | `209:ssh;205:docker,uwsgi;207:docker` | `ctid:svc1,svc2;ctid:svc3`; empty list = no check |
| `N8N_WEBHOOK_URL` | no | `https://n8n.example.com/webhook/p7-autopatch` | Preferred notify path if set |
| `TELEGRAM_BOT_TOKEN` | no | *bot token* | Fallback notify if n8n not set |
| `TELEGRAM_CHAT_ID` | no | `-1001234567890` | Required if using Telegram |

`SKIP_HOSTS` is checked before any work happens — a CT in the list causes
an immediate return with a `P7 skip: ct<id> on SKIP_HOSTS` alert
(`src/p7/orchestrator.py:78`).

### CLI reference

```
python -m p7 list                                    # browse DefectDojo
    [--product-id N] [--limit N] [--patchable-only]
    [--log-level LEVEL]

python -m p7 run --target CTID                       # one patch cycle
    [--dry-run]                                      # pct echo, no execute
    [--backend {apt,apk}]                            # default: apt
    [--product-id N]                                 # scope DD query
    [--verify-cves]                                  # Trivy rescan after
    [--writeback]                                    # mitigate in DD on OK
    [--max-change {patch,minor,major}]               # default: patch
    [--log-level LEVEL]

python -m p7 serve                                   # web dashboard (optional)
    [--host 0.0.0.0] [--port 7777]
```

### systemd install (hypervisor-side)

Timer-driven, patch-only, Trivy-verified, write-back on success:

```ini
# /etc/systemd/system/p7-autopatch@.service
[Unit]
Description=p7-autopatch for CT %i
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/root/p7-autopatch
EnvironmentFile=/root/p7-autopatch/.env
ExecStart=/usr/bin/python3 -m p7 run --target %i --backend apt \
    --verify-cves --writeback --max-change patch
```

```ini
# /etc/systemd/system/p7-autopatch@.timer
[Unit]
Description=Weekly p7-autopatch for CT %i

[Timer]
OnCalendar=Wed 03:30
Persistent=true
RandomizedDelaySec=600

[Install]
WantedBy=timers.target
```

Enable per container:

```bash
systemctl enable --now p7-autopatch@209.timer
systemctl enable --now p7-autopatch@205.timer
```

### Pipeline configuration

Everything shaping orchestrator behaviour lives in two places:

- `.env` — static, operator-owned (what hosts exist, what services to
    check, who to notify).
- CLI flags — per-run (what ceiling, which backend, write-back or not).

There is intentionally no YAML config file. Two config surfaces is enough.

### ZFS snapshot naming

```
p7-pre-<unix_timestamp>-<defectdojo_finding_id>
```

Example: `p7-pre-1730180000-4421`. One snapshot per finding, so a run that
patches three packages leaves three independently-rollback-able snapshots.
`pct snapshot` creates a ZFS snapshot named
`rpool/data/subvol-209-disk-0@p7-pre-1730180000-4421` (or equivalent for
your pool layout). Retention is manual; see **Safety / Scope** below.

### Extending

**Add a package manager backend.** Implement the `Patcher` Protocol in
`src/p7/patcher.py`:

```python
class DnfPatcher:
    name = "dnf"
    def __init__(self, pct: Pct) -> None: self.pct = pct
    def update_index(self, ctid: int) -> PctResult:
        return self.pct.exec(ctid, "dnf", "makecache", "-q")
    def apply(self, ctid: int, pkg: str, version: str) -> PctResult:
        return self.pct.exec(ctid, "dnf", "install", "-y", f"{pkg}-{version}")
    def installed_version(self, ctid: int, pkg: str) -> str | None:
        res = self.pct.exec(ctid, "rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg)
        return res.stdout.strip() if res.ok else None
```

Then wire it into `select_patcher` and add `"dnf"` to the `--backend`
`choices` list in `src/p7/__main__.py`. Add a `tests/test_patcher.py` case
mirroring the existing `AptPatcher` and `ApkPatcher` tests.

**Add a verifier.** The current `TrivyVerifier` is the template. A new
verifier only has to expose `(cleared: bool, raw_result)` from a
`rescan_rootfs(ctid, cve_id)` style method. Wire into
`Orchestrator.__init__` and gate behind a new CLI flag like
`--verify-with-grype`.

**Add a notifier.** Implement the `Notifier` Protocol in
`src/p7/notify.py` (one `send(text) -> bool` method). Pick it up in
`from_env()` by env variable sniffing. The existing `NullNotifier`,
`TelegramNotifier`, `N8nWebhookNotifier` set the pattern.

---

## Safety / Scope

**Tested environments.**

- Proxmox VE 8.x host, kernel 6.x, with `local-zfs` storage pool on a
    `rpool/data` dataset.
- Debian 12 and Ubuntu 22.04 LXC containers for the `apt` backend.
- Alpine 3.19 LXC containers for the `apk` backend.
- DefectDojo 2.35+ (findings API shape).
- Trivy 0.50+ inside each CT for the `--verify-cves` path.

Everything else is possible but unverified — if you run on LVM-thin or on
VMs instead of LXCs, the `pct` wrapper will not work and `Pct` needs
replacing with a `qm` equivalent.

**Snapshot retention.** `p7-autopatch` creates snapshots and does not
delete them. One cycle = one snapshot per finding. Clean up with:

```bash
# list all p7 snapshots on a CT
pct listsnapshot 209 | grep p7-pre-

# delete a specific one once the patch has settled
pct delsnapshot 209 p7-pre-1730180000-4421

# cron: delete p7 snapshots older than 7 days
pct listsnapshot 209 --output-format=json | \
    jq -r '.[] | select(.name|startswith("p7-pre-")) | .name' | \
    while read snap; do
        ts=$(echo "$snap" | awk -F- '{print $3}')
        age=$(( ( $(date +%s) - ts ) / 86400 ))
        [ "$age" -gt 7 ] && pct delsnapshot 209 "$snap"
    done
```

**Rollback window.** Rollback is called immediately on failure, in-process.
The time between a failed healthcheck and a healthy pre-patch state is
dominated by `pct reboot` (10-30s depending on CT size). Services with
longer startup (databases) can appear "down" during that window — size the
healthcheck list accordingly.

**Scope non-goals.**

- Not an EDR. If the patch introduces malware, `p7-autopatch` will happily
    ship it as long as the service stays `active`. Trivy rescan is the only
    layer that would catch a *regressed* CVE; it will not catch a *new* one
    unless Trivy knows about it.
- Not a config-management tool. No templating, no Puppet/Ansible overlap,
    no file deployment. Package versions only.
- No Docker-image patching. See **Not yet done** below. Rebuilding an
    image is a different workflow (needs registry push + redeploy).
- No pip / npm / cargo. Language ecosystems need per-ecosystem thought
    (lockfiles, vendored deps, build steps). Scope creep deferred.
- Not multi-host sweeping. One `--target` per invocation; parallelism via
    systemd template timers.

**Hard rules.**

- Never auto-applies anything above `--max-change` (default: `patch`).
- Never patches a CT in `SKIP_HOSTS`.
- Never writes back to DefectDojo on a dry-run (gated on
    `pct.dry_run` in `src/p7/orchestrator.py:146`).
- Never retries a failed patch — rollback is terminal for that cycle.

---

## Why This Was Built

**Homelab need.** Running an on-prem security stack (Greenbone, Trivy on
8+ containers, Wazuh on all nodes, Semgrep in CI) produces a steady 50-150
new High/Critical findings a week in DefectDojo. Manually reconciling that
against `apt list --upgradable` on every CT is a weekend-eating chore.
After the third weekend lost, the lazy move was to automate the lazy case
— the patch-level bumps where the fix is already in the finding and the
risk is small.

**Career angle.** The job market in 2026 keeps pulling cybersec job
descriptions toward two words: *prioritization* and *remediation*.
Everyone can run a scanner. Fewer people can take raw CVE output, filter
to what matters, close the loop with a safe patch, prove the loop closed,
and write the result back somewhere auditable. `p7-autopatch` is a
compact artefact that shows the whole pipeline end-to-end, with tests, on
hardware you can inspect — not a slide deck.

The design doubles as a reference for the next generation: the lazy right
move for SMB security teams is almost always a boring glue layer between
tools that already exist, not a new tool.

---

## FAQ

**Q: Does this touch my production servers?**
A: Only if you point `--target` at one and the hypervisor is Proxmox. The
tool is a thin orchestration layer over `pct`; it refuses to run outside
Proxmox because `pct` is not installed. Use `--dry-run` first. Keep the
hypervisor itself in `SKIP_HOSTS`.

**Q: What happens if DefectDojo is down?**
A: `requests.get` raises; the orchestrator exits non-zero before any
snapshot is taken. No partial state possible.

**Q: Why not just `unattended-upgrades`?**
A: `unattended-upgrades` has no concept of *which CVE this fix maps to*
and no rollback. It will happily brick a container on a bad conffile
merge or a broken service after an upgrade. `p7-autopatch` is the
rollback-aware, DefectDojo-coupled version — same low ambition, more
guard rails.

**Q: Can I run it on bare metal, not LXC?**
A: Not as-is. The `Pct` wrapper assumes `pct exec`. For bare metal, swap
`Pct` for an SSH-based `Shell` class that implements the same four
methods (`snapshot`, `rollback`, `reboot`, `exec`) against a ZFS boot
environment tool like `beadm` or `zectl`. Everything above `Pct` is
Proxmox-agnostic.

**Q: Why not use GitHub Actions / cloud CI to drive this?**
A: Zero cloud deps is a design goal. The homelab stays reachable from a
cold boot with no internet. Everything runs on the hypervisor and talks
to the local DefectDojo + local n8n. A GitHub-hosted runner would need to
reach into the LAN to call `pct` — no.

**Q: How does it handle a package that triggers a kernel upgrade?**
A: Inside an LXC, kernel upgrades are a no-op — the container shares the
host kernel. For VMs this would matter and `p7-autopatch` would need a
reboot-and-verify step; today it does not support VMs
(see **Safety / Scope**).

**Q: What if two findings target the same package?**
A: They are processed in order; the second one is likely to see the fix
already installed by the first and classify as `UNKNOWN` (equal
versions), which is skipped. Harmless.

**Q: Is `--writeback` destructive?**
A: Yes — it mutates DefectDojo state. The `is_mitigated=true` /
`active=false` edit is reversible via the DefectDojo UI, but any
automation watching `is_mitigated` will react. Dry-run suppresses it.

---

## License

MIT. See `LICENSE`.
