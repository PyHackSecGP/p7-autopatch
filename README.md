# P7 — Autonomous CVE Remediation Pipeline (MVP)

Closed-loop CVE patching: **detect → classify → snapshot → patch → verify → rollback-on-fail**.

**MVP scope (1 day):** APT-only · single target LXC · Proxmox `pct` snapshot/rollback · `systemctl is-active` healthcheck · console output, no Telegram.

## Flow

```
DefectDojo (CT205) ──High+ findings──►  classifier (semver patch-only)
                                            │
                                            ▼
                                   pct snapshot <ct> pre-patch-<ts>
                                            │
                                            ▼
                                   pct exec <ct> apt-get install pkg=ver
                                            │
                                            ▼
                                   pct exec <ct> systemctl is-active <svcs>
                                            │
                                 ┌──────────┴──────────┐
                                 ▼                     ▼
                              healthy             any failure
                                 │                     │
                              commit            pct rollback <ct> <snap>
                                                        │
                                                   pct reboot <ct>
```

## Requirements

- Run **on the Proxmox host** (needs `pct` command)
- Python 3.11+
- DefectDojo API token (reads `.env`)
- SSH / root on Proxmox host

## Install

```bash
cd ~/projects/p7-autopatch
pip install -r requirements.txt
cp .env.example .env   # fill in DOJO_URL + DOJO_TOKEN
```

## Usage

```bash
# dry-run (safe) — classify + print plan, no actions
python -m p7 --target 209 --dry-run

# live run against single CT
python -m p7 --target 209

# limit to patch-level only (semver patch component change)
python -m p7 --target 209 --max-change patch
```

## Classification

| semver diff | behavior |
|---|---|
| patch (1.2.3 → 1.2.4) | **auto-apply** |
| minor (1.2.3 → 1.3.0) | log + skip (phase 2 adds Telegram approval) |
| major (1.x → 2.x) | log + skip |

## Blast-radius controls

- Snapshot every CT **before** patch via `pct snapshot`
- Fail-closed: any healthcheck fail → rollback + reboot
- Skip list: hypervisor + hosts in `SKIP_HOSTS` env var

## Not yet done (phase 2+)

- Docker image patching
- pip / language-specific pkg managers
- Telegram HITL inline approval buttons
- Trivy rescan verify loop
- Metrics export to DefectDojo as "autopatch note"
