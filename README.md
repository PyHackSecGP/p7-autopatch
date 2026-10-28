# P7 — Autonomous CVE Remediation Pipeline

Closed-loop CVE patching for a Proxmox homelab: **detect → classify → snapshot → patch → healthcheck → Trivy rescan → rollback-on-fail → DefectDojo write-back → Telegram alert**.

Reads findings from **DefectDojo** (where Greenbone, Trivy, Semgrep, Wazuh, etc. all converge), classifies the semver jump, snapshots the target CT via `pct snapshot`, patches with `apt` or `apk`, verifies services are still active and the CVE is actually cleared via Trivy rescan, and rolls back + reboots the moment anything fails.

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
# browse what DefectDojo has
PYTHONPATH=src python -m p7 list                        # list all products
PYTHONPATH=src python -m p7 list --product-id 2 --limit 2000   # Container Images (Trivy)

# dry-run against single CT (classify + plan only, no pct actions)
PYTHONPATH=src python -m p7 run --target 209 --dry-run

# live apt run
PYTHONPATH=src python -m p7 run --target 209 --backend apt

# live apk run with full belt-and-braces (Trivy verify + DefectDojo write-back)
PYTHONPATH=src python -m p7 run --target 205 --backend apk \
  --product-id 2 --verify-cves --writeback

# cap allowed risk tier
PYTHONPATH=src python -m p7 run --target 209 --max-change patch
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

## Done

- APT + APK backends via `--backend {apt,apk}`
- Trivy rootfs rescan verify loop (`--verify-cves`) — CVE still present after patch = rollback
- DefectDojo write-back (`--writeback`) — mark finding mitigated + note
- Outbound Telegram / n8n webhook notifications (env-driven)
- Product-scoped queries (`--product-id`)
- 40 tests, all green

## Not yet done

- Docker image patching from the host side (rebuild + redeploy)
- pip / language-specific package managers
- Bi-directional Telegram HITL inline approval buttons (needs n8n webhook server workflow)
- Multi-host sweep (`--target all`)
