"""CLI entrypoint — `python -m p7 --target 209 [--dry-run]`."""
from __future__ import annotations

import argparse
import logging
import os
import sys

from dotenv import load_dotenv

from .classifier import ChangeLevel
from .dojo import DojoClient
from .healthcheck import parse_healthcheck_env
from .orchestrator import Orchestrator
from .pct import Pct


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    p = argparse.ArgumentParser(prog="p7", description="Autonomous CVE remediation (MVP).")
    p.add_argument("--target", type=int, required=True, help="Proxmox CT ID to patch")
    p.add_argument("--dry-run", action="store_true", help="Classify + print plan; no pct actions")
    p.add_argument(
        "--max-change",
        choices=[c.value for c in ChangeLevel if c is not ChangeLevel.UNKNOWN],
        default=ChangeLevel.PATCH.value,
        help="Highest semver change level allowed to auto-apply (default: patch)",
    )
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    log = logging.getLogger("p7")

    dojo_url = os.environ.get("DOJO_URL")
    dojo_token = os.environ.get("DOJO_TOKEN")
    if not dojo_url or not dojo_token:
        log.error("DOJO_URL + DOJO_TOKEN required in .env")
        return 2

    skip = {int(x) for x in os.environ.get("SKIP_HOSTS", "").split(",") if x.strip().isdigit()}
    checks = parse_healthcheck_env(os.environ.get("HEALTHCHECKS", ""))

    dojo = DojoClient(dojo_url, dojo_token)
    pct = Pct(dry_run=args.dry_run)
    orch = Orchestrator(
        dojo=dojo,
        pct=pct,
        healthchecks=checks,
        max_change=ChangeLevel(args.max_change),
        skip_hosts=skip,
    )

    outcomes = orch.run(args.target)
    _print_summary(outcomes)
    bad = sum(1 for o in outcomes if o.rolled_back or (not o.applied and o.level is ChangeLevel.PATCH))
    return 1 if bad else 0


def _print_summary(outcomes) -> None:
    """Print concise end-of-run table to stdout."""
    print("\n== P7 run summary ==")
    if not outcomes:
        print("  (no actions)")
        return
    for o in outcomes:
        status = "APPLIED" if o.applied else ("ROLLBACK" if o.rolled_back else "SKIP")
        print(f"  [{status:8}] {o.pkg} {o.from_version} -> {o.to_version} ({o.level.value}) — {o.note}")


if __name__ == "__main__":
    sys.exit(main())
