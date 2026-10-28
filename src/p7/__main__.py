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
    sub = p.add_subparsers(dest="cmd")

    pl = sub.add_parser("list", help="List DefectDojo products + top High/Critical findings")
    pl.add_argument("--product-id", type=int, help="Scope to one product id")
    pl.add_argument("--limit", type=int, default=500, help="Max findings to pull")
    pl.add_argument("--patchable-only", action="store_true", help="Only show rows w/ component+fix")
    pl.add_argument("--log-level", default="WARNING")

    pr = sub.add_parser("run", help="Run the patch loop against one CT target")
    pr.add_argument("--target", type=int, required=True, help="Proxmox CT ID to patch")
    pr.add_argument("--dry-run", action="store_true", help="Classify + print plan; no pct actions")
    pr.add_argument("--backend", choices=["apt", "apk"], default="apt", help="Package backend")
    pr.add_argument("--product-id", type=int, help="Scope DefectDojo query to one product id")
    pr.add_argument("--verify-cves", action="store_true", help="Trivy rescan after patch; rollback if CVE still present")
    pr.add_argument("--writeback", action="store_true", help="Mark finding mitigated in DefectDojo on success")
    pr.add_argument(
        "--max-change",
        choices=[c.value for c in ChangeLevel if c is not ChangeLevel.UNKNOWN],
        default=ChangeLevel.PATCH.value,
        help="Highest semver change level to auto-apply (default: patch)",
    )
    pr.add_argument("--log-level", default="INFO")

    # legacy top-level flags map to `run` for backward compat
    p.add_argument("--target", type=int, help=argparse.SUPPRESS)
    p.add_argument("--dry-run", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--max-change", default=None, help=argparse.SUPPRESS)
    p.add_argument("--log-level", default="INFO", help=argparse.SUPPRESS)

    args = p.parse_args(argv)
    if args.cmd is None and args.target:
        args.cmd = "run"

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

    dojo = DojoClient(dojo_url, dojo_token)

    if args.cmd == "list":
        return _cmd_list(dojo, args)

    if args.cmd == "run" or args.target:
        from .notify import from_env as notifier_from_env
        skip = {int(x) for x in os.environ.get("SKIP_HOSTS", "").split(",") if x.strip().isdigit()}
        checks = parse_healthcheck_env(os.environ.get("HEALTHCHECKS", ""))
        max_change = args.max_change or ChangeLevel.PATCH.value
        pct = Pct(dry_run=args.dry_run)
        orch = Orchestrator(
            dojo=dojo, pct=pct, healthchecks=checks,
            max_change=ChangeLevel(max_change), skip_hosts=skip,
            backend=getattr(args, "backend", "apt"),
            product_id=getattr(args, "product_id", None),
            notifier=notifier_from_env(),
            verify_cves=getattr(args, "verify_cves", False),
            writeback=getattr(args, "writeback", False),
        )
        outcomes = orch.run(args.target)
        _print_summary(outcomes)
        bad = sum(1 for o in outcomes if o.rolled_back)
        return 1 if bad else 0

    p.print_help()
    return 2


def _cmd_list(dojo, args) -> int:
    """List CVE findings grouped by product."""
    from collections import Counter
    from .classifier import classify, ChangeLevel

    print(f"\n== DefectDojo Products (hub: {os.environ.get('DOJO_URL')}) ==")
    for p in sorted(dojo.list_products(), key=lambda x: x["id"]):
        print(f"  [{p['id']:>3}] {p['name']}")

    pid = args.product_id
    scope = f"product {pid}" if pid else "ALL products"
    print(f"\n== High/Critical findings ({scope}, up to {args.limit}) ==")
    findings = list(dojo.iter_high_findings(limit=args.limit, page_size=min(500, args.limit), product_id=pid))
    if args.patchable_only:
        findings = [f for f in findings if f.is_patchable]

    print(f"  pulled: {len(findings)}")
    patchable = [f for f in findings if f.is_patchable]
    print(f"  patchable (component + fix): {len(patchable)}")

    by_sev = Counter(f.severity for f in findings)
    by_pkg = Counter(f.component_name for f in patchable if f.component_name)
    by_cve = Counter(f.cve for f in findings if f.cve)

    print(f"\n  severity: {dict(by_sev)}")
    print(f"\n  top packages ({min(15, len(by_pkg))}):")
    for pkg, n in by_pkg.most_common(15):
        print(f"    {n:4}x  {pkg}")

    print(f"\n  top CVEs ({min(15, len(by_cve))}):")
    for c, n in by_cve.most_common(15):
        print(f"    {n:4}x  {c}")

    levels = Counter()
    easy = []
    for f in patchable:
        first_fix = (f.fix_available or "").split(",")[0].strip()
        lv = classify(f.component_version, first_fix)
        levels[lv.value] += 1
        if lv is ChangeLevel.PATCH:
            easy.append((f, first_fix))
    print(f"\n  classification: {dict(levels)}")

    print(f"\n  easiest wins (semver PATCH, {min(20, len(easy))} of {len(easy)}):")
    for f, fix in easy[:20]:
        print(f"    {f.severity:8} {f.cve or '-':16} {f.component_name:28} {f.component_version:18} -> {fix:18} ({f.host or '-'})")

    return 0


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
