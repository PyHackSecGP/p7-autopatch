"""P7 dashboard — single-pane view over DefectDojo findings.

Serves two routes: `/` lists products, `/product/<id>` drills into findings
with classification + easy-wins highlighted. No DB; pulls live each request.
"""
from __future__ import annotations

import os
import time
from collections import Counter

from flask import Flask, render_template, request

_CACHE_TTL = 60
_cache: dict[str, tuple[float, object]] = {}


def _memo(key: str, fn):
    """Tiny in-process TTL cache — avoid hammering DefectDojo on every request."""
    now = time.time()
    hit = _cache.get(key)
    if hit and now - hit[0] < _CACHE_TTL:
        return hit[1]
    val = fn()
    _cache[key] = (now, val)
    return val

from .classifier import ChangeLevel, classify
from .dojo import DojoClient


def create_app(dojo: DojoClient | None = None) -> Flask:
    app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))
    if dojo is None:
        dojo = DojoClient(os.environ["DOJO_URL"], os.environ["DOJO_TOKEN"])

    @app.route("/")
    def index():
        def build():
            products = dojo.list_products()
            counts: dict[int, int] = {}
            for p in products:
                try:
                    counts[p["id"]] = _total_count(dojo, p["id"])
                except Exception:
                    counts[p["id"]] = -1
            return products, counts

        products, counts = _memo("home", build)
        return render_template(
            "index.html",
            products=sorted(products, key=lambda x: -counts.get(x["id"], 0)),
            counts=counts,
            dojo_url=os.environ.get("DOJO_URL", ""),
        )

    @app.route("/product/<int:pid>")
    def product(pid: int):
        limit = int(request.args.get("limit", 500))
        findings = _memo(f"p{pid}:{limit}", lambda: list(dojo.iter_high_findings(limit=limit, product_id=pid)))
        patchable = [f for f in findings if f.is_patchable]

        rows = []
        levels = Counter()
        for f in patchable:
            fix = (f.fix_available or "").split(",")[0].strip()
            lv = classify(f.component_version, fix)
            levels[lv.value] += 1
            rows.append({
                "id": f.id, "cve": f.cve or "-", "severity": f.severity,
                "pkg": f.component_name, "cur": f.component_version,
                "fix": fix, "level": lv.value, "host": f.host or "-",
            })

        by_sev = Counter(f.severity for f in findings)
        by_pkg = Counter(f.component_name for f in patchable if f.component_name).most_common(20)
        by_cve = Counter(f.cve for f in findings if f.cve).most_common(20)

        easy_wins = sorted(
            [r for r in rows if r["level"] == "patch"],
            key=lambda r: (0 if r["severity"] == "Critical" else 1, r["cve"]),
        )

        pname = next((p["name"] for p in dojo.list_products() if p["id"] == pid), f"product-{pid}")
        return render_template(
            "product.html",
            product_id=pid, product_name=pname,
            total=len(findings), patchable=len(patchable),
            levels=dict(levels), by_sev=dict(by_sev), by_pkg=by_pkg, by_cve=by_cve,
            rows=rows, easy_wins=easy_wins,
            dojo_url=os.environ.get("DOJO_URL", ""),
        )

    return app


def _total_count(dojo: DojoClient, product_id: int) -> int:
    """Fast count via HEAD-style query — use `count` field from DefectDojo paginator."""
    url = f"{dojo.base}/api/v2/findings/"
    params = {
        "severity": "High,Critical", "active": "true",
        "is_mitigated": "false", "duplicate": "false",
        "test__engagement__product": product_id, "limit": 1,
    }
    r = dojo._session.get(url, params=params, timeout=dojo.timeout)
    r.raise_for_status()
    return int(r.json().get("count", 0))


def serve(host: str = "0.0.0.0", port: int = 7777) -> None:
    app = create_app()
    app.run(host=host, port=port, debug=False)
