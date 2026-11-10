#!/usr/bin/env python3
"""End-to-end pipeline: generate telemetry -> store -> detect -> dashboard.

Usage:
    python scripts/run_pipeline.py [--db reports/soc.db] [--html reports/dashboard.html]
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import argparse
from pathlib import Path

from soc import engine, telemetry
from soc.dashboard import write as write_dashboard
from soc.rules import load_rules
from soc.scope import assert_source_allowed
from soc.store import Store

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(ROOT / "reports" / "soc.db"))
    ap.add_argument("--html", default=str(ROOT / "reports" / "dashboard.html"))
    ap.add_argument("--rules", default=str(ROOT / "rules"))
    args = ap.parse_args()

    Path(args.db).unlink(missing_ok=True)
    store = Store(args.db)
    rules = load_rules(args.rules)

    events = telemetry.generate()
    for ev in events:
        assert_source_allowed(ev.source)  # scope guard on every ingest
        ev.uid = store.add_event(ev)

    raised = engine.run(store, rules)
    write_dashboard(store, args.html)

    print(f"rules loaded     : {len(rules)}")
    print(f"events ingested  : {store.count_events()}")
    print(f"alerts raised    : {raised}")
    print(f"dashboard        : {args.html}")


if __name__ == "__main__":
    main()
