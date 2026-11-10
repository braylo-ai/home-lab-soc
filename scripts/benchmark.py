#!/usr/bin/env python3
"""Run the detection benchmark and write reports/benchmark_results.json.

All numbers are computed live from the seeded synthetic dataset; nothing is
hand-entered.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
from datetime import datetime, timezone
from pathlib import Path

from soc import telemetry
from soc.benchmark import evaluate
from soc.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    rules = load_rules(ROOT / "rules")
    events = telemetry.generate()
    result = evaluate(events, rules)
    result["meta"] = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rules": len(rules),
        "dataset": "synthetic (seed=1337)",
    }
    out = ROOT / "reports" / "benchmark_results.json"
    out.write_text(json.dumps(result, indent=2))

    s = result["summary"]
    print(json.dumps(s, indent=2))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
