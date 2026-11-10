"""Benchmark detection quality against labeled synthetic telemetry.

Metrics (per rule and overall):
  - detections: events labeled for rule R that raised an alert from rule R
  - detection_rate: detections / events labeled R
  - benign false positives: benign (label=None) events that raised ANY alert
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .engine import detect
from .models import Event, Rule


def evaluate(events: Iterable[Event], rules: list[Rule]) -> dict:
    events = list(events)
    labeled_total: dict[str, int] = defaultdict(int)
    detected: dict[str, int] = defaultdict(int)
    benign_total = 0
    benign_fp = 0

    for ev in events:
        alerts = detect(ev, rules)
        fired_rule_ids = {a.rule_id for a in alerts}
        if ev.label is None:
            benign_total += 1
            if fired_rule_ids:
                benign_fp += 1
        else:
            labeled_total[ev.label] += 1
            if ev.label in fired_rule_ids:
                detected[ev.label] += 1

    per_rule = {}
    for rule in rules:
        total = labeled_total.get(rule.id, 0)
        hits = detected.get(rule.id, 0)
        per_rule[rule.id] = {
            "title": rule.title,
            "technique_id": rule.attack.technique_id,
            "tactic": rule.attack.tactic,
            "labeled_events": total,
            "detections": hits,
            "detection_rate": round(hits / total, 4) if total else None,
        }

    total_labeled = sum(labeled_total.values())
    total_detected = sum(detected.values())
    return {
        "summary": {
            "events_total": len(events),
            "malicious_labeled": total_labeled,
            "malicious_detected": total_detected,
            "overall_detection_rate": (
                round(total_detected / total_labeled, 4) if total_labeled else None
            ),
            "benign_events": benign_total,
            "benign_false_positives": benign_fp,
            "false_positive_rate": (
                round(benign_fp / benign_total, 4) if benign_total else None
            ),
        },
        "per_rule": per_rule,
    }
