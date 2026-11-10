"""Detection engine: run rules over events, emit alerts."""

from __future__ import annotations

from typing import Iterable

from .models import Alert, Event, Rule
from .rules import rule_matches
from .store import Store


def detect(event: Event, rules: Iterable[Rule]) -> list[Alert]:
    """Return the alerts raised by a single event."""
    alerts: list[Alert] = []
    for rule in rules:
        if rule_matches(rule, event.fields):
            alerts.append(
                Alert(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    level=rule.level,
                    technique_id=rule.attack.technique_id,
                    technique=rule.attack.technique,
                    tactic=rule.attack.tactic,
                    event_uid=event.uid,
                    event_ts=event.ts,
                    matched_fields=dict(event.fields),
                )
            )
    return alerts


def run(store: Store, rules: list[Rule]) -> int:
    """Evaluate every stored event against all rules; persist alerts.

    Returns the number of alerts raised.
    """
    raised = 0
    for event in store.iter_events():
        for alert in detect(event, rules):
            store.add_alert(alert)
            raised += 1
    return raised
