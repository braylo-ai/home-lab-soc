"""Core data models for the mini-SIEM."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Event:
    """A normalized log event.

    `fields` holds the raw event key/values (e.g. EventID, Image,
    CommandLine). `source` is where the SOC read it from (scope-checked).
    `label` is optional ground-truth used only for benchmarking:
    None for benign, else the rule id the event is designed to trip.
    """

    ts: str
    source: str
    fields: dict[str, Any]
    label: str | None = None
    uid: int | None = None


@dataclass
class AttackMapping:
    tactic: str
    technique_id: str
    technique: str


@dataclass
class Rule:
    id: str
    title: str
    level: str
    logsource: dict[str, Any]
    detection: dict[str, Any]
    condition: str
    attack: AttackMapping
    description: str = ""


@dataclass
class Alert:
    rule_id: str
    rule_title: str
    level: str
    technique_id: str
    technique: str
    tactic: str
    event_uid: int | None
    event_ts: str
    matched_fields: dict[str, Any] = field(default_factory=dict)
