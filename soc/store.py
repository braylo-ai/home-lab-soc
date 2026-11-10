"""SQLite-backed storage for events and alerts."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable, Iterator

from .models import Alert, Event

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    uid     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    source  TEXT NOT NULL,
    label   TEXT,
    fields  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id      TEXT NOT NULL,
    rule_title   TEXT NOT NULL,
    level        TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    technique    TEXT NOT NULL,
    tactic       TEXT NOT NULL,
    event_uid    INTEGER,
    event_ts     TEXT NOT NULL,
    matched      TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # --- events -------------------------------------------------------
    def add_event(self, event: Event) -> int:
        cur = self.conn.execute(
            "INSERT INTO events (ts, source, label, fields) VALUES (?, ?, ?, ?)",
            (event.ts, event.source, event.label, json.dumps(event.fields)),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def add_events(self, events: Iterable[Event]) -> int:
        n = 0
        for ev in events:
            self.add_event(ev)
            n += 1
        return n

    def iter_events(self) -> Iterator[Event]:
        for row in self.conn.execute("SELECT * FROM events ORDER BY uid"):
            yield Event(
                ts=row["ts"],
                source=row["source"],
                fields=json.loads(row["fields"]),
                label=row["label"],
                uid=row["uid"],
            )

    def count_events(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    # --- alerts -------------------------------------------------------
    def add_alert(self, alert: Alert) -> int:
        cur = self.conn.execute(
            "INSERT INTO alerts (rule_id, rule_title, level, technique_id, "
            "technique, tactic, event_uid, event_ts, matched) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert.rule_id,
                alert.rule_title,
                alert.level,
                alert.technique_id,
                alert.technique,
                alert.tactic,
                alert.event_uid,
                alert.event_ts,
                json.dumps(alert.matched_fields),
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def iter_alerts(self) -> Iterator[Alert]:
        for row in self.conn.execute("SELECT * FROM alerts ORDER BY id"):
            yield Alert(
                rule_id=row["rule_id"],
                rule_title=row["rule_title"],
                level=row["level"],
                technique_id=row["technique_id"],
                technique=row["technique"],
                tactic=row["tactic"],
                event_uid=row["event_uid"],
                event_ts=row["event_ts"],
                matched_fields=json.loads(row["matched"]),
            )

    def count_alerts(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
