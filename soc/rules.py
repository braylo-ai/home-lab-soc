"""Sigma-style detection rules: loading and matching.

This implements a deliberately small, well-tested subset of the Sigma
detection syntax -- enough for home-lab process/network telemetry, not a
full Sigma engine.

Supported field modifiers:  contains, startswith, endswith, re (regex).
Default (no modifier) is case-insensitive equality.
A field whose value is a list matches if *any* list item matches (OR).
A selection (dict of fields) matches if *all* its fields match (AND).

Supported `condition` forms (case-insensitive):
  - "sel"
  - "sel1 and sel2"      /  "sel1 or sel2"
  - "sel and not filt"
  - "all of them"        (all selections must match)
  - "1 of them"          (any selection must match)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from .models import AttackMapping, Rule


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else [v]


def _match_scalar(modifier: str, event_val: Any, rule_val: Any) -> bool:
    if event_val is None:
        return False
    ev = str(event_val)
    rv = str(rule_val)
    if modifier == "contains":
        return rv.lower() in ev.lower()
    if modifier == "startswith":
        return ev.lower().startswith(rv.lower())
    if modifier == "endswith":
        return ev.lower().endswith(rv.lower())
    if modifier == "re":
        return re.search(rv, ev) is not None
    # default: case-insensitive equality
    return ev.lower() == rv.lower()


def _match_field(field_spec: str, rule_val: Any, event: dict[str, Any]) -> bool:
    if "|" in field_spec:
        name, modifier = field_spec.split("|", 1)
    else:
        name, modifier = field_spec, ""
    event_val = event.get(name)
    # list of candidate rule values -> OR
    return any(_match_scalar(modifier, event_val, rv) for rv in _as_list(rule_val))


def match_selection(selection: dict[str, Any], event: dict[str, Any]) -> bool:
    """A selection matches when every field spec in it matches (AND)."""
    return all(
        _match_field(field_spec, rule_val, event)
        for field_spec, rule_val in selection.items()
    )


def _tokenize_condition(condition: str) -> list[str]:
    return condition.replace("(", " ( ").replace(")", " ) ").split()


def evaluate_condition(
    condition: str, selection_results: dict[str, bool]
) -> bool:
    """Evaluate a (small) Sigma condition against pre-computed selection bools."""
    cond = condition.strip().lower()

    if cond in ("all of them", "all of selection*"):
        return all(selection_results.values())
    if cond in ("1 of them", "1 of selection*"):
        return any(selection_results.values())

    tokens = _tokenize_condition(cond)
    # Build a boolean python expression from whitelisted tokens only.
    py: list[str] = []
    for tok in tokens:
        if tok in ("and", "or", "not", "(", ")"):
            py.append(tok)
        elif tok in selection_results:
            py.append(str(selection_results[tok]))
        else:
            raise ValueError(f"Unknown token in condition: {tok!r}")
    expr = " ".join(py)
    # Only literals True/False and boolean operators remain -> safe to eval.
    return bool(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307


def rule_matches(rule: Rule, event: dict[str, Any]) -> bool:
    selections = {
        name: match_selection(sel, event)
        for name, sel in rule.detection.items()
        if isinstance(sel, dict)
    }
    return evaluate_condition(rule.condition, selections)


def load_rule(path: str | Path) -> Rule:
    raw = yaml.safe_load(Path(path).read_text())
    attack = raw.get("attack", {})
    detection = dict(raw["detection"])
    condition = detection.pop("condition")
    return Rule(
        id=raw["id"],
        title=raw["title"],
        level=raw.get("level", "medium"),
        logsource=raw.get("logsource", {}),
        detection=detection,
        condition=condition,
        description=raw.get("description", ""),
        attack=AttackMapping(
            tactic=attack.get("tactic", "unknown"),
            technique_id=attack.get("technique_id", "unknown"),
            technique=attack.get("technique", "unknown"),
        ),
    )


def load_rules(rules_dir: str | Path) -> list[Rule]:
    rules_dir = Path(rules_dir)
    rules = [load_rule(p) for p in sorted(rules_dir.glob("*.yml"))]
    rules += [load_rule(p) for p in sorted(rules_dir.glob("*.yaml"))]
    return rules
