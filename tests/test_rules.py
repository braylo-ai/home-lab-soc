from soc.models import AttackMapping, Rule
from soc.rules import (
    evaluate_condition,
    load_rules,
    match_selection,
    rule_matches,
)

RULES_DIR = "rules"


def _rule(detection, condition):
    return Rule(
        id="t",
        title="t",
        level="high",
        logsource={},
        detection=detection,
        condition=condition,
        attack=AttackMapping("Execution", "T1059", "x"),
    )


def test_selection_equality_case_insensitive():
    assert match_selection({"Image": "cmd.exe"}, {"Image": "CMD.EXE"})
    assert not match_selection({"Image": "cmd.exe"}, {"Image": "powershell.exe"})


def test_modifier_endswith():
    assert match_selection(
        {"Image|endswith": "\\powershell.exe"},
        {"Image": "C:\\x\\powershell.exe"},
    )


def test_modifier_contains_list_is_or():
    sel = {"CommandLine|contains": ["-enc", "FromBase64String"]}
    assert match_selection(sel, {"CommandLine": "x -enc y"})
    assert match_selection(sel, {"CommandLine": "FromBase64String(x)"})
    assert not match_selection(sel, {"CommandLine": "clean"})


def test_modifier_regex():
    assert match_selection({"CommandLine|re": r"\^"}, {"CommandLine": "a^b"})
    assert not match_selection({"CommandLine|re": r"\^"}, {"CommandLine": "ab"})


def test_missing_field_does_not_match():
    assert not match_selection({"Image": "x"}, {"CommandLine": "x"})


def test_condition_and_not():
    res = {"sel": True, "filt": False}
    assert evaluate_condition("sel and not filt", res)
    assert not evaluate_condition("sel and not filt", {"sel": True, "filt": True})


def test_condition_all_of_them():
    assert evaluate_condition("all of them", {"a": True, "b": True})
    assert not evaluate_condition("all of them", {"a": True, "b": False})


def test_condition_one_of_them():
    assert evaluate_condition("1 of them", {"a": False, "b": True})
    assert not evaluate_condition("1 of them", {"a": False, "b": False})


def test_condition_rejects_unknown_token():
    import pytest

    with pytest.raises(ValueError):
        evaluate_condition("sel and __import__", {"sel": True})


def test_rule_matches_two_selection_and():
    rule = _rule(
        {
            "selection": {"EventID": 1, "CommandLine|contains": "lsass"},
            "tools": {"Image|endswith": "\\procdump64.exe"},
        },
        "selection and tools",
    )
    ev = {
        "EventID": 1,
        "Image": "C:\\procdump64.exe",
        "CommandLine": "procdump64 -ma lsass.exe",
    }
    assert rule_matches(rule, ev)
    assert not rule_matches(rule, {**ev, "Image": "C:\\notepad.exe"})


def test_load_rules_shipped():
    rules = load_rules(RULES_DIR)
    assert len(rules) >= 9
    ids = {r.id for r in rules}
    assert "win_powershell_encoded" in ids
    for r in rules:
        assert r.attack.technique_id.startswith("T")
