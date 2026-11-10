import pytest

from soc import engine, telemetry
from soc.benchmark import evaluate
from soc.dashboard import render
from soc.rules import load_rules
from soc.scope import ScopeError, assert_source_allowed, is_source_allowed
from soc.store import Store

RULES_DIR = "rules"


@pytest.fixture
def rules():
    return load_rules(RULES_DIR)


def test_store_roundtrip():
    store = Store(":memory:")
    events = telemetry.generate(n_benign=10, per_rule=2)
    for ev in events:
        ev.uid = store.add_event(ev)
    assert store.count_events() == len(events)
    assert len(list(store.iter_events())) == len(events)


def test_engine_raises_alerts(rules):
    store = Store(":memory:")
    for ev in telemetry.generate(n_benign=50, per_rule=5):
        ev.uid = store.add_event(ev)
    raised = engine.run(store, rules)
    assert raised > 0
    assert store.count_alerts() == raised


def test_benchmark_detects_all_rule_families(rules):
    events = telemetry.generate(n_benign=100, per_rule=10)
    result = evaluate(events, rules)
    # every malicious family in the generator should be detected at 100%
    for rule_id in telemetry.malicious_rule_ids():
        assert result["per_rule"][rule_id]["detection_rate"] == 1.0


def test_benchmark_zero_false_positives(rules):
    events = telemetry.generate(n_benign=300, per_rule=10)
    result = evaluate(events, rules)
    assert result["summary"]["benign_false_positives"] == 0
    assert result["summary"]["false_positive_rate"] == 0.0


def test_dashboard_renders_html(rules):
    store = Store(":memory:")
    for ev in telemetry.generate(n_benign=20, per_rule=3):
        ev.uid = store.add_event(ev)
    engine.run(store, rules)
    html = render(store)
    assert "<html" in html
    assert "ATT&amp;CK" in html


def test_scope_allows_local_sources():
    for src in [
        "localhost",
        "127.0.0.1",
        "synthetic",
        "./data/x.json",
        "file:///tmp/a",
    ]:
        assert is_source_allowed(src)
        assert_source_allowed(src)  # no raise


def test_scope_blocks_external_sources():
    for src in ["http://example.com", "https://8.8.8.8", "evil.net"]:
        assert not is_source_allowed(src)
        with pytest.raises(ScopeError):
            assert_source_allowed(src)


def test_telemetry_is_deterministic():
    a = telemetry.generate(seed=42)
    b = telemetry.generate(seed=42)
    assert [e.fields for e in a] == [e.fields for e in b]
