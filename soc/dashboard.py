"""Generate a small static HTML dashboard from the alert store."""

from __future__ import annotations

import html
from collections import Counter
from pathlib import Path

from .store import Store

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>home-lab-soc dashboard</title>
<style>
 body {{ font-family: -apple-system, system-ui, sans-serif; margin: 2rem;
         background:#0f1117; color:#e6e6e6; }}
 h1 {{ font-size:1.4rem; }}
 .cards {{ display:flex; gap:1rem; flex-wrap:wrap; margin:1rem 0; }}
 .card {{ background:#1b1f2a; border:1px solid #2a2f3a; border-radius:8px;
          padding:1rem 1.25rem; min-width:150px; }}
 .card .n {{ font-size:1.8rem; font-weight:700; }}
 table {{ border-collapse:collapse; width:100%; margin-top:1rem; }}
 th,td {{ text-align:left; padding:.4rem .6rem; border-bottom:1px solid #2a2f3a;
          font-size:.9rem; }}
 th {{ color:#9aa4b2; }}
 .critical {{ color:#ff6b6b; }} .high {{ color:#ffa94d; }}
 .medium {{ color:#ffd43b; }} .low {{ color:#74c0fc; }}
 code {{ color:#b2f2bb; word-break:break-all; }}
</style>
</head>
<body>
<h1>home-lab-soc &mdash; alert dashboard</h1>
<p>Local lab telemetry only. Generated from the SQLite alert store.</p>
<div class="cards">
 <div class="card"><div class="n">{total_alerts}</div>total alerts</div>
 <div class="card"><div class="n">{total_techniques}</div>ATT&amp;CK techniques</div>
 <div class="card"><div class="n">{total_critical}</div>critical/high</div>
</div>
<h2>Alerts by ATT&amp;CK technique</h2>
<table><tr><th>Technique</th><th>ID</th><th>Tactic</th><th>Count</th></tr>
{technique_rows}
</table>
<h2>Recent alerts</h2>
<table><tr><th>Time</th><th>Level</th><th>Rule</th><th>Technique</th><th>Evidence</th></tr>
{alert_rows}
</table>
</body></html>
"""


def render(store: Store, limit: int = 50) -> str:
    alerts = list(store.iter_alerts())
    by_tech: Counter = Counter()
    tech_meta: dict[str, tuple[str, str]] = {}
    for a in alerts:
        by_tech[a.technique_id] += 1
        tech_meta[a.technique_id] = (a.technique, a.tactic)

    technique_rows = "\n".join(
        f"<tr><td>{html.escape(tech_meta[t][0])}</td><td>{html.escape(t)}</td>"
        f"<td>{html.escape(tech_meta[t][1])}</td><td>{c}</td></tr>"
        for t, c in by_tech.most_common()
    )

    rows = []
    for a in alerts[-limit:][::-1]:
        evidence = a.matched_fields.get("CommandLine") or a.matched_fields.get(
            "TargetUserName", ""
        )
        rows.append(
            f"<tr><td>{html.escape(a.event_ts)}</td>"
            f"<td class='{html.escape(a.level)}'>{html.escape(a.level)}</td>"
            f"<td>{html.escape(a.rule_title)}</td>"
            f"<td>{html.escape(a.technique_id)}</td>"
            f"<td><code>{html.escape(str(evidence))}</code></td></tr>"
        )
    alert_rows = "\n".join(rows)

    crit_high = sum(1 for a in alerts if a.level in ("critical", "high"))
    return _TEMPLATE.format(
        total_alerts=len(alerts),
        total_techniques=len(by_tech),
        total_critical=crit_high,
        technique_rows=technique_rows,
        alert_rows=alert_rows,
    )


def write(store: Store, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(render(store))
    return path
