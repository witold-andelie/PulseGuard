"""Celonis-ready export and event-derived KPIs (framework 10.1).

Reads revio ``src/revio/agent/findings_store.py``-style SQLite events; timestamp/resource
semantics follow tradepulse ``trace.py``. No model, case-state table or fabricated KPI data.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from statistics import mean
from typing import Any

from pulseguard.store import Store

CSV_COLUMNS = ("case_id", "activity", "timestamp", "resource", "priority", "score", "run_mode")
_STATES = {
    "FINDING_INGESTED": "raw", "FINDING_QUARANTINED": "quarantined",
    "EVIDENCE_BUILT": "normalized", "VERDICT_CONFIRMED": "confirmed",
    "VERDICT_UNCERTAIN": "uncertain", "FALSE_POSITIVE_DROPPED": "false_positive",
    "ABSTAINED_ESCALATED": "escalated", "PATCH_APPLIED": "remediated",
    "REJECTED": "rejected", "ROLLED_BACK": "rolled_back",
}


def read_events(store: Store, mode: str | None = None) -> list[dict[str, Any]]:
    """Snapshot events in sequence order; recover missing S1 run modes via the run relation.

    Event-only fixtures work without cases or runs. API exports filter to the serving mode;
    they never relabel old REPLAY events as LIVE when a database is reused.
    """
    with store.connect() as conn:
        rows = conn.execute(
            "SELECT e.*, r.mode AS stored_mode FROM events e "
            "LEFT JOIN cases c ON c.case_id = e.case_id "
            "LEFT JOIN runs r ON r.run_id = c.run_id ORDER BY e.seq"
        ).fetchall()
    events = []
    for row in rows:
        event = dict(row)
        attributes = json.loads(event.pop("attributes_json"))
        stored_mode = event.pop("stored_mode")
        event_mode = attributes.get("run_mode") or stored_mode
        if mode and event_mode != mode.upper():
            continue
        event["attributes"] = {**attributes, "run_mode": event_mode}
        events.append(event)
    return events


def _timestamp(value: str) -> datetime:
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("event timestamp must have a UTC offset")
    return stamp.astimezone(UTC)


def export_csv(events: Iterable[dict[str, Any]]) -> str:
    """Emit the exact framework columns, UTC timestamps, UTF-8-ready text and LF rows."""
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for event in events:
        attrs = event.get("attributes", {})
        writer.writerow({
            "case_id": event["case_id"], "activity": event["activity"],
            "timestamp": _timestamp(event["ts"]).isoformat().replace("+00:00", "Z"),
            "resource": event["resource"], "priority": attrs.get("priority"),
            "score": attrs.get("score"), "run_mode": attrs.get("run_mode"),
        })
    return output.getvalue()


def compute_kpis(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Compute case outcomes and durations from the ordered log alone.

    Final state is the latest classification/outcome event (open cases remain included).
    MTTR uses remediated CASE_CLOSED minus first FINDING_INGESTED, excluding rejected,
    dropped and rolled-back cases. No completed remediations gives null, not zero.
    A rework loop is a failure followed by a new proposal; intervening events are allowed,
    repeated failures before one proposal count once. Mean includes cases with zero loops.
    """
    by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    counts: Counter[str] = Counter()
    automatic = human = 0
    for event in sorted(events, key=lambda item: item["seq"]):
        by_case[event["case_id"]].append(event)
        activity = event["activity"]
        counts[activity] += 1
        if activity == "APPROVED":
            attrs = event.get("attributes", {})
            if attrs.get("policy_tier") == "auto" or event["resource"] == "policy:auto":
                automatic += 1
            else:
                human += 1
    durations: list[float] = []
    loops: list[int] = []
    final_states: Counter[str] = Counter()
    for case_events in by_case.values():
        state = "raw"
        ingested: datetime | None = None
        closed: datetime | None = None
        applied = False
        pending_failure = False
        rework = 0
        for event in case_events:
            activity = event["activity"]
            attrs = event.get("attributes", {})
            if activity in _STATES:
                state = _STATES[activity]
            if activity == "FINDING_INGESTED" and ingested is None:
                ingested = _timestamp(event["ts"])
            elif activity == "PATCH_APPLIED":
                applied = True
            elif activity == "ROLLED_BACK":
                applied = False
                closed = None
            elif activity == "CASE_CLOSED":
                state = attrs.get("outcome") or attrs.get("state") or (
                    "remediated" if applied else state)
                if state == "remediated":
                    closed = _timestamp(event["ts"])
            if activity == "SANDBOX_FAILED":
                pending_failure = True
            elif activity == "PATCH_PROPOSED" and pending_failure:
                rework += 1
                pending_failure = False
        final_states[state] += 1
        if state == "remediated" and closed is not None and ingested is not None:
            seconds = (closed - ingested).total_seconds()
            if seconds >= 0:
                durations.append(seconds)
        loops.append(rework)
    return {
        "mean_time_to_remediate_s": mean(durations) if durations else None,
        "false_positives_dropped": counts["FALSE_POSITIVE_DROPPED"],
        "approvals_automatic": automatic, "approvals_human": human,
        "rework_loops": {"mean": mean(loops) if loops else 0.0, "max": max(loops, default=0)},
        "cases_total": len(by_case), "cases_by_final_state": dict(sorted(final_states.items())),
    }
