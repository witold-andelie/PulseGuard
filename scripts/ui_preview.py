"""SYNTHETIC UI preview server — not wired into the app, replay, Render or Dockerfile.

Serves ``web/`` and a read-only fake API built from ``tests/fixtures/ui/bundle.json``.
Every payload is marked SYNTHETIC. POST decision/rollback return simulated labels
and do not persist.

Run: ``python scripts/ui_preview.py --port 8765``
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from statistics import mean
from urllib.parse import urlparse

MARKER = "SYNTHETIC — UI development fixture, not a recording"
ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
BUNDLE_PATH = ROOT / "tests" / "fixtures" / "ui" / "bundle.json"

CSV_COLUMNS = ("case_id", "activity", "timestamp", "resource", "priority", "score", "run_mode")
STATES = {
    "FINDING_INGESTED": "raw", "FINDING_QUARANTINED": "quarantined",
    "EVIDENCE_BUILT": "normalized", "VERDICT_CONFIRMED": "confirmed",
    "VERDICT_UNCERTAIN": "uncertain", "FALSE_POSITIVE_DROPPED": "false_positive",
    "ABSTAINED_ESCALATED": "escalated", "PATCH_APPLIED": "remediated",
    "REJECTED": "rejected", "ROLLED_BACK": "rolled_back",
}


def load_bundle() -> dict:
    raw = BUNDLE_PATH.read_text(encoding="utf-8")
    if MARKER not in raw:
        raise SystemExit("fixture is missing the SYNTHETIC marker")
    return json.loads(raw)


def list_item(detail: dict, run_id: str) -> dict:
    case = detail["case"]
    finding = case.get("finding") or {}
    return {
        "case_id": case["case_id"],
        "run_id": run_id,
        "rule_id": case["rule_id"],
        "file": case["file"],
        "line": case["line"],
        "state": case["state"],
        "priority": detail.get("priority") or case.get("priority"),
        "scanner": finding.get("scanner") or case.get("scanner"),
        "created_at": case.get("created_at"),
        "closed_at": case.get("closed_at"),
    }


def all_events(bundle: dict) -> list[dict]:
    events = []
    for detail in bundle["cases"]:
        events.extend(detail.get("events") or [])
    return events


def export_csv(events: list[dict]) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for event in events:
        attrs = event.get("attributes") or {}
        writer.writerow({
            "case_id": event["case_id"], "activity": event["activity"],
            "timestamp": event["ts"], "resource": event["resource"],
            "priority": attrs.get("priority"), "score": attrs.get("score"),
            "run_mode": attrs.get("run_mode", "REPLAY"),
        })
    return output.getvalue()


def _stamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def compute_kpis(events: list[dict]) -> dict:
    by_case: dict[str, list[dict]] = defaultdict(list)
    counts: Counter[str] = Counter()
    automatic = human = 0
    for event in events:
        by_case[event["case_id"]].append(event)
        counts[event["activity"]] += 1
        if event["activity"] == "APPROVED":
            attrs = event.get("attributes") or {}
            if attrs.get("policy_tier") == "auto" or event["resource"] == "policy:auto":
                automatic += 1
            else:
                human += 1
    durations: list[float] = []
    loops: list[int] = []
    final_states: Counter[str] = Counter()
    for case_events in by_case.values():
        state = "raw"
        ingested = closed = None
        pending = False
        rework = 0
        for event in case_events:
            activity = event["activity"]
            attrs = event.get("attributes") or {}
            if activity in STATES:
                state = STATES[activity]
            if activity == "FINDING_INGESTED" and ingested is None:
                ingested = event["ts"]
            elif activity == "CASE_CLOSED":
                state = attrs.get("outcome") or state
                if state == "remediated":
                    closed = event["ts"]
            if activity == "SANDBOX_FAILED":
                pending = True
            elif activity == "PATCH_PROPOSED" and pending:
                rework += 1
                pending = False
        final_states[state] += 1
        if state == "remediated" and closed and ingested:
            seconds = (_stamp(closed) - _stamp(ingested)).total_seconds()
            if seconds >= 0:
                durations.append(seconds)
        loops.append(rework)
    return {
        "mean_time_to_remediate_s": mean(durations) if durations else None,
        "false_positives_dropped": counts["FALSE_POSITIVE_DROPPED"],
        "approvals_automatic": automatic, "approvals_human": human,
        "rework_loops": {"mean": mean(loops) if loops else 0.0, "max": max(loops, default=0)},
        "cases_total": len(by_case), "cases_by_final_state": dict(sorted(final_states.items())),
        "_comment": MARKER,
    }


def mime(path: Path) -> str:
    return {
        ".html": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".js": "text/javascript; charset=utf-8",
        ".svg": "image/svg+xml",
        ".json": "application/json; charset=utf-8",
    }.get(path.suffix, "application/octet-stream")


def make_handler(bundle: dict) -> type[BaseHTTPRequestHandler]:
    cases = {item["case"]["case_id"]: item for item in bundle["cases"]}
    run_id = bundle["mode"]["run_id"]
    mode = dict(bundle["mode"])
    mode.setdefault("synthetic", True)
    mode.setdefault("label", MARKER)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            sys.stderr.write("preview: " + (fmt % args) + "\n")

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-PulseGuard-Fixture", "SYNTHETIC")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: object) -> None:
            self._send(status, json.dumps(payload, indent=2).encode("utf-8"),
                       "application/json; charset=utf-8")

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            parts = parsed.path.rstrip("/").split("/")
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            if len(parts) == 5 and parts[1] == "api" and parts[2] == "cases":
                case_id, action = parts[3], parts[4]
                if case_id not in cases:
                    self._json(404, {"detail": f"case {case_id} not found"})
                    return
                if action == "decision":
                    self._json(200, {
                        "simulated": True,
                        "label": "REPLAY - simulated decision; nothing was applied or stored",
                        "approval": {
                            "decision": "approve", "simulated": True, "actor": "demo-visitor",
                        },
                        "_comment": MARKER,
                    })
                    return
                if action == "rollback":
                    self._json(200, {
                        "simulated": True,
                        "label": "REPLAY - simulated rollback; nothing was restored",
                        "rollback": {"available": False, "rolled_back": False, "simulated": True},
                        "_comment": MARKER,
                    })
                    return
            self._json(404, {"detail": "not found"})

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/health":
                self._json(200, {"status": "ok", "mode": "REPLAY", "synthetic": True,
                                 "replay_verified": True})
                return
            if path == "/api/mode":
                self._json(200, mode)
                return
            if path == "/api/cases":
                self._json(200, {
                    "mode": "REPLAY", "run_id": run_id,
                    "cases": [list_item(item, run_id) for item in bundle["cases"]],
                    "_comment": MARKER,
                })
                return
            if path == "/api/kpis":
                self._json(200, compute_kpis(all_events(bundle)))
                return
            if path == "/api/eventlog.csv":
                body = export_csv(all_events(bundle)).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition",
                                 'attachment; filename="pulseguard-eventlog.csv"')
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-PulseGuard-Fixture", "SYNTHETIC")
                self.end_headers()
                self.wfile.write(body)
                return
            parts = path.rstrip("/").split("/")
            if len(parts) >= 4 and parts[1] == "api" and parts[2] == "cases":
                case_id = parts[3]
                detail = cases.get(case_id)
                if detail is None:
                    self._json(404, {"detail": f"case {case_id} not found"})
                    return
                if len(parts) == 5 and parts[4] == "trace":
                    self._json(200, {
                        "case_id": case_id, "mode": "REPLAY",
                        "events": detail.get("events") or [], "_comment": MARKER,
                    })
                    return
                if len(parts) == 4:
                    payload = {key: value for key, value in detail.items() if key != "events"}
                    payload["mode"] = "REPLAY"
                    payload["_comment"] = MARKER
                    self._json(200, payload)
                    return
            relative = "index.html" if path == "/" else path.lstrip("/")
            target = (WEB / relative).resolve()
            try:
                target.relative_to(WEB.resolve())
            except ValueError:
                self._json(404, {"detail": "not found"})
                return
            if not target.is_file():
                self._json(404, {"detail": "not found"})
                return
            self._send(200, target.read_bytes(), mime(target))

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=MARKER)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    bundle = load_bundle()
    server = ThreadingHTTPServer((args.host, args.port), make_handler(bundle))
    print(f"SYNTHETIC preview http://{args.host}:{args.port}  ({MARKER})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
