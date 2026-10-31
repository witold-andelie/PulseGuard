"""SQLite case store (WAL, one writer) with the tables of framework section 10.

Adapted from revio ``src/revio/agent/findings_store.py`` (fingerprint = dedup key). LangGraph
checkpoints (``AsyncSqliteSaver``) live in the same file but manage their own tables.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pulseguard.contracts.validate import assert_payload
from pulseguard.trace import redact

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    mode            TEXT NOT NULL CHECK (mode IN ('REPLAY', 'LIVE')),
    started_at      TEXT NOT NULL,
    source_commit   TEXT,
    manifest_sha256 TEXT
);
CREATE TABLE IF NOT EXISTS cases (
    case_id     TEXT PRIMARY KEY,
    run_id      TEXT REFERENCES runs(run_id),
    fingerprint TEXT NOT NULL UNIQUE,
    rule_id     TEXT NOT NULL,
    file        TEXT NOT NULL,
    line        INTEGER NOT NULL,
    state       TEXT NOT NULL,
    priority    TEXT,
    created_at  TEXT NOT NULL,
    closed_at   TEXT,
    finding_json TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id  TEXT NOT NULL,
    case_id      TEXT NOT NULL REFERENCES cases(case_id),
    kind         TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (case_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS verdicts (
    verdict_id          TEXT PRIMARY KEY,
    case_id             TEXT NOT NULL REFERENCES cases(case_id),
    role                TEXT NOT NULL,
    score               REAL NOT NULL,
    band                TEXT NOT NULL,
    cited_evidence_json TEXT NOT NULL,
    steps_json          TEXT NOT NULL,
    model               TEXT,
    created_at          TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS patches (
    patch_id            TEXT PRIMARY KEY,
    case_id             TEXT NOT NULL REFERENCES cases(case_id),
    attempt             INTEGER NOT NULL,
    state               TEXT NOT NULL,
    patchset_json       TEXT NOT NULL,
    sandbox_report_json TEXT
);
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    patch_id    TEXT NOT NULL REFERENCES patches(patch_id),
    decision    TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    actor       TEXT NOT NULL,
    policy_tier TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         TEXT NOT NULL,
    activity        TEXT NOT NULL,
    ts              TEXT NOT NULL,
    resource        TEXT NOT NULL,
    attributes_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_state ON cases(state);
CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id, seq);
CREATE TABLE IF NOT EXISTS runtime_state (
    case_id TEXT PRIMARY KEY REFERENCES cases(case_id),
    state_json TEXT NOT NULL
);
"""

STEP_KEYS = ("step1_dataflow", "step2_constraint", "step3_context", "step4_verdict")
REPLAY_CONTEXT_KEYS = (
    "evidence_block", "bundle", "review_status", "review_reason", "priority",
    "verification", "skeptic", "counterfactual", "counterfactual_verdict", "poc",
    "analysis_limits", "z3_veto", "blast_radius", "policy", "bus_health", "rollback",
    "approval", "verdict_metadata", "model_calls", "topology_extraction",
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class Store:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._lock = threading.RLock()  # one writer

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            with self._lock:
                yield conn
                conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> Store:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(SCHEMA)
        return self

    def journal_mode(self) -> str:
        with self.connect() as conn:
            return str(conn.execute("PRAGMA journal_mode").fetchone()[0])

    def reset(self) -> None:
        """Delete all PulseGuard rows (used when re-seeding from the replay bundle)."""
        with self.connect() as conn:
            for table in ("runtime_state", "approvals", "patches", "verdicts", "evidence", "events",
                          "cases", "runs"):
                conn.execute(f"DELETE FROM {table}")  # noqa: S608 - fixed table names
            conn.execute("DELETE FROM sqlite_sequence WHERE name = 'events'")

    # ------------------------------------------------------------------ runs
    def create_run(self, run_id: str, mode: str, *, source_commit: str | None = None,
                   manifest_sha256: str | None = None, started_at: str | None = None) -> str:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO runs VALUES (?, ?, ?, ?, ?) ON CONFLICT(run_id) DO UPDATE SET "
                "mode=excluded.mode, started_at=excluded.started_at, "
                "source_commit=excluded.source_commit, manifest_sha256=excluded.manifest_sha256",
                (run_id, mode.upper(), started_at or _now(), source_commit, manifest_sha256),
            )
        return run_id

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return dict(row) if row else None

    def list_runs(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM runs ORDER BY started_at")]

    # ----------------------------------------------------------------- cases
    def upsert_case(self, finding: dict[str, Any], *, run_id: str | None = None,
                    priority: str | None = None, created_at: str | None = None) -> str:
        """Insert or update by fingerprint (dedup key). Returns the stored case_id."""
        assert_payload("finding", finding)
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT case_id FROM cases WHERE fingerprint = ?", (finding["fingerprint"],)
            ).fetchone()
            if existing:
                finding = {**finding, "case_id": existing["case_id"]}
                conn.execute(
                    "UPDATE cases SET state = ?, line = ?, finding_json = ?, "
                    "run_id = COALESCE(?, run_id) WHERE case_id = ?",
                    (finding["state"], finding["line"], json.dumps(finding), run_id,
                     existing["case_id"]),
                )
                return str(existing["case_id"])
            conn.execute(
                "INSERT INTO cases (case_id, run_id, fingerprint, rule_id, file, line, state,"
                " priority, created_at, finding_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (finding["case_id"], run_id, finding["fingerprint"], finding["rule_id"],
                 finding["file"], finding["line"], finding["state"], priority,
                 created_at or _now(), json.dumps(finding)),
            )
            return str(finding["case_id"])

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        return self._case_row(row) if row else None

    def list_cases(self, state: str | None = None, *, mode: str | None = None
                   ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM cases"
        conditions, args = [], []
        if state:
            conditions.append("state = ?")
            args.append(state)
        if mode:
            conditions.append("run_id IN (SELECT run_id FROM runs WHERE mode = ?)")
            args.append(mode.upper())
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        with self.connect() as conn:
            rows = conn.execute(sql + " ORDER BY created_at, case_id", args).fetchall()
        return [self._case_row(r) for r in rows]

    def update_case_state(self, case_id: str, state: str, *, closed: bool = False) -> None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT finding_json FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if row is None:
                raise KeyError(case_id)
            finding = json.loads(row["finding_json"])
            finding["state"] = state
            assert_payload("finding", finding)
            cur = conn.execute(
                "UPDATE cases SET state = ?, finding_json = ?, "
                "closed_at = CASE WHEN ? THEN ? ELSE closed_at END"
                " WHERE case_id = ?", (state, json.dumps(finding), closed, _now(), case_id))
            if cur.rowcount == 0:
                raise KeyError(case_id)

    @staticmethod
    def _case_row(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        raw = d.pop("finding_json", None)
        d["finding"] = json.loads(raw) if raw else None
        return d

    # -------------------------------------------------------------- evidence
    def add_evidence(self, case_id: str, evidence_id: str, kind: str,
                     payload: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute("INSERT OR REPLACE INTO evidence VALUES (?, ?, ?, ?)",
                         (evidence_id, case_id, kind, json.dumps(payload)))

    def list_evidence(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE case_id = ? "
                "ORDER BY CAST(SUBSTR(evidence_id, 2) AS INTEGER)", (case_id,)).fetchall()
        return [{"evidence_id": r["evidence_id"], "case_id": r["case_id"], "kind": r["kind"],
                 **json.loads(r["payload_json"])} for r in rows]

    # -------------------------------------------------------------- verdicts
    def add_verdict(self, case_id: str, verdict: dict[str, Any],
                    created_at: str | None = None) -> str:
        assert_payload("verdict", verdict)
        vid = _new_id("V")
        steps = {k: verdict.get(k, "") for k in STEP_KEYS}
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO verdicts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (vid, case_id, verdict.get("role", "adjudicator"), float(verdict["score"]),
                 verdict["band"], json.dumps(verdict.get("cited_evidence", [])),
                 json.dumps({**steps, "is_exploitable": verdict.get("is_exploitable")}),
                 verdict.get("model"), created_at or _now()))
        return vid

    def list_verdicts(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM verdicts WHERE case_id = ? ORDER BY created_at",
                                (case_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["cited_evidence"] = json.loads(d.pop("cited_evidence_json"))
            d["steps"] = json.loads(d.pop("steps_json"))
            out.append(d)
        return out

    def get_runtime(self, case_id: str) -> dict[str, Any] | None:
        """Latest materialised graph state, available without model configuration."""
        with self.connect() as conn:
            row = conn.execute("SELECT state_json FROM runtime_state WHERE case_id = ?",
                               (case_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def set_replay_context(self, case_id: str, case: dict[str, Any]) -> None:
        """Retain recorded detail fields; absent legacy fields remain absent."""
        context = {key: case[key] for key in REPLAY_CONTEXT_KEYS if key in case}
        if context:
            with self.connect() as conn:
                conn.execute("INSERT OR REPLACE INTO runtime_state VALUES (?, ?)",
                             (case_id, json.dumps(context)))

    def sync_runtime(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        """Atomically project a checkpoint into all S1 tables; return newly written events.

        Stable artifact ids and event offsets make checkpoint projection safe to repeat.
        """
        finding = state["finding"]
        case_id = finding["case_id"]
        assert_payload("finding", finding)
        with self.connect() as conn:
            row = conn.execute("SELECT state_json FROM runtime_state WHERE case_id = ?",
                               (case_id,)).fetchone()
            previous = json.loads(row[0]) if row else {}
            closed = any(e.get("activity") == "CASE_CLOSED" for e in state.get("events", []))
            priority = state.get("priority") or state.get("blast_radius", {}).get("priority")
            conn.execute(
                "UPDATE cases SET finding_json = ?, state = ?, "
                "priority = COALESCE(?, priority), closed_at = "
                "CASE WHEN ? THEN COALESCE(closed_at, ?) ELSE closed_at END WHERE case_id = ?",
                (json.dumps(finding), finding["state"], priority,
                 closed, _now(), case_id))
            for item in state.get("evidence", []):
                conn.execute("INSERT OR REPLACE INTO evidence VALUES (?, ?, ?, ?)",
                             (item["evidence_id"], case_id, item["kind"],
                              json.dumps({"text": item["text"], **item.get("payload", {})})))
            self._sync_verdict(conn, case_id, state)
            self._sync_patch(conn, case_id, state)
            added = []
            for event in state.get("events", [])[len(previous.get("events", [])):]:
                event = {**event, "attributes": redact(event.get("attributes", {}))}
                assert_payload("event", {"seq": 0, **event})
                cursor = conn.execute(
                    "INSERT INTO events (case_id, activity, ts, resource, attributes_json) "
                    "VALUES (?, ?, ?, ?, ?)", (case_id, event["activity"], event["ts"],
                                               event["resource"], json.dumps(event["attributes"])))
                added.append({"seq": cursor.lastrowid, **event})
            conn.execute("INSERT OR REPLACE INTO runtime_state VALUES (?, ?)",
                         (case_id, json.dumps(state)))
        return added

    @staticmethod
    def _sync_verdict(conn: sqlite3.Connection, case_id: str, state: dict[str, Any]) -> None:
        rows: list[tuple[dict[str, Any], dict[str, Any]]] = []
        if state.get("verdict"):
            rows.append((state["verdict"], state.get("verdict_metadata") or {}))
        if state.get("skeptic"):
            rows.append((state["skeptic"], {}))
        if state.get("counterfactual_verdict"):
            rows.append((state["counterfactual_verdict"], {}))
        for verdict, metadata in rows:
            assert_payload("verdict", verdict)
            steps = {key: verdict.get(key, "") for key in STEP_KEYS}
            steps.update(is_exploitable=verdict.get("is_exploitable"), model_metadata=metadata)
            role = verdict.get("role", "adjudicator")
            conn.execute(
                "INSERT INTO verdicts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(verdict_id) DO UPDATE SET steps_json=excluded.steps_json, "
                "score=excluded.score, band=excluded.band",
                (f"V-{case_id}-{role}", case_id, role, verdict["score"], verdict["band"],
                 json.dumps(verdict.get("cited_evidence", [])), json.dumps(steps),
                 verdict.get("model"), _now()))

    @staticmethod
    def _sync_patch(conn: sqlite3.Connection, case_id: str, state: dict[str, Any]) -> None:
        patch = state.get("patchset")
        if not patch:
            return
        assert_payload("patchset", patch)
        patch_id = f"P-{case_id}-{patch['attempt']}"
        report = state.get("sandbox_report") if patch.get("state") != "proposed" else None
        conn.execute("INSERT INTO patches VALUES (?, ?, ?, ?, ?, ?) "
                     "ON CONFLICT(patch_id) DO UPDATE SET state=excluded.state, "
                     "patchset_json=excluded.patchset_json, "
                     "sandbox_report_json=excluded.sandbox_report_json",
                     (patch_id, case_id, patch["attempt"], patch["state"],
                      json.dumps(patch), json.dumps(report) if report else None))
        approval = state.get("approval")
        if approval:
            conn.execute("INSERT OR REPLACE INTO approvals VALUES (?, ?, ?, ?, ?, ?)",
                         (f"A-{case_id}", patch_id, approval["decision"], approval["actor"],
                          approval["policy_tier"], approval["created_at"]))

    # --------------------------------------------------------------- patches
    def add_patch(self, case_id: str, patchset: dict[str, Any], *, state: str = "proposed",
                  sandbox_report: dict[str, Any] | None = None, patch_id: str | None = None) -> str:
        assert_payload("patchset", patchset)
        pid = patch_id or _new_id("P")
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO patches VALUES (?, ?, ?, ?, ?, ?)",
                (pid, case_id, int(patchset.get("attempt", 1)), state, json.dumps(patchset),
                 json.dumps(sandbox_report) if sandbox_report is not None else None))
        return pid

    def update_patch(self, patch_id: str, *, state: str | None = None,
                     sandbox_report: dict[str, Any] | None = None) -> None:
        with self.connect() as conn:
            if state is not None:
                conn.execute("UPDATE patches SET state = ? WHERE patch_id = ?", (state, patch_id))
            if sandbox_report is not None:
                conn.execute("UPDATE patches SET sandbox_report_json = ? WHERE patch_id = ?",
                             (json.dumps(sandbox_report), patch_id))

    def list_patches(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM patches WHERE case_id = ? ORDER BY attempt",
                                (case_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["patchset"] = json.loads(d.pop("patchset_json"))
            sr = d.pop("sandbox_report_json")
            d["sandbox_report"] = json.loads(sr) if sr else None
            out.append(d)
        return out

    # ------------------------------------------------------------- approvals
    def add_approval(self, patch_id: str, decision: str, actor: str, policy_tier: str = "manual",
                     created_at: str | None = None) -> str:
        aid = _new_id("A")
        with self.connect() as conn:
            conn.execute("INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?)",
                         (aid, patch_id, decision, actor, policy_tier, created_at or _now()))
        return aid

    def list_approvals(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT a.* FROM approvals a JOIN patches p ON p.patch_id = a.patch_id "
                "WHERE p.case_id = ? ORDER BY a.created_at", (case_id,)).fetchall()
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------- events
    def patch_runtime(self, case_id: str, **fields: Any) -> dict[str, Any]:
        """Merge ``fields`` into the materialised graph state."""
        with self.connect() as conn:
            row = conn.execute("SELECT state_json FROM runtime_state WHERE case_id = ?",
                               (case_id,)).fetchone()
            state = json.loads(row[0]) if row else {}
            state.update(fields)
            conn.execute("INSERT OR REPLACE INTO runtime_state VALUES (?, ?)",
                         (case_id, json.dumps(state)))
        return state

    def add_event(self, event: dict[str, Any]) -> int:
        event = {**event, "attributes": redact(event.get("attributes", {}))}
        assert_payload("event", {"seq": 0, **event})
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO events (case_id, activity, ts, resource, attributes_json)"
                " VALUES (?, ?, ?, ?, ?)",
                (event["case_id"], event["activity"], event["ts"], event["resource"],
                 json.dumps(event.get("attributes", {}))))
            if event["activity"] == "CASE_CLOSED":
                conn.execute(
                    "UPDATE cases SET closed_at = COALESCE(closed_at, ?) WHERE case_id = ?",
                    (_now(), event["case_id"]))
            return int(cur.lastrowid or 0)

    def list_events(self, case_id: str | None = None) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM events", ()
        if case_id:
            sql, args = sql + " WHERE case_id = ?", (case_id,)
        with self.connect() as conn:
            rows = conn.execute(sql + " ORDER BY seq", args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["attributes"] = json.loads(d.pop("attributes_json"))
            out.append(d)
        return out
