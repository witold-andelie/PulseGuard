"""Run/resume durable cases, adapted from revio ``src/revio/agent/runner.py``.

AsyncSqliteSaver and the materialised case store share PG_DB_PATH. Every completed node
projects its state to SQLite and appends its process events to the JSONL audit trail.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from weakref import WeakKeyDictionary

from langgraph.types import Command

from pulseguard.agents.graph import GraphDeps, build_graph
from pulseguard.agents.state import SecOpsState
from pulseguard.governance.approval import record_decision
from pulseguard.paths import default_db_path
from pulseguard.store import Store
from pulseguard.trace import redact

# Serialise operations per database within an event loop (CLI processes use SQLite WAL).
_LOCKS: WeakKeyDictionary[asyncio.AbstractEventLoop, dict[str, asyncio.Lock]] = WeakKeyDictionary()


class CaseNotAwaitingApproval(ValueError):
    """Only a pending LangGraph approval interrupt accepts a decision."""


@asynccontextmanager
async def open_checkpointer(db_path: str | Path) -> AsyncIterator[Any]:
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

    async with AsyncSqliteSaver.from_conn_string(str(db_path)) as saver:
        yield saver


def _config(case_id: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": case_id}}


async def _status(graph: Any, case_id: str) -> dict[str, Any]:
    snap = await graph.aget_state(_config(case_id))
    interrupts = [i.value for task in snap.tasks for i in getattr(task, "interrupts", ())]
    return {"case_id": case_id, "next": list(snap.next), "awaiting_approval": bool(interrupts),
            "interrupts": interrupts, "values": dict(snap.values)}


def _persist(store: Store, state: dict[str, Any]) -> None:
    state = {key: value for key, value in state.items() if not key.startswith("__")}
    events = store.sync_runtime(state)
    path = store.db_path.with_suffix(".trace.jsonl")
    if events:
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            for event in events:
                handle.write(json.dumps(redact(event), sort_keys=True) + "\n")


async def _run(graph: Any, value: Any, case_id: str, store: Store) -> dict[str, Any]:
    async for state in graph.astream(value, _config(case_id), stream_mode="values"):
        await asyncio.to_thread(_persist, store, state)
    status = await _status(graph, case_id)
    await asyncio.to_thread(_persist, store, status["values"])
    return status


def _lock(db_path: str | Path) -> asyncio.Lock:
    locks = _LOCKS.setdefault(asyncio.get_running_loop(), {})
    return locks.setdefault(str(Path(db_path).resolve()), asyncio.Lock())


async def start_case(
    state: SecOpsState, deps: GraphDeps | None = None, db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Run until completion or manual approval; never overwrite an existing case thread."""
    deps, db_path = deps or GraphDeps(), db_path or default_db_path()
    store = Store(db_path).init_db()
    state = dict(state)
    case_id = state["finding"]["case_id"]
    state.setdefault("case_id", case_id)
    state.setdefault("mode", deps.mode)
    state.setdefault("run_id", f"live-{uuid.uuid4().hex[:12]}")
    if deps.target_root:
        state.setdefault("target_root", str(deps.target_root.resolve()))
    if deps.output_dir:
        state.setdefault("output_dir", str(deps.output_dir.resolve()))
    async with _lock(db_path), open_checkpointer(db_path) as saver:
        graph = build_graph(deps).compile(checkpointer=saver)
        previous = await _status(graph, case_id)
        if previous["values"]:
            return previous
        store.create_run(state["run_id"], deps.mode)
        stored_id = store.upsert_case(state["finding"], run_id=state["run_id"])
        if stored_id != case_id:
            raise ValueError("finding fingerprint belongs to a different case")
        return await _run(graph, state, case_id, store)


async def resume_case(
    case_id: str, decision: str, actor: str, deps: GraphDeps | None = None,
    db_path: str | Path | None = None, *, comment: str = "",
) -> dict[str, Any]:
    """Resume a pending approval, including after the original CLI process has exited."""
    deps, db_path = deps or GraphDeps(), db_path or default_db_path()
    record_decision(case_id, decision, actor, mode=deps.mode, comment=comment)
    store = Store(db_path).init_db()
    async with _lock(db_path), open_checkpointer(db_path) as saver:
        graph = build_graph(deps).compile(checkpointer=saver)
        status = await _status(graph, case_id)
        if not status["awaiting_approval"]:
            raise CaseNotAwaitingApproval(f"case {case_id} is not awaiting approval")
        # Bring projections up to date if a previous process stopped after checkpointing.
        await asyncio.to_thread(_persist, store, status["values"])
        answer = {"decision": decision, "actor": actor, "comment": comment}
        return await _run(graph, Command(resume=answer), case_id, store)
