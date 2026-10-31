"""Run / resume a case graph with a persistent ``AsyncSqliteSaver`` checkpointer.

Adapted from revio ``src/revio/agent/runner.py``: pause at Approving (LangGraph interrupt),
resume on the human decision; checkpoints share the SQLite file with the case store.

S1 status: stub-level - the functions are real but nothing in the API calls them yet (LIVE runs
are not exposed in S1), and LIVE deps raise ``NotImplementedError``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from langgraph.types import Command

from pulseguard.agents.graph import GraphDeps, build_graph
from pulseguard.agents.state import SecOpsState


@asynccontextmanager
async def open_checkpointer(db_path: str | Path) -> AsyncIterator[Any]:
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

    async with AsyncSqliteSaver.from_conn_string(str(db_path)) as saver:
        yield saver


def _config(case_id: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": case_id}}


async def _status(graph: Any, case_id: str) -> dict[str, Any]:
    snap = await graph.aget_state(_config(case_id))
    interrupts = [i.value for t in snap.tasks for i in getattr(t, "interrupts", ())]
    return {"case_id": case_id, "next": list(snap.next), "awaiting_approval": bool(interrupts),
            "interrupts": interrupts, "values": dict(snap.values)}


async def start_case(state: SecOpsState, deps: GraphDeps, db_path: str | Path) -> dict[str, Any]:
    """Run until the graph ends or pauses at ``approve``."""
    case_id = state["finding"]["case_id"]
    async with open_checkpointer(db_path) as saver:
        graph = build_graph(deps).compile(checkpointer=saver)
        await graph.ainvoke(state, _config(case_id))
        return await _status(graph, case_id)


async def resume_case(case_id: str, decision: str, actor: str, deps: GraphDeps,
                      db_path: str | Path) -> dict[str, Any]:
    """Resume a paused case with an approve/reject decision."""
    async with open_checkpointer(db_path) as saver:
        graph = build_graph(deps).compile(checkpointer=saver)
        await graph.ainvoke(Command(resume={"decision": decision, "actor": actor}),
                            _config(case_id))
        return await _status(graph, case_id)
