"""FastAPI event-log routes, following tradepulse ``api.py`` factory/state conventions."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from pulseguard.eventlog import compute_kpis, export_csv, read_events

router = APIRouter()


def _events(request: Request) -> list[dict[str, Any]]:
    info = request.app.state.info
    if info.get("replay_error"):
        raise HTTPException(status_code=503, detail=info["replay_error"])
    return read_events(request.app.state.store, mode=info["mode"])


@router.get("/api/eventlog.csv")
def eventlog_csv(request: Request) -> Response:
    return Response(
        export_csv(_events(request)), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="pulseguard-eventlog.csv"'},
    )


@router.get("/api/kpis")
def kpis(request: Request) -> dict[str, Any]:
    return compute_kpis(_events(request))
