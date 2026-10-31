"""S3 PoC witness, new for PulseGuard framework 4.2 (E5), 4.5 and scenario 5.

Uses revio ``src/revio/layers/static/bandit.py`` subprocess isolation patterns. Only copies
of the bundled demo modules are imported; a proposal supplies data, never executable code.
This is a bounded demo check, not an operating-system sandbox for arbitrary Python programs.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import time
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from pulseguard.agents.json_parse import parse_json_response
from pulseguard.agents.llm import (
    LLMClient,
    error_metadata,
    make_llm,
    model_facing_schema,
    output_schema,
)
from pulseguard.agents.prompts import POC_SYSTEM, build_poc_user
from pulseguard.patching.patch import PatchApplier, PatchSet
from pulseguard.paths import REPO_ROOT

DEMO_ROOT = REPO_ROOT / "demo_target" / "order_api"
DEMO_MODULES = ("routes.py", "order_note.py")
# Two child runs (before and after) share this budget; slow hosts (Render free tier) need headroom.
MAX_TIMEOUT_S = 20.0

# -I -S prevents user/sitecustomize imports before the network guard. Trusted interpreter
# package paths are supplied explicitly so Flask remains available in a Python 3.12 venv.
_BOOTSTRAP = r'''
import contextlib
import json
import os
import re
import socket
import sqlite3
import sys

def blocked(*args, **kwargs):
    raise PermissionError("PoC policy: outbound network blocked")

socket.socket.connect = blocked
socket.socket.connect_ex = blocked
socket.socket.sendto = blocked
if hasattr(socket.socket, "sendmsg"):
    socket.socket.sendmsg = blocked
socket.create_connection = blocked
socket.getaddrinfo = blocked
socket.gethostbyname = blocked
socket.gethostbyname_ex = blocked
socket.gethostbyaddr = blocked

def network_audit(event, args):
    if event in {"socket.connect", "socket.sendto", "socket.getaddrinfo",
                 "socket.gethostbyname", "socket.gethostbyaddr"}:
        blocked()

sys.addaudithook(network_audit)
payload = json.load(sys.stdin)
sys.path[:0] = [payload["root"], *payload["packages"]]
result = {}
with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink), \
        contextlib.redirect_stderr(sink):
    try:
        import routes
        app = routes.app
        app.config.update(TESTING=False, DEBUG=False, PROPAGATE_EXCEPTIONS=False,
                          DATABASE=os.path.join(payload["root"], "fixture.sqlite"))
        proposal = payload["proposal"]
        # Match before exercising the client: no missing routes, POST-only routes or redirects.
        endpoint, values = app.url_map.bind("localhost").match(proposal["route"], method="GET")
        with sqlite3.connect(app.config["DATABASE"]) as db:
            db.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, item TEXT, qty INTEGER)")
            db.executemany("INSERT INTO orders VALUES (?, ?, ?)",
                           [(str(i), "order-" + str(i), i) for i in range(1, 13)])
        with app.test_client() as client:
            response = client.get(proposal["route"], query_string=proposal["params"],
                                  follow_redirects=False)
            data = response.get_json(silent=True)
            rows = len(data) if isinstance(data, list) else None
            body = response.get_data(as_text=True)
            leak = bool(re.search(r"sqlite|OperationalError|ProgrammingError|SQL syntax|"
                                  r"syntax error|unrecognized token|no such (?:column|table)",
                                  body, re.I))
            result = {"http_status": response.status_code, "rows": rows, "sql_error": leak,
                      "deviation": leak or (rows is not None and
                                            rows > proposal["expected_max_rows"])}
            if rows is None and not leak:
                result["error"] = "response does not expose a row count or SQL error"
    except Exception as exc:
        # No exception text or response body: those may contain host data or credentials.
        result = {"error": type(exc).__name__, "rejected": True}
print(json.dumps(result))
'''


def is_demo_copy(root: Path) -> bool:
    """Accept the bundled source or an unchanged sandbox copy, never another service."""
    try:
        return all((root / name).read_bytes() == (DEMO_ROOT / name).read_bytes()
                   for name in DEMO_MODULES)
    except OSError:
        return False


def propose_poc(
    evidence_block: str, *, case_id: str, llm: LLMClient | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Use the same model-facing schema adapter as revio-style patch proposals."""
    try:
        schema = output_schema("poc")
        response = (llm or make_llm()).chat(
            POC_SYSTEM, build_poc_user(evidence_block), schema=model_facing_schema(schema),
            session=f"pg-{case_id}-poc",
        )
    except Exception as exc:
        if metadata is not None:
            metadata.update(error_metadata(exc))
        raise
    if metadata is not None:
        metadata.update(response.metadata())
    proposal = parse_json_response(response.text)
    Draft202012Validator(schema).validate(proposal)
    if proposal["route"].startswith("//") or ".." in proposal["route"].split("/"):
        raise ValueError("PoC route must be a local registered GET route")
    return proposal


def _execute(root: Path, proposal: dict[str, Any], timeout: float) -> dict[str, Any]:
    """Exercise one copy in a child with a hard deadline and no inherited secrets/proxies."""
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}}
    env.update({"HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "", "NO_PROXY": "*",
                "http_proxy": "", "https_proxy": "", "all_proxy": "", "no_proxy": "*"})
    packages = sorted({sysconfig.get_path("purelib"), sysconfig.get_path("platlib")})
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-S", "-c", _BOOTSTRAP], cwd=root, env=env,
            input=json.dumps({"root": str(root), "proposal": proposal, "packages": packages}),
            capture_output=True, text=True, timeout=max(0.001, timeout), check=False,
        )
    except subprocess.TimeoutExpired:
        return {"error": "hard timeout", "timed_out": True}
    if proc.returncode:
        return {"error": "child process failed"}
    try:
        result = json.loads(proc.stdout)
        if isinstance(result, dict):
            return result
    except ValueError:
        pass
    return {"error": "invalid child result"}


def witness(
    root: Path, patchset: PatchSet, evidence_block: str, *, case_id: str,
    llm: LLMClient | None = None, metadata: dict[str, Any] | None = None,
    timeout_s: float = MAX_TIMEOUT_S,
) -> dict[str, Any]:
    """Run a model-proposed request on fresh copies before and after the sandboxed patch.

    No baseline deviation is inconclusive. A witnessed baseline followed by an error or
    timeout cannot establish repair and fails closed before approval.
    """
    result: dict[str, Any] = {
        "status": "not_witnessed", "route": None, "params": {}, "before": {}, "after": {},
        "detail": "PoC witness: inconclusive; bundled demo source required",
    }
    if not is_demo_copy(root):
        return result
    if not math.isfinite(timeout_s) or not 0 < timeout_s <= MAX_TIMEOUT_S:
        raise ValueError(f"PoC timeout must be in (0, {MAX_TIMEOUT_S}]")
    try:
        proposal = propose_poc(evidence_block, case_id=case_id, llm=llm, metadata=metadata)
        result.update(route=proposal["route"], params=proposal["params"],
                      expected_max_rows=proposal["expected_max_rows"],
                      rationale=proposal["rationale"])
        if any(op.path not in DEMO_MODULES for op in patchset.ops):
            raise ValueError("PoC patch outside bundled demo modules")
        with tempfile.TemporaryDirectory(prefix="pg-poc-") as tmp:
            before, after = Path(tmp) / "before", Path(tmp) / "after"
            for work in (before, after):
                work.mkdir()
                for name in DEMO_MODULES:
                    shutil.copyfile(root / name, work / name)
            PatchApplier(after).apply(patchset)
            deadline = time.monotonic() + timeout_s
            result["before"] = _execute(before, proposal, deadline - time.monotonic())
            result["after"] = _execute(after, proposal, deadline - time.monotonic())
    except Exception as exc:
        if result["before"].get("deviation") or result["after"].get("deviation"):
            result.update(status="failed", detail=(
                f"PoC witness: repair could not be verified ({type(exc).__name__})"))
        else:
            result["detail"] = (
                f"PoC witness: rejected or unavailable ({type(exc).__name__}); inconclusive")
        return result
    baseline, patched = result["before"], result["after"]
    if patched.get("deviation") or (baseline.get("deviation") and patched.get("error")):
        result.update(status="failed", detail=(
            "PoC witness: deviation remains after patch or repair could not be verified"))
    elif not baseline.get("deviation"):
        reason = baseline.get("error") or "no deviation before patch"
        result["detail"] = f"PoC witness: not_witnessed; {reason}; inconclusive"
    else:
        value = json.dumps(next(iter(proposal["params"].values()), ""), ensure_ascii=True)
        observation = ("leaked an SQL error" if baseline.get("sql_error") else
                       f"returned {baseline['rows']} rows, "
                       f"expected <= {proposal['expected_max_rows']}")
        result.update(status="witnessed", detail=(
            f"PoC witness: input {value} {observation}; none after patch"))
    return result
