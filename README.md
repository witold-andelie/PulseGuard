# PulseGuard

Governed security operations: scanner findings → guard → deterministic evidence → adjudication
→ sandbox → manual approval → local remediation bundle.

The authoritative design is [PULSEGUARD_FRAMEWORK.md](PULSEGUARD_FRAMEWORK.md), with the
[OPM model](pulseguard_opm.dot). Both design files remain at the repository root.

## Sprint 1 skeleton

Working: JSON Schema 2020-12 contracts and Pydantic models, in-memory bus, scanner adapters,
reviewer-directed injection guard, E1–E3 evidence, score bands, tolerant JSON parsing, patch
application, JSONL tracing, SQLite WAL store, hash-verified replay, FastAPI and a no-build UI.
The graph is tested with injected dependencies, including persistent approval interruption,
rejection and resumption. Every real patch requires manual approval.

The bundled case is **PLACEHOLDER / SYNTHETIC**, with recorded=false. Its verdict, trace and
patch proposal illustrate the data shapes; they are not outputs from a recorded scanner or model
run. Its sandbox has not run, and replay approval/rejection is explicitly simulated without
mutating the stored case or any file. Failed replay integrity checks return HTTP 503 and block
case access.

Still stubbed: LIVE adjudicator and remediator calls, default graph-to-sandbox wiring, and
API-to-runner integration (LIVE decisions return 501). The sandbox helper has real patch,
re-scan and pytest operations; the rule's 1 → 0 behaviour is verified (see below), but the
helper's end-to-end gate has not yet run on a model-proposed patch.
No real Trivy report is bundled; the loader is tested using synthetic temporary input.
Sprint 2/3 and stretch features are absent.

## Run locally

Requires Python **3.12** (the Docker image is `python:3.12-slim`). On Windows, use
`.venv\Scripts\python` instead of `.venv/bin/python`.

    python3.12 -m venv .venv
    .venv/bin/python -m pip install -e ".[dev]"
    .venv/bin/python -m pytest -q
    .venv/bin/python -m ruff check .
    .venv/bin/python -m pulseguard.contracts.validate
    .venv/bin/python -m pulseguard.replay.verify
    .venv/bin/python -m uvicorn pulseguard.api:create_app --factory --port 8000

Open http://localhost:8000/. Pytest collects both tests/ and demo_target/order_api/tests/.
PG_MODE defaults to replay; live exposes an empty board until LIVE runs are connected.
SQLite and checkpoints use PG_DB_PATH, defaulting to the system temp directory.
LIVE model configuration uses PG_MODEL_BASE_URL, PG_MODEL_NAME and PG_MODEL_API_KEY;
the model-calling agent functions remain stubs even when these are set.

## Scanning and deployment

The optional scan extra installs Semgrep 1.183.0 and a compatible FastAPI version:

    .venv/bin/python -m pip install -e ".[dev,scan]"
    .venv/bin/semgrep --metrics=off --config pulseguard/rules/semgrep/flask-sqli-taint.yaml demo_target/order_api/

Verified with Semgrep 1.183.0 against the bundled demo route:

| Variant of `/order` | Findings |
| --- | --- |
| String-concatenated SQL from `request.args.get("id")` (as shipped) | 1 (`routes.py:37`) |
| Parameterised query `conn.execute(q, (order_id,))` | 0 |
| Value passed through `int()` before concatenation | 0 (sanitizer) |

`SemgrepRunner` parses the `--dataflow-traces` text output into a source → intermediate → sink
trace (lines 32 → 35 → 37), and `normalize()` turns it into a `Finding` with a stable fingerprint.

The main Dockerfile uses python:3.12-slim, a non-root user, Semgrep, and the PORT environment
variable. Render configuration matches framework section 11.1. CI runs Ruff, both pytest suites,
contract validation and replay verification. The Docker daemon was unavailable locally, so the
image was not built and nothing was deployed.

The Flask demo is deliberately vulnerable and uses a throwaway SQLite database in tests.
Its separate Dockerfile is for local use only; creating and populating a demo database is manual.

## Pre-existing components

The skeleton follows the reuse map in framework section 7. Module docstrings name the source
files to adapt: revio (graph, agents, scanner/patch/store patterns), tradepulse (guard, contracts,
trace, API and replay), SymbAI-Taint (evidence, adjudication protocol, parser and bands),
quant-foundation-gat (in-memory bypass and CI pattern), and PerpPulse (static UI and deployment).
These are provenance/design references; this skeleton does not claim that future adaptations or
LLM integrations have already been completed.
