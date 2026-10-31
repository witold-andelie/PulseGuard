# PulseGuard

Governed security operations: scan → guard → deterministic evidence → adjudication →
sandbox → manual approval → local remediation bundle.

The design document and its OPM model are maintained outside this repository; "framework
section N" references in code and docs point to that document.

## Sprint 1 status

Implemented: OpenAI-compatible structured chat with timeout, bounded retries and plain-JSON
fallback; evidence-first adjudication with four short steps; three score bands; trace-confined
PatchSets; isolated temporary-copy patching with a Semgrep 1 → 0 gate and demo pytest gate;
up to three remediation attempts with sandbox feedback; durable LangGraph manual approval;
SQLite state projections and JSONL audit events; output bundles; local LIVE CLI; LIVE decision
API; hash-verified REPLAY; and the plain-JavaScript case detail and approval UI.

Approval applies into the bundle's **output copy**, never into the repository demo. A bundle
contains `patch.diff`, `pr_description.md`, `metadata.json` and the patched `target/` copy.
The description includes the finding, evidence ids, verdict, sandbox report and approver.
Nothing is committed or pushed. Changed source between sandbox and approval blocks bundling.

The workflow is tested using a scripted FakeLLM and fake scanner. The sandbox is also tested
with a fake scanner and the actual demo pytest suite. Real Semgrep integration tests cover the
parameterised patch and a no-op negative control; they carry `@pytest.mark.semgrep` and skip
when the CLI cannot execute. A sandbox failure in LIVE always fails the gate.

**No genuine model run has been recorded in this repository yet.** The committed
`s1-placeholder` replay remains **PLACEHOLDER / SYNTHETIC** with
`recorded=false`; its verdict, patch and trace are illustrative and its sandbox was not run.
REPLAY decisions remain labelled simulations and do not change the stored run. A recording
command is implemented, but requires real PG_MODEL_* configuration and working Semgrep.
The replay loader handles multiple runs and prefers `recorded=true` over any placeholder.

No real Trivy report is bundled; its report loader remains available and unit-tested.
Sprint 2/3 and stretch investigation features are absent. Cases needing human intervention
use `review_status=human_review`, including quarantine, uncertain verdicts and exhausted
sandbox attempts; this does not introduce the S2 `escalated` finding state or S2 activities.
Rejected cases retain their finding classification and have `closed_at` plus `CASE_CLOSED`.

## Run locally

Requires Python **3.12**. Use the existing virtual environment on Windows:

    .venv/Scripts/python -m pip install -e ".[dev,scan]"
    .venv/Scripts/python -m pytest -q
    .venv/Scripts/python -m ruff check .
    .venv/Scripts/python -m pulseguard.contracts.validate
    .venv/Scripts/python -m pulseguard.replay.verify
    .venv/Scripts/python -m uvicorn pulseguard.api:create_app --factory --port 8000

On Linux, substitute `.venv/bin/python`. Open http://localhost:8000/.
PG_MODE defaults to `replay`; hashes are verified before any replay case is served.
Invalid replay bundles return HTTP 503. Pytest collects both application and demo tests.

For LIVE, configure the three variables with your own OpenAI-compatible provider:
`PG_MODEL_BASE_URL`, `PG_MODEL_NAME`, `PG_MODEL_API_KEY`. They have no built-in defaults.
Do not put credentials in source files.

Both LIVE and recording accept `--env-file <config.env>` to load literal `KEY=VALUE` lines
into the current process, overriding existing environment variables. Blank lines and `#`
comment lines are ignored; matching single/double quotes are removed. Values are never
expanded as shell code. Keep the file outside the source tree. Its contents are not copied
into replay bundles, traces or model metadata.

| Variable | Default / meaning |
| --- | --- |
| `PG_MODEL_BASE_URL` | Required OpenAI-compatible endpoint |
| `PG_MODEL_NAME` | Required provider model id |
| `PG_MODEL_API_KEY` | Required secret; never recorded |
| `PG_MODEL_TIMEOUT_S` | `120`; positive timeout per request, in seconds |
| `PG_MODEL_MAX_TOKENS` | `8192`; output budget, including provider reasoning tokens |
| `PG_MODEL_STRUCTURED` | `auto`; `on` requires JSON Schema output, `off` never sends `response_format` |
| `PG_MODEL_EXTRA_BODY` | `{}`; JSON object forwarded as SDK `extra_body` |
| `PG_MODEL_SESSION_HEADER` | Unset; optional header carrying stable `pg-<case_id>-<role>` ids |
| `PG_MODEL_USER_AGENT` | `PulseGuard/<package version>`; the client's own User-Agent |

In `auto`, a schema/grammar capability error (HTTP 400/404/422) disables structured output
for that client and retries once with plain JSON guidance. Transient retries remain bounded.
The full local contracts still enforce score bounds, unique citations and patch validity.
There is no automatic switch to another provider. Reasoning content is ignored. Recorded
call metadata includes the actual model, endpoint **host only**, configured/effective
structured-output mode, latency and usage, including provider cost extras.

### Tested providers

Endpoint comparison on **2026-10-31** measured these configurations:

- **Primary: Meta Muse Spark**, model `muse-spark-1.3-contributor`, via opencode Go at
  `https://opencode.ai/inference/go/openai/v1`. Chat completions and JSON Schema output
  worked. Set `PG_MODEL_SESSION_HEADER=x-opencode-session`; requests without it returned
  HTTP 400. Use `PG_MODEL_STRUCTURED=auto` (or `on`) and the PulseGuard User-Agent.
  Calls used roughly 1,100–1,700 reasoning tokens and took up to about 35 seconds;
  usage included an `opencode` cost block.
- **Fallback: NVIDIA NIM**, model `nvidia/nemotron-3-ultra-550b-a55b`, with
  `PG_MODEL_BASE_URL` set to your NIM endpoint and `PG_MODEL_STRUCTURED=off`. Set
  `PG_MODEL_EXTRA_BODY={"chat_template_kwargs":{"enable_thinking":true}}` for thinking.
  The endpoint rejected `uniqueItems`; schema-constrained long patch strings also
  degenerated. Plain JSON with the tolerant parser produced passing patches in 2/2
  measured attempts. Latency reached about 50 seconds. `message.reasoning_content`
  is ignored; an out-of-range score becomes uncertain and is never clamped.

Data handling (framework section 12), **pending confirmation**: review opencode Go's usage
terms and retention/training policy for the selected service tier. The `contributor` model
variant may use request data; the applicable terms and data use remain to be confirmed.

In PowerShell, configure a dedicated LIVE database and launch a scan:

    $env:PG_MODE = "live"
    $env:PG_DB_PATH = Join-Path $env:TEMP "pulseguard-live.sqlite"
    .venv/Scripts/python -m pulseguard.run --target demo_target/order_api

The CLI prints the case id and stops at the approval interrupt after sandbox verification.
Start the API from another terminal with the **same PG_MODE and PG_DB_PATH** to review the
Hard Evidence Block, four adjudication steps, score/band, diff, sandbox report and timeline.
Enter an approver name and approve/reject in the card, or resume from the CLI:

    .venv/Scripts/python -m pulseguard.run --resume <case_id> --decision approve --actor <name>
    .venv/Scripts/python -m pulseguard.run --resume <case_id> --decision reject --actor <name>

Resuming a passed patch does not require a new model call. The checkpoint preserves the
source and output paths across processes. Duplicate decisions return HTTP 409. The default
output is `<database directory>/pulseguard-bundles/<run_id>/<case_id>/`; a scan can choose
another parent with `--output-dir`. Existing case threads are deduplicated by finding
fingerprint; use a fresh database for an independent run or recording.

The only S1 LIVE target is the bundled `demo_target/order_api`.
`POST /api/runs` remains absent. LIVE operation is local; public token-gated runs are S3.
Use separate database files for LIVE and REPLAY, since REPLAY rebuilds its case tables at boot.

## Record a real run

With all three PG_MODEL_* variables set and Semgrep working, choose a fresh database:

    .venv/Scripts/python scripts/record_run.py --db-path <fresh.sqlite> --auto-approve-as <actor>
    .venv/Scripts/python scripts/record_run.py --env-file <config.env> --db-path <fresh.sqlite>
    .venv/Scripts/python -m pulseguard.replay.verify

`--auto-approve-as` is available **only to the recording command** and attributes the
decision to the supplied actor. Without it, recording asks for an explicit interactive
approval and approver name. The command refuses missing model configuration, failed gates,
cases belonging to another run, and unfinished remediations.

A successful recording writes `replay/runs/<run_id>/`: case, evidence, verdicts with provider
model/host/structured-mode/latency/usage metadata (`model_calls.json` retains every attempt),
all accepted patch attempts with sandbox reports, approval,
trace JSONL and bundle files. It sets `recorded=true`, keeps the placeholder, regenerates
`replay/manifest.sha256.json` and verifies every file. `--run-id` selects a run name;
`--root` selects a replay directory. The recorder never substitutes fake model responses.

## Scanning and deployment

The scan extra installs Semgrep **1.183.0** and its compatible FastAPI version. Run only the
real scanner integration tests with:

    .venv/Scripts/python -m pytest -q -m semgrep -rs

The bundled taint rule uses the SQL argument as the focused sink. Previous host verification
found one result for the shipped concatenated query, zero for a parameterised query, and zero
after an int-cast sanitizer. `SemgrepRunner` combines JSON sink locations with text
`--dataflow-traces` to capture source → intermediate → sink.

The main Dockerfile uses python:3.12-slim, a non-root user, Semgrep and PORT.
Render configuration follows framework section 11.1. CI runs Ruff, pytest, contract validation
and replay verification. This implementation has not been deployed or built into a Docker image.
The deliberately vulnerable Flask service uses a throwaway SQLite fixture in its tests.

## Pre-existing components

Module docstrings follow framework section 7: revio graph, runner, model, patch and store
patterns; tradepulse guard, contracts, trace, API and replay patterns; SymbAI-Taint evidence,
adjudication protocol, JSON parsing and confidence bands; quant-foundation-gat's in-memory
bus bypass; and PerpPulse's static UI and serving modes. The original skeleton established
these contracts and seams; this increment connects the S1 model, sandbox, approval,
persistence, bundling and recording paths.
