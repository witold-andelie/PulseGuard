# PulseGuard

Governed security operations: scan → guard → deterministic evidence → adjudication →
sandbox → governed approval → local remediation bundle.

The design document and its OPM model are maintained outside this repository; "framework
section N" references in code and docs point to that document.

## Status: S1 deployed, Sprint 2 SURFACE increment

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

S1 is deployed on Render. The existing `recorded-20261031T012001-4192c0` bundle is a
**RECORDED LIVE** S1 run using Muse Spark. The older `s1-placeholder` remains explicitly
**PLACEHOLDER / SYNTHETIC** (`recorded=false`). The loader prefers the recorded run.
REPLAY decisions remain labelled simulations and do not change recorded results.
This SURFACE increment does not record or alter any replay run.

S2 SURFACE adds Bandit and Trivy adapters, three demo scenarios, event-log CSV and computed
KPIs, and no-build case-detail views for verification, skeptic, counterfactual, priority,
policy, bus health, rollback and a service topology SVG with the scored path highlighted.
The UI tolerates missing S2 fields in the existing S1 replay. The process view includes a
CSV download and final-state counts. The REPLAY/LIVE badge remains visible while scrolling.

S2 CORE supplies the graph wiring, deterministic dependency bump, falsification checks,
risk, tiered approval and rollback endpoint in a separate workstream. Until merged, the
LIVE CLI still follows its S1 Semgrep-only path and manual approval; the new scanner
adapters can be exercised independently. No S3 or stretch features are added here.

## Sprint 2 demo scenarios

| Scenario | Scanner / expected S2 behavior |
| --- | --- |
| `/order?id=1` | Original SQL injection, unchanged; one Semgrep taint finding; human approval after verification |
| `requirements.txt` | Scan-only `requests==2.31.0`; real Trivy CVEs and fixed versions; CORE uses a deterministic bump with P2/P3 automatic approval when policy permits |
| `/order_by_number?number=1` | Bandit B608 despite the `int()` cast; assignment context exposes the sanitizer; Semgrep taint rule stays silent; score below 0.3 is dropped and logged |
| `/order_note?note=bond` | Bandit B608 pattern match on parameterized SQL with a planted reviewer instruction; guard quarantine and human review |

`order_note.py` holds scenario 4 and is registered from `routes.py`. Its own file prevents
the file-scoped guard from quarantining unrelated scenarios. Every route keeps its request
source and SQL sink inside one function. The original Semgrep rule is unchanged.
`# @vuln` / `# @safe` comments are ground truth, never proof of exploitability.

The dependency manifest is **scanner input**. Do not install
`demo_target/order_api/requirements.txt` into your development/test environment. The demo
does not import Requests. The project's `dev` extra supplies Flask and pytest; the sandbox
copies the target but uses that existing interpreter without installing the target manifest.
The demo Dockerfile also installs Flask directly. The three demo pytest cases exercise all
routes, including rejection of non-integer numbers and parameterized note searches.

`demo_target/order_api/scan/trivy-report.json` is **RECORDED**, produced by official
Trivy **0.76.1** on **2026-10-31** with `trivy fs --format json --scanners vuln`.
Its added `PulseGuard` provenance block records tool version, timestamp, manifest SHA-256
and the Windows release archive SHA-256, checked against the
[official release checksums](https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_checksums.txt).
The scanner reported three medium findings: CVE-2024-35195 (fixed 2.32.0),
CVE-2024-47081 (fixed 2.32.4) and CVE-2026-25645 (fixed 2.33.0).
The first is documented in the
[Requests advisory](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56).
A bump to 2.33.0 addresses all three findings in this report; bumping only to 2.32.0
addresses the first. No scanner rows were fabricated or filtered out of this report.
Unattested and synthetic report inputs normalise with `Finding.extra.recorded=false` and
the UI labels them SYNTHETIC / unrecorded. A scanner failure never substitutes fake output.

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

### Event log and KPIs

`GET /api/eventlog.csv` exports exactly
`case_id,activity,timestamp,resource,priority,score,run_mode`, with ISO-8601 UTC timestamps.
This is Celonis-ready CSV, without a Celonis service integration. `GET /api/kpis` computes
from the same event rows in the serving mode, for both replay-seeded and LIVE databases:

- `mean_time_to_remediate_s`: remediated `CASE_CLOSED` minus first `FINDING_INGESTED`,
  excluding rejected, dropped, incomplete and rolled-back cases; null if none qualify.
- `false_positives_dropped`, `approvals_automatic`, `approvals_human`: activity counts,
  with automatic approvals identified by `policy_tier=auto` or resource `policy:auto`.
- `rework_loops`: `mean` and `max` of failures followed by a new proposal, per case;
  intervening events are allowed, and cases with zero loops count toward the mean.
- `cases_total`, `cases_by_final_state`: distinct event case ids and their latest observed
  classification or `CASE_CLOSED` outcome; open cases are included.

Missing optional event priority/score values export as empty CSV fields. Legacy S1 events
recover their mode from the run relation. Mode-filtered exports never relabel REPLAY as LIVE.
Invalid replay data blocks telemetry with HTTP 503, like the case endpoints.

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

The only LIVE target is the bundled `demo_target/order_api`.
Use separate database files for LIVE and REPLAY, since REPLAY rebuilds its case tables at boot.

### Sprint 3: PoC witness and token-gated LIVE

Code findings that pass the sandbox now get a model-proposed PoC request alongside the
counterfactual check. The executor accepts only registered GET routes on fresh sandbox copies
of the bundled demo, with capped string parameters and a deterministic twelve-order SQLite
fixture. Flask test clients run in isolated child processes with outbound sockets blocked,
proxies disabled and a shared five-second execution deadline. E5 and the case-detail `poc`
field report `witnessed`, inconclusive `not_witnessed`, or `failed`; a remaining deviation
blocks approval. If a witnessed baseline cannot be checked after patching, it also escalates.

To enable the API locally, configure the model variables above, set `PG_MODE=live` and
`PG_LIVE_TOKEN` to a secret, then launch the API. Start and inspect a run from PowerShell:

    $headers = @{ Authorization = "Bearer $env:PG_LIVE_TOKEN" }
    $run = Invoke-RestMethod http://localhost:8000/api/runs -Method Post -Headers $headers `
        -ContentType application/json -Body '{"scanners":["semgrep","bandit","trivy"]}'
    Invoke-RestMethod "http://localhost:8000/api/runs/$($run.run_id)" -Headers $headers

The request body may only select these scanners; omitted selection runs all three. Trivy
uses the committed **RECORDED** report, with no Trivy binary or database in the image.
LIVE run status is process-local, with one scan at a time (409) and three starts/minute
(429). LIVE results are lost on restart; the API payload and UI status label say so.
REPLAY returns 404 for run endpoints; LIVE without a configured token returns 503 and bad
credentials return 401. Render remains **REPLAY by default**, with `PG_LIVE_TOKEN` marked
`sync: false`; this work does not change the deployed service or record a new replay.

## Playground

The public web UI includes a **Playground** (`#playground`) that accepts a pasted Flask
Python snippet and runs PulseGuard's non-executing analysis on it: Guard, Semgrep (local
taint rule), Bandit, Hard Evidence, z3 validator proof, model adjudication, citation
checks and the z3 veto. Two models are switchable, with a compare-both mode: **Meta Muse
Spark** (primary) and **NVIDIA Nemotron** (control). Endpoints:

| Method and path | Purpose |
| --- | --- |
| `GET /api/playground/config` | Enabled flag, model names, caps, limits, remaining budget |
| `GET /api/playground/examples` | Built-in snippets (SQLi concat/f-string, parameterised, allow-list, z3 unsat, unanchored regex, CommentInject, planted AI reviewer) |
| `POST /api/playground/analyze` | `{code, model: "muse"\|"nemotron"\|"both"}` → Guard, scanners, evidence, verdict, verification, decision |

**What it never does.** It does not import, `exec`, `eval`, compile-to-run, sandbox,
pytest, patch, remediate or store the snippet. Parse is `ast.parse` only. A temp file
exists solely so Semgrep and Bandit can read text; the per-request directory under the
system temp is deleted afterwards. Playground results are ephemeral: they are not written
to `replay/` or the case store. Every response is labelled
"Playground — static analysis + model adjudication; nothing is executed or stored".

**Limits.** UTF-8 text, ≤ 6 KB, ≤ 200 lines, must parse as Python. `# @vuln` / `# @safe`
annotations are stripped before any model sees the text. Guard runs first; a flagged
snippet is quarantined and never reaches a model. Per client IP (first `X-Forwarded-For`
hop from Render's proxy): 5 analyses/minute, 40/day, one concurrent analysis. Global
daily model-call budget `PG_PLAYGROUND_DAILY_CALLS` (default 300). In-memory counters
reset when the process restarts. HTTP 429 includes `Retry-After`. When keys are absent
or the budget is exhausted, the Playground degrades to static analysis and says so.

Model endpoints and keys come only from server environment variables, never from the
browser. Responses and logs carry no secrets and no host paths. Provider errors return
the exception type and status only.

| Variable | Meaning |
| --- | --- |
| `PG_PLAYGROUND_MUSE_BASE_URL` / `_NAME` / `_API_KEY` | Meta Muse Spark OpenAI-compatible endpoint |
| `PG_PLAYGROUND_MUSE_SESSION_HEADER` | Defaults to `x-opencode-session` (per-request id) |
| `PG_PLAYGROUND_MUSE_STRUCTURED` / `_EXTRA_BODY` / `_TIMEOUT_S` | Optional knobs; User-Agent is PulseGuard's |
| `PG_PLAYGROUND_NEMOTRON_BASE_URL` / `_NAME` / `_API_KEY` | NVIDIA Nemotron endpoint |
| `PG_PLAYGROUND_NEMOTRON_STRUCTURED` | Defaults to `off` |
| `PG_PLAYGROUND_NEMOTRON_EXTRA_BODY` / `_SESSION_HEADER` / `_TIMEOUT_S` | Optional knobs |
| `PG_PLAYGROUND_DAILY_CALLS` | Global model-call budget per process-day (default 300) |
| `PG_PLAYGROUND_TIMEOUT_S` | Overall analysis deadline in seconds (default 90) |

Set the `PG_PLAYGROUND_MUSE_*` and `PG_PLAYGROUND_NEMOTRON_*` values in the Render
dashboard (`sync: false` in `render.yaml`). The Playground works in both REPLAY and
LIVE serving modes.

## How to record

Use the existing Python environment with Semgrep and Bandit available. Keep the env file
outside the repository and set `PG_MODEL_BASE_URL`, `PG_MODEL_NAME`, `PG_MODEL_API_KEY` and
`PG_TOPOLOGY_SOURCE=image` there. Recording runs Semgrep, Bandit and the committed recorded
Trivy report on `demo_target/order_api`; it does not invoke a Trivy binary. Choose a fresh
database for each run. From the repository root (`.venv/bin/python` on Linux/macOS):

    .venv/Scripts/python scripts/record_run.py --env-file <config.env> --db-path <fresh.sqlite> --auto-approve-as <actor>
    .venv/Scripts/python -m pulseguard.replay.verify

`--auto-approve-as` is available **only to the recording command** and attributes the
decision to the supplied actor with a recording-approval comment. Without it, recording
asks for an interactive approval and approver name for each paused human approval.
Policy-approved dependency cases retain `actor=policy:auto`; dropped false positives and
quarantined/escalated cases retain their terminal outcome and human-review reason without
a bundle. Unexpected or unfinished states, simulated approvals, missing model configuration
and cases belonging to another run are refused.

A successful recording writes `replay/runs/<run_id>/` with every case, evidence (including
the SQLi case's E5 PoC witness), adjudicator/skeptic/counterfactual verdicts, verification,
analysis limits, z3 veto status, priority, blast radius, policy, bus health, rollback status,
patch attempts with sandbox reports, approvals, review reasons and event traces. Bundle
files are included only where remediation completed. Run-level topology extraction retains
the model call metadata and deterministic validation result, never image bytes. Rejected
image input or invalid topology selects the fixture and records the fallback reason.

Files use LF and portable bundle paths; credentials and applied host directories are not
exported. The command sets `recorded=true`, preserves both the S1 recording and placeholder,
regenerates `replay/manifest.sha256.json` and verifies every file. The newest recorded run
becomes the default REPLAY, with event-derived CSV/KPIs and simulated decisions/rollback.
`--run-id` selects a run name; `--root` selects another replay directory. Scripted test runs
stay in temporary directories; the recorder never substitutes fake model responses.

## Scanning and deployment

The scan extra installs Semgrep **1.183.0**, its compatible FastAPI version and Bandit.
Bandit runs as a pure-Python subprocess. Real Semgrep tests carry `@pytest.mark.semgrep`
and skip when the CLI cannot execute. Real Trivy tests carry `@pytest.mark.trivy` and skip
when the binary is absent. No tests make real model calls. Run scanner checks with:

    .venv/Scripts/python -m pytest -q -m semgrep -rs
    .venv/Scripts/python -m bandit -r demo_target/order_api -f json -x "*/tests/*,*/test_*.py,*/*_test.py,*/conftest.py" -s B101
    .venv/Scripts/python -m pytest -q -m trivy -rs

`BanditRunner` excludes `tests/`, `test_*.py`, `*_test.py` and `conftest.py`, and skips
`B101` (`assert_used`) by default. Asserts in pytest code express test expectations and
are not production findings. Callers can configure `excludes` and `skips` (use `()` to
disable either default); `eval_cases/` remains scanned.

Dependency cases bypass model adjudication, skeptic and counterfactual calls. Every grouped
CVE must match the manifest, package and installed version in the committed RECORDED Trivy
report. A recorded fixed version produces a `verifier` verdict (`model=none`, score 1.0),
then verification, a manifest-only bump to the highest fix, sandbox pytest and tiered policy
approval. Missing fixes require human review; missing CVEs or provenance escalate the case.

Install Trivy from an official release and verify its archive against that release's
checksum list. Set `PG_TRIVY_BIN` if it is not on PATH; `PG_TRIVY_CACHE_DIR` selects the
cache directory for integration tests. A local scan can refresh scanner output with:

    trivy fs --format json --scanners vuln demo_target/order_api

Preserve actual output, tool version, date and manifest hash when replacing the bundled
report. Do not mark hand-written fixtures RECORDED. `TrivyReportLoader` consumes report
JSON; `TrivyRunner` is optional local tooling and does not download databases at API boot.

The bundled taint rule uses the SQL argument as the focused sink. Previous host verification
found one result for the shipped concatenated query, zero for a parameterised query, and zero
after an int-cast sanitizer. `SemgrepRunner` combines JSON sink locations with text
`--dataflow-traces` to capture source → intermediate → sink.

The main Dockerfile uses python:3.12-slim, a non-root user, Semgrep and PORT.
Render configuration follows framework section 11.1. CI runs Ruff, pytest, contract validation
and replay verification. S1 is live on Render; this S2 increment has not been deployed.
The deliberately vulnerable Flask service uses a throwaway SQLite fixture in its tests.

## Stretch: z3 constraint solving (ST-1)

On the taint path inside the sink's function, PulseGuard extracts input validators
(`re.fullmatch` / anchored `re.match`, length bounds, and optionally character
checks), records their exact source lines, and uses Python's AST to classify how
the value enters SQL. A quoted string sink asks whether a quote can pass. An
unquoted numeric sink asks whether **any character outside `[0-9]`** can pass:
`1 OR 1=1` needs no quote. Unclassifiable SQL makes no claim.

| Validator / sink | Result |
| --- | --- |
| `^[A-Za-z0-9_-]{1,12}$` / string | unsat: a quote cannot pass |
| `^[0-9]{1,8}$` / numeric | unsat: a non-digit cannot pass |
| length ≤ 8 only / numeric | sat: `1 OR 1=1` fits |
| lookahead / backreference / unknown SQL context | unknown (no claim) |

**Rule 1: symbolic checks may veto a neural conclusion, never decide one.** Solved
checks become E6, for example `validator model: ^[0-9]{1,8}$ admits a non-digit
(numeric sink)? unsat`. E6 informs the adjudicator's Constraint step. After
Verifying, an `unsat` proof blocks a score in the confirmed band only when every
modelled validator is a top-level exit guard on the same variable in the sink's
function, before the sink, with no intervening reassignment or possible mutation.
Nested guards, helpers, swallowed exceptions or uncertainty disable this veto.
The contradiction abstains the verdict and escalates the finding for human review,
before blast-radius scoring or remediation. It never lowers the model's score or
decides `false_positive`; a low-score decision remains the adjudicator's.

Only an already available E5 PoC with `status=witnessed` for this case overrides
the veto. The normal graph produces E5 after remediation, sandbox verification
and counterfactual checking, so it is unavailable at the veto and the veto stands.
The pipeline order is unchanged. A `sat` string can seed a later PoC proposal.

**Rule 2: unknown is an analysis limit, not evidence.** Unsupported constructs and
solver timeouts receive an L-id in a separate Analysis Limits section, never an
E-id or a Hard Evidence item. The case payload exposes `analysis_limits`; the UI
labels these “Not covered (analysis limit)” and explains why. L-ids must never be
cited. Any citation of a limit, an unknown/non-claim item or a missing id invalidates
the verdict and escalates the case, including low-score verdicts. The Verifier
also checks E6's validator lines against their exact text in the target.

Non-executing examples live in `demo_target/z3_cases/` and are **not** registered by
the demo app. They contain no evaluation labels or SQL execute calls and do not
change the evaluation corpus. Evidence and limits are built before adjudication.

    .venv/Scripts/python -m pytest tests/test_z3_check.py -q

Limits: Semgrep CE is intraprocedural, so source and sink must share a function. Only
the regex subset above is modelled. A solver timeout is `unknown`. z3 is an optional
extra (`pip install -e ".[z3]"`).

## Stretch: MCP tool exposure (ST-4)

`python -m pulseguard.mcp_server` (or the `pulseguard-mcp` script) serves FastMCP over
stdio, following revio's MCP server pattern. Three tools:

- `triage_finding(finding_json)` — validates `contracts/finding.schema.json`, runs the
  guard and deterministic evidence building, returns the Hard Evidence Block. An
  adjudicator verdict is included only when `PG_MODEL_*` is configured; otherwise the
  tool says so and returns evidence only.
- `get_case_evidence(case_id)` — evidence items, verdicts, verification and blast
  radius from the SQLite store at `PG_DB_PATH`.
- `request_approval(case_id, decision, actor)` — never applies a patch. In REPLAY the
  request is simulated and labelled. In LIVE it records an `APPROVAL_REQUESTED` event
  only; human approval stays in the existing approval flow.

Invalid inputs are rejected. The tools do not open a shell or write files outside the
store. Optional extra: `pip install -e ".[mcp]"`.

    .venv/Scripts/python -m pulseguard.mcp_server

## Pre-existing components

Module docstrings follow framework section 7: revio graph, runner, model, patch and store
patterns; tradepulse guard, contracts, trace, API and replay patterns; SymbAI-Taint evidence,
adjudication protocol, JSON parsing and confidence bands; quant-foundation-gat's in-memory
bus bypass; and PerpPulse's static UI and serving modes. The original skeleton established
these contracts and seams; this increment connects the S1 model, sandbox, approval,
persistence, bundling and recording paths. S2 SURFACE adapts revio's Bandit subprocess
pattern to Bandit/Trivy, tradepulse/revio event-store conventions to CSV/KPIs and PerpPulse's
static UI pattern to the S2 contract views. The demo and event aggregation are local additions.
