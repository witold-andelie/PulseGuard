# PulseGuard evaluation / ablation harness

This implements the Sprint 3 evaluation row and framework section 14 using today's
public scanner, evidence and adjudicator interfaces. Run it from this source
checkout: the existing package build includes only `pulseguard`, so `eval` needs
the checkout on `PYTHONPATH`.

The corpus has **27 labels: 14 vulnerable and 13 safe**. Twenty-two labels are in
three new files in `demo_target/eval_cases/`; five are in the existing demo. The
new files are scanner fixtures, never imported or registered by the demo app or
its tests. Judge their handlers as if called with a request and a populated
orders table. The in-memory database keeps the source self-contained; these are
static-analysis cases, not executable deployment or exploitability proofs.

This is a small, author-written set, not a held-out benchmark. Counts describe
only these cases. Do not generalise the ratios to production code, other Flask
services, other classes, or the effectiveness of an LLM without a real model run.
Thresholds remain at the framework defaults; no tuning claim is made.

## Run

Use the shared interpreter, without creating a virtual environment here:

```powershell
$python = 'D:/AI_Models/hackson/PulseGuard/.venv/Scripts/python'
$env:PYTHONPATH = (Get-Location).Path
$env:PIP_CACHE_DIR = 'D:/AI_Models/hackson/_pulseguard_work/pip-cache'
$env:TMP = 'D:/AI_Models/hackson/_pulseguard_work/tmp'
$env:TEMP = $env:TMP
$env:PYTHONIOENCODING = 'utf-8'

& $python -m eval.ablation --target demo_target --out eval/results --name deterministic
```

The default modes are `semgrep,bandit,llm,neurosymbolic`. Outputs are
`<out>/<name>.md` and `<out>/<name>.json`; `--name` defaults to `ablation`.
Missing scanners produce explicit **not run** rows and a nonzero exit status,
while successful modes still produce reports. Missing LLM opt-in alone does not
make the command fail. A successful scan with zero hits is a completed row.

Bandit alone can run on this sandbox host:

```powershell
& $python -m eval.ablation --target demo_target --out eval/results/local-bandit --modes bandit
```

Semgrep uses the existing local `flask-sqli-taint.yaml` and a 30-second subprocess
timeout. Bandit uses the existing runner and its normal set of checks. Neither
scanner is replaced with synthetic findings when it fails.

For a reviewer-run model evaluation, use a host where both scanners work and an
environment file containing `PG_MODEL_BASE_URL`, `PG_MODEL_NAME` and
`PG_MODEL_API_KEY` for the existing client:

```powershell
& $python -m eval.ablation --target demo_target --out eval/results/real-llm `
    --env-file 'D:/path/to/model.env' --modes semgrep,bandit,llm,neurosymbolic
```

Both neural modes require the complete Semgrep/Bandit candidate union. If either
scan is unavailable, those modes are **not run**, even with a configured client.
Library callers use `run_ablation(target, llm=client, semgrep=runner, bandit=runner)`
to inject an `LLMClient` and scanner runners. Ambient model credentials alone
never enable model calls; CLI opt-in requires `--env-file`. Tests inject only
`tests.fakes.FakeLLM` and never call a real model.

## What the modes measure

| Mode | Candidates and positive decision |
| --- | --- |
| `semgrep` | A labelled SQLi site is flagged when the existing taint rule reports a matching hit. |
| `bandit` | A site is flagged when Bandit reports a matching hit; B608 maps to SQLi. This is a pattern baseline, with no taint-proof claim. |
| `llm` | Every labelled site plus unmatched scanner hits. The shared adjudicator receives the enclosing function without a Hard Evidence Block. Score >= 0.7 flags a site. |
| `neurosymbolic` | Semgrep/Bandit hits only. The shared evidence builder produces the block, then the shared adjudicator scores it. The configured `Bands` top band flags a site; duplicate confirmations are OR-ed. |

LLM-only prompts use a neutral `eval-<class>` question instead of the scanner
rule. Class selects the question for both vulnerable and safe sites; neither the
truth label nor its reason is sent. Code-only does retain the shared adjudicator
system prompt and four-step response contract. Normal excerpts contain only the
enclosing function, including decorators. Dependency manifests have no function
and receive a short manifest slice; unmatched module-level scanner hits use the
shared helper's bounded fallback.

Both `@vuln` and `@safe` comment tokens are stripped before prompting, with line
numbers preserved. Trace text is rebuilt from the stripped source before evidence
building, so scanner traces cannot leak label comments. Ordinary comments,
including planted prompt-injection instructions, remain untrusted code data.
Malformed/provider-failed replies remain negative, are counted separately as
unusable replies, and cannot be promoted by lowering a band threshold. Abstained
replies are also negative.

This ablation covers scanner evidence and adjudication. It does not run Guard,
Skeptic, citation verification, counterfactuals, PoC execution, exposure inference,
patching or governance. A confirmed ablation decision is not permission to remediate.
Neuro-symbolic uses the scanner union, so it has a different candidate pool from
Semgrep alone; interpret that comparison accordingly.

## Labels and matching

`eval/labels.py` reads Python comment tokens, so annotation-looking strings and
docstrings do not become labels. It accepts inline or standalone `# @vuln sqli`,
`# @safe sqli: reason`, and bare safe reasons such as `# @safe int() cast`. Bare
safe reasons default to SQLi in this SQL-focused corpus. A comment immediately
before a function/decorator is associated with that function. Async functions,
nested functions and class methods have qualified function names.

`requirements.txt` supports preceding and inline `# @vuln dependency: ...` and
`# @safe dependency: ...` comments. A preceding label covers the next requirement
through intervening comments. Each site's JSON includes file, annotation line,
qualified function, label, class, reason and span.

A scanner hit matches an exact target-relative file, the same innermost function,
and the same class. The nearest annotation must lie within **12 lines**. This
allows Bandit's query-construction line and Semgrep's sink line to map to the same
site, without crossing function boundaries. Equal-distance same-class labels are
ambiguous and unmatched. Multiple hits on one site count once. Manifest-wide
line-zero findings can match dependency labels, with CVE disambiguation when
provided; tests exercise the public Trivy normalizer with this form.

The four modes do not ingest Trivy reports or evaluate prompt-injection detection
by Guard. Their aggregate includes the existing dependency and prompt-injection
labels, so scanner-only misses on those classes are explicit FNs. Reports also
give per-class confusion counts: SQLi has **25 sites (12 vulnerable, 13 safe)**;
dependency and prompt injection each have one vulnerable site. The original
`order_note` function legitimately has different labels for prompt injection and
SQLi; a SQL scanner hit cannot satisfy its prompt-injection label.

## Metrics and report interpretation

TP/FP/FN/TN use the explicit vulnerable/safe site universe. Unflagged vulnerable
sites are FNs, including scanner misses, uncertainty and abstention; unflagged
safe sites are TNs. Unmatched or unlabelled scanner hits are audited separately,
not silently counted as FPs or added to the labelled denominator.

Precision = TP/(TP+FP), recall = TP/(TP+FN),
F1 = 2TP/(2TP+FP+FN), FP rate = FP/(FP+TN), FN rate = FN/(FN+TP).
A zero denominator yields 0.0, following the upstream convention. Unrun metrics
are JSON `null` and Markdown missing cells, never zero-valued measurements.

JSON records the labelled sites, scanner-hit matches, flagged site IDs, individual
model decisions and unusable-reply counts, Python/scanner versions, model name,
thresholds and SHA-256 hashes of the Python/manifests in the target. Reports do
not include credentials or raw provider exception messages.

## Actual deterministic run

The checked-in [Markdown](results/deterministic.md) and
[JSON](results/deterministic.json) come from a real local run. Bandit 1.9.4 produced
34 raw hits: 23 matched hits and 11 unlabelled/unmatched hits. Its 12 SQLi true
positives and 11 SQLi false positives give the following aggregate over all labels:

| Mode | Status | TP | FP | FN | TN | Precision | Recall | F1 | FP rate | FN rate |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| semgrep | not run | — | — | — | — | — | — | — | — | — |
| bandit | completed | 12 | 11 | 2 | 2 | 0.5217 | 0.8571 | 0.6486 | 0.8462 | 0.1429 |
| llm | not run | — | — | — | — | — | — | — | — | — |
| neurosymbolic | not run | — | — | — | — | — | — | — | — | — |

Semgrep failed with `CertOpenSystemStore returned NULL` inside the Windows
sandbox. No LLM was supplied. There is no measured neural improvement or
threshold-tuning result to report. Keep these artifacts as the deterministic
baseline and write any real model run to a separate output directory.

## Verification

```powershell
& $python -m pytest -q -rs
& $python -m ruff check .
```

Real Semgrep tests carry `@pytest.mark.semgrep` and skip with their scanner failure
reason. The real Bandit integration test asserts the measured labelled confusion
counts. Tests also cover annotation forms, exact scope/window/class matching,
hand-computed metrics, report formatting, fake end-to-end modes, scanner misses,
empty scans, duplicate hits, prompt hygiene and model failures.

This restricted Windows session additionally needs external temporary-directory
ACL compatibility for pytest's private temporary directories. The compatibility
runner is outside the repository at
`D:/AI_Models/hackson/_pulseguard_work/tools/s3_eval_runner.py`; it changes temporary
directory creation only under the approved `TMP` and propagates to Python child
processes. The test command used here is:

```powershell
$evalTestTemp = $env:TMP + '/s3-eval-full-' + [guid]::NewGuid().ToString('N')
& $python D:/AI_Models/hackson/_pulseguard_work/tools/s3_eval_runner.py `
    -m pytest -q -rs --tb=short -p no:cacheprovider --basetemp $evalTestTemp
```

The fixtures intentionally preserve `%` and `.format` SQL construction;
`UP031`/`UP032` are suppressed locally in those three fixture files. Other Ruff
checks apply normally.

## Source adaptation

The annotation-driven ground-truth approach is adapted from
[SymbAI-Taint `src/ground_truth/extractor.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/main/src/ground_truth/extractor.py).
Finite site-based counts and ratios adapt
[`src/evaluation/metrics.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/main/src/evaluation/metrics.py);
paired JSON/Markdown reporting adapts
[`src/evaluation/reporter.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/main/src/evaluation/reporter.py).
These are Python/Flask reimplementations of those ideas; no C/binary analysis,
DWARF inference, angr, TYGR or inferred ground truth is brought into the harness.
