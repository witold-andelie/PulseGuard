# PulseGuard evaluation / ablation harness

This implements the Sprint 3 evaluation row and framework section 14 using today's
public scanner, evidence and adjudicator interfaces. Run it from this source
checkout: the existing package build includes only `pulseguard`, so `eval` needs
the checkout on `PYTHONPATH`.

The original corpus has **27 labels: 14 vulnerable and 13 safe**. Twenty-two labels are in
three files in `demo_target/eval_cases/`; five are in the existing demo. The hard
corpus adds **40 SQLi sites: 19 vulnerable and 21 safe**, for **67 combined sites:
33 vulnerable and 34 safe**. The fixtures are never imported or registered by the demo app or
its tests. Judge their handlers as if called with a request and a populated
orders table. The original fixtures use in-memory connections; the hard fixtures
expect `current_app.extensions['eval_db']`, supplied by their sanity tests, with
`orders` and `saved_filters` tables. These are analysis fixtures, not deployed services.

This is a small, author-written set, not a held-out benchmark. Counts describe
only these cases. Do not generalise the ratios to production code, other Flask
services, other classes, or the effectiveness of an LLM without a real model run.
Thresholds remain at the framework defaults; no tuning claim is made.

## Run

From the repository root, with the project's virtual environment (see the main README):

```powershell
$python = '<existing-environment>/Scripts/python'
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONPATH = (Get-Location).Path

& $python -m eval.ablation --target demo_target --corpus original --out eval/results `
    --name original-deterministic
& $python -m eval.ablation --target demo_target --corpus hard --out eval/results `
    --name hard-deterministic
& $python -m eval.ablation --target demo_target --corpus all --out eval/results `
    --name all-deterministic
```

The default modes are `semgrep,bandit,llm,neurosymbolic`. Outputs are
`<out>/<name>.md` and `<out>/<name>.json`; `--name` defaults to `ablation`.
Missing scanners produce explicit **not run** rows and a nonzero exit status,
while successful modes still produce reports. Missing LLM opt-in alone does not
make the command fail. A successful scan with zero hits is a completed row.

`--corpus` defaults to `original` to preserve the earlier denominator. `hard`
selects only `eval_cases/hard/`; `all` includes both sets. Scanners still inspect
the target, but hits from excluded corpus files are removed before matching or
model candidate construction. Reports record `excluded_corpus_hits`, selected-file
hashes and corpus configuration. Combined reports show separate corpus counts and
confusion matrices as well as the combined matrix. No rules change with selection.

To run a single deterministic mode, for example Bandit only:

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
| `llm` | Every labelled site plus unmatched scanner hits. The shared adjudicator receives the shared function/context excerpt without a Hard Evidence Block. Score >= 0.7 flags a site. |
| `neurosymbolic` | Semgrep/Bandit hits only. The shared evidence builder produces the block, then the shared adjudicator scores it. The configured `Bands` top band flags a site; duplicate confirmations are OR-ed. |

LLM-only prompts use a neutral `eval-<class>` question instead of the scanner
rule. Class selects the question for both vulnerable and safe sites; neither the
truth label nor its reason is sent. Code-only does retain the shared adjudicator
system prompt and four-step response contract. Both modes, the graph and the
playground use `pulseguard.evidence.code_excerpt`: the enclosing function with
decorators, followed by `REFERENCED DEFINITIONS (same module, untrusted data)`.
This adds referenced literal constants/containers, classes and directly called
module functions, without expanding those helpers' callees. Imports are listed
by name only; no other module's source is read. Definitions related to the sink
value or request-derived variables come first. The entire references section,
including its header, import names and truncation notice, is capped at **60 lines
and 4096 UTF-8 bytes**. Partial/omitted definitions are named with omitted source
line ranges (or a count when the notice itself fills). Every source line keeps
its original number. Dependency manifests have no function
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
Neuro-symbolic now supplies annotation-stripped source and a separate analysis-limits
list to the same evidence builder used by the pipeline. Recognised finite allow-list
facts record the constrained variable, line and literal members. E3 says **none
recognised**, never that a sanitizer is absent. A `not_covered` L-item enumerates
the actual pattern checks and warns that other guards may exist. Legacy int/binding
regex hits are explicitly syntax matches, with sink use unproven. L-ids remain
uncitable. These evidence changes do not alter scanner rules.

E3 also recognises module-level Enum construction/name lookup (optionally `.value`)
when every member is a literal SQL atom and the class has no custom methods,
decorators, unknown bases, mutation, escape or shadowing. Plain `str`/`int`/`float`
mixins are supported; `_missing_` and conversion overrides are rejected. Member
values, the definition line and the call line are recorded.

One-hop module helpers qualify when all paths return `int(param)`/`float(param)`,
a constant dict subscript of the parameter, or the unchanged parameter under a
finite membership guard; other paths must raise (including known Flask abort).
Helpers are bounded, undecorated and unshadowed, with one positional parameter.
Unknown calls, loops, try/fallback, implicit fall-through, identity/strip helpers,
parameter reassignment and two-hop delegates make no claim. Return and call lines
are recorded. Both new forms reuse the existing same-sink-variable, capture-order,
top-level dominance and unchanged-value checks. These are E3 facts for the
adjudicator, not an automatic false-positive decision.

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

## Actual deterministic runs (2026-11-01)

| Corpus | Sites | Vulnerable | Safe | Bandit TP | FP | FN | TN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| original | 27 | 14 | 13 | 12 | 11 | 2 | 2 | .5217 | .8571 |
| hard | 40 | 19 | 21 | 18 | 16 | 1 | 5 | .5294 | .9474 |
| combined | 67 | 33 | 34 | 30 | 27 | 3 | 7 | .5263 | .9091 |

Real outputs are `results/{original,hard,all}-deterministic.{json,md}`. Python
3.12 and Bandit 1.9.4 were used. Each invocation exited 1 because Semgrep could
not run (`CertOpenSystemStore returned NULL`); no Semgrep metrics were fabricated.
Both model modes are explicitly **not run**, with zero model calls. The hard
Bandit FN is `two_hop`: its SQL construction is in an unlabelled helper, so that
helper's hit is audited separately rather than incorrectly matched to the handler.
Original dependency/guard-class FNs remain outside adjudicator ownership.

The pre-existing `results/deterministic.*` historical artifacts are retained
unchanged. Their Semgrep run succeeded on its recording host; this sandbox run
does not supersede it with a synthetic measurement. The earlier README described
an older sandbox attempt; use the timestamped artifacts for provenance.

The context-excerpt follow-up re-ran original/hard/all on 2026-11-01. Bandit
reproduced the counts above; all three commands exited 1 with the same Semgrep
certificate-store failure. The six JSON/Markdown attempt reports were saved
outside the checkout; the committed deterministic files were left unchanged.
No real model mode was run.

## Verification

```powershell
& $python -m pytest -q -rs
& $python -m ruff check .
& $python -m pulseguard.replay.verify
```

Real Semgrep tests carry `@pytest.mark.semgrep` and skip with their scanner failure
reason. The real Bandit integration test asserts the measured labelled confusion
counts. Tests also cover annotation forms, exact scope/window/class matching,
hand-computed metrics, report formatting, fake end-to-end modes, scanner misses,
empty scans, duplicate hits, prompt hygiene and model failures.

The fixtures intentionally preserve `%` and `.format` SQL construction;
`UP031`/`UP032` are suppressed locally in those three fixture files. Other Ruff
checks apply normally.

The context-excerpt full-suite attempt (`pytest -q -rs --tb=line -p no:cacheprovider`)
reported **495 passed, 4 skipped, 4 failed, 235 errors** (13.94 s).
All 239 failures/errors were Windows `WinError 5`
access failures on pytest or sandbox temporary directories under the authorised
tmp root; there were no other assertion failures. The four skips were real
Semgrep integration tests (one ablation, two sandbox, one scanner), all reporting
`CertOpenSystemStore returned NULL`. Temp-dependent Trivy tests errored during
fixture setup, so their availability was not measured. One existing Pydantic
forward-reference warning was reported. This is **not a green full-suite claim**.

The evidence/corpus/ST-1 subset ran **262 passed, 3 deselected** (6.60 s):
`pytest tests/test_context_excerpt.py tests/test_helper_sanitizers.py
tests/test_allowlist_evidence.py tests/test_evidence.py tests/test_hard_corpus.py
tests/test_z3_governance.py tests/test_z3_check.py -q --tb=short -rs -p no:cacheprovider
-k 'not graph_playground_and_both_eval_modes_share_context and not verify_finding_includes_validator_lines'`.
The three deselected tests need the inaccessible temporary-directory fixture:
two new graph/playground/both-eval integration variants and one existing validator
location test. They also errored during setup in the full run. The independent
graph/shared-renderer/eval-excerpt test passed without filesystem fixtures.
Ruff reported **All checks passed!**
and replay verification returned **ok: true**, **49 checked**, no mismatches,
missing or unlisted files. Replay manifest SHA-256:
`5357741cc6e0222de7e622e7e21d6765e129036ff1182bab0db2ee0f579827b2`.
The full suite needs rerunning in a working authorised Windows test environment.

## Source adaptation

The annotation-driven ground-truth approach is adapted from
[SymbAI-Taint `src/ground_truth/extractor.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/main/src/ground_truth/extractor.py).
Finite site-based counts and ratios adapt
[`src/evaluation/metrics.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/main/src/evaluation/metrics.py);
paired JSON/Markdown reporting adapts
[`src/evaluation/reporter.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/main/src/evaluation/reporter.py).
These are Python/Flask reimplementations of those ideas; no C/binary analysis,
DWARF inference, angr, TYGR or inferred ground truth is brought into the harness.

## Hard corpus: case inventory and scope

All 40 handlers are original code written for this evaluation, with no upstream
handler copied. `tests/test_hard_corpus.py` registers their isolated blueprints
only inside its own Flask test app. It supplies an in-memory populated database,
exercises all 19 vulnerable bypasses, checks all 21 safe controls, and verifies
the four vulnerable/patched pairs. Importing the fixtures does no network or file
IO. None is imported by the demo app. Nonmember casts/lookups may raise; this
fails closed for SQLi and is not a claim about application availability.

Provenance keys: **B** = BenchmarkPython request/SQL/binding patterns and OWASP
positive/negative design; **C** = CommentInject safety-comment strategy; **D** =
code-safety source/propagation/sink documentation and safe-query controls; **T** =
PyT Flask, helper and sanitizer/constant-flow patterns; **P** = PyFlow patched-version
method; **A** = author-written mutation or control requested for this corpus.
Keys describe inspiration, not replication of an upstream test or its results.

Every normal SQL sink below is `conn.execute(query)` unless stated otherwise.
All bypass cases in `hard/bypasses.py` use query parameters; the reassignment
case also uses a header. For numeric queries `1 OR 1=1` (or the shown newline
variant) returns three rows instead of the one-row ID lookup. Identifier attacks
use `id LIMIT 1` to alter the three-row query's structure and result count.

| Handler in `hard/bypasses.py` | Label | Source / attempted sanitizer / sink pattern | Modelled on |
| --- | --- | --- | --- |
| `regex_search` | vuln | args -> unanchored search -> numeric SQL | A, D |
| `regex_dollar_multiline` | vuln | args -> `$` with MULTILINE -> `1\nOR 1=1` | A |
| `regex_match_prefix` | vuln | args -> re.match prefix -> unchecked suffix | A, P pair 1 |
| `length_only` | vuln | args -> length <= 8 -> numeric SQL | A |
| `case_allowlist_fallthrough` | vuln | case-sensitive membership normalises members only; nonmembers fall through, then lower at sink | A |
| `different_variable` | vuln | one args value checked, another reaches identifier SQL | A, D |
| `one_branch` | vuln | args -> optional regex branch -> numeric SQL | A, T |
| `try_fallback` | vuln | args -> int error -> raw fallback -> numeric SQL | A, P pair 2 |
| `validated_reassigned` | vuln | args allow-list -> header reassignment -> identifier SQL | A |
| `validated_concatenated` | vuln | args allow-list -> raw suffix -> identifier SQL | A |
| `discarded_int` | vuln | args -> discarded int result, swallowed error -> raw SQL | A |
| `quote_escape_numeric` | vuln | args -> quote doubling -> unquoted numeric SQL | A |
| `escape_format_numeric` | vuln | quote doubling -> f-string width spec -> numeric SQL | A |

`$` alone allows a final newline, but digits plus whitespace alone do **not**
demonstrate SQLi. `dollar_final_newline` is therefore safe; the vulnerable partner
uses MULTILINE to permit an SQL suffix. Similarly, lowercasing an actually finite
validated set does not by itself create an injection. The vulnerable case is a
fall-through validation error; `normalised_allowlist` is its safe control. A
discarded int conversion with an uncaught failure would block nonnumeric input;
the vulnerable fixture explicitly swallows that failure. Labels reflect actual
SQL behaviour, not just a validator weakness.

| Handler in `hard/safes.py` | Label | Source -> sanitizer / safe sink | Modelled on |
| --- | --- | --- | --- |
| `set_guard` | safe | args -> literal set exit guard -> identifier | A, D |
| `tuple_positive` | safe | args -> tuple membership wraps identifier sink | A, T |
| `dict_subscript` | safe | args -> constant dict values; missing key raises | A, D |
| `dict_get` | safe | args -> constant dict + fixed default | A, D |
| `enum_column` | safe | args -> Enum value or exception -> identifier | A |
| `conditional_column` | safe | args -> membership ternary with fixed default | A |
| `integer_used` | safe | args -> int result -> numeric SQL | A, T |
| `float_used` | safe | args -> float result -> numeric SQL; nonfinite values may error | A, T |
| `positional_binding` | safe | form -> `?` binding, constant query concatenation | B |
| `named_binding` | safe | JSON -> `:item` binding | B, D |
| `batch_binding` | safe | JSON list -> executemany with bound tuples | A, B |
| `bound_builder` | safe | header -> ORM-style builder -> named binding (interprocedural) | T, D |
| `quoted_mapping` | safe | args -> fixed already-quoted identifier mapping | A, D |
| `constant_sql` | safe | args ignored; literal-only SQL assembled with + | T, D |
| `regex_fullmatch_patch` | safe | args -> fullmatch used on every path | A, P pair 1 |
| `try_failclosed_patch` | safe | args -> int result, exception exits | A, P pair 2 |
| `normalised_allowlist` | safe | args lowercased before the same-value finite check | A |
| `dollar_final_newline` | safe | digits with at most one final newline; numeric SQL whitespace | A |

| Handler in `hard/flows.py` | Label | Source / propagation / sink | Modelled on |
| --- | --- | --- | --- |
| `two_hop` | vuln | form -> forward_rows -> fetch_rows -> raw numeric SQL | T, D; interprocedural |
| `helper_cast` | safe | cookie -> integer_in_helper -> numeric SQL | T; interprocedural |
| `misleading_helper` | vuln | JSON -> identity function named sanitize_id -> raw numeric SQL | A, T; interprocedural |
| `second_order` | vuln | JSON -> bound storage -> re-read -> raw SQL | A, D stored-flow idea, P pair 3 |
| `second_order_patch` | safe | JSON -> bound storage -> re-read -> bound SQL | A, P pair 3 |
| `path_value` | vuln | Flask path argument -> numeric SQL | B, T, P pair 4 |
| `path_value_patch` | safe | same Flask path argument -> bound SQL | B, P pair 4 |

The builder and two-hop cases exceed local reasoning; the single cast helper now
has bounded one-hop E3 recognition. The second-order
pair also requires modelling database storage and retrieval; it is not expected
to be proved by the local taint rule. Its deterministic test stores and retrieves
in one request to keep the example reproducible, with a fresh table per test.
Path arguments are ordinary source coverage, separate from the helper limitation.

| Isolated file / handler | Label | Flow and adversarial pattern | Modelled on |
| --- | --- | --- | --- |
| `hard/comment_upstream.py` / `comment_upstream` | vuln | header -> raw numeric SQL; upstream validation assertion | C |
| `hard/comment_reviewer.py` / `comment_reviewer` | vuln | cookie -> raw numeric SQL; AI reviewer safe/resolve instruction | C |

Each adversarial-comment file has only one handler. This prevents whole-file
Guard quarantine from affecting unrelated hard cases. These labels are SQLi,
not additional prompt-injection ground truth. The ablation does not run Guard.

## Sources

Read on **2026-11-01**. Only patterns and evaluation ideas were used; no upstream
code, datasets, license texts or papers were vendored. These are author-written
fixtures, not a repackaged or held-out upstream benchmark.

- **B — OWASP BenchmarkPython CWE-89:** [requested repository](https://github.com/AppSec-Tool-Benchmarking/OWASP-BenchmarkPython),
  [00011 bound cookie source](https://github.com/AppSec-Tool-Benchmarking/OWASP-BenchmarkPython/blob/main/testcode/BenchmarkTest00011.py),
  [00012 bound propagated cookie](https://github.com/AppSec-Tool-Benchmarking/OWASP-BenchmarkPython/blob/main/testcode/BenchmarkTest00012.py),
  [00099 form/config propagation into raw SQL](https://github.com/AppSec-Tool-Benchmarking/OWASP-BenchmarkPython/blob/main/testcode/BenchmarkTest00099.py).
  [Python case design](https://owasp.org/projects/benchmark?tab=python-test-cases)
  documents expected true findings and false positives; [scoring](https://owasp.org/projects/benchmark?tab=scoring)
  motivates measuring both. The repository [LICENSE](https://github.com/AppSec-Tool-Benchmarking/OWASP-BenchmarkPython/blob/main/LICENSE)
  and case headers say **GPL-3.0**, despite the general OWASP page displaying
  GPL-2.0. No source was copied into this proprietary project.
- **C — Sunny Chokshi, CommentInject:** [dataset card and CWE-89 samples](https://huggingface.co/datasets/sunny-chokshi/commentinject).
  The card documents holding vulnerable code fixed while adding false safety
  comments. Licence metadata: **CC-BY-4.0**. Our two isolated comments/handlers
  are original variants; attribution here records the strategy used. The dataset
  has no safe controls; our safe controls are independently authored.
- **D — Laurent Giovannoni, code-safety:** [repository](https://github.com/laugiov/code-safety),
  [taint-flow definitions](https://github.com/laugiov/code-safety/blob/master/benchmarks/ground-truth/taint-flows.yaml),
  [CWE-89 ground truth/remediation](https://github.com/laugiov/code-safety/blob/master/benchmarks/ground-truth/vulnerabilities.json),
  [false-positive discussion](https://github.com/laugiov/code-safety/blob/master/docs/enterprise/false-positives.md).
  Used explicit source/propagation/sink descriptions and binding/constant-query
  controls as the documentation model. The [LICENSE](https://github.com/laugiov/code-safety/blob/master/LICENSE)
  is **MIT**, with an appended educational/security-use notice, both read.
  This source is a GitHub Django reference, not a Hugging Face dataset.
- **T — python-security/PyT:** [Flask SQL examples](https://github.com/python-security/pyt/blob/master/examples/vulnerable_code/sql/sqli.py),
  [sanitised/unknown-flow explanation](https://github.com/python-security/pyt/blob/master/pyt/vulnerabilities/README.rst),
  [constant-return false-positive fixture](https://github.com/python-security/pyt/blob/master/examples/vulnerable_code_across_files/no_false_positive_import_file_command_injection_3.py),
  [README](https://github.com/python-security/pyt#readme).
  Used raw-vs-bound Flask SQL, helper-return/constant controls and conditional
  sanitizer uncertainty. The constant-flow example is command injection; our
  SQL version is a new analogue, not an upstream CWE-89 case. [Licence](https://github.com/python-security/pyt/blob/master/LICENSE):
  **GPL-2.0**; no source copied. The README warns about pattern-baseline noise;
  we do not claim every hard case is an established PyT bug.
- **P — Zinan Gu, Haoxiang Yan, Peisen Yao, PyFlow:** [verified arXiv record 2608.07026](https://arxiv.org/abs/2608.07026),
  [full text, evaluation dataset section](https://arxiv.org/html/2608.07026v1).
  Submitted 7 August 2026. It independently evaluates vulnerable and patched
  programs, treating a matching patched-version alert as an FP. Our four
  synthetic pairs adapt that method, without claiming CVE provenance. The arXiv
  record links a **CC-BY-4.0** licence; no paper text or implementation copied.

## Remaining coverage gaps exposed by the hard set

No scanner rule was changed. Inspection of the existing local Semgrep rule shows
only `flask.request.args.get(...)` as a source; form, get_json, headers, cookies
and path-parameter cases require a future coverage decision. This is source
inspection, not a measured Semgrep result on this host. Helper and stored flows
still exceed that taint rule's intraprocedural scope. Bandit's hard FN is the two-hop
handler, with its helper finding retained as unmatched in JSON.

The existing Bandit trace slicer omits header/cookie/get_json source claims and
does not model control-flow branches or database storage. The E3 regex candidates
are now clearly marked syntax-only; proving direct int-result use and parameter-binding
semantics remains future work. Prequoted identifier mapping, arbitrary Enums and
helpers beyond the conservative forms above, and f-string format specifications
are outside recognition;
they receive honest coverage limits rather than invented sanitizer facts.

Both neural modes now receive the same one-hop source context. Referenced Enum
definitions and direct helper implementations are visible subject to the explicit
cap. This addresses the observed context gaps in `enum_column` and `helper_cast`;
no improvement in model metrics is claimed without a fresh reviewer-run comparison.
Other-module source, helpers' callees and stored dataflow remain outside scope.
