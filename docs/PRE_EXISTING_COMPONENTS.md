# Pre-existing components and attribution

PulseGuard builds on earlier public repositories and established libraries. The team does not
claim those repositories, third-party models or platforms as inventions made for this hackathon.
The contribution here is the security workflow, its contracts and adapters, grounded review
experience, bounded patch validation, replay evidence and infrastructure integration.

## Verification method and scope

Verified on 31 October 2026 against each repository's `main` branch. The GitHub commit API resolved
the branch tip, and the recursive Git tree API fetched its tree with `truncated: false` for every
repository. Source links below are pinned to those commits. **Verified** means the exact file path
occurs as a blob in that fetched tree. It does not assert that every upstream behavior was ported,
that a container ran, or that this document independently proves authorship dates.

Target paths were checked in this worktree. **Exists** records a file's presence; implementation
limits are in the adaptation column and [architecture](ARCHITECTURE.md). **Planned (sprint)** means
the target is absent here; the label names a scope increment, not a completion claim or calendar.
Parallel work in other worktrees is not counted as implemented here.

The tables include the complete file-level reuse map, the attribution-document pattern, the
symbolic-filtering caveat source, and the resolved historical-serving filename. Function names
are symbols within the named source files, not extra repository paths.

| Repository | Verified `main` commit | Recursive tree SHA |
| --- | --- | --- |
| [revio](https://github.com/witold-andelie/revio) | `1a528594d8c2a5f52041762c67f69d83eda22d02` | `e536747fdee33bdca9e75b0a0ca2811f18a898d2` |
| [tradepulse](https://github.com/witold-andelie/tradepulse) | `546648b563906feac72b51947f530a9a9dceb221` | `0433d49e189317f413112ed16dd08a8e8790cda0` |
| [quant-foundation-gat](https://github.com/witold-andelie/quant-foundation-gat) | `9eeeeb56e21c66f6e08a150563ea55599e845d66` | `26f3c633db6c2de1745b628e326fa6032bcd49b8` |
| [SymbAI-Taint](https://github.com/witold-andelie/SymbAI-Taint) | `e0992b567de69930ca1ea3b66b40fa126a6433dd` | `75cf8d58d62f4918242b68bc94a766be53b69ba1` |
| [PerpPulse](https://github.com/witold-andelie/PerpPulse) | `1acb5426eda2127d5a3c3557784057ded7d954dd` | `bb3de398afd570227f7cc04d3153298e030dc9a3` |

## Pre-existing work and project adaptations

The left-hand paths belong to the reference repositories. PulseGuard target paths and descriptions
identify the hackathon-specific adaptation or intended adaptation. Reimplementation of streaming
uses the upstream design as a reference; it does not vendor the upstream source files.

### revio

The language-tier adapters below were checked against the same pinned commit in the local
revio clone on 1 November 2026. Each adapted module retains Apache-2.0 attribution and names
its source in its docstring. The upstream [license](../pulseguard/lang/REVIO_LICENSE.txt) and
[NOTICE](../pulseguard/lang/REVIO_NOTICE.txt) are included. Grammar wheels remain dependencies;
the SQL injection rules are new PulseGuard work, written without registry rule content.
The C/C++ extension uses the same attributed loaders, function node tables and C declarator
extraction approach. Its input-source tables, buffer/stream taint rules and fixtures are
new PulseGuard code. No cppcheck runner or binary-analysis runtime is added.

| Pre-existing source file | Source check | PulseGuard adaptation | Target and local status | Scope |
| --- | --- | --- | --- | --- |
| [`src/revio/layers/parser/language_support.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/layers/parser/language_support.py) | local clone verified | Adapt lazy optional grammar loading and cached failures; share immutable grammars with a fresh parser per request. | [`pulseguard/lang/language_support.py`](../pulseguard/lang/language_support.py) - exists | languages |
| [`src/revio/layers/parser/treesitter_generic.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/layers/parser/treesitter_generic.py) | local clone verified | Adapt node-type tables, source traversal and innermost-function selection for snippets; add numbered, annotation-stripped, capped one-hop definitions. | [`pulseguard/lang/treesitter_generic.py`](../pulseguard/lang/treesitter_generic.py) - exists | languages |
| [`src/revio/layers/parser/function_index.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/layers/parser/function_index.py) | local clone verified | Adapt comment/string-aware token comparison, retaining variable and literal spelling for exact-line trace grounding; source tables are new. No dedup/similarity index is ported. | [`pulseguard/lang/trace_check.py`](../pulseguard/lang/trace_check.py) - exists | languages |
| [`src/revio/detect/fingerprint.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/detect/fingerprint.py) | local clone verified | Adapt explicit profile precedence and marker-based language selection from directories to pasted syntax. Generic, COBOL and SAS profiles inform graceful grammar/advisory tier routing; no profile classes or reasoning prompts are copied. | [`pulseguard/lang/detect.py`](../pulseguard/lang/detect.py) - exists | languages |
| [`src/revio/agent/graph.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/agent/graph.py) | verified | Rework the agent graph into guard, evidence, adjudication, sandbox and approval nodes. | [`pulseguard/agents/graph.py`](../pulseguard/agents/graph.py) - exists | S1 |
| [`src/revio/agent/state.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/agent/state.py) | verified | Define SecOpsState and accumulated case events for the security workflow. | [`pulseguard/agents/state.py`](../pulseguard/agents/state.py) - exists | S1 |
| [`src/revio/agent/llm.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/agent/llm.py) | verified | Use a configurable model-provider seam; the current client implements the compatible chat endpoint. | [`pulseguard/agents/llm.py`](../pulseguard/agents/llm.py) - exists | S1 |
| [`src/revio/agent/prompts.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/agent/prompts.py) | verified | Organize security role prompts; Skeptic prompt implementation remains planned for S2. | [`pulseguard/agents/prompts.py`](../pulseguard/agents/prompts.py) - exists | S1/S2 |
| [`src/revio/agent/runner.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/agent/runner.py) | verified | Use SQLite graph checkpoints and a durable approval interrupt/resume. | [`pulseguard/agents/runner.py`](../pulseguard/agents/runner.py) - exists | S1 |
| [`src/revio/output/models.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/output/models.py) | verified | Reshape finding/evidence models around security case identity, trace and evidence IDs. | [`pulseguard/contracts/models.py`](../pulseguard/contracts/models.py) - exists | S1 |
| [`src/revio/layers/static/bandit.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/layers/static/bandit.py) | verified | Adapt bounded subprocess/report handling for Semgrep, Trivy and Bandit scanner adapters. | [`pulseguard/scanners/semgrep.py`](../pulseguard/scanners/semgrep.py) - exists<br>[`pulseguard/scanners/trivy.py`](../pulseguard/scanners/trivy.py) - exists<br>[`pulseguard/scanners/bandit.py`](../pulseguard/scanners/bandit.py) - exists | S1/S2 |
| [`src/revio/agent/patch.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/agent/patch.py) | verified | Use exact replacement operations, structured PatchSets and scoped application to a copy. | [`pulseguard/patching/patch.py`](../pulseguard/patching/patch.py) - exists<br>[`contracts/patchset.schema.json`](../contracts/patchset.schema.json) - exists | S1 |
| [`src/revio/cli/fix.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/cli/fix.py) | verified | Translate terminal approval semantics into an approval request and API/UI decision. | [`pulseguard/governance/approval.py`](../pulseguard/governance/approval.py) - exists | S1 |
| [`src/revio/agent/findings_store.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/agent/findings_store.py) | verified | Build a fingerprint-deduplicated SQLite case store and related records. | [`pulseguard/store.py`](../pulseguard/store.py) - exists | S1 |
| [`src/revio/agent/grounding.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/agent/grounding.py) | verified | Planned evidence-ID, file/line and scanner-grounding checks. | `pulseguard/verify.py` - planned (S2) | S2 |
| [`src/revio/agent/fix_history.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/agent/fix_history.py) | verified | Planned snapshots and rollback of the patched output copy. | `pulseguard/patching/history.py` - planned (S2) | S2 |
| [`src/revio/mcp_server/server.py`](https://github.com/witold-andelie/revio/blob/1a528594d8c2a5f52041762c67f69d83eda22d02/src/revio/mcp_server/server.py) | verified | Planned MCP registration for triage, evidence access and approval requests. | `pulseguard/mcp_server.py` - planned (ST-4) | ST-4 |

### tradepulse

| Pre-existing source file | Source check | PulseGuard adaptation | Target and local status | Scope |
| --- | --- | --- | --- | --- |
| [`tradepulse/guard.py`](https://github.com/witold-andelie/tradepulse/blob/546648b563906feac72b51947f530a9a9dceb221/tradepulse/guard.py) | verified | Screen untrusted text and add reviewer-directed manipulation patterns. Destructive-intent expansion is planned for S2. | [`pulseguard/guard.py`](../pulseguard/guard.py) - exists | S1/S2 |
| [`tradepulse/verify.py`](https://github.com/witold-andelie/tradepulse/blob/546648b563906feac72b51947f530a9a9dceb221/tradepulse/verify.py) | verified | Planned small named checks for evidence, CVEs, patch scope and rerun fingerprints. | `pulseguard/verify.py` - planned (S2) | S2 |
| [`tradepulse/trace.py`](https://github.com/witold-andelie/tradepulse/blob/546648b563906feac72b51947f530a9a9dceb221/tradepulse/trace.py) | verified | Add case identity and activity to validated JSONL traces with redaction. | [`pulseguard/trace.py`](../pulseguard/trace.py) - exists | S1 |
| [`tradepulse/contracts.py`](https://github.com/witold-andelie/tradepulse/blob/546648b563906feac72b51947f530a9a9dceb221/tradepulse/contracts.py) | verified | Reuse the JSON Schema validation pattern for security payloads. | [`pulseguard/contracts/validate.py`](../pulseguard/contracts/validate.py) - exists | S1 |
| [`contracts/api/tradepulse.schema.json`](https://github.com/witold-andelie/tradepulse/blob/546648b563906feac72b51947f530a9a9dceb221/contracts/api/tradepulse.schema.json) | verified | Define security finding, verdict, patch and event schemas. | [`contracts/finding.schema.json`](../contracts/finding.schema.json) - exists<br>[`contracts/verdict.schema.json`](../contracts/verdict.schema.json) - exists<br>[`contracts/patchset.schema.json`](../contracts/patchset.schema.json) - exists<br>[`contracts/event.schema.json`](../contracts/event.schema.json) - exists | S1 |
| [`tradepulse/api.py`](https://github.com/witold-andelie/tradepulse/blob/546648b563906feac72b51947f530a9a9dceb221/tradepulse/api.py) | verified | Adapt the app factory and startup/readiness pattern to cases and replay. | [`pulseguard/api.py`](../pulseguard/api.py) - exists | S1 |
| [`serve.py`](https://github.com/witold-andelie/tradepulse/blob/546648b563906feac72b51947f530a9a9dceb221/serve.py) | verified | Serve the API and static case board from a single application. | [`pulseguard/api.py`](../pulseguard/api.py) - exists | S1 |
| [`tradepulse/store.py`](https://github.com/witold-andelie/tradepulse/blob/546648b563906feac72b51947f530a9a9dceb221/tradepulse/store.py) | verified | Validate run identifiers and save/load replay material atomically. | [`pulseguard/replay/store.py`](../pulseguard/replay/store.py) - exists | S1 |
| [`scripts/review_demo.py`](https://github.com/witold-andelie/tradepulse/blob/546648b563906feac72b51947f530a9a9dceb221/scripts/review_demo.py) | verified | Verify replay hashes before exposing recorded results; avoid generation in replay. | [`pulseguard/replay/verify.py`](../pulseguard/replay/verify.py) - exists | S1 |
| [`Dockerfile`](https://github.com/witold-andelie/tradepulse/blob/546648b563906feac72b51947f530a9a9dceb221/Dockerfile) | verified | Use a slim Python runtime, non-root user and PORT-driven service. | [`Dockerfile`](../Dockerfile) - exists | S1 |
| [`README.md`](https://github.com/witold-andelie/tradepulse/blob/546648b563906feac72b51947f530a9a9dceb221/README.md) | verified | Reuse role separation and honest recorded/live labels as workflow design; security Skeptic/Verifier remain planned. | [`pulseguard/agents/graph.py`](../pulseguard/agents/graph.py) - exists<br>`pulseguard/agents/skeptic.py` - planned (S2)<br>`pulseguard/verify.py` - planned (S2) | S1/S2 |
| [`docs/PRE_EXISTING_COMPONENTS.md`](https://github.com/witold-andelie/tradepulse/blob/546648b563906feac72b51947f530a9a9dceb221/docs/PRE_EXISTING_COMPONENTS.md) | verified | Follow the attribution pattern: identify earlier work and bound the new project contribution. | [`docs/PRE_EXISTING_COMPONENTS.md`](../docs/PRE_EXISTING_COMPONENTS.md) - exists | S3 |

### quant-foundation-gat

| Pre-existing source file | Source check | PulseGuard adaptation | Target and local status | Scope |
| --- | --- | --- | --- | --- |
| [`src/quant_alpha/streaming/demo_signals.py`](https://github.com/witold-andelie/quant-foundation-gat/blob/9eeeeb56e21c66f6e08a150563ea55599e845d66/src/quant_alpha/streaming/demo_signals.py) | verified | Provide a broker-free path suitable for local tests and Render. | [`pulseguard/bus/memory.py`](../pulseguard/bus/memory.py) - exists | S1 |
| [`src/quant_alpha/graph/propagate.py`](https://github.com/witold-andelie/quant-foundation-gat/blob/9eeeeb56e21c66f6e08a150563ea55599e845d66/src/quant_alpha/graph/propagate.py) | verified | Planned deterministic risk propagation using privilege, data sensitivity and hop decay. | `pulseguard/risk/blast_radius.py` - planned (S2) | S2 |
| [`src/quant_alpha/streaming/redpanda_producer.py`](https://github.com/witold-andelie/quant-foundation-gat/blob/9eeeeb56e21c66f6e08a150563ea55599e845d66/src/quant_alpha/streaming/redpanda_producer.py) | verified | Reimplement Kafka publication with schemaless Avro, delivery acknowledgement and wrapped failures for security.findings. | [`pulseguard/bus/redpanda.py`](../pulseguard/bus/redpanda.py) - exists | S3 |
| [`src/quant_alpha/streaming/redpanda_consumer.py`](https://github.com/witold-andelie/quant-foundation-gat/blob/9eeeeb56e21c66f6e08a150563ea55599e845d66/src/quant_alpha/streaming/redpanda_consumer.py) | verified | Reimplement callback consumption and commit-after-handler behavior; runner selection remains planned. | [`pulseguard/bus/redpanda.py`](../pulseguard/bus/redpanda.py) - exists | S3 |
| [`schemas/energy_signal.avsc`](https://github.com/witold-andelie/quant-foundation-gat/blob/9eeeeb56e21c66f6e08a150563ea55599e845d66/schemas/energy_signal.avsc) | verified | Create an independent security-finding Avro record with the JSON contract field names. | [`contracts/finding.avsc`](../contracts/finding.avsc) - exists | S3 |
| [`docker-compose.yml`](https://github.com/witold-andelie/quant-foundation-gat/blob/9eeeeb56e21c66f6e08a150563ea55599e845d66/docker-compose.yml) | verified | Declare a local broker, Console and PulseGuard replay app with healthchecks. Docker execution is unverified on this host. | [`docker-compose.yml`](../docker-compose.yml) - exists | S3 |
| [`.github/workflows/ci.yml`](https://github.com/witold-andelie/quant-foundation-gat/blob/9eeeeb56e21c66f6e08a150563ea55599e845d66/.github/workflows/ci.yml) | verified | Retain verification while adding scanner/stream dependencies, explicit marked tests and checksum-verified Trivy. | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) - exists | S1/S3 |

### SymbAI-Taint

| Pre-existing source file | Source check | PulseGuard adaptation | Target and local status | Scope |
| --- | --- | --- | --- | --- |
| [`src/orchestrator/llm_client.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/e0992b567de69930ca1ea3b66b40fa126a6433dd/src/orchestrator/llm_client.py) | verified | Adapt analyze_taint_path_cot evidence-first reasoning to dataflow, constraints, context and verdict. | [`pulseguard/agents/adjudicator.py`](../pulseguard/agents/adjudicator.py) - exists<br>[`pulseguard/agents/prompts.py`](../pulseguard/agents/prompts.py) - exists | S1 |
| [`src/orchestrator/llm_client.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/e0992b567de69930ca1ea3b66b40fa126a6433dd/src/orchestrator/llm_client.py) | verified | Adapt _parse_json_response-style tolerant response parsing; security contracts still validate the result. | [`pulseguard/agents/json_parse.py`](../pulseguard/agents/json_parse.py) - exists | S1 |
| [`src/symbolic_exec/constraint_extractor.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/e0992b567de69930ca1ea3b66b40fa126a6433dd/src/symbolic_exec/constraint_extractor.py) | verified | Use the build_semantic_evidence idea to turn scanner facts into cited evidence. | [`pulseguard/evidence.py`](../pulseguard/evidence.py) - exists | S1 |
| [`src/pipeline.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/e0992b567de69930ca1ea3b66b40fa126a6433dd/src/pipeline.py) | verified | Replace a single confidence cutoff with three score bands; per-path evidence informs adjudication. | [`pulseguard/agents/bands.py`](../pulseguard/agents/bands.py) - exists | S1 |
| [`src/taint_analysis/counterfactual.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/e0992b567de69930ca1ea3b66b40fa126a6433dd/src/taint_analysis/counterfactual.py) | verified | Planned original-versus-patched judgment consistency check inspired by counterfactual validation. | `pulseguard/falsify/counterfactual.py` - planned (S2) | S2 |
| [`src/ground_truth/extractor.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/e0992b567de69930ca1ea3b66b40fa126a6433dd/src/ground_truth/extractor.py) | verified | Planned extraction of Python vulnerability annotations for labelled evaluation. | `eval/labels.py` - planned (S3) | S3 |
| [`src/evaluation/metrics.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/e0992b567de69930ca1ea3b66b40fa126a6433dd/src/evaluation/metrics.py) | verified | Planned precision/recall/F1 and error-rate calculations for ablations. | `eval/` - planned (S3) | S3 |
| [`src/evaluation/reporter.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/e0992b567de69930ca1ea3b66b40fa126a6433dd/src/evaluation/reporter.py) | verified | Planned ablation report output; the eval directory is owned by separate work. | `eval/` - planned (S3) | S3 |
| [`scripts/run_pipeline.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/e0992b567de69930ca1ea3b66b40fa126a6433dd/scripts/run_pipeline.py) | verified | Optional future binary analysis recording only, with no binary-analysis runtime in this image. | [`replay/`](../replay/) - exists; binary example planned (ST-2) | ST-2 |
| [`tests/test_programs/command_injection.c`](https://github.com/witold-andelie/SymbAI-Taint/blob/e0992b567de69930ca1ea3b66b40fa126a6433dd/tests/test_programs/command_injection.c) | verified | Optional input for that recorded binary example; not the bundled Flask service. | [`replay/`](../replay/) - exists; binary example planned (ST-2) | ST-2 |
| [`src/taint_analysis/taint_engine_v2.py`](https://github.com/witold-andelie/SymbAI-Taint/blob/e0992b567de69930ca1ea3b66b40fa126a6433dd/src/taint_analysis/taint_engine_v2.py) | verified | Caveat inspection only: its symbolic filtering method retains paths; no filtering capability is attributed to PulseGuard. | [`pulseguard/evidence.py`](../pulseguard/evidence.py) - exists | S1 |

### PerpPulse

| Pre-existing source file | Source check | PulseGuard adaptation | Target and local status | Scope |
| --- | --- | --- | --- | --- |
| [`render.yaml`](https://github.com/witold-andelie/PerpPulse/blob/1acb5426eda2127d5a3c3557784057ded7d954dd/render.yaml) | verified | Use a Docker web service, health route, explicit mode and environment configuration. | [`render.yaml`](../render.yaml) - exists | S1 |
| [`Dockerfile`](https://github.com/witold-andelie/PerpPulse/blob/1acb5426eda2127d5a3c3557784057ded7d954dd/Dockerfile) | verified | Translate the slim non-root serving pattern from Rust to Python. | [`Dockerfile`](../Dockerfile) - exists | S1 |
| [`web/index.html`](https://github.com/witold-andelie/PerpPulse/blob/1acb5426eda2127d5a3c3557784057ded7d954dd/web/index.html) | verified | Adapt a no-build page into the security case board and detail views. | [`web/index.html`](../web/index.html) - exists | S1 |
| [`web/app.js`](https://github.com/witold-andelie/PerpPulse/blob/1acb5426eda2127d5a3c3557784057ded7d954dd/web/app.js) | verified | Adapt mode labels, unavailable-source handling and drill-down interactions. | [`web/app.js`](../web/app.js) - exists | S1 |
| [`web/style.css`](https://github.com/witold-andelie/PerpPulse/blob/1acb5426eda2127d5a3c3557784057ded7d954dd/web/style.css) | verified | Adapt static UI presentation to evidence, patches, policy and process views. | [`web/style.css`](../web/style.css) - exists | S1 |
| [`deploy/entrypoint.sh`](https://github.com/witold-andelie/PerpPulse/blob/1acb5426eda2127d5a3c3557784057ded7d954dd/deploy/entrypoint.sh) | verified | Translate PERPPULSE_SERVE_MODE-style selection into PG_MODE. | [`pulseguard/api.py`](../pulseguard/api.py) - exists | S1 |
| [`crates/perppulse/src/serve.rs`](https://github.com/witold-andelie/PerpPulse/blob/1acb5426eda2127d5a3c3557784057ded7d954dd/crates/perppulse/src/serve.rs) | verified | Separate recorded playback and live serving semantics. | [`pulseguard/api.py`](../pulseguard/api.py) - exists | S1 |
| `historical.rs` | not verified (root-relative shorthand) | The original design uses this basename shorthand. It is not a root file; the fully qualified source is verified in the next row. | [`pulseguard/api.py`](../pulseguard/api.py) - exists | S1 |
| [`crates/perppulse/src/historical.rs`](https://github.com/witold-andelie/PerpPulse/blob/1acb5426eda2127d5a3c3557784057ded7d954dd/crates/perppulse/src/historical.rs) | verified | Resolved historical-serving source: keep replay and fresh execution explicit. | [`pulseguard/api.py`](../pulseguard/api.py) - exists | S1 |
| [`.github/workflows/verify.yml`](https://github.com/witold-andelie/PerpPulse/blob/1acb5426eda2127d5a3c3557784057ded7d954dd/.github/workflows/verify.yml) | verified | Fold verification into the retained CI verify job. | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) - exists | S1 |
| [`crates/perppulse/src/live.rs`](https://github.com/witold-andelie/PerpPulse/blob/1acb5426eda2127d5a3c3557784057ded7d954dd/crates/perppulse/src/live.rs) | verified | Planned freshness/stall watcher and advice-only degradation. | `pulseguard/bus/watchdog.py` - planned (S2) | S2 |
| [`perppulse_opm.dot`](https://github.com/witold-andelie/PerpPulse/blob/1acb5426eda2127d5a3c3557784057ded7d954dd/perppulse_opm.dot) | verified | Diagram-authoring conventions informed the private design; this is a design reference, not a shipped runtime component. | [`docs/`](../docs/) - exists; private design reference only | design |
| [`deploy/application.ps1`](https://github.com/witold-andelie/PerpPulse/blob/1acb5426eda2127d5a3c3557784057ded7d954dd/deploy/application.ps1) | verified; source read again 1 November 2026 | Reimplement immutable image-digest validation and opt-in deployment in Bash; build with buildx, use replay settings and smoke-test both endpoints. No upstream account identifiers are reused. | [`deploy/gcp/deploy.sh`](../deploy/gcp/deploy.sh), [`deploy/gcp/bootstrap.sh`](../deploy/gcp/bootstrap.sh) - exists, not cloud-tested | ST-3 |
| [`deploy/foundation.ps1`](https://github.com/witold-andelie/PerpPulse/blob/1acb5426eda2127d5a3c3557784057ded7d954dd/deploy/foundation.ps1) | verified; source read again 1 November 2026 | Reimplement describe-before-create provisioning and separate identities; narrow secret, registry, service and actAs permissions. Add main-only GitHub WIF and a cumulative USD budget with a billing shutdown function. Exclude upstream SQL, evidence storage and password generation. | [`deploy/gcp/bootstrap.sh`](../deploy/gcp/bootstrap.sh) - exists, not cloud-tested | ST-3 |

## Built during the hackathon

Project-specific work present in this checkout includes the Finding/Verdict/PatchSet/Event
contracts, scanner normalization and evidence builder, adjudication/remediation role integration,
case graph with durable manual approval, scoped patch/sandbox/bundle workflow, case/event store,
verified replay serving, event-derived CSV/KPIs and the static security review UI. Those modules
adapt earlier patterns; they are not claims to have invented LangGraph, scanners or SQLite.

This infrastructure contribution adds `contracts/finding.avsc`, the optional
`pulseguard/bus/redpanda.py` transport, fake-client/Avro tests, local Compose configuration,
expanded scanner CI and these public submission documents. The `stream` dependency extra is
optional. Runner selection by `PG_BUS` is still planned: the current local LIVE runner constructs
`InMemoryBus` directly. Render retains that memory bus.

Absent targets in the tables remain planned, including separate verification/Skeptic, risk and
policy modules, counterfactual checking, rollback, evaluation output modules, binary replay,
cloud deployment scripts and MCP exposure. Their presence in a design map is not evidence of
completion. Existing UI placeholders do not change those statuses. No new model inference or
Docker execution is claimed by this documentation change. Docker is not running on this host.

Existing dependencies and platforms are credited separately from the team's adaptations:
LangGraph and its SQLite checkpointer, FastAPI/Uvicorn, Pydantic/jsonschema, the compatible model
SDK, SQLite, Semgrep, Bandit, Trivy, Redpanda/Console, confluent-kafka/librdkafka and fastavro.
The recorded model calls identify `muse-spark-1.3-contributor` through `opencode.ai`; model
training and the hosting service are not hackathon-authored components. PulseGuard's source
license does not replace third-party licenses.

## SymbAI-Taint filtering caveat

The verified `src/taint_analysis/taint_engine_v2.py::_filter_with_symbolic_results` implementation
retains the input paths, including when symbolic results are supplied. Its loop appends each path;
there is no implemented function-level pruning to credit. PulseGuard therefore attributes the
evidence-first judgment protocol, parsing approach, counterfactual idea and evaluation discipline,
not a working symbolic path-filtering engine. Evidence construction is not a claim of symbolic
execution or a proof that an exploit exists.

## Deliberately excluded components

| Pre-existing component or idea | Why it is outside the current system |
| --- | --- |
| quant-foundation-gat trained GAT and `data/warehouse/gat_equity.pt` | Equity-trained weights do not establish security risk accuracy. A future graph adapter needs suitable labelled security data; the planned deterministic risk seam does not imply a trained security model. |
| SymbAI-Taint angr, TYGR and GNN type recovery | These target binaries and require a separate, older numerical stack. The current target is Python; any future binary example would be a labelled recording rather than an added runtime. |
| SymbAI-Taint `lifecycle_tracker.py` | C allocation/free lifetime analysis is different from the security-case process log. PulseGuard events come from its tracer/store. |
| PerpPulse `scripts/check_repository_policy.py` | Repository text/local-file policy checks do not detect leaked credentials. No secret-scanning capability is inferred from them; current Trivy execution requests vulnerability scanning only. |
| PerpPulse Envio integration, Rust market ledger and PostgreSQL serving schema | Those implement another product's market-data domain. PulseGuard's small case store uses SQLite. PerpPulse itself is not a Kafka source. |
| tradepulse React application | The selected security UI is static HTML/CSS/JavaScript and needs no Node build. |
| Meterless H-MEM, RisingWave, Helm and Terraform | None is required by the implemented workflow or shipped infrastructure here. They are not presented as integrated features. |

quant-foundation-gat's broker is Redpanda speaking the Kafka API, not an Apache Kafka installation;
its sample messages are synthetic market data. PulseGuard defines its own security-finding topic
and contract. See [demo script](DEMO_SCRIPT.md) for the recorded/live presentation boundary.

Verification totals: **59 distinct source files verified** (55 via the original tree checks,
4 language-layer sources also checked in the pinned local revio clone), **1 literal source
path not verified**. The latter is PerpPulse's root-relative `historical.rs`;
`crates/perppulse/src/historical.rs` is verified. Every listed PulseGuard target was checked
for local existence.
