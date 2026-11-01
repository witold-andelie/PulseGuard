# Ablation results

Real runs, not projections. Each row comes from a committed JSON/Markdown report in this folder or
from the run named in the commit history. The corpus is small and author-written (27 original + 40
hard sites); see `eval/README.md` for how it was built and its sources. Report counts, do not
generalise.

Models: **Meta Muse Spark 1.3** (primary, via opencode) and **NVIDIA Nemotron 3 Ultra** (control,
via NVIDIA NIM, thinking enabled, structured output off). Semgrep 1.183.0 and Bandit 1.9.4.

## Three rounds

| Round | Corpus | Mode | Muse F1 (FP) | Nemotron F1 (FP) |
| --- | --- | --- | --- | --- |
| 1 Baseline | original, 27 | Semgrep | 0.76 (4) | 0.76 (4) |
| | | Bandit | 0.65 (11) | 0.65 (11) |
| | | LLM-only | 0.92 (0) | 0.92 (0) |
| | | Neuro-symbolic | 0.92 (0) | **0.89 (1)** |
| 2 One-hop context | original + hard, 67 | Semgrep | 0.65 (15) | 0.65 (15) |
| | | Bandit | 0.67 (27) | 0.67 (27) |
| | | LLM-only | 0.95 (0) | 0.94 (1) |
| | | Neuro-symbolic | 0.95 (0) | **0.91 (3)** |
| 3 True hard evidence | original + hard, 67 | Semgrep | 0.65 (15) | 0.65 (15) |
| | | Bandit | 0.67 (27) | 0.67 (27) |
| | | LLM-only | **0.95 (0)** | **0.95 (0)** |
| | | Neuro-symbolic | **0.95 (0)** | **0.95 (0)\*** |

Files: round 1 `baseline-muse.*`, `baseline-nemotron.*`; round 3 `all-muse.*`, `all-nemotron.*`;
deterministic modes per corpus in `original-/hard-/all-deterministic.*`.

## What changed between rounds, and why

- **Round 1 → 2.** Nemotron's neuro-symbolic false positive on a finite allow-list came from our own
  E3 claiming "no allow-list" when the builder simply did not recognise that guard. E3 now says "none
  recognised" and lists what was checked as an analysis limit; allow-lists, Enums and one-hop helper
  casts are recognised; the model sees the sink function plus referenced same-module definitions.
- **Round 2 → 3.** Nemotron's three neuro-symbolic false positives each traced to false hard
  evidence: a `float()` around the source not recognised, a numeric z3 question that counted a
  trailing newline as a bypass, and a Bandit-derived trace that named `try:` as the source. Hard
  evidence is now confirmed against the code line by line; unconfirmable facts become analysis limits.
- Muse Spark was not misled by any of these evidence defects; Nemotron was. The defects were ours.

## Honest reading

- On this corpus the neuro-symbolic mode **ties** LLM-only (F1 0.95, zero false positives for both
  models in round 3). It does not raise the score here. Its value is that every confirmed verdict rests
  on checked facts, can be falsified (Verifying, counterfactual, PoC, z3 veto) and leaves an audit
  trail; when the evidence was wrong, it made a model worse, which is why round 3 exists.
- Pattern tools stay far behind on the hard corpus (Semgrep F1 0.57 there, Bandit 27 false positives
  overall).
- The three false negatives in every LLM row are: `two_hop` (two helper hops; the excerpt follows one;
  Nemotron's LLM-only row misses `regex_match_prefix` instead) and the dependency and
  prompt-injection labels, which the adjudicator does not own — the deterministic dependency path and
  the guard handle them in the full pipeline (see the recorded REPLAY run).

\* **Nemotron round 3, neuro-symbolic:** 9 of 103 model calls failed (7 NVIDIA rate-limit errors,
2 internal server errors). Failed calls become `uncertain` (human review), the governed behaviour.
Three safe sites (`integer_percent`, `integer_used`, `positional_binding`) were decided only by failed
calls, so they count as "not flagged" without a model judgement; read Nemotron's round-3
neuro-symbolic row with that in mind. Muse Spark had no failed calls in any round.
