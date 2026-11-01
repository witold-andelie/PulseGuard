# PulseGuard evaluation

Labelled sites: **67** (**33 vulnerable**, **34 safe**).

| Corpus | Sites | Vulnerable | Safe |
| --- | ---: | ---: | ---: |
| hard | 40 | 19 | 21 |
| original | 27 | 14 | 13 |
| combined | 67 | 33 | 34 |

| Mode | Status | TP | FP | FN | TN | Precision | Recall | F1 | FP rate | FN rate |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| semgrep | completed | 23 | 15 | 10 | 19 | 0.6053 | 0.6970 | 0.6479 | 0.4412 | 0.3030 |
| bandit | completed | 30 | 27 | 3 | 7 | 0.5263 | 0.9091 | 0.6667 | 0.7941 | 0.0909 |
| llm | completed | 30 | 1 | 3 | 33 | 0.9677 | 0.9091 | 0.9375 | 0.0294 | 0.0909 |
| neurosymbolic | completed | 30 | 3 | 3 | 31 | 0.9091 | 0.9091 | 0.9091 | 0.0882 | 0.0909 |

## Coverage and run details

Target: `demo_target`. Generated: 2026-11-01T11:07:02.689296+00:00.

- semgrep: 38 candidates; 0 model calls; 0 unusable replies.
- bandit: 65 candidates; 0 model calls; 0 unusable replies.
- llm: 75 candidates; 75 model calls; 0 unusable replies.
- neurosymbolic: 103 candidates; 103 model calls; 0 unusable replies.
- semgrep 1.183.0: 38 raw hits; 38 matched hits; 0 unlabelled/unmatched hits.
- bandit 1.9.4: 65 raw hits; 57 matched hits; 8 unlabelled/unmatched hits.

## Counts by class

| Class | Sites | Vulnerable | Safe |
| --- | ---: | ---: | ---: |
| dependency | 1 | 1 | 0 |
| prompt-injection | 1 | 1 | 0 |
| sqli | 65 | 31 | 34 |

### semgrep: confusion counts by class

| Class | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| dependency | 0 | 0 | 1 | 0 |
| prompt-injection | 0 | 0 | 1 | 0 |
| sqli | 23 | 15 | 8 | 19 |

### semgrep: confusion counts by corpus

| Corpus | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| hard | 12 | 11 | 7 | 10 |
| original | 11 | 4 | 3 | 9 |

### bandit: confusion counts by class

| Class | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| dependency | 0 | 0 | 1 | 0 |
| prompt-injection | 0 | 0 | 1 | 0 |
| sqli | 30 | 27 | 1 | 7 |

### bandit: confusion counts by corpus

| Corpus | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| hard | 18 | 16 | 1 | 5 |
| original | 12 | 11 | 2 | 2 |

### llm: confusion counts by class

| Class | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| dependency | 0 | 0 | 1 | 0 |
| prompt-injection | 0 | 0 | 1 | 0 |
| sqli | 30 | 1 | 1 | 33 |

### llm: confusion counts by corpus

| Corpus | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| hard | 18 | 1 | 1 | 20 |
| original | 12 | 0 | 2 | 13 |

### neurosymbolic: confusion counts by class

| Class | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| dependency | 0 | 0 | 1 | 0 |
| prompt-injection | 0 | 0 | 1 | 0 |
| sqli | 30 | 3 | 1 | 31 |

### neurosymbolic: confusion counts by corpus

| Corpus | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| hard | 18 | 2 | 1 | 19 |
| original | 12 | 1 | 2 | 12 |

Small, author-written set; these counts describe only this corpus. Do not generalise to production code or other vulnerability classes. Unlabelled scanner hits are audited separately, not counted as false positives.

Missing metrics mean **not run**, not zero. Zero denominators in completed rows yield 0.0. JSON includes site decisions, source hashes and configuration.
