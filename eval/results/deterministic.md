# PulseGuard evaluation

Labelled sites: **27** (**14 vulnerable**, **13 safe**).

| Mode | Status | TP | FP | FN | TN | Precision | Recall | F1 | FP rate | FN rate |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| semgrep | completed | 11 | 4 | 3 | 9 | 0.7333 | 0.7857 | 0.7586 | 0.3077 | 0.2143 |
| bandit | completed | 12 | 11 | 2 | 2 | 0.5217 | 0.8571 | 0.6486 | 0.8462 | 0.1429 |

## Coverage and run details

Target: `demo_target`. Generated: 2026-10-31T21:16:54.586649+00:00.

- semgrep: 15 candidates; 0 model calls; 0 unusable replies.
- bandit: 34 candidates; 0 model calls; 0 unusable replies.
- semgrep 1.183.0: 15 raw hits; 15 matched hits; 0 unlabelled/unmatched hits.
- bandit 1.9.4: 34 raw hits; 23 matched hits; 11 unlabelled/unmatched hits.

## Counts by class

| Class | Sites | Vulnerable | Safe |
| --- | ---: | ---: | ---: |
| dependency | 1 | 1 | 0 |
| prompt-injection | 1 | 1 | 0 |
| sqli | 25 | 12 | 13 |

### semgrep: confusion counts by class

| Class | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| dependency | 0 | 0 | 1 | 0 |
| prompt-injection | 0 | 0 | 1 | 0 |
| sqli | 11 | 4 | 1 | 9 |

### bandit: confusion counts by class

| Class | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| dependency | 0 | 0 | 1 | 0 |
| prompt-injection | 0 | 0 | 1 | 0 |
| sqli | 12 | 11 | 0 | 2 |

Small, author-written set; these counts describe only this corpus. Do not generalise to production code or other vulnerability classes. Unlabelled scanner hits are audited separately, not counted as false positives.

Missing metrics mean **not run**, not zero. Zero denominators in completed rows yield 0.0. JSON includes site decisions, source hashes and configuration.
