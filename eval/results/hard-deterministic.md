# PulseGuard evaluation

Labelled sites: **40** (**19 vulnerable**, **21 safe**).

| Corpus | Sites | Vulnerable | Safe |
| --- | ---: | ---: | ---: |
| hard | 40 | 19 | 21 |

| Mode | Status | TP | FP | FN | TN | Precision | Recall | F1 | FP rate | FN rate |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| semgrep | completed | 12 | 11 | 7 | 10 | 0.5217 | 0.6316 | 0.5714 | 0.5238 | 0.3684 |
| bandit | completed | 18 | 16 | 1 | 5 | 0.5294 | 0.9474 | 0.6792 | 0.7619 | 0.0526 |

## Coverage and run details

Target: `demo_target`. Generated: 2026-11-01T07:30:13.839359+00:00.

- semgrep: 23 candidates; 0 model calls; 0 unusable replies.
- bandit: 35 candidates; 0 model calls; 0 unusable replies.
- semgrep 1.183.0: 23 raw hits; 23 matched hits; 0 unlabelled/unmatched hits.
- bandit 1.9.4: 35 raw hits; 34 matched hits; 1 unlabelled/unmatched hits.

## Counts by class

| Class | Sites | Vulnerable | Safe |
| --- | ---: | ---: | ---: |
| sqli | 40 | 19 | 21 |

### semgrep: confusion counts by class

| Class | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| sqli | 12 | 11 | 7 | 10 |

### semgrep: confusion counts by corpus

| Corpus | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| hard | 12 | 11 | 7 | 10 |

### bandit: confusion counts by class

| Class | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| sqli | 18 | 16 | 1 | 5 |

### bandit: confusion counts by corpus

| Corpus | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| hard | 18 | 16 | 1 | 5 |

Small, author-written set; these counts describe only this corpus. Do not generalise to production code or other vulnerability classes. Unlabelled scanner hits are audited separately, not counted as false positives.

Missing metrics mean **not run**, not zero. Zero denominators in completed rows yield 0.0. JSON includes site decisions, source hashes and configuration.
