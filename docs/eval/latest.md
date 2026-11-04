# Eval report

Engine `stub-0` | split `all` | n=30 | 2026-11-04 20:36Z

| TP | FP | FN | TN | abstain (pos/neg) | error (pos/neg) |
|---|---|---|---|---|---|
| 0 | 0 | 19 | 0 | 19/11 | 0/0 |

| precision | recall | recall (answered only) | F1 | abstain rate | error rate |
|---|---|---|---|---|---|
| n/a | 0.000 | n/a | 0.000 | 1.000 | 0.000 |

Latency: p50 0.006 ms, p95 0.012 ms, max 0.036 ms.

FN counts abstentions and errors on positive samples (ADR-005). `n/a` = undefined (zero denominator). Small corpus: treat as a pipeline check, not a quality claim.
