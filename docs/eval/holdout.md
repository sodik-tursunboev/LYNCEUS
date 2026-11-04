# Eval report

Split `holdout`, n=49. Engine `1.0.0`, ruleset `1.0.0+a01a3baf2dc5`. 2026-11-04 22:52Z.

**Synthetic positives measure rule correctness, not the real-world detection rate.** The same author wrote the rules and the corpus, from shared templates.

| TP | FP | FN | TN | abstain (malicious / benign) | error (malicious / benign) |
|---|---|---|---|---|---|
| 29 | 0 | 1 | 7 | 1 / 12 | 0 / 0 |

| Metric | Value | Wilson 95% interval |
|---|---|---|
| Precision | 1.000 | 0.883 to 1.000 |
| Recall (abstentions are misses) | 0.967 | 0.833 to 0.994 |
| Recall (answered only) | 1.000 | |
| F1 | 0.983 | |
| Flag rate on benign (UNKNOWN is not flagged) | 0.000 | 0.000 to 0.168 |
| Abstain rate | 0.265 | 0.162 to 0.403 |
| Error rate | 0.000 | |

Latency per URL: p50 18.697 ms, p95 44.365 ms, max 297.297 ms.

## Rules

Precision here is the share of a rule's hits on malicious samples. Weak rules are meant to be low: they only count in combination.

| Rule | Hits | Malicious | Benign | Precision | Wilson 95% interval |
|---|---|---|---|---|---|
| `url.brand_in_domain` | 1 | 0 | 1 | 0.000 | 0.000 to 0.793 |
| `url.brand_in_subdomain` | 3 | 3 | 0 | 1.000 | 0.439 to 1.000 |
| `url.combosquat` | 6 | 6 | 0 | 1.000 | 0.610 to 1.000 |
| `url.dangerous_scheme` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `url.encoded_target` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `url.homograph_brand` | 5 | 5 | 0 | 1.000 | 0.566 to 1.000 |
| `url.host_shape` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `url.ip_literal` | 3 | 2 | 1 | 0.667 | 0.208 to 0.939 |
| `url.ip_obfuscated` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `url.login_path` | 24 | 24 | 0 | 1.000 | 0.862 to 1.000 |
| `url.mixed_script` | 5 | 5 | 0 | 1.000 | 0.566 to 1.000 |
| `url.open_redirect` | 3 | 3 | 0 | 1.000 | 0.439 to 1.000 |
| `url.parser_tricks` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `url.prefilled_identity` | 5 | 5 | 0 | 1.000 | 0.566 to 1.000 |
| `url.shortener` | 2 | 1 | 1 | 0.500 | 0.095 to 0.905 |
| `url.typosquat` | 4 | 4 | 0 | 1.000 | 0.510 to 1.000 |
| `url.userinfo_deception` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |

Rules with no hits on this split: `url.credential_bait`, `url.excessive_length`, `url.odd_port`.

FN counts abstentions and errors on malicious samples (ADR-005). `n/a` means undefined (zero denominator).
