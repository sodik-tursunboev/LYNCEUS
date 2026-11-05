# Eval report (url)

Split `dev`, n=150. Engine `1.0.0`, ruleset `1.0.0+a01a3baf2dc5`. 2026-11-05 17:56Z.

**Synthetic positives measure rule correctness, not the real-world detection rate.** The same author wrote the rules and the corpus, from shared templates.

| TP | FP | FN | TN | abstain (malicious / benign) | error (malicious / benign) |
|---|---|---|---|---|---|
| 84 | 0 | 3 | 18 | 3 / 45 | 0 / 0 |

| Metric | Value | Wilson 95% interval |
|---|---|---|
| Precision | 1.000 | 0.956 to 1.000 |
| Recall (abstentions are misses) | 0.966 | 0.903 to 0.988 |
| Recall (answered only) | 1.000 | |
| F1 | 0.982 | |
| Flag rate on benign (UNKNOWN is not flagged) | 0.000 | 0.000 to 0.057 |
| Abstain rate | 0.320 | 0.251 to 0.398 |
| Error rate | 0.000 | |

Latency per URL: p50 0.891 ms, p95 1.535 ms, max 19.946 ms. Wall time on a shared development machine: the same code measured 1.4 ms and 14 ms p50 hours apart, so read it as an order of magnitude.

## Rules

Precision here is the share of a rule's hits on malicious samples. Weak rules are meant to be low: they only count in combination.

| Rule | Hits | Malicious | Benign | Precision | Wilson 95% interval |
|---|---|---|---|---|---|
| `url.brand_in_domain` | 2 | 1 | 1 | 0.500 | 0.095 to 0.905 |
| `url.brand_in_subdomain` | 8 | 8 | 0 | 1.000 | 0.676 to 1.000 |
| `url.combosquat` | 23 | 23 | 0 | 1.000 | 0.857 to 1.000 |
| `url.dangerous_scheme` | 3 | 3 | 0 | 1.000 | 0.439 to 1.000 |
| `url.encoded_target` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `url.excessive_length` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `url.homograph_brand` | 9 | 9 | 0 | 1.000 | 0.701 to 1.000 |
| `url.host_shape` | 2 | 1 | 1 | 0.500 | 0.095 to 0.905 |
| `url.ip_literal` | 10 | 7 | 3 | 0.700 | 0.397 to 0.892 |
| `url.ip_obfuscated` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `url.login_path` | 61 | 59 | 2 | 0.967 | 0.888 to 0.991 |
| `url.mixed_script` | 9 | 9 | 0 | 1.000 | 0.701 to 1.000 |
| `url.odd_port` | 3 | 3 | 0 | 1.000 | 0.439 to 1.000 |
| `url.open_redirect` | 13 | 13 | 0 | 1.000 | 0.772 to 1.000 |
| `url.parser_tricks` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `url.prefilled_identity` | 11 | 11 | 0 | 1.000 | 0.741 to 1.000 |
| `url.shortener` | 6 | 3 | 3 | 0.500 | 0.188 to 0.812 |
| `url.typosquat` | 13 | 13 | 0 | 1.000 | 0.772 to 1.000 |
| `url.userinfo_deception` | 9 | 9 | 0 | 1.000 | 0.701 to 1.000 |

Rules with no hits on this split: `url.credential_bait`.

FN counts abstentions and errors on malicious samples (ADR-005). `n/a` means undefined (zero denominator).
