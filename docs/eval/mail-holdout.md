# Eval report (mail)

Split `holdout`, n=35. Engine `email-1.1.0`, ruleset `1.1.0+9790be320fdd`. 2026-11-05 02:57Z.

**Synthetic positives measure rule correctness, not the real-world detection rate.** The same author wrote the rules and the corpus, from shared templates.

| TP | FP | FN | TN | abstain (malicious / benign) | error (malicious / benign) |
|---|---|---|---|---|---|
| 22 | 0 | 0 | 0 | 0 / 13 | 0 / 0 |

| Metric | Value | Wilson 95% interval |
|---|---|---|
| Precision | 1.000 | 0.851 to 1.000 |
| Recall (abstentions are misses) | 1.000 | 0.851 to 1.000 |
| Recall (answered only) | 1.000 | |
| F1 | 1.000 | |
| Flag rate on benign (UNKNOWN is not flagged) | 0.000 | 0.000 to 0.228 |
| Abstain rate | 0.371 | 0.232 to 0.537 |
| Error rate | 0.000 | |

Latency per message (includes starting the sandbox): p50 353.915 ms, p95 1065.151 ms, max 1093.415 ms. Wall time on a shared development machine: the same code measured 1.4 ms and 14 ms p50 hours apart, so read it as an order of magnitude.

## Rules

Precision here is the share of a rule's hits on malicious samples. Weak rules are meant to be low: they only count in combination.

| Rule | Hits | Malicious | Benign | Precision | Wilson 95% interval |
|---|---|---|---|---|---|
| `email.archive_attachment` | 5 | 4 | 1 | 0.800 | 0.376 to 0.964 |
| `email.archive_contents_dangerous` | 3 | 3 | 0 | 1.000 | 0.439 to 1.000 |
| `email.attachment_type_mismatch` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.auth_failure` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `email.dangerous_attachment` | 4 | 4 | 0 | 1.000 | 0.510 to 1.000 |
| `email.display_name_brand` | 9 | 9 | 0 | 1.000 | 0.701 to 1.000 |
| `email.double_extension` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.hidden_link` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.html_attachment` | 3 | 3 | 0 | 1.000 | 0.439 to 1.000 |
| `email.html_smuggling` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.image_only_link` | 1 | 0 | 1 | 0.000 | 0.000 to 0.793 |
| `email.link_text_brand_mismatch` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.macro_attachment` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.malformed_mime` | 1 | 0 | 1 | 0.000 | 0.000 to 0.793 |
| `email.password_form` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `email.pdf_javascript` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.pdf_launch_action` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.qr_code_link` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.reply_to_mismatch` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.rtl_filename` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.script_content` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `email.sender.brand_in_domain` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `email.sender.brand_in_subdomain` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.sender.combosquat` | 4 | 4 | 0 | 1.000 | 0.510 to 1.000 |
| `email.social_engineering` | 4 | 4 | 0 | 1.000 | 0.510 to 1.000 |
| `url.brand_in_subdomain` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `url.combosquat` | 4 | 4 | 0 | 1.000 | 0.510 to 1.000 |
| `url.credential_bait` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `url.ip_literal` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `url.login_path` | 4 | 4 | 0 | 1.000 | 0.510 to 1.000 |
| `url.prefilled_identity` | 3 | 3 | 0 | 1.000 | 0.439 to 1.000 |

Rules with no hits on this split: `email.archive_bomb`, `email.archive_contains_macro`, `email.archive_double_extension`, `email.archive_encrypted`, `email.archive_nested`, `email.archive_traversal`, `email.file_inspection_incomplete`, `email.image_bomb`, `email.link_flood`, `email.link_text_mismatch`, `email.meta_refresh`, `email.multiple_from`, `email.parser_limits`, `email.pdf_embedded_file`, `email.pdf_encrypted`, `email.pdf_xfa`, `email.sender.homograph_brand`, `email.sender.mixed_script`, `email.sender.typosquat`, `url.brand_in_domain`, `url.dangerous_scheme`, `url.encoded_target`, `url.excessive_length`, `url.homograph_brand`, `url.host_shape`, `url.ip_obfuscated`, `url.mixed_script`, `url.odd_port`, `url.open_redirect`, `url.parser_tricks`, `url.shortener`, `url.typosquat`, `url.userinfo_deception`.

FN counts abstentions and errors on malicious samples (ADR-005). `n/a` means undefined (zero denominator).
