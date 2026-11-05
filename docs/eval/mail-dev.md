# Eval report (mail)

Split `dev`, n=119. Engine `email-1.1.0`, ruleset `1.1.0+9790be320fdd`. 2026-11-05 17:57Z.

**Synthetic positives measure rule correctness, not the real-world detection rate.** The same author wrote the rules and the corpus, from shared templates.

| TP | FP | FN | TN | abstain (malicious / benign) | error (malicious / benign) |
|---|---|---|---|---|---|
| 72 | 0 | 2 | 0 | 2 / 45 | 0 / 0 |

| Metric | Value | Wilson 95% interval |
|---|---|---|
| Precision | 1.000 | 0.949 to 1.000 |
| Recall (abstentions are misses) | 0.973 | 0.907 to 0.993 |
| Recall (answered only) | 1.000 | |
| F1 | 0.986 | |
| Flag rate on benign (UNKNOWN is not flagged) | 0.000 | 0.000 to 0.079 |
| Abstain rate | 0.395 | 0.312 to 0.485 |
| Error rate | 0.000 | |

Latency per message (includes starting the sandbox): p50 301.856 ms, p95 949.954 ms, max 1008.885 ms. Wall time on a shared development machine: the same code measured 1.4 ms and 14 ms p50 hours apart, so read it as an order of magnitude.

## Rules

Precision here is the share of a rule's hits on malicious samples. Weak rules are meant to be low: they only count in combination.

| Rule | Hits | Malicious | Benign | Precision | Wilson 95% interval |
|---|---|---|---|---|---|
| `email.archive_attachment` | 17 | 13 | 4 | 0.765 | 0.527 to 0.904 |
| `email.archive_bomb` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.archive_contains_macro` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.archive_contents_dangerous` | 8 | 8 | 0 | 1.000 | 0.676 to 1.000 |
| `email.archive_double_extension` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `email.archive_encrypted` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `email.archive_nested` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.attachment_type_mismatch` | 3 | 3 | 0 | 1.000 | 0.439 to 1.000 |
| `email.auth_failure` | 9 | 9 | 0 | 1.000 | 0.701 to 1.000 |
| `email.dangerous_attachment` | 11 | 11 | 0 | 1.000 | 0.741 to 1.000 |
| `email.display_name_brand` | 33 | 33 | 0 | 1.000 | 0.896 to 1.000 |
| `email.double_extension` | 3 | 3 | 0 | 1.000 | 0.439 to 1.000 |
| `email.hidden_link` | 3 | 3 | 0 | 1.000 | 0.439 to 1.000 |
| `email.html_attachment` | 7 | 7 | 0 | 1.000 | 0.646 to 1.000 |
| `email.html_smuggling` | 4 | 4 | 0 | 1.000 | 0.510 to 1.000 |
| `email.image_only_link` | 5 | 0 | 5 | 0.000 | 0.000 to 0.434 |
| `email.link_text_brand_mismatch` | 5 | 5 | 0 | 1.000 | 0.566 to 1.000 |
| `email.macro_attachment` | 3 | 3 | 0 | 1.000 | 0.439 to 1.000 |
| `email.malformed_mime` | 5 | 0 | 5 | 0.000 | 0.000 to 0.434 |
| `email.password_form` | 7 | 7 | 0 | 1.000 | 0.646 to 1.000 |
| `email.pdf_embedded_file` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `email.pdf_encrypted` | 1 | 0 | 1 | 0.000 | 0.000 to 0.793 |
| `email.pdf_javascript` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `email.pdf_launch_action` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `email.qr_code_link` | 7 | 5 | 2 | 0.714 | 0.359 to 0.918 |
| `email.reply_to_mismatch` | 3 | 3 | 0 | 1.000 | 0.439 to 1.000 |
| `email.rtl_filename` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `email.script_content` | 6 | 6 | 0 | 1.000 | 0.610 to 1.000 |
| `email.sender.brand_in_domain` | 6 | 6 | 0 | 1.000 | 0.610 to 1.000 |
| `email.sender.brand_in_subdomain` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `email.sender.combosquat` | 16 | 16 | 0 | 1.000 | 0.806 to 1.000 |
| `email.social_engineering` | 21 | 21 | 0 | 1.000 | 0.845 to 1.000 |
| `url.brand_in_domain` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `url.brand_in_subdomain` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `url.combosquat` | 16 | 16 | 0 | 1.000 | 0.806 to 1.000 |
| `url.credential_bait` | 2 | 2 | 0 | 1.000 | 0.342 to 1.000 |
| `url.dangerous_scheme` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `url.ip_literal` | 1 | 1 | 0 | 1.000 | 0.207 to 1.000 |
| `url.login_path` | 14 | 14 | 0 | 1.000 | 0.785 to 1.000 |
| `url.prefilled_identity` | 11 | 11 | 0 | 1.000 | 0.741 to 1.000 |

Rules with no hits on this split: `email.archive_traversal`, `email.file_inspection_incomplete`, `email.image_bomb`, `email.link_flood`, `email.link_text_mismatch`, `email.meta_refresh`, `email.multiple_from`, `email.parser_limits`, `email.pdf_xfa`, `email.sender.homograph_brand`, `email.sender.mixed_script`, `email.sender.typosquat`, `url.encoded_target`, `url.excessive_length`, `url.homograph_brand`, `url.host_shape`, `url.ip_obfuscated`, `url.mixed_script`, `url.odd_port`, `url.open_redirect`, `url.parser_tricks`, `url.shortener`, `url.typosquat`, `url.userinfo_deception`.

FN counts abstentions and errors on malicious samples (ADR-005). `n/a` means undefined (zero denominator).
