# Detection engine

`core/detection/engine.py`: URL string in, parsed URL, verdict and evidence out. Deterministic and offline. Decisions are in ADR-012 (parsing) and ADR-013 (verdicts and scoring); weights and thresholds are in `rules/url/scoring.toml`.

## Flow
1. `parse_url` normalises to what a browser would open, or returns a failure reason (UNKNOWN).
2. Every rule runs, in id order. A hit becomes a `Signal` plus an `Evidence` record.
3. `core/risk/scoring.py` combines signals: noisy-OR inside a category, capped, then noisy-OR across categories, 0 to 100.
4. State: MALICIOUS needs the malicious score and two independent strong categories. SUSPICIOUS needs the suspicious score. BENIGN needs an allowlisted official host and a low score. Everything else is UNKNOWN. An exception is ERROR.

## Rule catalog (`rules/url/`)
| Rule | Category | ATT&CK | Fires on |
|---|---|---|---|
| `url.ip_literal` | host | T1566.002 | IP address as host |
| `url.ip_obfuscated` | host | T1566.002 | decimal, hex, octal, short or IPv4-mapped forms |
| `url.userinfo_deception` | deception | T1566.002 | brand or domain-like text before `@` |
| `url.homograph_brand` | impersonation | T1566.002 | non-ASCII label with the UTS #39 skeleton of a brand |
| `url.mixed_script` | impersonation | T1566.002 | one label mixing alphabets |
| `url.typosquat` | impersonation | T1566.002 | brand name on an unofficial domain, lookalike digits, misspellings |
| `url.combosquat` | impersonation | T1566.002 | brand plus keyword in the registered label |
| `url.brand_in_domain` | impersonation | T1566.002 | brand in the label with no keyword (weak) |
| `url.brand_in_subdomain` | impersonation | T1566.002 | official domain or brand used as a subdomain |
| `url.shortener` | obfuscation | T1566.002 | known shortener; destination unknown, never enough alone |
| `url.open_redirect` | redirect | T1566.002 | redirect parameter pointing off-site |
| `url.encoded_target` | redirect | T1566.002 | base64 or double-encoded off-site URL in any parameter |
| `url.credential_bait` | credential | T1598.003 | brand and login word in the path or query, off the brand's domain |
| `url.prefilled_identity` | credential | T1598.003 | email address prefilled in an identity parameter |
| `url.login_path` | credential | T1598.003 | path ending in a login-style page (weak) |
| `url.dangerous_scheme` | scheme | T1204.001 | `javascript:`, `data:`, `vbscript:`, `file:`, `blob:` |
| `url.odd_port` | structure | T1566.002 | port outside the ordinary list |
| `url.excessive_length` | structure | T1566.002 | very long URL |
| `url.host_shape` | structure | T1566.002 | many hyphens or subdomain levels |
| `url.parser_tricks` | obfuscation | T1566.002 | backslashes, control or invisible characters, encoded hosts, double encoding |

## Adding a rule
1. Write a pure function in `rules/url/`: `ParsedUrl` in, a summary string or `None` out. Decorate it with `@rule(id, category, attack)`.
2. Summaries name facts, never the URL's path, query or credentials.
3. Add its weight to `scoring.toml`, and a category cap if the category is new.
4. Add at least one positive and one negative fixture to `corpus/rule_fixtures.toml`. Positives stay on reserved hosts.
5. Keep the work bounded: URLs reach 8192 characters and hosts can hold thousands of labels. `tests/unit/test_engine.py` has the hostile cases.
6. Tune on the dev split only. Any data or weight change alters `ruleset_version`.

## Limits
- No reputation, domain age, page content, redirect following, or JS and meta-refresh redirects. A fresh phishing domain with no brand or keyword is UNKNOWN.
- Shorteners stay UNKNOWN: the destination cannot be known offline.
- The brand list is unverified general knowledge and only covers listed brands.
- Rules and corpus share an author and templates, so dev scores measure rule correctness, not real-world detection.
