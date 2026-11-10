# The URL engine on real data (E1)

2026-11-10 13:29Z. Engine 1.0.0, ruleset 1.0.0+960efe1e20f7. 299,460 URLs (train and test splits; the reserve split, about 10%, is sealed). Every URL was parsed as text only: none was opened. Sources and licences: `.data/eval/sources.json`. Intervals are Wilson 95%.

**Real data, not written by this project.** UNKNOWN counts as a miss, never as safe.

## Phishing caught (SUSPICIOUS or MALICIOUS)

| Set | Caught |
|---|---|
| all | 2.5% (2.4 to 2.6), n=133,195 |
| fresh feeds | 3.2% (3.1 to 3.4), n=42,721 |
| historical phiusiil | 2.2% (2.1 to 2.3), n=90,474 |
| on home pages | 1.4% (1.4 to 1.5), n=76,492 |
| with a path | 4.0% (3.8 to 4.1), n=56,703 |
| malicious | 0.2% (0.2 to 0.2), n=133,195 |

## False alarms on legitimate URLs

| Set | Flagged |
|---|---|
| all | 0.3% (0.3 to 0.3), n=166,265 |
| home pages | 0.3% (0.3 to 0.3), n=166,181 |
| with a path | 9.5% (4.9 to 17.7), n=84 |

Rules behind the false alarms on legitimate URLs with a path: `url.login_path` 5, `url.parser_tricks` 5, `url.open_redirect` 3.

## By source

| Source | Label | n | Result |
|---|---|---|---|
| edge_history legit | legit | 87 | 9.2% (4.7 to 17.1), n=87 |
| openphish phish | phish | 266 | 22.9% (18.3 to 28.3), n=266 |
| phishtank phish | phish | 42,455 | 3.1% (2.9 to 3.3), n=42,455 |
| phiusiil legit | legit | 121,258 | 0.1% (0.1 to 0.1), n=121,258 |
| phiusiil phish | phish | 90,474 | 2.2% (2.1 to 2.3), n=90,474 |
| tranco legit | legit | 44,920 | 0.9% (0.8 to 1.0), n=44,920 |

## The lexical ceiling

- Real phishing URLs on which **no URL rule fires at all**: 91.2% (91.0 to 91.3), n=133,195. Reading the address cannot catch these; only looking at the page (or a list) can.
- Rules fired but too weakly to flag: 6.3% (6.2 to 6.5), n=133,195.

## Phishing by kind of host

| Host | n | Caught | No rule fired |
|---|---|---|---|
| own domain | 84,106 | 2.9% (2.8 to 3.0), n=84,106 | 93.5% (93.3 to 93.6), n=84,106 |
| platform | 41,461 | 1.1% (1.0 to 1.2), n=41,461 | 92.9% (92.7 to 93.2), n=41,461 |
| shortener | 6,860 | 0.2% (0.1 to 0.4), n=6,860 | 60.4% (59.3 to 61.6), n=6,860 |
| ip address | 611 | 73.7% (70.0 to 77.0), n=611 | 0.0% (0.0 to 0.6), n=611 |
| punycode | 157 | 7.6% (4.4 to 12.9), n=157 | 90.5% (84.8 to 94.1), n=157 |

## Rules on real data

| Rule | On phishing | On legitimate | Phishing hit rate | Legitimate hit rate |
|---|---|---|---|---|
| `url.shortener` | 2,715 | 17 | 0.0204 | 0.0001 |
| `url.brand_in_domain` | 1,794 | 567 | 0.0135 | 0.0034 |
| `url.host_shape` | 2,204 | 21 | 0.0165 | 0.0001 |
| `url.login_path` | 2,111 | 7 | 0.0158 | 0.0 |
| `url.typosquat` | 365 | 495 | 0.0027 | 0.003 |
| `url.open_redirect` | 852 | 3 | 0.0064 | 0.0 |
| `url.credential_bait` | 824 | 0 | 0.0062 | 0.0 |
| `url.brand_in_subdomain` | 776 | 3 | 0.0058 | 0.0 |
| `url.ip_literal` | 611 | 0 | 0.0046 | 0.0 |
| `url.combosquat` | 297 | 5 | 0.0022 | 0.0 |
| `url.prefilled_identity` | 278 | 0 | 0.0021 | 0.0 |
| `url.parser_tricks` | 34 | 5 | 0.0003 | 0.0 |
| `url.userinfo_deception` | 14 | 0 | 0.0001 | 0.0 |
| `url.odd_port` | 13 | 0 | 0.0001 | 0.0 |
| `url.excessive_length` | 9 | 3 | 0.0001 | 0.0 |
| `url.encoded_target` | 7 | 0 | 0.0001 | 0.0 |
| `url.mixed_script` | 4 | 1 | 0.0 | 0.0 |

## Fitted weights (phase B)

Method: coordinate search over each rule's weight (0.05 to 0.95), thresholds, caps and the two-category rule unchanged; objective: recall on train without more false alarms on train than today's weights.

| On the test split | Caught | False alarms |
|---|---|---|
| hand-set weights | 2.5% (2.4 to 2.7), n=44,257 | 0.3% (0.3 to 0.4), n=55,630 |
| fitted weights | 2.7% (2.5 to 2.8), n=44,257 | 0.3% (0.3 to 0.4), n=55,630 |

Changed: `url.ip_literal` 0.3 to 0.45.
Adopt: **no** (fitted recall interval entirely above today's, and false alarms not worse).
