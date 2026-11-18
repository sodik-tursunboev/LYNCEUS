# False alarms on legitimate addresses with paths and queries (DA2)

2026-11-17 15:10Z. 1,640 archived pages of 358 public domains (498 with a query string), sampled from four Tranco rank bands. Seed `lynceus-da2-deeplinks`. Rules may be tuned only by looking at dev; test is read once. Counts only (the addresses stay in .data/eval/deeplinks). Intervals are Wilson 95%. Archived pages include some junk even from good domains, so a few flags may be real junk, not false alarms.

## as the product runs (popular list on)

| set | flagged (SUSPICIOUS or MALICIOUS) |
|---|---|
| dev | 2.51% (1.61 to 3.89), 19 of 757 |
| test | 2.27% (1.47 to 3.47), 20 of 883 |
| all | 2.38% (1.74 to 3.23), 39 of 1640 |

| rank band (all) | flagged |
|---|---|
| rank 1 to 1,000 | 3.53% (1.87 to 6.57), 9 of 255 |
| rank 1,001 to 10,000 | 2.42% (1.32 to 4.39), 10 of 414 |
| rank 10,001 to 100,000 | 0.67% (0.23 to 1.95), 3 of 449 |
| rank 100,001 to 1,000,000 | 3.26% (2.04 to 5.15), 17 of 522 |

Rules on the flagged addresses (all): `url.learned_domain` 22, `url.credential_bait` 9, `url.open_redirect` 6, `url.brand_in_subdomain` 4, `url.host_shape` 2, `url.login_path` 2

## as an unknown site (list off)

| set | flagged (SUSPICIOUS or MALICIOUS) |
|---|---|
| dev | 3.83% (2.68 to 5.45), 29 of 757 |
| test | 3.40% (2.39 to 4.81), 30 of 883 |
| all | 3.60% (2.80 to 4.61), 59 of 1640 |

| rank band (all) | flagged |
|---|---|
| rank 1 to 1,000 | 5.49% (3.30 to 9.00), 14 of 255 |
| rank 1,001 to 10,000 | 4.83% (3.15 to 7.34), 20 of 414 |
| rank 10,001 to 100,000 | 1.78% (0.91 to 3.48), 8 of 449 |
| rank 100,001 to 1,000,000 | 3.26% (2.04 to 5.15), 17 of 522 |

Rules on the flagged addresses (all): `url.learned_domain` 27, `url.typosquat` 15, `url.credential_bait` 9, `url.open_redirect` 6, `url.brand_in_subdomain` 4, `url.host_shape` 2, `url.login_path` 2
