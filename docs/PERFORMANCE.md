# Performance (measured, not promised)

Measured 2026-11-05 18:14 UTC on: Windows-11-10.0.26300-SP0, 12 logical CPUs, Python 3.14.7.
Wall-clock times on a shared development machine: an order of magnitude. Regenerate with `python -m eval.perf --write`.

## URL engine, in process (ms per URL)

- n 60, p50 9.159 ms, p95 11.417 ms, max 49.346 ms

## URL engine note

each sample is 12 URLs; divide by 12 for one

## message engine through the sandbox (ms per message)

| case | n | p50 | p95 | max |
|---|---|---|---|---|
| plain | 30 | 313.916 | 364.127 | 380.749 |
| html_links | 30 | 349.773 | 400.851 | 401.735 |
| attachment | 30 | 698.595 | 768.616 | 869.97 |

## file engine through the sandbox (ms per file)

| case | n | p50 | p95 | max |
|---|---|---|---|---|
| 1 KB text | 30 | 197.166 | 211.56 | 212.237 |
| 1 MiB random | 30 | 188.707 | 204.646 | 213.532 |
| small PDF | 30 | 458.164 | 499.237 | 572.842 |
| zip with 20 entries | 30 | 265.489 | 288.83 | 302.277 |
| 8 MiB random | 30 | 210.81 | 231.416 | 240.022 |

## API, 8 concurrent clients, URL analysis, no database

- workers: 8
- requests: 2789
- failures: 0
- requests_per_second: 278.9
- p50: 27.5
- p95: 44.032
- max: 235.589

## sizes

- console bundle (bytes): 617624
- extension service worker (bytes): 13837

