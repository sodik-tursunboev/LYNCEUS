# Data provenance: tests/data/wpt

## urltestdata.subset.json
| | |
|---|---|
| What | Subset of the web-platform-tests URL parser test data |
| Source | https://github.com/web-platform-tests/wpt, `url/resources/urltestdata.json` |
| Source commit | `c48d58747e1f211527fb695fd60548a997fae617` (last commit touching the file, 2026-09-19) |
| Retrieved | 2026-11-04 |
| Upstream SHA-256 | `81e85fd3c199c08ef9c34cf651b3580eeedd080316493bfaf277a6b5ff8cf652` (229610 bytes) |
| Subset rule | Every test object with no base URL; only `input` and `href` or `failure` kept; comments dropped; order kept |
| Subset size | 560 of 896 cases |
| Subset SHA-256 | `eb39997494b5c4201a1bb957015f9940b0b6f691435b1571ecf39e812ccfe3c1` |
| License | 3-Clause BSD, copyright web-platform-tests contributors (`LICENSE.md`, copied verbatim from the same commit) |
| Used by | `tests/unit/test_urls_wpt.py` |

Cases with a base URL are left out because a URL analysed by Lynceus never has one.
