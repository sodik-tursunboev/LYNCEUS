# Data provenance: core/urls/data

## public_suffix_list.dat
| | |
|---|---|
| What | Public Suffix List (ICANN + PRIVATE sections), unmodified |
| Source | https://publicsuffix.org/list/public_suffix_list.dat |
| Retrieved | 2026-11-04 (HTTP 200, `Date: Wed, 04 Nov 2026 19:57:34 GMT`) |
| List version | `VERSION: 2026-11-04_19-07-29_UTC`, `COMMIT: aae37acca5d0f3d09e7c1fe4da9024c514674ac9` |
| Size | 338546 bytes |
| SHA-256 | `019fcc1daca33416846853ee1f3b99ea6cc6f03388ecd4ce3e5317039bcfd004` |
| License | Mozilla Public License 2.0 (header of the file; https://mozilla.org/MPL/2.0/) |
| Used by | `core/urls/psl.py`: registered domain, public suffix, shared-hosting detection |

Notes
- Bundled so nothing is fetched at runtime. The list goes stale as suffixes are added; refresh by replacing the file and updating this table (a test pins the hash, so a changed file fails until the hash is updated on purpose).
- The file is marked `-text` in `.gitattributes` so its bytes are never rewritten by line-ending conversion.
- The PRIVATE section lists multi-tenant hosts (github.io, blogspot.com, ...). Those are treated as suffixes, so `evil.github.io` is its own registered domain and never inherits `github.io`'s reputation.
