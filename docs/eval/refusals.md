# Why live pages refuse the sandbox (DA5 Phase 0b and 0d)

2026-11-22T20:29:56+00:00. Nothing was opened: this reads the pages D1 and DA1 kept (read only) and judges them with today's rules. Counts only, no addresses and no page text. Intervals are Wilson 95%. The halves are each run's own dev and test halves; `both` is their sum.

**Who is classified.** Every kept page that was refused (HTTP 4xx/5xx, or the sandbox could not load it) or showed under 200 characters of text. Each lands in the first class that fits, in this order: the sandbox's own proxy refusal (`refused: dns` and the like, a 403 that is not the site's; dns and connect count as takedown, the rest as other); a host or registrar notice (reported as phishing, suspended, removed, parked, for sale) is a **takedown**; a bot check (`just a moment`, captcha, `verify you are human`) is a **challenge**; HTTP 404, 410 or 521 to 523 is a **takedown**; HTTP 401, 403, 429, 451 or `access denied` text with no challenge is **blocked**; a page that loaded, shows under 200 characters and has no form is an **empty_stub**; a connection that failed before any page, with nothing kept, is **unknown_no_body**; the rest is **other**. Classes are phrase lists applied to the status, title, text and final host. There is no labelled truth set: they are a reading of the kept data, not ground truth.

## Run `d1`: 1098 pages kept, 638 classified

2 rows have no kept page and are not classified.

### Phishing (pages kept: dev 177, test 223, both 400; classified: dev 120, test 156, both 276)

| class | dev | test | both |
|---|---|---|---|
| takedown | 45.0% (36.4 to 53.9), 54 of 120 | 46.2% (38.5 to 54.0), 72 of 156 | 45.7% (39.9 to 51.5), 126 of 276 |
| challenge | 4.2% (1.8 to 9.4), 5 of 120 | 1.9% (0.7 to 5.5), 3 of 156 | 2.9% (1.5 to 5.6), 8 of 276 |
| blocked | 3.3% (1.3 to 8.3), 4 of 120 | 2.6% (1.0 to 6.4), 4 of 156 | 2.9% (1.5 to 5.6), 8 of 276 |
| empty_stub | 11.7% (7.1 to 18.6), 14 of 120 | 10.9% (6.9 to 16.8), 17 of 156 | 11.2% (8.0 to 15.5), 31 of 276 |
| other | 23.3% (16.7 to 31.7), 28 of 120 | 22.4% (16.6 to 29.6), 35 of 156 | 22.8% (18.3 to 28.1), 63 of 276 |
| unknown_no_body | 12.5% (7.7 to 19.6), 15 of 120 | 16.0% (11.1 to 22.6), 25 of 156 | 14.5% (10.8 to 19.1), 40 of 276 |
| *blocked + challenge* | 7.5% (4.0 to 13.6), 9 of 120 | 4.5% (2.2 to 9.0), 7 of 156 | 5.8% (3.6 to 9.2), 16 of 276 |

### Legitimate (pages kept: dev 329, test 371, both 700; classified: dev 159, test 203, both 362)

| class | dev | test | both |
|---|---|---|---|
| takedown | 32.7% (25.9 to 40.3), 52 of 159 | 25.1% (19.7 to 31.5), 51 of 203 | 28.5% (24.1 to 33.3), 103 of 362 |
| challenge | 5.0% (2.6 to 9.6), 8 of 159 | 3.9% (2.0 to 7.6), 8 of 203 | 4.4% (2.7 to 7.1), 16 of 362 |
| blocked | 9.4% (5.8 to 15.0), 15 of 159 | 12.8% (8.9 to 18.1), 26 of 203 | 11.3% (8.5 to 15.0), 41 of 362 |
| empty_stub | 4.4% (2.1 to 8.8), 7 of 159 | 4.4% (2.3 to 8.2), 9 of 203 | 4.4% (2.7 to 7.1), 16 of 362 |
| other | 9.4% (5.8 to 15.0), 15 of 159 | 3.9% (2.0 to 7.6), 8 of 203 | 6.4% (4.3 to 9.4), 23 of 362 |
| unknown_no_body | 39.0% (31.8 to 46.7), 62 of 159 | 49.8% (42.9 to 56.6), 101 of 203 | 45.0% (40.0 to 50.2), 163 of 362 |
| *blocked + challenge* | 14.5% (9.8 to 20.8), 23 of 159 | 16.7% (12.2 to 22.5), 34 of 203 | 15.7% (12.4 to 19.9), 57 of 362 |

### Detail inside each class (both halves)

| class / detail | phishing | legitimate |
|---|---|---|
| blocked/cloudflare_block | 3 | 3 |
| blocked/http_403 | 4 | 34 |
| blocked/http_403_no_body | 0 | 2 |
| blocked/http_451 | 0 | 1 |
| blocked/text | 1 | 1 |
| challenge/text | 6 | 2 |
| challenge/title | 2 | 14 |
| empty_stub/blank | 5 | 6 |
| empty_stub/short_text | 26 | 10 |
| other/http_400 | 1 | 3 |
| other/http_405 | 0 | 2 |
| other/http_406_no_body | 0 | 1 |
| other/http_412 | 0 | 1 |
| other/http_500 | 0 | 1 |
| other/http_503 | 2 | 1 |
| other/http_503_no_body | 2 | 0 |
| other/proxy_port | 1 | 0 |
| other/short_with_form | 57 | 14 |
| takedown/host_notice | 46 | 2 |
| takedown/host_notice+form | 48 | 2 |
| takedown/http_404 | 17 | 97 |
| takedown/http_410 | 0 | 1 |
| takedown/origin_down | 0 | 1 |
| takedown/proxy_connect | 1 | 0 |
| takedown/proxy_dns | 14 | 0 |
| unknown_no_body/connection_dropped | 0 | 6 |
| unknown_no_body/other_error | 0 | 9 |
| unknown_no_body/partial_blank | 4 | 4 |
| unknown_no_body/proxy_tunnel_failed | 21 | 129 |
| unknown_no_body/sandbox_timeout | 4 | 0 |
| unknown_no_body/tls_error | 11 | 15 |

Phone retry (desktop refused, phone then read): not measurable here. These pages were kept before DA1 and before the retry existed (H1 C5).

### Pages that answered HTTP 403 (the refusal most often named), by class

|  | phish dev | phish test | phish both | legit dev | legit test | legit both |
|---|---|---|---|---|---|---|
| all 403 answers | 50 | 65 | 115 | 22 | 31 | 53 |
| takedown | 47 | 60 | 107 | 0 | 0 | 0 |
| challenge | 0 | 0 | 0 | 8 | 6 | 14 |
| blocked | 3 | 4 | 7 | 14 | 25 | 39 |
| empty_stub | 0 | 0 | 0 | 0 | 0 | 0 |
| other | 0 | 1 | 1 | 0 | 0 | 0 |
| unknown_no_body | 0 | 0 | 0 | 0 | 0 | 0 |

### 0d: would the automatic opener have opened the page-only catches?

|  | dev | test | both |
|---|---|---|---|
| page-only catches (phishing, alive, flagged with the page, not by the address) | 8 | 7 | 15 |
| would pass `worth_opening` | 1 | 0 | 1 |
| would fail | 7 | 7 | 14 |
| cannot tell | 0 | 0 | 0 |

Why the fails fail (`worth_opening` needs SUSPICIOUS, or UNKNOWN with a sign, off the official and popular hosts): UNKNOWN with no sign 13, official or popular host 1

## Run `da1`: 1000 pages kept, 608 classified

### Phishing (pages kept: dev 217, test 183, both 400; classified: dev 180, test 159, both 339)

| class | dev | test | both |
|---|---|---|---|
| takedown | 65.6% (58.4 to 72.1), 118 of 180 | 59.7% (52.0 to 67.1), 95 of 159 | 62.8% (57.6 to 67.8), 213 of 339 |
| challenge | 0.0% (0.0 to 2.1), 0 of 180 | 1.3% (0.3 to 4.5), 2 of 159 | 0.6% (0.2 to 2.1), 2 of 339 |
| blocked | 0.6% (0.1 to 3.1), 1 of 180 | 1.3% (0.3 to 4.5), 2 of 159 | 0.9% (0.3 to 2.6), 3 of 339 |
| empty_stub | 4.4% (2.3 to 8.5), 8 of 180 | 5.7% (3.0 to 10.4), 9 of 159 | 5.0% (3.2 to 7.9), 17 of 339 |
| other | 12.2% (8.2 to 17.8), 22 of 180 | 12.6% (8.3 to 18.6), 20 of 159 | 12.4% (9.3 to 16.3), 42 of 339 |
| unknown_no_body | 17.2% (12.4 to 23.4), 31 of 180 | 19.5% (14.1 to 26.3), 31 of 159 | 18.3% (14.5 to 22.8), 62 of 339 |
| *blocked + challenge* | 0.6% (0.1 to 3.1), 1 of 180 | 2.5% (1.0 to 6.3), 4 of 159 | 1.5% (0.6 to 3.4), 5 of 339 |

### Legitimate (pages kept: dev 293, test 307, both 600; classified: dev 131, test 138, both 269)

| class | dev | test | both |
|---|---|---|---|
| takedown | 22.1% (15.9 to 30.0), 29 of 131 | 15.9% (10.8 to 23.0), 22 of 138 | 19.0% (14.7 to 24.1), 51 of 269 |
| challenge | 6.9% (3.7 to 12.5), 9 of 131 | 5.8% (3.0 to 11.0), 8 of 138 | 6.3% (4.0 to 9.9), 17 of 269 |
| blocked | 9.2% (5.3 to 15.3), 12 of 131 | 14.5% (9.6 to 21.3), 20 of 138 | 11.9% (8.6 to 16.3), 32 of 269 |
| empty_stub | 6.9% (3.7 to 12.5), 9 of 131 | 7.2% (4.0 to 12.8), 10 of 138 | 7.1% (4.6 to 10.8), 19 of 269 |
| other | 9.2% (5.3 to 15.3), 12 of 131 | 6.5% (3.5 to 11.9), 9 of 138 | 7.8% (5.2 to 11.6), 21 of 269 |
| unknown_no_body | 45.8% (37.5 to 54.3), 60 of 131 | 50.0% (41.8 to 58.2), 69 of 138 | 48.0% (42.1 to 53.9), 129 of 269 |
| *blocked + challenge* | 16.0% (10.7 to 23.3), 21 of 131 | 20.3% (14.4 to 27.8), 28 of 138 | 18.2% (14.1 to 23.3), 49 of 269 |

### Detail inside each class (both halves)

| class / detail | phishing | legitimate |
|---|---|---|
| blocked/cloudflare_block | 2 | 4 |
| blocked/http_401 | 0 | 1 |
| blocked/http_403 | 1 | 24 |
| blocked/http_403_no_body | 0 | 1 |
| blocked/http_451 | 0 | 2 |
| challenge/text | 2 | 0 |
| challenge/title | 0 | 17 |
| empty_stub/blank | 6 | 6 |
| empty_stub/short_text | 11 | 13 |
| other/http_400 | 0 | 2 |
| other/http_500 | 1 | 1 |
| other/http_502 | 0 | 1 |
| other/http_503 | 0 | 3 |
| other/http_520 | 0 | 1 |
| other/proxy_private_address | 22 | 3 |
| other/short_with_form | 19 | 10 |
| takedown/host_notice | 146 | 0 |
| takedown/host_notice+form | 56 | 1 |
| takedown/http_404 | 9 | 49 |
| takedown/origin_down | 0 | 1 |
| takedown/proxy_dns | 2 | 0 |
| unknown_no_body/connection_dropped | 1 | 1 |
| unknown_no_body/other_error | 0 | 3 |
| unknown_no_body/partial_blank | 0 | 1 |
| unknown_no_body/proxy_tunnel_failed | 50 | 92 |
| unknown_no_body/sandbox_timeout | 2 | 11 |
| unknown_no_body/tls_error | 9 | 21 |

Pages the desktop visit was refused and the phone visit then read: phishing 0.0% (0.0 to 1.0), 0 of 400; legitimate 0.3% (0.1 to 1.2), 2 of 600.

### Pages that answered HTTP 403 (the refusal most often named), by class

|  | phish dev | phish test | phish both | legit dev | legit test | legit both |
|---|---|---|---|---|---|---|
| all 403 answers | 122 | 101 | 223 | 22 | 26 | 48 |
| takedown | 108 | 90 | 198 | 0 | 0 | 0 |
| challenge | 0 | 0 | 0 | 8 | 8 | 16 |
| blocked | 1 | 2 | 3 | 11 | 18 | 29 |
| empty_stub | 0 | 0 | 0 | 0 | 0 | 0 |
| other | 13 | 9 | 22 | 3 | 0 | 3 |
| unknown_no_body | 0 | 0 | 0 | 0 | 0 | 0 |

### 0d: would the automatic opener have opened the page-only catches?

|  | dev | test | both |
|---|---|---|---|
| page-only catches (phishing, alive, flagged with the page, not by the address) | 4 | 4 | 8 |
| would pass `worth_opening` | 1 | 1 | 2 |
| would fail | 3 | 3 | 6 |
| cannot tell | 0 | 0 | 0 |

Why the fails fail (`worth_opening` needs SUSPICIOUS, or UNKNOWN with a sign, off the official and popular hosts): UNKNOWN with no sign 5, official or popular host 1

## What the kept data cannot say

- `proxy_tunnel_failed` (HTTPS): Chrome reports only that the sandbox's proxy could not connect. The proxy's reason (name does not resolve, nothing answered, a private address or an odd port) is hidden, so those pages stay `unknown_no_body`. On plain http the reason is visible (`proxy_dns`, `proxy_connect`, `proxy_<other>` in the detail table): the only evidence for how the hidden ones might split.
- A host notice is the host's warning, not proof the page behind it is gone. The kept page does not show whether a continue button leads to a live page (`+form` only says the notice carries some form).
- `blocked` is a refusal with no challenge text. Whether it is the sandbox's fingerprint, its region, its address range or a block of every visitor needs a second visit from elsewhere; the kept data holds at most one phone retry.
- A challenge that drew no text, or a page waiting for a script, reads as `empty_stub` or `unknown_no_body`.
- Pages that loaded and showed 200 characters or more are not examined, so a long parked page is not counted.
- 0d assumes the address verdict without the feeds (every address here is on a feed), a link that arrives through an enabled channel (browser or mail), today's rules and today's popular-domain list.
