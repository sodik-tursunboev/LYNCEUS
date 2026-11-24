# Investigate: the evidence dossier (DA5 1a)

```
python -m core.cli investigate <target> [--json] [--html FILE] [--page-report FILE]
```

`<target>` is a web address, the path of an `.eml` (a message, parsed in the sandbox), or the path of
any other file (opened in the sandbox, never run). The command is offline: it opens no socket and
calls no provider. It runs the engine's own analysis (`analyze_url`, `analyze_message`,
`analyze_file`) and adds what explains it. The verdict state and score in a dossier are the engine's,
unchanged; a test checks that on a fixed set of addresses and one development-split corpus address
per category.

Exit code: 0, 1 if the engine's verdict is ERROR, 2 for an unreadable file or page report.

## Output

`--json` prints one object with exactly these keys, in this order: `target`, `engine`, `verdict`,
`sections`, `attribution`, `counterfactuals`, `limits`. `--html FILE` also writes one self-contained
HTML file (no script, nothing loaded, every string escaped; a content security policy forbids both).
Without `--json` a text dossier is printed. Control and invisible characters in hostile text
(terminal escapes, bidi overrides) are shown as `<U+XXXX>` in text and HTML; JSON is pure ASCII.

`sections` holds the same nine names for a web address, a message and a file, each as
`{status, note, facts}`: `anatomy`, `learned`, `established`, `redirect_chain`, `domain`, `fetch`,
`page`, `brand`, `intel`. A status is `ok`, `not applicable` (the section does not fit this input),
`not asked (offline)` (it would need the network or Docker) or `not available` (a needed part is
missing, such as the model weights or a parsed message).

| section | web address | message | file |
|---|---|---|---|
| anatomy | scheme, userinfo, host kind, registered domain, subdomain labels, path, query key names (not values), port, parser flags (IDN, punycode, ...) | parts, attachments, each link with its address verdict, each attachment's facts | name, size, hashes, what was found inside |
| learned | the registered-domain model's probability, threshold, the tokens that pushed it, whether it fired | n/a | n/a |
| established | popular list, brand official domain, shared hosting, the engine's allowlist test | n/a | n/a |
| redirect_chain, domain | not asked | not asked | n/a |
| fetch | from `--page-report` | not asked | n/a |
| page | the page rules' signals, judged from `--page-report` by the existing judge | n/a | n/a |
| brand | the page's own title and headings against the brand list (text only) | n/a | n/a |
| intel | not asked | not asked | the known-bad hash lists on this machine |

`--page-report FILE` is a saved page report: the `PageReport` JSON the detonator returns (the pages
`eval.detonate` keeps). It is not what `detonate --json` prints, which is the judged verdict and
holds no page content; that file is refused with a message. A page report that could not be
opened (`dead`, `error`) adds nothing and the dossier says so; it is never read as safe.

## Attribution

The engine (`core/risk/scoring.py`) scores noisy-OR inside each category, capped, then noisy-OR
across categories. `attribution` lists every number needed to rebuild it:

```
capped_c  = min(1 - prod_{s in c}(1 - w_s), cap_c)          per category c
risk      = round(100 * (1 - prod_c(1 - capped_c)))          the score shown
```

then the state: `MALICIOUS` if `risk >= 80` and at least 2 categories hold a signal of weight
`>= 0.5`; else `SUSPICIOUS` if `risk >= 45`; else `BENIGN` (with the score) for an allowlisted
address, `UNKNOWN` (no score shown) otherwise. A signal named under `[certain]` in the pack's
config makes the state `MALICIOUS` with score `max(risk, 95)`. `attribution.rebuilt_state` and
`rebuilt_score` are recomputed from the listed signal weights, category caps and thresholds alone
(`core.investigate.attribution.rebuild`), and `matches_verdict` says they equal the engine's. For
UNKNOWN the engine shows no score; `risk_points` is the value it computed before hiding it.

Points per signal split the unrounded `risk_points = 100 * (1 - prod_c(1 - capped_c))` by the
survival decomposition (the standard split for noisy-OR): a category's share is
`-ln(1 - capped_c) / sum_c -ln(1 - capped_c)`, a signal's share inside its category is
`-ln(1 - w_s) / sum_s -ln(1 - w_s)`. The shares sum to one, so signal points sum to `risk_points`,
category points sum to it too, and a capped category's signals share its capped points. The split is
order-independent. A weight of exactly 1 is clamped inside the logarithm only (the rebuild uses the
weights as they are).

## Counterfactuals

Each is a stated change to the engine's own signal list, scored again with the engine's real scorer
(`core.risk.scoring.score`); the figures reported are that call's output, never an estimate. The
rules are not re-run, so a change says what the scorer does with a different list, nothing about
other inputs. Items (`kind`):

- `remove_one`: each signal on its own.
- `remove_fewest_below_suspicious`, `remove_fewest_below_malicious`: the fewest signals whose removal
  leaves the verdict below that state. Every set of each size is tried in turn (up to 20,000 scorer
  calls; past that `searched_up_to` says how far it got and `found` is false). `alternatives` counts
  the other sets of the same size; the one listed is the first in signal order.
- `add_to_reach_suspicious`, `add_to_reach_malicious`: the smallest weight (steps of 0.001) of one
  extra signal from a category not already present that makes the scorer reach that state, with the
  scorer also confirming that one step less does not. `points` is the threshold minus the score.
  No rule is claimed to produce such a signal.

An input that was not analysed (empty, too long, unparseable, a parser or sandbox failure) has no
attribution and no counterfactuals; both say `not applicable`.

## Limits

What the dossier could not look at is in `limits`: the address was not visited, no redirect, domain
age or certificate was looked up, no list feed or outside service was asked, and without a page
report no page rule ran. A verdict from this evidence alone is never evidence of safety.

Only stored evidence is named. Every string in a dossier is the input, the engine's own evidence
(signal descriptions, rule ids, the explanation), rule data (brand names and domains) or a sentence
from `core/investigate/words.py`; a test walks every string and checks that.

## Not in this version

Redirect chain, domain age, the visit, page structure fingerprints, kit fingerprints, outside intel
and the brain's reading (DA5 1a stages 2 to 4 and 7, 8 and 10) need the network or Docker, or are
planned later; their sections say `not asked (offline)`. The console "Investigate" tab is not built.

## Tests

`tests/unit/test_investigate.py`: the dossier equals the engine on 14 fixed and the corpus's
development-split addresses; the numbers rebuild the score (including 600 random signal sets against
the real scorer); counterfactuals are re-scored and their minimality checked by brute force; no
socket is opened; a saved page report is read; the three input kinds share section names; only
stored evidence is named; hostile text is escaped.
