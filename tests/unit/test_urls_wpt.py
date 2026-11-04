"""WHATWG conformance against web-platform-tests URL data (see tests/data/wpt/PROVENANCE.md)."""

import hashlib
import json
import re
from pathlib import Path

from ada_url import URL

from core.urls.parse import ParsedUrl, UrlFlag, parse_url

DATA = Path(__file__).parents[1] / "data" / "wpt"
SUBSET = DATA / "urltestdata.subset.json"
CASES: list[dict[str, str]] = json.loads(SUBSET.read_text(encoding="ascii"))
# We strip trailing dots: nothing is left of these, or the rest is a bad IPv4. We report failure.
TRAILING_DOT_BY_DESIGN = {"http://./", "http://../", "http://foo.09.."}


def want(case: dict[str, str]) -> str | None:
    return None if case.get("failure") else case["href"]


def test_subset_matches_its_recorded_provenance() -> None:
    text = (DATA / "PROVENANCE.md").read_text(encoding="utf-8")
    recorded = re.search(r"Subset SHA-256 \| `([0-9a-f]{64})`", text)
    assert recorded and hashlib.sha256(SUBSET.read_bytes()).hexdigest() == recorded.group(1)
    assert len(CASES) > 500


def test_ada_url_matches_the_standard() -> None:
    bad = []
    for case in CASES:
        try:
            got = URL(case["input"]).href
        except ValueError:
            got = None
        if got != want(case):
            bad.append((case["input"], got))
    assert not bad


def test_our_layer_differs_only_where_documented() -> None:
    assumed, bad = 0, []
    for case in CASES:
        r = parse_url(case["input"])
        got = r.normalized if isinstance(r, ParsedUrl) else None
        if got == want(case) or case["input"] in TRAILING_DOT_BY_DESIGN:
            continue
        # The standard fails text with no scheme; we complete it, and say so in a flag.
        if want(case) is None and isinstance(r, ParsedUrl) and UrlFlag.SCHEME_ASSUMED in r.flags:
            assumed += 1
            continue
        bad.append((case["input"], got, want(case)))
    assert not bad
    assert assumed <= 10  # a sudden rise means the scheme heuristic has started guessing
