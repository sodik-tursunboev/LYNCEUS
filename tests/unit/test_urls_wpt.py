"""WHATWG conformance against web-platform-tests URL data (see tests/data/wpt/PROVENANCE.md)."""

import hashlib
import json
import re
import socket
from pathlib import Path

import pytest
from ada_url import URL

from core.urls.parse import ParsedUrl, UrlFlag, parse_url

DATA = Path(__file__).parents[1] / "data" / "wpt"
SUBSET = DATA / "urltestdata.subset.json"
CASES: list[dict[str, str]] = json.loads(SUBSET.read_text(encoding="ascii"))
# The six deliberate differences, with reasons, are tabled in ADR-012. The list is exact: a new
# difference, or one that goes away, must be looked at.
COMPLETED_WITH_HTTPS = {"a", "a/", "a//"}  # the standard fails text with no scheme
TRAILING_DOTS_FAIL = {"http://./", "http://../", "http://foo.09.."}  # we strip dots, then give up


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


def test_our_layer_differs_only_in_the_six_documented_cases() -> None:
    differs = {}
    for case in CASES:
        r = parse_url(case["input"])
        got = r.normalized if isinstance(r, ParsedUrl) else None
        if got != want(case):
            differs[case["input"]] = r
    assert set(differs) == COMPLETED_WITH_HTTPS | TRAILING_DOTS_FAIL
    for raw in COMPLETED_WITH_HTTPS:
        r = differs[raw]
        assert isinstance(r, ParsedUrl) and UrlFlag.SCHEME_ASSUMED in r.flags
    for raw in TRAILING_DOTS_FAIL:
        assert not isinstance(differs[raw], ParsedUrl)  # fails, so the verdict is UNKNOWN


def test_network_guard_is_on() -> None:
    with pytest.raises(RuntimeError):
        socket.getaddrinfo("example.com", 80)
