"""Every rule proves itself on its fixtures, and the pack stays consistent with its config."""

import hashlib
import re
import tomllib
from pathlib import Path

import pytest

from core.urls.parse import ParsedUrl, parse_url
from eval.corpus import is_synthetic_host
from rules.url import RULES
from rules.url.data import CONFUSABLES, brands, official_domains, ruleset_version, scoring, skeleton
from rules.url.impersonation import _distance

FIXTURES = tomllib.loads(
    (Path(__file__).parents[2] / "corpus" / "rule_fixtures.toml").read_text(encoding="utf-8")
)
BY_ID = {r.id: r for r in RULES}
ATTACK_V20 = {"T1566.002", "T1598.003", "T1204.001"}  # checked on attack.mitre.org, ATT&CK v20


def parsed(url: str) -> ParsedUrl:
    # PATH<n> pads to n characters: a long fixture stays readable.
    if m := re.search(r"PATH(\d+)$", url):
        url = url[: m.start()] + "a" * (int(m.group(1)) - m.start())
    u = parse_url(url)
    assert isinstance(u, ParsedUrl), url
    return u


CASES = [(rid, sign, url) for rid, f in FIXTURES.items() for sign in f for url in f[sign]]


@pytest.mark.parametrize(("rule_id", "sign", "url"), CASES)
def test_fixture(rule_id: str, sign: str, url: str) -> None:
    fired = BY_ID[rule_id].check(parsed(url)) is not None
    assert fired is (sign == "positive"), url


def test_every_rule_has_both_kinds_of_fixture() -> None:
    assert set(FIXTURES) == set(BY_ID)
    assert all(f["positive"] and f["negative"] for f in FIXTURES.values())


def test_positive_fixtures_are_on_reserved_hosts() -> None:
    for f in FIXTURES.values():
        for url in f["positive"]:
            u = parsed(url)
            assert u.host is None or is_synthetic_host(u.mapped_ipv4 or u.host), url


def test_every_rule_has_a_weight_and_a_verified_attack_id() -> None:
    assert set(scoring()["weights"]) == set(BY_ID)
    assert len(BY_ID) == len(RULES)
    assert all(r.attack in ATTACK_V20 for r in RULES)
    assert all(0 < w <= 1 for w in scoring()["weights"].values())


def test_no_single_rule_can_be_malicious_alone() -> None:
    assert scoring()["thresholds"]["min_categories"] >= 2


def test_brand_list_shape() -> None:
    assert len(brands()) >= 100
    names = {b.name for b in brands()}
    assert {"InPost", "Poczta Polska", "PKO BP", "mBank", "Allegro", "OLX", "BLIK"} <= names
    assert all(t == t.lower() and t.isascii() for b in brands() for t in b.terms)
    assert "paypal.com" in official_domains()


def test_skeleton_follows_uts39() -> None:
    assert skeleton("аpple") == skeleton("apple")  # Cyrillic a
    assert skeleton("paypa1") == skeleton("paypal")
    assert skeleton("g00gle") == skeleton("google")
    assert skeleton("arnazon") == skeleton("amazon")  # rn looks like m
    assert skeleton("example") != skeleton("exempla")


def test_confusables_snapshot_matches_its_provenance() -> None:
    text = (CONFUSABLES.parent / "PROVENANCE.md").read_text(encoding="utf-8")
    recorded = re.search(r"SHA-256 \| `([0-9a-f]{64})`", text)
    assert recorded and hashlib.sha256(CONFUSABLES.read_bytes()).hexdigest() == recorded.group(1)


def test_ruleset_version_is_semver_plus_data_hash() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+\+[0-9a-f]{12}", ruleset_version())


@pytest.mark.parametrize(
    ("a", "b", "want"),
    [("paypal", "paypal", 0), ("paypal", "paypa", 1), ("paypal", "payapl", 1), ("abc", "xyz", 3)],
)
def test_distance(a: str, b: str, want: int) -> None:
    assert _distance(a, b, 3) == want
