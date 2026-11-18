"""AI1 P1: the learned domain model as shipped. It loads only when the weights match their header,
reads the registered domain only (a subdomain or path never changes its answer), stays silent on
official and popular domains, explains itself with domain parts only, and alone only warns."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from core.contracts import VerdictState as V
from core.detection.engine import analyze_url
from core.learn import model as learned
from core.learn.hostfeatures import tokens
from core.urls import popular
from core.urls.parse import ParsedUrl, parse_url

SHIPPED = learned.DEFAULT


def url(text: str) -> ParsedUrl:
    u = parse_url(text)
    assert isinstance(u, ParsedUrl)
    return u


def rules_of(text: str) -> set[str]:
    return {s.rule_id for s in analyze_url(text).verdict.signals}


def test_the_shipped_weights_match_their_header() -> None:
    meta = json.loads(SHIPPED.read_text(encoding="utf-8"))
    raw = SHIPPED.with_suffix(".bin").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == meta["sha256"] and len(raw) == 2 * meta["buckets"]
    assert learned.current() is not None


def test_tampered_or_missing_weights_load_nothing(tmp_path: Path) -> None:
    header = tmp_path / "url_host.json"
    shutil.copy(SHIPPED, header)
    raw = bytearray(SHIPPED.with_suffix(".bin").read_bytes())
    raw[100] ^= 0xFF
    (tmp_path / "url_host.bin").write_bytes(bytes(raw))
    assert learned.current(header) is None
    assert learned.current(tmp_path / "nothing.json") is None


def test_only_the_registered_domain_is_read() -> None:
    m = learned.current()
    assert m is not None
    base = m.probability(url("https://kzxqwvbn-auth.test/"))[0]
    for other in (
        "https://login.secure.kzxqwvbn-auth.test/",
        "https://kzxqwvbn-auth.test/wp-admin/x?a=1",
    ):
        assert m.probability(url(other))[0] == base
    assert all(not t.startswith("s:") for t in tokens(url("https://a.b.c.example.org/")))


def test_it_warns_alone_and_needs_a_second_category_for_malicious() -> None:
    alone = analyze_url("https://kzxqwvbn-auth.test/").verdict
    assert {s.rule_id for s in alone.signals} == {
        "url.learned_domain"
    } and alone.state is V.SUSPICIOUS
    both = analyze_url("https://paypal-secure-login-verify.test/").verdict
    assert {"url.learned_domain", "url.combosquat"} <= {s.rule_id for s in both.signals}
    assert both.state is V.MALICIOUS


def test_measurement_can_switch_the_model_off_and_back() -> None:
    """eval.learn_url compares the rules alone with the product through `use`."""
    m = learned.current()
    assert m is not None
    learned.use(None)
    try:
        assert "url.learned_domain" not in rules_of("https://kzxqwvbn-auth.test/")
    finally:
        learned.use(m)
    assert "url.learned_domain" in rules_of("https://kzxqwvbn-auth.test/")


def test_official_and_popular_domains_are_never_judged_by_the_model() -> None:
    assert "url.learned_domain" not in rules_of("https://www.paypal.com/signin")
    assert "url.learned_domain" in rules_of("https://kzxqwvbn-auth.test/")
    popular.use(frozenset({"kzxqwvbn-auth.test"}))
    assert "url.learned_domain" not in rules_of("https://kzxqwvbn-auth.test/")


def test_the_explanation_names_domain_parts_never_the_path() -> None:
    v = analyze_url("https://kzxqwvbn-auth.test/SECRET-TOKEN-42/reset?u=jane").verdict
    text = next(s.description for s in v.signals if s.rule_id == "url.learned_domain")
    assert "kzxqwvbn-auth.test" in text
    assert "SECRET" not in text and "jane" not in text and "reset" not in text


@pytest.mark.parametrize("text", ["https://203.0.113.5/x", "https://localhost/", "https://co.uk/"])
def test_hosts_without_a_registered_domain_are_not_scored(text: str) -> None:
    assert "url.learned_domain" not in rules_of(text)
