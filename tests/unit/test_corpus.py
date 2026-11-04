import base64
from collections import Counter
from pathlib import Path
from urllib.parse import quote

import pytest
from pydantic import ValidationError

from core.urls.parse import HostKind, ParsedUrl, UrlFlag, parse_url
from eval.corpus import (
    CorpusEntry,
    Label,
    Origin,
    Split,
    embedded_hosts,
    is_synthetic_host,
    load_manifest,
    split_hash,
)

CORPUS = Path(__file__).parents[2] / "corpus"
MANIFEST = CORPUS / "manifest.jsonl"
MALICIOUS_CATEGORIES = {
    "ip_based", "userinfo_deception", "punycode_homograph", "lookalike_typo", "combosquat",
    "brand_in_subdomain", "shortener", "encoded_redirect", "credential_harvest",
    "structure_oddity", "multi_signal",
}  # fmt: skip


@pytest.fixture(scope="module")
def entries() -> list[CorpusEntry]:
    return load_manifest(MANIFEST)  # also enforces unique ids, synthetic hosts, hidden-host checks


def test_size_and_splits(entries: list[CorpusEntry]) -> None:
    sizes = Counter(e.split for e in entries)
    assert len(entries) >= 240
    assert sizes[Split.DEV] >= 140 and sizes[Split.HOLDOUT] >= 45 and sizes[Split.RESERVE] >= 45


def test_both_labels_in_every_split(entries: list[CorpusEntry]) -> None:
    seen = {(e.label, e.split) for e in entries}
    assert seen == {(lbl, s) for lbl in Label for s in Split}


def test_every_malicious_category_is_in_dev_and_holdout(entries: list[CorpusEntry]) -> None:
    for cat in MALICIOUS_CATEGORIES:
        splits = {e.split for e in entries if e.category == cat and e.label is Label.MALICIOUS}
        assert {Split.DEV, Split.HOLDOUT} <= splits, cat


def test_hard_negative_categories_exist_in_dev(entries: list[CorpusEntry]) -> None:
    benign = {e.category for e in entries if e.label is Label.BENIGN and e.split is Split.DEV}
    wanted = {
        "benign_idn", "benign_login_real", "benign_cdn_tracking", "benign_at_sign",
        "benign_redirect", "benign_keywords", "benign_brand_adjacent", "shortener",
    }  # fmt: skip
    assert wanted <= benign


def test_real_urls_are_benign_only_and_documented(entries: list[CorpusEntry]) -> None:
    real = [e for e in entries if e.origin is Origin.PUBLIC_REAL]
    assert 0 < len(real) <= 40
    assert all(e.label is Label.BENIGN and e.source.startswith("public:") and e.notes for e in real)
    assert all(e.origin is Origin.SYNTHETIC for e in entries if e.label is Label.MALICIOUS)


def test_every_seed_parses(entries: list[CorpusEntry]) -> None:
    bad = [e.id for e in entries if not isinstance(parse_url(e.value), ParsedUrl)]
    assert not bad


# The categories mean what they say (structure only; whether a rule fires is M1 step 3).
STRUCTURE = {
    "ip_based": lambda u: u.host_kind in (HostKind.IPV4, HostKind.IPV6),
    "userinfo_deception": lambda u: UrlFlag.USERINFO in u.flags,
    "benign_at_sign": lambda u: UrlFlag.USERINFO not in u.flags,
    "punycode_homograph": lambda u: UrlFlag.PUNYCODE in u.flags,
    "benign_idn": lambda u: {UrlFlag.IDN, UrlFlag.PUNYCODE} <= set(u.flags),
    "benign_nonweb": lambda u: UrlFlag.NON_HTTP_SCHEME in u.flags,
}


@pytest.mark.parametrize("category", sorted(STRUCTURE))
def test_category_structure(entries: list[CorpusEntry], category: str) -> None:
    members = [e for e in entries if e.category == category]
    assert members
    for e in members:
        u = parse_url(e.value)
        assert isinstance(u, ParsedUrl) and STRUCTURE[category](u), e.id


def test_encoded_redirects_hide_a_target(entries: list[CorpusEntry]) -> None:
    for e in entries:
        if e.category == "encoded_redirect":
            assert len(embedded_hosts(e.value)) >= 2, e.id  # the carrier host and the hidden one


def test_holdout_and_reserve_are_pinned() -> None:
    pins = dict(line.split() for line in (CORPUS / "pins.txt").read_text().splitlines() if line)
    for split in (Split.HOLDOUT, Split.RESERVE):
        assert split_hash(MANIFEST, split) == pins[split.value], (
            f"{split.value} changed. If that is deliberate (a holdout failure drove a fix and a "
            "new holdout is drawn from reserve), say why in the commit and run "
            "python -m eval.corpus"
        )


# ---- validator -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "ok"),
    [
        ("login.examplebank.test", True),
        ("xn--exmplebank-hmf.test", True),
        ("x.invalid", True),
        ("www.example.com", True),
        ("203.0.113.45", True),
        ("2001:db8::7", True),
        ("[2001:db8::7]", True),
        ("8.8.8.8", False),
        ("example.com.evil.com", False),
        ("notexample.com", False),
        ("", False),
        (None, False),
    ],
)
def test_synthetic_host_check(host: str | None, ok: bool) -> None:
    assert is_synthetic_host(host) is ok


def entry(value: str, **over: object) -> CorpusEntry:
    base: dict[str, object] = {
        "id": "x", "value": value, "label": Label.MALICIOUS, "category": "c",
        "origin": Origin.SYNTHETIC, "source": "s", "split": Split.DEV,
    }  # fmt: skip
    return CorpusEntry.model_validate(base | over)


def test_real_host_is_rejected_in_a_synthetic_entry() -> None:
    with pytest.raises(ValidationError):
        entry("https://realsite.com/")


def test_host_hidden_in_an_encoded_parameter_is_rejected() -> None:
    target = "http://realsite.com/login"
    for hidden in (quote(target, safe=""), quote(quote(target, safe=""), safe=""),
                   base64.b64encode(target.encode()).decode(), "//realsite.com/login"):  # fmt: skip
        with pytest.raises(ValidationError):
            entry(f"https://www.example.com/r?u={hidden}")
    entry("https://www.example.com/r?u=" + quote("http://phish.invalid/login", safe=""))  # fine


def test_the_browsers_host_is_the_one_checked() -> None:
    # urllib would see good.test here; the browser goes to realsite.com.
    with pytest.raises(ValidationError):
        entry("http://realsite.com\\@good.test/")


def test_public_real_rules() -> None:
    ok = {"origin": Origin.PUBLIC_REAL, "label": Label.BENIGN, "source": "public:x", "notes": "n"}
    entry("https://www.paypal.com/signin", **ok)
    for bad in ({"label": Label.MALICIOUS}, {"source": "synthetic:x"}, {"notes": ""}):
        with pytest.raises(ValidationError):
            entry("https://www.paypal.com/signin", **(ok | bad))


def test_embedded_hosts() -> None:
    hosts = embedded_hosts("https://a.test/r?u=http%3A%2F%2Fphish.invalid%2Fx")
    assert hosts == ["a.test", "phish.invalid"]
    assert "x.invalid" in embedded_hosts("javascript:go('http://x.invalid')")
    assert embedded_hosts("mailto:a@example.test") == []
