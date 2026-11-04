import time

import pytest

from core.urls.extract import MAX_TEXT_LEN, MAX_URLS, extract_urls
from core.urls.parse import MAX_URL_LEN, FailReason, ParsedUrl, ParseFailure, parse_url


def urls(text: str) -> tuple[str, ...]:
    return extract_urls(text).urls


@pytest.mark.parametrize(
    ("text", "want"),
    [
        ("see https://a.test/x now", ("https://a.test/x",)),
        ("(https://a.test/x).", ("https://a.test/x",)),
        ("<https://a.test/x>", ("https://a.test/x",)),
        ('"https://a.test/x",', ("https://a.test/x",)),
        ("go to https://a.test/x?y=1&z=2!", ("https://a.test/x?y=1&z=2",)),
        ("wiki https://en.example.test/wiki/A_(b) ok", ("https://en.example.test/wiki/A_(b)",)),
        ("(wiki https://en.example.test/wiki/A_(b))", ("https://en.example.test/wiki/A_(b)",)),
        ("hxxps://evil[.]example/z, then", ("hxxps://evil[.]example/z",)),
        ("hxxp[://]evil.example/z", ("hxxp[://]evil.example/z",)),
        ("visit www.b.test/q today", ("www.b.test/q",)),
        ("ftp://f.test/file", ("ftp://f.test/file",)),
        ("HTTP://UPPER.TEST/X", ("HTTP://UPPER.TEST/X",)),
        (
            "a https://a.test/1 b https://a.test/1 c https://b.test/2",
            ("https://a.test/1", "https://b.test/2"),
        ),
        ("no links here, just words.", ()),
        ("mailtohttps://x.test/", ()),  # glued to a word: not a URL start
        ("", ()),
    ],
)
def test_extraction(text: str, want: tuple[str, ...]) -> None:
    assert urls(text) == want


def test_candidates_feed_parse_url() -> None:
    found = urls("Click hxxps://login-verify[.]example/a?b=1. Also www.c.test/x")
    parsed = [parse_url(u) for u in found]
    assert all(isinstance(p, ParsedUrl) for p in parsed)
    assert [p.normalized for p in parsed if isinstance(p, ParsedUrl)] == [
        "https://login-verify.example/a?b=1",
        "https://www.c.test/x",
    ]


def test_url_count_cap() -> None:
    text = " ".join(f"https://h{i}.test/" for i in range(MAX_URLS + 5))
    r = extract_urls(text)
    assert len(r.urls) == MAX_URLS and r.truncated


def test_text_length_cap() -> None:
    text = "x " * (MAX_TEXT_LEN // 2) + " https://beyond-the-cap.test/"
    r = extract_urls(text)
    assert r.urls == () and r.truncated


def test_oversize_candidate_is_reported_by_parse_url_not_dropped() -> None:
    (candidate,) = urls("https://a.test/" + "a" * (MAX_URL_LEN + 500))
    r = parse_url(candidate)
    assert isinstance(r, ParseFailure) and r.reason is FailReason.TOO_LONG


@pytest.mark.parametrize(
    "text",
    [
        "https://a.test/" + ")" * 500_000,
        "https://a.test/" + "." * 500_000,
        "(" * 300_000 + "https://a.test/" + ")" * 300_000,
        "http://" * 140_000,
        "www." * 240_000,
        "hxxp[://]" * 100_000,
        "https://" + "[" * 900_000,
    ],
)
def test_pathological_text_is_linear(text: str) -> None:
    t0 = time.perf_counter()
    extract_urls(text)
    assert time.perf_counter() - t0 < 2.0
