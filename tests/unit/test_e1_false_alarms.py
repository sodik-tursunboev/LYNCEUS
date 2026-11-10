# ruff: noqa: E501  (sample URLs are long literal lines)
"""Regression for the false alarms found on the owner's own browsing in E1 (2026-11-10): nine of 87
real URLs were flagged. The shapes are reproduced here with made-up hosts; the real addresses are
not stored anywhere. Each fix keeps the attack it was written for."""

import pytest

from core.contracts import VerdictState as V
from core.detection.engine import analyze_url


def rules(url: str) -> set[str]:
    return {s.rule_id for s in analyze_url(url).verdict.signals}


def state(url: str) -> V:
    return analyze_url(url).verdict.state


# ---- 1. sign-in pages that carry an encoded return address (5 of the 9) ---------------------------
@pytest.mark.parametrize(
    "url",
    [
        "https://app.example-saas.test/en/login?next=%252Fdashboard%253Ftab%253D1",
        "https://portal.example-saas.test/auth?next=%252Fworkspace%252F42&form=1",
        "https://example-saas.test/login?next=%252F",
    ],
)
def test_a_sign_in_page_with_an_encoded_return_address_is_not_flagged(url: str) -> None:
    assert "url.parser_tricks" not in rules(url)
    assert state(url) not in (V.SUSPICIOUS, V.MALICIOUS)


def test_double_encoding_in_the_path_is_still_a_trick() -> None:
    assert "url.parser_tricks" in rules("https://example.test/a%252Fb/login")


def test_an_off_site_address_hidden_by_double_encoding_is_still_caught() -> None:
    url = "https://go.portal.test/r?x=http%253A%252F%252Fphish.invalid%252Flogin"
    assert "url.encoded_target" in rules(url)


# ---- 2. share dialogs on an official site (4 of the 9) --------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "https://www.linkedin.com/shareArticle?url=https%3A%2F%2Fnews.example.test%2Fa&title=t&summary=s",
        "https://www.linkedin.com/feed/?shareActive=true&url=https%3A%2F%2Fnews.example.test%2Fa"
        "&shareUrl=https%3A%2F%2Fnews.example.test%2Fa&linkOrigin=x",
        "https://www.linkedin.com/sharing/share-offsite/?url=https%3A%2F%2Fnews.example.test%2Fa",
        "https://www.facebook.com/sharer/sharer.php?u=https%3A%2F%2Fnews.example.test%2Fa",
        "https://x.com/intent/tweet?url=https%3A%2F%2Fnews.example.test%2Fa&text=hi",
    ],
)
def test_a_share_dialog_is_not_an_open_redirect(url: str) -> None:
    assert "url.open_redirect" not in rules(url)
    assert state(url) not in (V.SUSPICIOUS, V.MALICIOUS)


@pytest.mark.parametrize(
    "url",
    [
        "https://www.linkedin.com/redir/redirect?url=https%3A%2F%2Fphish.invalid%2Flogin",
        "https://www.linkedin.com/feed/?url=https%3A%2F%2Fphish.invalid%2Flogin",  # no share marker
        "https://www.google.com/url?q=https%3A%2F%2Fevil-login.test%2Fverify",
        "https://share.evil-host.test/shareArticle?url=https%3A%2F%2Fphish.invalid%2Fx",  # not official
    ],
)
def test_real_redirectors_and_look_alike_share_paths_are_still_flagged(url: str) -> None:
    assert "url.open_redirect" in rules(url)
    assert state(url) is V.SUSPICIOUS


def test_a_share_dialog_is_still_not_vouched_for_as_the_official_site() -> None:
    """It passes a URL along, so the allow-list must not call it BENIGN (independent review R1)."""
    v = analyze_url(
        "https://www.linkedin.com/shareArticle?url=https%3A%2F%2Fnews.example.test%2Fa"
    ).verdict
    assert v.state is not V.BENIGN and "Official domain" not in v.explanation
