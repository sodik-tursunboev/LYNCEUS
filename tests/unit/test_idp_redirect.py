"""DA5 1d: a sign-in service's redirect_uri weighs little; 'auth' inside 'oauth' is no login word.

These use real sign-in host names as plain inputs to pure rule functions: nothing is fetched. The
rule fixtures in corpus/ stay on reserved hosts.
"""

import pytest

from core.detection.engine import analyze_url
from core.urls.parse import parse_url
from rules.url.content import credential_bait, idp_redirect, open_redirect

CB = "redirect_uri=https%3A%2F%2Fapp.example.test%2Fcb"


@pytest.mark.parametrize(
    "host",
    ["login.microsoftonline.com", "tenant.b2clogin.com", "accounts.google.com", "dev-1.okta.com"],
)
def test_a_sign_in_services_redirect_uri_is_weak_not_an_open_redirect(host: str) -> None:
    u = parse_url(f"https://{host}/oauth2/v2.0/authorize?{CB}")
    assert open_redirect(u) is None
    assert idp_redirect(u) is not None


def test_the_same_parameter_on_any_other_host_is_still_an_open_redirect() -> None:
    u = parse_url(f"https://portal.other.test/oauth?{CB}")
    assert open_redirect(u) is not None
    assert idp_redirect(u) is None


def test_other_redirect_parameters_on_a_sign_in_host_still_count() -> None:
    u = parse_url("https://login.microsoftonline.com/x?url=https%3A%2F%2Fevil.example.test%2F")
    assert open_redirect(u) is not None


def test_the_weak_signal_alone_cannot_warn() -> None:
    report = analyze_url(f"https://tenant.b2clogin.com/x/oauth2/v2.0/authorize?{CB}")
    assert report.verdict.state.value not in ("SUSPICIOUS", "MALICIOUS")


def test_auth_inside_oauth_is_not_a_login_word() -> None:
    assert (
        credential_bait(parse_url("https://apps.example.test/oauth-callback?state=paypal")) is None
    )
    assert (
        credential_bait(parse_url("https://apps.example.test/auth-callback?state=paypal"))
        is not None
    )
    assert credential_bait(parse_url("https://evil.example.test/paypal/verify?x=1")) is not None
