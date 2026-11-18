"""Page rules (D1) on synthetic page reports: each fires on its case and not on its benign twin."""

from typing import Any

import pytest

from core.contracts import VerdictState as V
from core.detection.engine import analyze_url
from core.detonate.judge import judge
from core.detonate.models import PageReport
from rules.page import RULES, evaluate, scoring

pytestmark = pytest.mark.usefixtures("no_learned_model")  # what the page adds to the address rules
PW = {"type": "password", "hint": "password"}
EMAIL = {"type": "email", "hint": "email"}


def page(url: str, **kw: Any) -> PageReport:
    base: dict[str, Any] = {"status": "ok", "final_url": url, "http_status": 200}
    return PageReport.model_validate({**base, **kw})


def form(action: str, *fields: dict[str, str]) -> dict[str, Any]:
    return {"action": action, "method": "post", "fields": list(fields)}


def hits(r: PageReport) -> set[str]:
    return {rule.id for rule, _ in evaluate(r)}


KIT = {
    "title": "Sign in to your Microsoft account",
    "logos": ["Microsoft microsoft_logo.svg"],
    "forms": [form("http://203.0.113.9/next.php", EMAIL, PW)],
    "script_refs": ["api.telegram.org/bot000000", "ipapi.co/json"],
    "markers": ["devtools_check", "key_block"],
}


def test_every_rule_has_a_weight_and_a_known_category() -> None:
    cfg = scoring()
    for r in RULES:
        assert r.id in cfg["weights"], r.id
        assert r.category in cfg["category_caps"], r.id


def test_a_phishing_kit_page_fires_every_rule_it_should() -> None:
    assert hits(page("https://secure-check.example/o365/", **KIT)) == {
        "page.brand_credential", "page.form_offsite", "page.collection_endpoint",
        "page.evasion", "page.geofence",
    }  # fmt: skip


# ---- brand_credential ----------------------------------------------------------------------------
def test_a_brand_sign_in_page_on_the_brands_own_domain_is_not_impersonation() -> None:
    r = page("https://login.microsoftonline.com/common", title="Sign in to your Microsoft account",
             forms=[form("https://login.microsoftonline.com/post", EMAIL, PW)])  # fmt: skip
    assert "page.brand_credential" not in hits(r)


def test_a_brand_sign_in_page_on_shared_hosting_of_that_brand_is_still_impersonation() -> None:
    r = page("https://sites.google.com/view/x", title="Google Account sign in",
             forms=[form("https://sites.google.com/view/x", EMAIL, PW)])  # fmt: skip
    assert "page.brand_credential" in hits(r)


@pytest.mark.parametrize(
    "logos,title",
    [
        (["Continue with Google", "Sign in with Microsoft"], "Acme Portal | Log in"),
        (["Acme"], "Pop-ups and banners | Log in"),  # "ups" inside "pop-ups" is not UPS
    ],
)
def test_offering_to_sign_in_with_a_brand_is_not_claiming_to_be_it(
    logos: list[str], title: str
) -> None:
    r = page("https://app.acme-portal.example/login", title=title, logos=logos,
             forms=[form("https://app.acme-portal.example/session", EMAIL, PW)])  # fmt: skip
    assert hits(r) == set()


def test_a_two_step_kit_asking_for_the_address_first_is_caught() -> None:
    r = page("https://verify-now.example/", title="Outlook", headings=["Sign in"],
             loose=[{"type": "text", "hint": "loginfmt email, phone, or skype"}])  # fmt: skip
    assert "page.brand_credential" in hits(r)


def test_page_only_brand_words_join_the_known_brand_and_its_domains() -> None:
    title = "Sign in to Office 365"
    own = page("https://portal.office365.com/", title=title,
               forms=[form("https://portal.office365.com/x", EMAIL, PW)])  # fmt: skip
    tenant = page("https://contoso.sharepoint.com/", title=title,
                  forms=[form("https://contoso.sharepoint.com/x", EMAIL, PW)])  # fmt: skip
    fake = page("https://docs-review.example/", title=title,
                forms=[form("https://docs-review.example/x", EMAIL, PW)])  # fmt: skip
    assert "page.brand_credential" not in hits(own)  # office365.com: a page-list domain
    assert "page.brand_credential" in hits(tenant)  # anyone can publish on SharePoint
    assert "page.brand_credential" in hits(fake)


@pytest.mark.parametrize("title", ["CITI Program | Log in", "Norton Healthcare MyChart"])
def test_ordinary_words_that_are_also_brand_names_are_left_out(title: str) -> None:
    r = page(
        "https://portal.example/", title=title, forms=[form("https://portal.example/x", EMAIL, PW)]
    )
    assert "page.brand_credential" not in hits(r)


def test_a_brand_named_on_a_page_that_asks_for_nothing_is_not_flagged() -> None:
    r = page(
        "https://news.example/", title="Microsoft announces new Surface", headings=["Microsoft"]
    )
    assert hits(r) == set()


# ---- card forms and brand pages on shared hosting ---------------------------------------------
CARD = {"type": "text", "hint": "cardnumber cc-number"}
EXP = {"type": "text", "hint": "exp-date mm/yy"}
CVV = {"type": "tel", "hint": "cvv security code"}


def test_a_parcel_brand_asking_for_card_details_elsewhere_is_impersonation() -> None:
    r = page("https://redelivery-fee.example/pay", title="DHL Express | Customs fee",
             forms=[form("https://redelivery-fee.example/pay", CARD, EXP, CVV)])  # fmt: skip
    found = {rule.id: text for rule, text in evaluate(r)}
    assert "page.brand_credential" in found and "card details" in found["page.brand_credential"]


def test_expiry_and_cvv_without_a_number_field_still_count_as_a_card_form() -> None:
    r = page(
        "https://verify.example/", title="DHL", forms=[form("https://verify.example/x", EXP, CVV)]
    )
    assert "page.brand_credential" in hits(r)


def test_a_shop_checkout_without_a_brand_claim_is_not_flagged() -> None:
    r = page("https://bakery.example/checkout", title="Checkout | The Bakery",
             forms=[form("https://bakery.example/pay", CARD, EXP, CVV)])  # fmt: skip
    assert hits(r) == set()


def test_a_brand_page_on_shared_hosting_is_weakly_flagged_before_any_form() -> None:
    lure = page("https://2-doc.s3.us-east-1.amazonaws.com/index.html",
                title="Shared Document - Microsoft OneDrive")  # fmt: skip
    blog = page("https://my-recipes.blogspot.com/", title="Grandma's recipes")
    assert hits(lure) == {"page.brand_on_hosting"}
    assert hits(blog) == set()
    v = judge(analyze_url(lure.final_url), lure).verdict
    assert v.state is not V.MALICIOUS  # weak alone: it needs something else


# ---- form_offsite ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "action",
    [
        "https://app.acme-portal.example/session",  # same site
        "https://api.acme-portal.example/v1/login",  # same registered domain
        "https://acme.okta.com/login/do-login",  # a single sign-on provider
        "https://login.microsoftonline.com/common/login",  # an official domain
    ],
)
def test_a_password_form_posting_to_a_trusted_place_is_fine(action: str) -> None:
    r = page("https://app.acme-portal.example/login", forms=[form(action, EMAIL, PW)])
    assert "page.form_offsite" not in hits(r)


@pytest.mark.parametrize("action", ["https://collect.example/p.php", "http://203.0.113.9/next.php"])
def test_a_password_form_posting_elsewhere_is_flagged(action: str) -> None:
    r = page("https://app.acme-portal.example/login", forms=[form(action, EMAIL, PW)])
    assert "page.form_offsite" in hits(r)


def test_a_newsletter_form_posting_elsewhere_is_not_a_credential_form() -> None:
    r = page("https://blog.example/", forms=[form("https://list-manage.example/subscribe", EMAIL)])
    assert "page.form_offsite" not in hits(r)


# ---- collection endpoints, hosting, evasion ------------------------------------------------------
def test_a_contact_form_service_without_a_credential_field_is_ordinary() -> None:
    r = page("https://bakery.example/contact", script_refs=["formspree.io/f"],
             forms=[form("https://formspree.io/f/xyz",
                         {"type": "text", "hint": "name"})])  # fmt: skip
    assert hits(r) == set()


def test_a_password_form_posting_to_a_form_service_is_a_kit() -> None:
    r = page("https://bakery.example/login", forms=[form("https://formspree.io/f/xyz", EMAIL, PW)])
    assert "page.collection_endpoint" in hits(r)


def test_a_sign_in_form_on_free_hosting_is_flagged_and_a_plain_page_there_is_not() -> None:
    login = page(
        "https://o365-verify.pages.dev/", forms=[form("https://o365-verify.pages.dev/x", EMAIL, PW)]
    )
    plain = page("https://my-portfolio.pages.dev/", title="My portfolio")
    assert "page.hosting_platform_login" in hits(login)
    assert hits(plain) == set()


def test_anti_analysis_code_matters_only_on_a_page_that_asks_for_credentials() -> None:
    gallery = page("https://photos.example/", markers=["key_block", "devtools_trap"])
    login = page("https://photos.example/login", markers=["key_block"],
                 forms=[form("https://photos.example/session", EMAIL, PW)])  # fmt: skip
    assert hits(gallery) == set()
    assert hits(login) == {"page.evasion"}


@pytest.mark.parametrize(
    "markers", [["context_block"], ["webdriver_check"], ["heavy_decoding"], ["devtools_check"]]
)
def test_markers_that_ordinary_sites_also_have_do_not_count(markers: list[str]) -> None:
    """D1 dev half: these were as common on legitimate sign-in pages as on phishing ones."""
    login = page("https://shop.example/login", markers=markers,
                 forms=[form("https://shop.example/session", EMAIL, PW)])  # fmt: skip
    assert hits(login) == set()


def test_logos_alone_do_not_claim_a_brand() -> None:
    """Payment marks, app-store badges and social icons are on every page."""
    r = page("https://flights.example/", title="Cheap flights | Fly Example",
             logos=["Visa", "Mastercard", "Download on the App Store Apple", "Facebook"],
             forms=[form("https://flights.example/login", EMAIL, PW)])  # fmt: skip
    assert hits(r) == set()


def test_a_listed_brands_own_site_showing_a_partner_brand_is_not_impersonation() -> None:
    r = page("https://www.allegro.pl/", title="Allegro - płać z PayPal",
             forms=[form("https://www.allegro.pl/login", EMAIL, PW)])  # fmt: skip
    assert "page.brand_credential" not in hits(r)


def test_a_newsletter_box_on_an_article_is_not_a_sign_in_page() -> None:
    r = page("https://news.example/story", title="PayPal changes its fees", headings=["Markets"],
             text="Create an account to get our newsletter",
             loose=[{"type": "email", "hint": "email"}])  # fmt: skip
    assert hits(r) == set()


# ---- downloads ---------------------------------------------------------------------------------
def test_a_file_built_in_the_page_is_smuggling_and_an_ordinary_download_is_drive_by() -> None:
    smuggled = page("https://docs-share.example/", downloads=[{"ext": "iso", "scheme": "blob"}])
    pushed = page("https://docs-share.example/", downloads=[{"ext": "exe", "scheme": "https"}])
    pdf = page("https://docs-share.example/", downloads=[{"ext": "pdf", "scheme": "https"}])
    assert hits(smuggled) == {"page.smuggling"}
    assert hits(pushed) == {"page.drive_by_download"}
    assert hits(pdf) == set()


# ---- the verdict ---------------------------------------------------------------------------------
def test_a_kit_page_behind_a_bland_url_becomes_malicious() -> None:
    start = analyze_url("https://secure-check.example/o365/")
    assert start.verdict.state is V.UNKNOWN  # the address alone says nothing
    v = judge(start, page("https://secure-check.example/o365/", **KIT)).verdict
    assert v.state is V.MALICIOUS
    assert v.engine_version.endswith("+page") and "+page." in v.ruleset_version


def test_impersonation_alone_is_suspicious_not_malicious() -> None:
    url = "https://secure-check.example/o365/"
    r = page(url, title="Sign in to your Microsoft account",
             forms=[form("https://secure-check.example/next", EMAIL, PW)])  # fmt: skip
    assert judge(analyze_url(url), r).verdict.state is V.SUSPICIOUS


def test_an_ordinary_login_page_at_a_login_path_stays_unknown() -> None:
    url = "https://app.acme-portal.example/login"
    start = analyze_url(url)
    r = page(url, title="Acme Portal | Log in", logos=["Continue with Google"],
             forms=[form("https://app.acme-portal.example/session", EMAIL, PW)])  # fmt: skip
    assert judge(start, r).verdict.state is start.verdict.state is V.UNKNOWN


def test_a_page_that_could_not_be_opened_changes_nothing_and_says_why() -> None:
    start = analyze_url("https://paypal-login.example/verify")
    v = judge(start, PageReport(status="dead", error="err_name_not_resolved")).verdict
    assert v.state is start.verdict.state
    assert [s.rule_id for s in v.signals] == [s.rule_id for s in start.verdict.signals]
    assert "Page not analysed" in v.explanation


def test_the_landing_address_is_judged_too() -> None:
    start = analyze_url("https://go.shortlink.example/abc")
    r = page("https://paypa1.example/signin")
    landed = judge(start, r).verdict
    landing = [s for s in landed.signals if s.description.startswith("landing page:")]
    assert {s.rule_id for s in landing} >= {"url.typosquat"}


def test_an_official_site_redirecting_to_its_own_country_site_is_trusted() -> None:
    start = analyze_url("https://www.paypal.com/")
    landed = judge(start, page("https://www.paypa1-country.example/")).verdict
    assert not [s for s in landed.signals if s.description.startswith("landing page:")]


def test_page_evidence_never_carries_url_text() -> None:
    url = "https://secure-check.example/o365/?email=victim%40example.test"
    v = judge(analyze_url(url), page(url, **KIT)).verdict
    for s in v.signals:
        if s.rule_id.startswith("page."):
            assert "victim" not in s.description and "o365" not in s.description


# ---- H1 C5: frames, the phone view and bot checks ---------------------------------------------


def test_a_password_form_inside_a_frame_is_seen_like_one_on_the_page() -> None:
    framed = {**form("https://collect.example.net/p.php", EMAIL, PW), "frame": True}
    r = page(
        "https://secure-check.example/login",
        title="Sign in to your Microsoft account",
        forms=[framed],
    )
    assert {"page.brand_credential", "page.form_offsite"} <= hits(r)


def test_a_frame_that_signs_in_through_an_identity_provider_is_not_offsite() -> None:
    framed = {**form("https://login.microsoftonline.com/common/login", EMAIL, PW), "frame": True}
    assert "page.form_offsite" not in hits(page("https://intranet.example.org/", forms=[framed]))


@pytest.mark.parametrize(
    "kw",
    [
        {"title": "Just a moment..."},
        {"title": "Attention Required! | Cloudflare"},
        {"title": "", "text": "Please verify", "hosts": ["challenges.cloudflare.com"]},
    ],
)
def test_a_bot_check_is_named_but_adds_no_weight(kw: dict[str, Any]) -> None:
    r = page("https://unknown-site.example/", **kw)
    assert "page.cloaked" in hits(r)
    base = analyze_url("https://unknown-site.example/")
    assert judge(base, r).verdict.risk_score == base.verdict.risk_score  # evidence only, for now


def test_a_page_that_only_uses_a_captcha_on_its_form_is_not_a_bot_check() -> None:
    r = page("https://shop.example/", title="Shop", text="x" * 2000, hosts=["www.recaptcha.net"])
    assert "page.cloaked" not in hits(r)


def test_the_phone_view_is_said_in_the_evidence() -> None:
    r = page(
        "https://unknown-site.example/",
        title="Just a moment...",
        phone_view=True,
        desktop_status="http_403",
    )
    assert any("phone" in why for rule, why in evaluate(r) if rule.id == "page.cloaked")


# ---- fresh_certificate (DA1) ---------------------------------------------------------------------
DAY = 86_400
VISIT = 1_794_000_000


def fresh(
    url: str, *, issued_days_before: float, visited: int | None = VISIT, **kw: Any
) -> PageReport:
    tls = {
        "valid_from": int(VISIT - issued_days_before * DAY),
        "valid_to": VISIT + 80 * DAY,
        "issuer": "R11",
    }
    return page(
        url,
        tls=tls,
        visited_at=visited,
        **{"title": "Sign in", "forms": [form(url, EMAIL, PW)], **kw},
    )


def test_a_sign_in_page_on_a_certificate_issued_days_ago_is_noted() -> None:
    r = fresh("https://account-review.example/signin", issued_days_before=2)
    found = [why for rule, why in evaluate(r) if rule.id == "page.fresh_certificate"]
    assert found and "2 days before the visit" in found[0]
    assert "the same day" in next(
        why
        for rule, why in evaluate(fresh("https://x-portal.example/", issued_days_before=0.2))
        if rule.id == "page.fresh_certificate"
    )


@pytest.mark.parametrize(
    "case",
    [
        {
            "url": "https://account-review.example/signin",
            "issued_days_before": 30,
        },  # an older certificate
        {
            "url": "https://account-review.example/signin",
            "issued_days_before": 2,
            "visited": None,
        },  # a report from before DA1
        {
            "url": "https://login.microsoftonline.com/common",
            "issued_days_before": 1,
        },  # a brand's own domain
        {
            "url": "https://account-review.example/",
            "issued_days_before": 1,
            "title": "Our menu",
            "forms": [],
        },  # asks nothing
    ],
)
def test_a_fresh_certificate_alone_or_on_a_brands_own_site_is_not_noted(
    case: dict[str, Any],
) -> None:
    assert "page.fresh_certificate" not in hits(fresh(case.pop("url"), **case))


def test_a_fresh_certificate_on_a_popular_domain_is_not_noted() -> None:
    from core.urls import popular

    popular.use(frozenset({"popular-shop.example"}))
    try:
        assert "page.fresh_certificate" not in hits(
            fresh("https://www.popular-shop.example/login", issued_days_before=1)
        )
    finally:
        popular.use(frozenset())


def test_a_fresh_certificate_is_shown_but_changes_no_verdict() -> None:
    """Evidence only until measured: next to url.login_path any weight would flag ordinary new
    sign-in pages (found by this test with a weight of 0.25)."""
    url = "https://account-review.example/signin"
    start = analyze_url(url)
    young = judge(start, fresh(url, issued_days_before=1))
    old = judge(start, fresh(url, issued_days_before=60))
    assert "page.fresh_certificate" in {s.rule_id for s in young.verdict.signals}
    assert "page.fresh_certificate" not in {s.rule_id for s in old.verdict.signals}
    assert (young.verdict.state, young.verdict.risk_score) == (
        old.verdict.state,
        old.verdict.risk_score,
    )
