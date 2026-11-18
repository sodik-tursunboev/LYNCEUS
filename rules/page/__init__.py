"""Page rule pack v1 (D1): what an opened page shows. A rule is a pure function: a PageCtx in, an
evidence summary out (None = no hit). Summaries name hosts, brands and counts, never URL text.

The page was produced by whoever controls the site, so every fact here is something the page
CLAIMS (a title, a logo, a form). A rule fires on a contradiction between a claim and where the
page really is: a Microsoft sign-in form that is not on a Microsoft domain; a password form that
posts to another site or to a Telegram bot.
"""

import hashlib
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from core.detonate.models import PageForm, PageReport
from core.urls.parse import HostKind, ParsedUrl, parse_url
from core.urls.popular import is_popular
from rules.url.data import Brand, brands, official_domains

HERE = Path(__file__).parent
CREDENTIAL_PHISH = "T1598.003"  # ATT&CK v20: Phishing for Information: Spearphishing Link
SMUGGLING = "T1027.006"  # Obfuscated Files or Information: HTML Smuggling
DRIVE_BY = "T1189"  # Drive-by Compromise
EVASION = "T1497"  # Virtualization/Sandbox Evasion
# Anti-analysis markers ordinary sites do not ship. Left out after the D1 dev half: checking
# navigator.webdriver, heavy decoding, right-click blocking and the word "devtools" are as common
# on legitimate pages.
_STRONG_MARKERS = frozenset({"devtools_trap", "key_block", "decoded_writer"})
_EMAILISH = re.compile(r"e-?mail|login|user|account|phone|identifier|loginfmt|userid|username")
# A payment-card number field (by autocomplete, name, id or placeholder), and the card's parts.
_CARD_NUMBER = re.compile(
    r"cc-?num|card.?num|cardnumber|card.?no\b|numer.?karty|n.mero.?de.?tarjeta|kartennummer"
)
_CARD_PART = re.compile(
    r"cc-|\bcvv|\bcvc|\bcsc\b|security.?code|expir|exp.?date|mm.?/.?yy|cardholder|card.?holder"
)


@cache
def lists() -> dict[str, Any]:
    return tomllib.loads((HERE / "lists.toml").read_text(encoding="utf-8"))


@cache
def scoring() -> dict[str, Any]:
    return tomllib.loads((HERE / "scoring.toml").read_text(encoding="utf-8"))


@cache
def page_brands() -> tuple[Brand, ...]:
    """The URL pack's brands plus the page-only ones (rules/page/brands.toml)."""
    extra = tomllib.loads((HERE / "brands.toml").read_text(encoding="utf-8"))["brands"]
    known = {b.name: b for b in brands()}
    added = []
    for b in extra:  # an entry for a known brand adds words; its domains are the union of both
        own = known[b["name"]].domains if b["name"] in known else ()
        domains = tuple(dict.fromkeys([*own, *b["domains"]]))
        added.append(Brand(b["name"], tuple(b["terms"]), domains, False))
    return brands() + tuple(added)


@cache
def ruleset_version() -> str:
    h = hashlib.sha256()
    for name in ("scoring.toml", "lists.toml", "brands.toml"):
        h.update((HERE / name).read_bytes())
    return f"{scoring()['ruleset']['version']}+{h.hexdigest()[:12]}"


@dataclass(frozen=True)
class PageCtx:
    report: PageReport
    page: ParsedUrl | None  # where the page really is (the landing address)

    @property
    def domain(self) -> str | None:
        return self.page.registered_domain if self.page else None


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    attack: str
    check: Callable[[PageCtx], str | None]


RULES: list[Rule] = []


def rule(rule_id: str, category: str, attack: str = CREDENTIAL_PHISH) -> Callable[..., Any]:
    def register(fn: Callable[[PageCtx], str | None]) -> Callable[[PageCtx], str | None]:
        RULES.append(Rule(rule_id, category, attack, fn))
        return fn

    return register


# ---- facts the rules share ---------------------------------------------------------------------
def has_password(r: PageReport) -> bool:
    return any(f.type == "password" for f in r.fields())


def asks_card(r: PageReport) -> bool:
    """A payment-card form: a card-number field, or two of its other parts (expiry, CVV, holder)."""
    hints = [f.hint for f in r.fields() if f.type in ("text", "tel", "number", "password", "")]
    return (
        any(_CARD_NUMBER.search(h) for h in hints)
        or sum(bool(_CARD_PART.search(h)) for h in hints) >= 2
    )


def asks_credentials(r: PageReport) -> bool:
    """A password field, a payment-card form, or an account field on a page that talks about
    signing in (two-step kits ask for the address first and the password on the next page)."""
    if has_password(r) or asks_card(r):
        return True
    account = any(
        f.type == "email" or (f.type in ("text", "tel", "") and _EMAILISH.search(f.hint))
        for f in r.fields()
    )
    words = f"{r.title} {' '.join(r.headings)}".lower()  # what the page says it is, not its body
    return account and any(w in words for w in lists()["sign_in_words"])


def claimed_brand(r: PageReport) -> tuple[Brand, str] | None:
    """The brand the page presents itself as, from its title and headings; not one it only offers
    to sign in with ("Continue with Google"). Logos are not used: payment marks, app-store badges
    and social icons are on every page (D1 dev half: 40 logo claims on legitimate pages, 8 on
    phishing pages)."""
    places = (("title", [r.title]), ("heading", r.headings))
    mention = "|".join(lists()["brand_mentions"])
    for b in page_brands():
        for term in b.terms:
            rx = re.compile(rf"(?<![a-z0-9-]){re.escape(term)}(?![a-z0-9-])")
            for where, texts in places:
                for text in texts:
                    low = text.lower()
                    for m in rx.finditer(low):
                        if re.search(
                            rf"\b(?:{mention})\s*$", low[max(0, m.start() - 16) : m.start()]
                        ):
                            continue
                        return b, where
    return None


def _host_matches(host: str, entries: list[str]) -> str | None:
    host = host.lower()
    return next((e for e in entries if host == e or host.endswith("." + e)), None)


def _ref_matches(ref: str, entries: list[str]) -> str | None:
    host, _, path = ref.partition("/")
    for e in entries:
        e_host, _, e_path = e.partition("/")
        if (host == e_host or host.endswith("." + e_host)) and path.startswith(e_path):
            return e
    return None


def _target(form: PageForm) -> ParsedUrl | None:
    t = parse_url(form.action)
    return t if isinstance(t, ParsedUrl) and t.scheme in ("http", "https") and t.host else None


def _trusted_target(ctx: PageCtx, t: ParsedUrl) -> bool:
    if t.host_kind is not HostKind.DOMAIN:
        return False
    same = t.registered_domain is not None and t.registered_domain == ctx.domain
    return bool(
        same
        or t.registered_domain in official_domains()
        or _host_matches(t.host or "", lists()["identity_providers"])
    )


# ---- rules -------------------------------------------------------------------------------------
@rule("page.brand_credential", "page.impersonation")
def brand_credential(ctx: PageCtx) -> str | None:
    r = ctx.report
    if ctx.page is None or not asks_credentials(r):
        return None
    found = claimed_brand(r)
    if found is None:
        return None
    brand, where = found
    host = ctx.page.host or ""
    shared = _host_matches(host, _shared()) or _host_matches(host, lists()["hosting_platforms"])
    if not shared and (ctx.domain in brand.domains or ctx.domain in _all_official()):
        return None  # the brand's own page, or another listed brand's own site naming a partner
    asks = "card details" if asks_card(r) and not has_password(r) else "credentials"
    return (
        f"the page presents itself as {brand.name} (in its {where}) and asks for {asks}, "
        f"on {ctx.domain or ctx.page.host}, which {brand.name} does not own"
    )


@cache
def _all_official() -> frozenset[str]:
    return frozenset(d for b in page_brands() for d in b.domains)


@cache
def _shared() -> list[str]:
    from rules.url.data import lists as url_lists

    return list(url_lists()["shared_hosts"])


@rule("page.form_offsite", "page.exfiltration")
def form_offsite(ctx: PageCtx) -> str | None:
    for form in ctx.report.forms:
        if not any(f.type == "password" for f in form.fields):
            continue
        t = _target(form)
        if t is None or _trusted_target(ctx, t):
            continue
        where = "a bare IP address" if t.host_kind is not HostKind.DOMAIN else t.registered_domain
        return f"a password form posts to {where}, not to {ctx.domain or 'this site'}"
    return None


@rule("page.collection_endpoint", "page.exfiltration")
def collection_endpoint(ctx: PageCtx) -> str | None:
    r = ctx.report
    if not asks_credentials(r):
        return None
    entries = lists()["collection_endpoints"]
    refs = [*r.script_refs]
    for form in r.forms:
        t = _target(form)
        if t is not None and t.host:
            refs.append(f"{t.host}{t.path}".lower())
    hit = next((e for ref in refs if (e := _ref_matches(ref, entries))), None)
    if hit:
        return f"asks for credentials and names a data-collection endpoint ({hit.split('/')[0]})"
    return None


@rule("page.hosting_platform_login", "page.hosting")
def hosting_platform_login(ctx: PageCtx) -> str | None:
    if ctx.page is None or not ctx.page.host or not asks_credentials(ctx.report):
        return None
    platform = _host_matches(ctx.page.host, lists()["hosting_platforms"])
    if platform:
        return f"a sign-in form on {platform}, where anyone can publish a page"
    return None


@rule("page.brand_on_hosting", "page.hosting")
def brand_on_hosting(ctx: PageCtx) -> str | None:
    """A page presenting itself as a brand on hosting anyone can use, before it asks for anything
    (the form often comes one click later: "View the shared document"). Weak alone."""
    if ctx.page is None or not ctx.page.host or asks_credentials(ctx.report):
        return None
    host = ctx.page.host
    where = _host_matches(host, lists()["hosting_platforms"]) or _host_matches(host, _shared())
    found = claimed_brand(ctx.report) if where else None
    if found is None:
        return None
    brand, place = found
    if ctx.domain in brand.domains and where not in _shared():
        return None
    return f"the page presents itself as {brand.name} (in its {place}) on {where}"


@rule("page.fresh_certificate", "page.freshness")
def fresh_certificate(ctx: PageCtx) -> str | None:
    """DA1: a sign-in page under a TLS certificate issued days before the visit. D1 dev half: 31% of
    live phishing pages had one under 7 days old, 8% of legitimate ones. Weak and in its own
    category: a site on a short-lived certificate renews often, so this only adds to other signs.
    Never on a brand's own domain or a popular one."""
    r = ctx.report
    if r.tls is None or r.visited_at is None or ctx.domain is None or not asks_credentials(r):
        return None
    days = (r.visited_at - r.tls.valid_from) / 86_400
    if not 0 <= days < scoring()["freshness"]["max_days"]:
        return None
    if ctx.domain in _all_official() or is_popular(ctx.domain):
        return None
    when = "the same day" if days < 1 else f"{int(days)} day{'s' if int(days) != 1 else ''} before"
    return f"asks for credentials on {ctx.domain}, whose certificate was issued {when} the visit"


@rule("page.evasion", "page.evasion", EVASION)
def evasion(ctx: PageCtx) -> str | None:
    r = ctx.report
    strong = [m for m in r.markers if m in _STRONG_MARKERS]
    if not strong or not asks_credentials(r):
        return None
    return f"a sign-in page that hides from analysis ({', '.join(strong)})"


@rule("page.geofence", "page.evasion", EVASION)
def geofence(ctx: PageCtx) -> str | None:
    r = ctx.report
    if not asks_credentials(r):
        return None
    hit = next(
        (e for ref in r.script_refs if (e := _ref_matches(ref, lists()["geo_lookups"]))), None
    )
    if hit:
        return f"a sign-in page that looks up the visitor's IP address ({hit})"
    return None


def bot_check(r: PageReport) -> bool:
    """The page is a bot check, not content: a known challenge title, or a challenge service loaded
    on a page with almost nothing else (no sign-in form)."""
    title = r.title.strip().lower()
    if any(title.startswith(t) for t in lists()["bot_check_titles"]):
        return True
    challenge = any(_host_matches(h, lists()["bot_check_hosts"]) for h in r.hosts)
    return challenge and len(r.text) < 800 and not asks_credentials(r)


@rule("page.cloaked", "page.evasion", EVASION)
def cloaked(ctx: PageCtx) -> str | None:
    """Evidence, not weight (H1 C5): next to url.login_path any weight would flag ordinary logins
    behind a bot-protection service. It tells the analyst the page rules saw a gate, not the
    page."""
    r = ctx.report
    if bot_check(r):
        seen = " (a phone was shown the same)" if r.phone_view else ""
        return f"the page showed a bot check instead of its content{seen}: the page was not seen"
    return None


@rule("page.smuggling", "page.delivery", SMUGGLING)
def smuggling(ctx: PageCtx) -> str | None:
    built = [d for d in ctx.report.downloads if d.scheme in ("blob", "data")]
    if built:
        ext = built[0].ext or "unknown type"
        return f"the page built a file inside the browser and started a download (.{ext})"
    return None


@rule("page.drive_by_download", "page.delivery", DRIVE_BY)
def drive_by_download(ctx: PageCtx) -> str | None:
    risky = [d for d in ctx.report.downloads if d.ext in lists()["dangerous_downloads"]]
    if risky and not smuggling(ctx):
        return f"the page started a download by itself (.{risky[0].ext})"
    return None


def evaluate(report: PageReport) -> list[tuple[Rule, str]]:
    parsed = parse_url(report.final_url) if report.final_url else None
    ctx = PageCtx(report, parsed if isinstance(parsed, ParsedUrl) else None)
    hits = []
    for r in sorted(RULES, key=lambda r: r.id):
        summary = r.check(ctx)
        if summary is not None:
            hits.append((r, summary))
    return hits
