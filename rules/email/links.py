"""Rules about the links in a message: what they say versus where they go."""

import re

from core.sandbox.guest.textscan import find_urls
from core.urls import psl
from core.urls.parse import ParsedUrl, parse_url
from rules.email import CREDENTIALS, LINK, Ctx, rule
from rules.email.data import scoring
from rules.url.data import official_domains

_DOMAIN = re.compile(r"(?<![\w@.-])((?:[a-z0-9-]{1,63}\.)+[a-z][a-z0-9-]{1,23})(?![\w-])", re.I)
_PAGE_KINDS = ("a", "area")


def shown_target(text: str) -> ParsedUrl | None:
    """The site a link's visible text claims to go to, if it names one."""
    urls, _ = find_urls(text, 3, 300)
    candidates = list(urls) + [m.group(1) for m in _DOMAIN.finditer(text)][:3]
    for candidate in candidates:
        parsed = parse_url(candidate)
        if (
            isinstance(parsed, ParsedUrl)
            and parsed.registered_domain
            and parsed.host
            and psl.known_suffix(parsed.host)
        ):
            return parsed
    return None


def _mismatches(ctx: Ctx, brand: bool) -> list[tuple[str, str]]:
    """(shown domain, real domain) for each link whose text names a different site."""
    out = []
    for link in ctx.links:
        if link.kind not in _PAGE_KINDS or link.parsed is None or not link.text:
            continue
        real = link.parsed.registered_domain
        target = shown_target(link.text)
        shown = target.registered_domain if target else None
        if shown is None or real is None or shown == real:
            continue
        if (shown in official_domains()) is brand:
            out.append((shown, real))
    return out


@rule("email.link_text_brand_mismatch", "deception", LINK)
def link_text_brand_mismatch(ctx: Ctx) -> str | None:
    """`<a href="https://evil.example">https://www.paypal.com/login</a>`"""
    found = _mismatches(ctx, brand=True)
    if not found:
        return None
    shown, real = found[0]
    return (
        f"link text shows {shown} but goes to {real}"
        f" ({len(found)} such link{'s' if len(found) > 1 else ''})"
    )


@rule("email.link_text_mismatch", "deception", LINK)
def link_text_mismatch(ctx: Ctx) -> str | None:
    found = _mismatches(ctx, brand=False)
    if not found:
        return None
    shown, real = found[0]
    return f"link text shows {shown} but goes to {real}"


@rule("email.hidden_link", "deception", LINK)
def hidden_link(ctx: Ctx) -> str | None:
    hidden = [link.parsed for link in ctx.links if "hidden" in link.flags and link.parsed]
    if not hidden:
        return None
    return f"{len(hidden)} link(s) a reader cannot see, e.g. to {hidden[0].host}"


@rule("email.image_only_link", "deception", LINK)
def image_only_link(ctx: Ctx) -> str | None:
    """Weak: marketing mail is full of them. It only matters next to something else."""
    plain = [
        link for link in ctx.links
        if "image_link" in link.flags and link.parsed is not None
        and link.parsed.registered_domain not in official_domains()
    ]  # fmt: skip
    return f"{len(plain)} link(s) with only an image to click" if plain else None


@rule("email.password_form", "credential", CREDENTIALS)
def password_form(ctx: Ctx) -> str | None:
    if ctx.scan.html.password_inputs == 0:
        return None
    posts = [link.parsed for link in ctx.links if link.kind == "form" and link.parsed is not None]
    where = f", posting to {posts[0].host}" if posts else ""
    return f"message contains a password field{where}"


@rule("email.script_content", "active_content")
def script_content(ctx: Ctx) -> str | None:
    js_links = sum("javascript" in link.flags for link in ctx.links)
    scripts = ctx.scan.html.scripts
    if scripts or js_links:
        return f"{scripts} script element(s) and {js_links} javascript: link(s) in the message"
    return None


@rule("email.meta_refresh", "active_content", LINK)
def meta_refresh(ctx: Ctx) -> str | None:
    for link in ctx.links:
        if link.kind == "meta_refresh" and link.parsed is not None:
            return f"the message redirects the reader to {link.parsed.host}"
    return None


@rule("email.link_flood", "structure")
def link_flood(ctx: Ctx) -> str | None:
    distinct = len({link.parsed.url_sha256 for link in ctx.links if link.parsed is not None})
    limit = scoring()["thresholds"]["many_links"]
    return f"{distinct} distinct links" if distinct >= limit else None
