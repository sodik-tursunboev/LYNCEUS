"""Rules about what the URL carries: shorteners, redirects, credential bait, odd structure."""

import base64
import binascii
import re
from collections.abc import Iterator
from urllib.parse import parse_qsl, unquote

from core.urls.parse import HostKind, ParsedUrl, UrlFlag, parse_url
from rules.url import rule
from rules.url.data import brands, lists, official_domains, scoring

CREDENTIAL_PHISH = "T1598.003"  # ATT&CK v20: Phishing for Information: Spearphishing Link
MALICIOUS_LINK = "T1204.001"  # ATT&CK v20: User Execution: Malicious Link

_MAX_PARAMS = 100  # bounded work on hostile input; a URL has 8192 characters at most
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_WORD = re.compile(r"[^a-z0-9]+")
_TRICKS = {
    UrlFlag.BACKSLASH: "backslash in the URL",
    UrlFlag.CONTROL_CHARS: "control characters",
    UrlFlag.INVISIBLE_CHARS: "invisible characters",
    UrlFlag.INTERIOR_WHITESPACE_REMOVED: "tab or newline inside the URL",
    UrlFlag.HOST_PERCENT_ENCODED: "percent-encoded host",
    UrlFlag.DOUBLE_ENCODED: "double percent-encoding",
}


def _official(u: ParsedUrl) -> bool:
    return u.registered_domain in official_domains()


def _params(u: ParsedUrl) -> list[tuple[str, str]]:
    return parse_qsl(u.query, keep_blank_values=True)[:_MAX_PARAMS]


def _base64_url(value: str) -> str | None:
    if not _BASE64.fullmatch(value):
        return None
    raw = value.replace("-", "+").replace("_", "/").rstrip("=")
    try:
        text = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("ascii")
    except (binascii.Error, UnicodeDecodeError):
        return None
    return text if text.lower().startswith(("http://", "https://", "//")) else None


def _elsewhere(u: ParsedUrl, candidate: str) -> ParsedUrl | None:
    """The parsed target, if it is an absolute URL on a different site from `u`."""
    if not candidate.lower().startswith(("http://", "https://", "//", "\\\\")):
        return None
    t = parse_url(candidate)
    if not isinstance(t, ParsedUrl) or t.host is None:
        return None
    if t.registered_domain is not None and t.registered_domain == u.registered_domain:
        return None
    known = official_domains()
    if u.registered_domain in known and known[u.registered_domain or ""] == known.get(
        t.registered_domain or ""
    ):
        return None  # google.com sending you to gmail.com
    return t


def _targets(u: ParsedUrl) -> Iterator[tuple[str, str, ParsedUrl]]:
    """(parameter, how it was hidden, target) for every off-site URL in the query."""
    for name, value in _params(u):
        hidden = ""
        candidate = value
        if "%" in value:
            candidate, hidden = unquote(value), "double-encoded"
        decoded = _base64_url(candidate)
        if decoded:
            candidate, hidden = decoded, "base64-encoded"
        target = _elsewhere(u, candidate)
        if target:
            yield name.lower(), hidden, target


def hands_over_control(u: ParsedUrl) -> bool:
    """True when the URL passes the visitor on to another site: an off-site URL in ANY query
    parameter (not only the well-known redirect names), or an AMP-style path that embeds a host.
    Such a link on an official domain is not "the official site", so the allowlist must not vouch
    for it (independent review R1)."""
    if next(_targets(u), None) is not None:
        return True
    return re.match(r"^/amp/s/[^/]+\.[^/]+", u.path, re.I) is not None


@rule("url.shortener", "obfuscation")
def shortener(u: ParsedUrl) -> str | None:
    """Destination unknown, and that is all it means: too weak to flag anything alone."""
    if u.registered_domain in lists()["shorteners"]:
        return f"URL shortener ({u.registered_domain}): the destination is unknown"
    return None


@rule("url.open_redirect", "redirect")
def open_redirect(u: ParsedUrl) -> str | None:
    for name, _, target in _targets(u):
        if name in lists()["redirect_params"]:
            return f"parameter '{name}' sends the visitor to another site ({target.host})"
    return None


@rule("url.encoded_target", "redirect")
def encoded_target(u: ParsedUrl) -> str | None:
    for _, hidden, target in _targets(u):
        if hidden:  # the parameter name is free text from the URL: it stays out of the evidence
            return f"{hidden} URL to another site ({target.host})"
    return None


def _brand_named(text: str) -> str | None:
    words = set(_WORD.split(text))
    for b in brands():
        if any(t in words or (len(t) >= 5 and t in text) for t in b.terms):
            return b.name
    return None


@rule("url.credential_bait", "credential", CREDENTIAL_PHISH)
def credential_bait(u: ParsedUrl) -> str | None:
    """A brand and a login word in the path or query of a site the brand does not own."""
    if u.host is None or _official(u):
        return None
    text = unquote(f"{u.path}?{u.query}").lower()
    brand = _brand_named(text)
    keyword = next((k for k in lists()["keywords"] if k in text), None)
    if brand and keyword:
        return f"path or query names {brand} and '{keyword}', on {u.registered_domain or u.host}"
    return None


@rule("url.prefilled_identity", "credential", CREDENTIAL_PHISH)
def prefilled_identity(u: ParsedUrl) -> str | None:
    if u.host is None or _official(u):
        return None
    for name, value in _params(u):
        if name.lower() in lists()["identity_params"] and "@" in value:
            return f"parameter '{name.lower()}' arrives prefilled with an email address"
    return None


@rule("url.login_path", "credential", CREDENTIAL_PHISH)
def login_path(u: ParsedUrl) -> str | None:
    """Weak alone: real sites have login pages too. It matters next to an IP host or a brand."""
    if u.host is None or _official(u):
        return None
    words = lists()["login_words"]
    parts = [p for p in u.path.lower().split("/") if p]
    if not parts:
        return None
    stem = parts[-1].rsplit(".", 1)[0]
    if all(w in words for w in stem.split("-")):
        return f"path ends in a login-style page ({stem})"
    if stem == "index" and len(parts) > 1 and parts[-2] in words:
        return f"path ends in a login-style page ({parts[-2]})"
    if any(p.startswith("wp-") for p in parts) and any(w in stem for w in words):
        return "login-style page inside a CMS folder"
    return None


@rule("url.dangerous_scheme", "scheme", MALICIOUS_LINK)
def dangerous_scheme(u: ParsedUrl) -> str | None:
    if u.has(UrlFlag.DANGEROUS_SCHEME):
        return f"{u.scheme}: URLs run or embed content instead of opening a page"
    return None


@rule("url.odd_port", "structure")
def odd_port(u: ParsedUrl) -> str | None:
    if u.port is not None and u.port not in lists()["ordinary_ports"]:
        return f"unusual port {u.port}"
    return None


@rule("url.excessive_length", "structure")
def excessive_length(u: ParsedUrl) -> str | None:
    limit = scoring()["thresholds"]["long_url"]
    if len(u.normalized) >= limit:
        return f"URL is {len(u.normalized)} characters long"
    return None


@rule("url.host_shape", "structure")
def host_shape(u: ParsedUrl) -> str | None:
    if u.host_kind is not HostKind.DOMAIN:
        return None
    t = scoring()["thresholds"]
    labels = (u.registered_domain or "").split(".")
    hyphens = sum(x.count("-") for x in labels if not x.startswith("xn--"))  # punycode's own
    depth = u.subdomain.count(".") + 1 if u.subdomain else 0
    if hyphens >= t["many_hyphens"]:
        return f"{hyphens} hyphens in the registered domain"
    if depth >= t["deep_subdomains"]:
        return f"{depth} subdomain levels"
    return None


@rule("url.parser_tricks", "obfuscation")
def parser_tricks(u: ParsedUrl) -> str | None:
    found = [text for flag, text in _TRICKS.items() if u.has(flag)]
    return "; ".join(found) or None
