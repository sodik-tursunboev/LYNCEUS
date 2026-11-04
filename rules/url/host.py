"""Rules about where the URL really points: IP-literal hosts and the userinfo trick."""

from core.urls.parse import HostKind, ParsedUrl, UrlFlag
from rules.url import rule
from rules.url.data import brands, official_domains


@rule("url.ip_literal", "host")
def ip_literal(u: ParsedUrl) -> str | None:
    if u.host_kind in (HostKind.IPV4, HostKind.IPV6):
        return f"host is an IP address ({u.ip_address})"
    return None


@rule("url.ip_obfuscated", "host")
def ip_obfuscated(u: ParsedUrl) -> str | None:
    if u.has(UrlFlag.IP_OBFUSCATED):
        return f"IP address written in an obfuscated form; it means {u.ip_address}"
    if u.has(UrlFlag.IPV4_MAPPED):
        return f"IPv4 address wrapped in IPv6; it means {u.mapped_ipv4}"
    return None


@rule("url.userinfo_deception", "deception")
def userinfo_deception(u: ParsedUrl) -> str | None:
    """`https://paypal.com@evil.example/`: the text before @ is decoration, the host is after it."""
    name = (u.username or "").lower()
    if not name or u.host_kind is HostKind.NONE:
        return None
    if any(name == d or name.endswith("." + d) for d in official_domains()):
        return f"a known brand's domain sits before the @; the real host is {u.host}"
    if any(t in name for b in brands() for t in b.terms if len(t) >= 5):
        return f"a known brand's name sits before the @; the real host is {u.host}"
    if "." in name:
        return f"a domain-like name sits before the @; the real host is {u.host}"
    return None
