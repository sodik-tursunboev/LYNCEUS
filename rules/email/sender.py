"""Rules about who the message claims to be from."""

import re

from core.urls.parse import ParsedUrl, parse_url
from rules.email import Ctx, rule
from rules.url.data import brands, official_domains

_SPLIT = re.compile(r"[^a-z0-9]+")


def registered(domain: str) -> str | None:
    """The registered domain of a sender address' domain, as a browser would read it."""
    parsed = parse_url("https://" + domain + "/")
    return parsed.registered_domain if isinstance(parsed, ParsedUrl) else None


@rule("email.multiple_from", "sender")
def multiple_from(ctx: Ctx) -> str | None:
    n = ctx.scan.headers.from_count
    return f"message has {n} From headers; mail clients show only one" if n > 1 else None


@rule("email.display_name_brand", "sender")
def display_name_brand(ctx: Ctx) -> str | None:
    """`"PayPal Support" <help@evil.example>`: the name a person reads, not the address."""
    if not ctx.scan.headers.from_ or ctx.from_domain is None:
        return None
    words = set(_SPLIT.split(ctx.scan.headers.from_[0].name.lower()))
    mine = registered(ctx.from_domain) or ctx.from_domain
    for b in brands():
        named = any(t in words or (len(t) >= 5 and t in "".join(words)) for t in b.terms)
        if named and mine not in official_domains() and mine not in b.domains:
            return f"display name names {b.name} but the address is on {mine}"
    return None


@rule("email.reply_to_mismatch", "sender")
def reply_to_mismatch(ctx: Ctx) -> str | None:
    headers = ctx.scan.headers
    if not headers.from_ or not headers.reply_to:
        return None
    sender, reply = registered(headers.from_[0].domain), registered(headers.reply_to[0].domain)
    if sender and reply and sender != reply:
        return f"replies go to {reply}, not to the sender's domain {sender}"
    return None


@rule("email.auth_failure", "authentication")
def auth_failure(ctx: Ctx) -> str | None:
    """Only as trustworthy as whoever added the header; absent or `none` results prove nothing."""
    auth = ctx.scan.headers.auth
    failed = [
        f"{name}={value}"
        for name, value in (("dmarc", auth.dmarc), ("spf", auth.spf), ("dkim", auth.dkim))
        if value in ("fail", "softfail")
    ]
    where = auth.authserv or "an unnamed server"
    return f"{', '.join(failed)} according to {where}" if failed else None


def _sender_rule(url_rule_id: str) -> None:
    name = url_rule_id.removeprefix("url.")

    def check(ctx: Ctx) -> str | None:
        if ctx.sender is None:
            return None
        for signal in ctx.sender.verdict.signals:
            if signal.rule_id == url_rule_id:
                return f"sender domain: {signal.description}"
        return None

    rule(f"email.sender.{name}", "sender")(check)


for _id in (
    "url.homograph_brand", "url.mixed_script", "url.typosquat", "url.combosquat",
    "url.brand_in_subdomain", "url.brand_in_domain",
):  # fmt: skip
    _sender_rule(_id)
