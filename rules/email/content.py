"""Rules about how the message is built and what it says. All weak on their own."""

from functools import cache

from rules.email import Ctx, rule
from rules.email.data import lists, plain


@cache
def _phrases(key: str) -> tuple[str, ...]:
    return tuple(plain(p) for p in lists()[key])


@rule("email.malformed_mime", "structure")
def malformed_mime(ctx: Ctx) -> str | None:
    defects = ctx.scan.defects
    return f"the MIME structure is malformed: {', '.join(defects[:5])}" if defects else None


@rule("email.parser_limits", "structure")
def parser_limits(ctx: Ctx) -> str | None:
    hit = ctx.scan.limits_hit
    return (
        f"the scan stopped at its limits ({', '.join(hit)}); the rest was not examined"
        if hit
        else None
    )


@rule("email.social_engineering", "content")
def social_engineering(ctx: Ctx) -> str | None:
    text = plain(f"{ctx.scan.headers.subject} {ctx.scan.excerpt}")
    urgent = [p for p in _phrases("urgency") if p in text]
    asks = [p for p in _phrases("credential_asks") if p in text]
    if (urgent and asks) or len(urgent) >= 3:
        return (
            f"urgent wording ({len(urgent)} phrase(s)) and "
            f"requests for credentials or payment ({len(asks)})"
        )
    return None
