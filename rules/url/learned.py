"""The learned domain model as a URL rule (AI1 P1): judgment fitted to 136,875 real domains.

It reads the registered domain only (core/learn/hostfeatures.py) and fires above the adopted
threshold. Its category `learned` is capped like one category of evidence: alone it reaches
SUSPICIOUS (a warning), never MALICIOUS. It stays silent on a brand's official domain and on a
popular domain (H1 B1). The evidence names the domain parts that pushed the score, never the path.
Measured in docs/eval/learned-url.md; without the shipped weights it never fires.
"""

from core.urls import popular
from core.urls.parse import ParsedUrl
from rules.url import SPEARPHISHING_LINK, rule
from rules.url.data import official_domains


def readable(token: str) -> str:
    """`l:^pay` -> `"pay" at the start`; `suffix:top` -> `.top`; structure tokens in words."""
    if token.startswith("l:"):
        part = token[2:]
        where = (
            " at the start" if part.startswith("^") else " at the end" if part.endswith("$") else ""
        )
        return f'"{part.strip("^$")}"{where}'
    if token.startswith("suffix:"):
        return f".{token[7:]}"
    name, _, value = token.partition(":")
    return f"{name.replace('_', ' ')} {value}".strip()


@rule("url.learned_domain", "learned", SPEARPHISHING_LINK)
def learned_domain(u: ParsedUrl) -> str | None:
    from core.learn.model import current  # here: the model's features read this package's lists

    model = current()
    domain = u.registered_domain
    if model is None or domain is None:
        return None
    if domain in official_domains() or popular.is_popular(domain):
        return None
    p, pushes = model.probability(u)
    if p < model.threshold:
        return None
    parts = ", ".join(readable(t) for t in pushes) or "its overall shape"
    return (
        f"the learned model rates the domain {domain} as phishing-like ({p:.3f}, above "
        f"{model.threshold}); what pushed it most: {parts}"
    )
