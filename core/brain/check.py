"""The checks that stand between a model's answer and a verdict (AI1 P6).

A model can be wrong, and the text it read can be written to steer it. So a claim counts only when
code can confirm it from the same evidence: a quote must occur in the source text, a brand must not
own the domain, an endpoint must be one the code extracted itself.
"""

import re
import unicodedata

from core.urls import popular
from rules.url.data import Brand

MIN_QUOTE = 8  # characters after normalising: shorter "quotes" (a single word) prove nothing
_SPACE = re.compile(r"\s+")
_FOLD = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"',
                       "–": "-", "—": "-", " ": " "})  # fmt: skip


def norm(text: str) -> str:
    """Case, width, curly quotes, dashes and whitespace folded; invisible characters removed."""
    text = unicodedata.normalize("NFKC", text).translate(_FOLD).casefold()
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    return _SPACE.sub(" ", text).strip()


def quoted(quote: str, source: str) -> bool:
    q = norm(quote)
    return len(q) >= MIN_QUOTE and q in norm(source)


def verified(quotes: list[str], source: str) -> list[str]:
    """The quotes that really occur in `source`, at most three, each once."""
    out: list[str] = []
    for q in quotes:
        if quoted(q, source) and norm(q) not in (norm(o) for o in out):
            out.append(q)
    return out[:3]


def find_brand(name: str, known: tuple[Brand, ...]) -> Brand | None:
    """A listed brand by its name or one of its terms (folded); None for an unlisted brand."""
    n = norm(name)
    if not n:
        return None
    for b in known:
        if n == norm(b.name) or n in (norm(t) for t in b.terms):
            return b
    return None


def _label(registered_domain: str) -> str:
    return re.sub(r"[^a-z0-9]", "", registered_domain.split(".")[0].lower())


def foreign(name: str, brand: Brand | None, registered_domain: str | None) -> bool:
    """True when the page's domain is clearly not the named brand's: a listed brand whose domains do
    not include it, or an unlisted brand whose name the domain does not even carry. A popular
    domain is never called foreign for an unlisted brand (it may well be theirs)."""
    if not registered_domain:
        return False
    if brand is not None:
        return registered_domain not in brand.domains
    words = re.sub(r"[^a-z0-9]", "", norm(name))
    if len(words) < 3 or popular.is_popular(registered_domain):
        return False
    return words not in _label(registered_domain) and _label(registered_domain) not in words
