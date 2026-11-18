"""The one gate in front of every outside query provider (ADR-015).

Only a *public registered domain* may be sent: a name under a suffix the Public Suffix List knows.
Never a path, query, fragment or user name (a `Query` cannot carry them), never an IP address, a
single-label name, or anything under a reserved or internal suffix (`.test`, `.local`, `.internal`,
`.lan`, ...). That also means the synthetic corpus, which lives on `.test`, can never be sent.
Since DA2 also never an established site: a domain on the popular list or a brand's own domain.
"""

import re

from core.urls import popular, psl
from core.urls.parse import HostKind, ParsedUrl
from rules.url.data import official_domains

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAX_NAME = 253
# Names the Public Suffix List knows but that are not on the public internet (RFC 6761, 7686, 8375,
# 9476): a home printer is `printer.home.arpa`, an onion service is reachable only through Tor.
_NOT_PUBLIC = (
    "home.arpa",
    "arpa",
    "onion",
    "alt",
    "example",
    "invalid",
    "localhost",
    "local",
    "test",
    "internal",
    "lan",
    "corp",
    "home",
    "intranet",
    "private",
)


def public_name(u: ParsedUrl) -> str | None:
    """The registered domain to ask an outside service about, or None: ask nobody."""
    if u.scheme not in ("http", "https") or u.host_kind is not HostKind.DOMAIN:
        return None
    host, name = u.host, u.registered_domain
    if not host or not name or len(name) > _MAX_NAME or not psl.known_suffix(host):
        return None
    if any(host == s or host.endswith("." + s) for s in _NOT_PUBLIC):
        return None
    labels = name.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return None  # also rejects non-ASCII and underscores: IDNs go as punycode or not at all
    # DA2: an established site (the popular list, or a brand's own domain) is not asked about: an
    # outside service knows nothing useful about google.com, and without this every site visited
    # would be sent. The local list feeds still see it (they match on this machine).
    if popular.is_popular(name) or name in official_domains():
        return None
    return name
