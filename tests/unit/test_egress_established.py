"""DA2 P3: an established site (the popular list, a brand's own domain) is never given to an outside
provider; an unknown site still is; the local list feeds still see both."""

import asyncio

from intelhelp import Fake, parsed, subject

from core.intel.base import IntelOutcome, Query, Sends
from core.intel.egress import public_name
from core.intel.orchestrator import Intel
from core.urls import popular


def ask(intel: Intel, url: str) -> IntelOutcome:
    async def go() -> IntelOutcome:
        outcome = await intel.query(subject(url))
        await intel.settle()
        return outcome

    return asyncio.run(go())


def test_an_established_site_is_never_given_to_an_outside_provider() -> None:
    popular.use(frozenset({"bigsite.com"}))
    outside = Fake(sends=Sends.HOST)
    for url in (
        "https://www.bigsite.com/a?b=1",
        "https://paypal.com/signin",
    ):  # popular; a brand's own
        assert public_name(parsed(url)) is None
        out = ask(Intel([outside]), url)
        assert not out.results and out.skipped and "established" in out.skipped[0][1]
    assert outside.queries == []


def test_an_unknown_site_is_still_asked() -> None:
    popular.use(frozenset({"bigsite.com"}))
    outside = Fake(sends=Sends.HOST)
    url = "https://www.rarely-seen-shop.com/a?token=SECRET"
    assert public_name(parsed(url)) == "rarely-seen-shop.com"
    ask(Intel([outside]), url)
    assert outside.queries == [Query(name="rarely-seen-shop.com")]


def test_the_local_lists_still_see_an_established_site() -> None:
    popular.use(frozenset({"bigsite.com"}))
    local = Fake(sends=Sends.NOTHING)
    ask(Intel([local]), "https://www.bigsite.com/a")
    (q,) = local.queries
    assert q.host == "www.bigsite.com" and len(q.url_sha256) == 64
