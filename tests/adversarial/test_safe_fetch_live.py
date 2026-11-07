"""Manual only: real sockets.

    LYNCEUS_LIVE_FETCH=1 python -m pytest tests/adversarial/test_safe_fetch_live.py

The fake-transport suite cannot show that connecting to a pinned IP, presenting the name for TLS,
and verifying the certificate work together on a real socket. This does, against example.com
(reserved for documentation), github.com (a real http-to-https redirect) and badssl.com (a public
TLS test service). It sends a handful of ordinary GET requests from this machine, which reveals
this machine's IP to those hosts. CDN edges can throttle or tarpit a client that sends many
requests quickly: if a run fails, wait and rerun before suspecting the code.
"""

import asyncio
import os

import pytest

from core.urls.safe_fetch import REDIRECTS, Outcome, follow, is_public

pytestmark = pytest.mark.skipif(
    os.environ.get("LYNCEUS_LIVE_FETCH") != "1", reason="manual: needs the network"
)


@pytest.mark.parametrize("url", ["http://example.com/", "https://example.com/"])
def test_real_sockets_pinned_ip_and_certificate_check(url: str) -> None:
    chain = asyncio.run(follow(url, enabled=True))
    assert chain.outcome is Outcome.COMPLETE, chain
    assert chain.hops and all(is_public(h.ip) for h in chain.hops)
    assert chain.hops[-1].status == 200


def test_a_real_redirect_is_followed_and_each_hop_is_checked() -> None:
    chain = asyncio.run(follow("http://github.com/", enabled=True))
    assert chain.outcome is Outcome.COMPLETE, chain
    assert len(chain.hops) >= 2 and chain.hops[0].status in REDIRECTS  # http to https
    assert all(is_public(h.ip) for h in chain.hops)
    assert chain.final_url and chain.final_url.startswith("https://")


def test_a_certificate_for_the_wrong_name_is_refused() -> None:
    # badssl.com is a public service for testing TLS clients. The control first: the service is
    # reachable and a good certificate passes, so the failure below can only be the certificate.
    control = asyncio.run(follow("https://badssl.com/", enabled=True))
    assert control.outcome is Outcome.COMPLETE, control
    bad = asyncio.run(follow("https://wrong.host.badssl.com/", enabled=True))
    assert bad.outcome is Outcome.FAILED and bad.hops == (), bad
