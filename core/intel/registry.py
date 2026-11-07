"""Build the enabled providers from settings. Nothing is enabled by default.

Naming a provider in LYNCEUS_INTEL_PROVIDERS *is* the operator's authorization for what it sends
(ADR-015); an unknown or not-yet-built name stops start-up instead of being ignored, so a typo can
never silently mean "protected by a provider that is not running".
"""

import logging
from collections.abc import Callable

from core.config import Settings
from core.intel.base import Provider
from core.intel.feeds import FEEDS, FeedStore, ListFeed
from core.intel.http import make_client
from core.intel.orchestrator import Intel
from core.intel.rdap import Rdap
from core.intel.urlscan import UrlScan
from core.intel.virustotal import VirusTotal

log = logging.getLogger(__name__)
Builder = Callable[[Settings], Provider]


def _rdap(_settings: Settings) -> Provider:
    return Rdap(make_client())


def _virustotal(settings: Settings) -> Provider:
    key = settings.virustotal_api_key
    if key is None or not key.get_secret_value():
        raise ValueError("virustotal is enabled but LYNCEUS_VIRUSTOTAL_API_KEY is not set")
    return VirusTotal(make_client(), key.get_secret_value())


def _urlscan(settings: Settings) -> Provider:
    key = settings.urlscan_api_key
    if key is None or not key.get_secret_value():
        raise ValueError("urlscan is enabled but LYNCEUS_URLSCAN_API_KEY is not set")
    return UrlScan(make_client(), key.get_secret_value())


# Providers that ask an outside service. Each sends one public registered domain, nothing else.
QUERY_BUILDERS: dict[str, Builder] = {
    "rdap": _rdap,
    "virustotal": _virustotal,
    "urlscan": _urlscan,
}


def known() -> frozenset[str]:
    return frozenset(FEEDS) | frozenset(QUERY_BUILDERS)


def build_providers(settings: Settings) -> list[Provider]:
    names = settings.intel_enabled()
    unknown = names - known()
    if unknown:
        raise ValueError(
            f"unknown intelligence provider(s) in LYNCEUS_INTEL_PROVIDERS: "
            f"{', '.join(sorted(unknown))} (known: {', '.join(sorted(known()))})"
        )
    store = FeedStore(settings.data_dir / "feeds")
    providers: list[Provider] = []
    for name in sorted(names):
        providers.append(
            ListFeed(FEEDS[name], store) if name in FEEDS else QUERY_BUILDERS[name](settings)
        )
    return providers


def build_intel(settings: Settings) -> Intel | None:
    providers = build_providers(settings)
    if not providers:
        return None
    for p in providers:
        log.info("intelligence provider enabled: %s (sends: %s)", p.name, p.sends.value)
    return Intel(
        providers, deadline=settings.intel_deadline, email_links=settings.intel_email_links
    )
