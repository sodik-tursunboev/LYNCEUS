"""Build the enabled providers from settings. Nothing is enabled by default.

Naming a provider in MIRAGE_INTEL_PROVIDERS *is* the operator's authorization for what it sends
(ADR-015); an unknown or not-yet-built name stops start-up instead of being ignored, so a typo can
never silently mean "protected by a provider that is not running".
"""

import logging
from collections.abc import Callable

from core.config import Settings
from core.intel.base import Provider
from core.intel.feeds import FEEDS, FeedStore, ListFeed
from core.intel.orchestrator import Intel

log = logging.getLogger(__name__)
Builder = Callable[[Settings], Provider]
# Providers that ask an outside service are registered here (RDAP, VirusTotal: M3 step 4).
QUERY_BUILDERS: dict[str, Builder] = {}


def known() -> frozenset[str]:
    return frozenset(FEEDS) | frozenset(QUERY_BUILDERS)


def build_providers(settings: Settings) -> list[Provider]:
    names = settings.intel_enabled()
    unknown = names - known()
    if unknown:
        raise ValueError(
            f"unknown intelligence provider(s) in MIRAGE_INTEL_PROVIDERS: "
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
