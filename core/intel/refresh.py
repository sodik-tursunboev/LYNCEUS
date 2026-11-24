"""Keep the downloaded lists fresh while the core runs.

Before this, a list was downloaded only when someone ran `python -m core.intel sync`, so a core
that had been running for a day answered "feed is N hours old" for every link and the verdicts fell
back to UNKNOWN. This loop does what that command does, on the feeds the operator named in
LYNCEUS_INTEL_PROVIDERS and nothing else: it downloads a list (never anything about your links), at
most as often as the feed's own interval allows, and keeps the previous list on any failure.
"""

import asyncio
import dataclasses
import logging
from collections.abc import Collection, Mapping

from core.config import Settings
from core.intel.feeds import FEEDS, HOUR, FeedSpec, FeedStore, OnNew, sync
from core.intel.http import make_client

log = logging.getLogger(__name__)

# seconds between looks at what is due (sync() itself enforces each feed's own interval)
CHECK_EVERY = 600.0
# a failed feed is not asked again sooner: servers answer repeat callers with 429 / 509
RETRY_AFTER_ERROR = 1 * HOUR
# a feed offered without a key allows only a few downloads a day
KEYLESS_INTERVAL = 6 * HOUR


def feed_keys(settings: Settings) -> dict[str, str | None]:
    """The keys the operator configured for the feeds that take one (never logged)."""

    def secret(v: object) -> str | None:
        return v.get_secret_value() if v is not None and hasattr(v, "get_secret_value") else None

    return {
        "phishtank": secret(settings.phishtank_key),
        "urlhaus": secret(settings.urlhaus_auth_key),
    }


def spec_for(name: str, key: str | None) -> FeedSpec:
    """The feed's spec, slowed down when it is used without a key."""
    spec = FEEDS[name]
    if key is None and spec.keyless_url is not None and spec.interval < KEYLESS_INTERVAL:
        return dataclasses.replace(spec, interval=KEYLESS_INTERVAL)
    return spec


async def keep_fresh(
    store: FeedStore,
    names: Collection[str],
    keys: Mapping[str, str | None],
    *,
    check_every: float = CHECK_EVERY,
    retry_after: float = RETRY_AFTER_ERROR,
    on_new: OnNew | None = None,
) -> None:
    """Run until cancelled. A failure is logged by name and reason only; it never stops the loop.
    `on_new` hears what each updated list adds (DA5 re-check: `partial(raise_alerts, engine)`)."""
    loop = asyncio.get_running_loop()
    not_before: dict[str, float] = {}
    while True:
        due = [n for n in sorted(names) if loop.time() >= not_before.get(n, 0.0)]
        if due:
            try:
                async with make_client(timeout=30.0) as client:
                    for name in due:
                        out = await sync(
                            spec_for(name, keys.get(name)), store, client, key=keys.get(name),
                            on_new=on_new,
                        )  # fmt: skip
                        if out.status == "error":
                            not_before[name] = loop.time() + retry_after
                            log.warning(
                                "intelligence list %s was not updated: %s", name, out.detail
                            )
                        elif out.status == "updated":
                            log.info("intelligence list %s updated: %d entries", name, out.entries)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001  (never let a download problem stop the core)
                log.warning("intelligence list refresh failed; trying again later")
        await asyncio.sleep(check_every)
