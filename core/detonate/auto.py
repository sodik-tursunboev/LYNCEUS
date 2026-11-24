"""Open risky links in the sandbox without a click (DA1 P3).

The owner's decision (2026-11-16): links the browser extension checks and links found in mail. A
link is opened when the address alone already looks wrong (SUSPICIOUS) or shows at least one sign
without a verdict (UNKNOWN with a signal), and it is not on a brand's own domain or the popular
list. Measured on D1's live pages, the page doubled what was caught (16.9% to 37.3%), but only when
someone pressed "Open in sandbox".

What this costs and how it is bounded:
- every opening is a visit from this computer's connection (the site sees its IP address), and for
  a link from mail it can tell the sender the message was read or use up a one-time link: the
  owner accepted that;
- each address is opened at most once per window (an hour by default), at most `max_pending` wait,
  and at most `workers` run at once: a flood of links cannot turn into a flood of visits;
- the deeper verdict is recorded as its own event and, for the browser, given back the next time
  the same address is checked, but only when it is graver: an opened page never lowers a verdict.
Nothing here logs an address.
"""

import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from core.contracts import VerdictState
from core.detection.engine import UrlAnalysis, _allowlisted, analyze_url
from core.urls.popular import is_popular

log = logging.getLogger(__name__)

_GRAVITY = {
    VerdictState.BENIGN: 0,
    VerdictState.UNKNOWN: 1,
    VerdictState.ERROR: 1,
    VerdictState.SUSPICIOUS: 2,
    VerdictState.MALICIOUS: 3,
}
SOURCES = frozenset({"browser", "mail"})
DEEPER_SECONDS = 12.0  # the sandbox takes 5 to 10 s (DA5 1b): when the browser should ask again


def worth_opening(analysis: UrlAnalysis) -> bool:
    """A web address whose own verdict is SUSPICIOUS, or UNKNOWN with a sign, off the brands' own
    domains and the popular list. MALICIOUS is left alone: it is already blocked or warned."""
    u = analysis.url
    if u is None or u.scheme not in ("http", "https") or not u.host:
        return False
    if _allowlisted(u) or is_popular(u.registered_domain):
        return False
    state = analysis.verdict.state
    return state is VerdictState.SUSPICIOUS or (
        state is VerdictState.UNKNOWN and bool(analysis.verdict.signals)
    )


class AutoOpener:
    """`open_page(raw, start)` opens the page and returns the deeper verdict and the page's status;
    `record(deeper, source, page_status)` stores it (an event, an audit row)."""

    def __init__(
        self,
        open_page: Callable[[str, UrlAnalysis], tuple[UrlAnalysis, str]],
        record: Callable[[UrlAnalysis, str, str], None],
        *,
        sources: frozenset[str] = SOURCES,
        workers: int = 2,
        max_pending: int = 8,
        window_seconds: float = 3600.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._open, self._record, self.sources = open_page, record, sources
        self._max_pending, self._window, self._clock = max_pending, window_seconds, clock
        self._pool = ThreadPoolExecutor(workers, thread_name_prefix="lynceus-auto-open")
        self._lock = threading.Lock()
        self._pending = 0
        self._opened: dict[str, float] = {}  # url sha256 -> when it was queued
        self._running: dict[str, float] = {}  # queued or being opened now (a failure leaves it)
        self._deeper: dict[str, tuple[float, UrlAnalysis]] = {}
        self.dropped = 0  # links not opened because the queue was full

    def consider(self, raw: str, analysis: UrlAnalysis, source: str) -> bool:
        """Queue the page if it is worth opening and was not opened recently. True when queued."""
        if source not in self.sources or not worth_opening(analysis) or analysis.url is None:
            return False
        key, now = analysis.url.url_sha256, self._clock()
        with self._lock:
            self._forget(now)
            if key in self._opened:
                return False
            if self._pending >= self._max_pending:
                self.dropped += 1
                return False
            self._opened[key] = self._running[key] = now
            self._pending += 1
        self._pool.submit(self._run, raw, analysis, source, key)
        return True

    def consider_link(self, raw: str, source: str) -> bool:
        """A link found in a message: judged by its address alone (offline, fast), then
        considered."""
        return self.consider(raw, analyze_url(raw), source)

    def deeper(self, analysis: UrlAnalysis) -> UrlAnalysis | None:
        """The verdict the opened page gave this exact address within the window, if graver."""
        if analysis.url is None:
            return None
        with self._lock:
            self._forget(self._clock())
            found = self._deeper.get(analysis.url.url_sha256)
        if found is None:
            return None
        deeper = found[1]
        return deeper if _GRAVITY[deeper.verdict.state] > _GRAVITY[analysis.verdict.state] else None

    def eta(self, analysis: UrlAnalysis) -> int | None:
        """Seconds until the page being opened for this address should be judged, or None when no
        opening is queued or running for it (not opened, finished, or failed)."""
        if analysis.url is None:
            return None
        with self._lock:
            queued = self._running.get(analysis.url.url_sha256)
        return None if queued is None else max(2, round(DEEPER_SECONDS - (self._clock() - queued)))

    def wait_idle(self, timeout: float = 30.0) -> bool:
        """For tests and shutdown: True once nothing is queued or running."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            with self._lock:
                if self._pending == 0:
                    return True
            time.sleep(0.01)
        return False

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    def _run(self, raw: str, analysis: UrlAnalysis, source: str, key: str) -> None:
        try:
            deeper, status = self._open(raw, analysis)
            with self._lock:
                self._deeper[key] = (self._clock(), deeper)
            self._record(deeper, source, status)
        except Exception:  # one failed page must not stop the next; no address in the log
            log.exception("an automatic page check failed")
        finally:
            with self._lock:
                self._pending -= 1
                self._running.pop(key, None)

    def _forget(self, now: float) -> None:
        """Drop what is older than the window (called with the lock held)."""
        for table in (self._opened, self._deeper):
            for key in [
                k
                for k, v in table.items()
                if now - (v if isinstance(v, float) else v[0]) >= self._window
            ]:
                del table[key]


def parse_sources(value: str) -> frozenset[str]:
    """`LYNCEUS_AUTO_DETONATION`: empty (off), "browser", "mail", or both separated by a comma."""
    chosen = frozenset(p.strip().lower() for p in value.split(",") if p.strip())
    unknown = chosen - SOURCES
    if unknown:
        raise ValueError(f"LYNCEUS_AUTO_DETONATION takes browser and mail, not {sorted(unknown)}")
    return chosen
