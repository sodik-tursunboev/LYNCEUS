"""Ask the enabled providers about one subject: concurrently, bounded, and never fatally.

Per provider: cache, then circuit breaker, then rate limit, then the call under its own timeout.
Every path ends in a stated `ProviderResult`; a provider that fails, is slow, is paused or is
refused is *recorded as such* and never counts as an answer, least of all as "safe". The overall
deadline bounds how long a caller waits; a slow provider's late answer still warms the cache.
"""

import asyncio
import logging
import re
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any

from core.contracts import ProviderResult, ProviderStatus
from core.intel.base import (
    ANSWER_STATES,
    MAX_DETAIL,
    Answer,
    IntelOutcome,
    IntelResult,
    Provider,
    ProviderError,
    ProviderRateLimited,
    ProviderUnavailable,
    Query,
    Sends,
    Subject,
)
from core.intel.resilience import Breaker, BreakerState, Cache, Cached, RateLimiter

log = logging.getLogger(__name__)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
DEFAULT_DEADLINE = 2.0


def _clean(text: str | None) -> str | None:
    if text is None:
        return None
    return _CONTROL.sub(" ", text).strip()[:MAX_DETAIL] or None


class Intel:
    def __init__(
        self,
        providers: Sequence[Provider],
        *,
        deadline: float = DEFAULT_DEADLINE,
        cache: Cache | None = None,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        email_links: bool = False,
    ) -> None:
        self.providers = tuple(providers)
        self.deadline, self.clock, self.now = deadline, clock, now
        self.email_links = email_links
        self.cache = cache or Cache(clock=clock)
        self.breakers = {p.name: Breaker(clock=clock) for p in self.providers}
        self.limiters = {
            p.name: RateLimiter(p.limit, clock=clock) for p in self.providers if p.limit
        }
        self._late: set[asyncio.Future[IntelResult]] = set()

    # ---- what each provider may be asked -------------------------------------------------------

    def _query_for(self, p: Provider, s: Subject, source: str) -> tuple[Query | None, str]:
        if p.sends is Sends.NOTHING:
            return Query(name=s.name, host=s.host, url_sha256=s.url_sha256), ""
        if source != "url" and not self.email_links:
            return None, "links from messages are not sent to outside services"
        if s.name is None:
            return None, "not a public name"
        return Query(name=s.name), ""  # a HOST provider gets the name and nothing else

    # ---- one provider --------------------------------------------------------------------------

    def _result(
        self,
        p: Provider,
        status: ProviderStatus,
        started: float,
        answer: Answer | None = None,
        detail: str | None = None,
        *,
        cached: Cached | None = None,
    ) -> IntelResult:
        if cached is not None:
            answer = cached.answer
        ok = status is ProviderStatus.OK and answer is not None
        result = ProviderResult(
            provider=p.name,
            status=status,
            state=answer.state if ok and answer else None,
            queried_at=cached.queried_at if cached else self.now(),
            latency_ms=cached.latency_ms if cached else int((self.clock() - started) * 1000),
            provenance=(answer.provenance if answer else p.source)[:200] or p.source,
            detail=_clean(detail if detail is not None else (answer.detail if answer else None)),
        )
        facts: dict[str, Any] = dict(answer.facts) if ok and answer else {}
        return IntelResult(result, facts, cached is not None)

    async def _ask(self, p: Provider, q: Query) -> IntelResult:
        started = self.clock()
        breaker, limiter = self.breakers[p.name], self.limiters.get(p.name)
        try:
            if p.sends is Sends.HOST and q.name and (hit := self.cache.get(p.name, q.name)):
                return self._result(p, ProviderStatus.OK, started, cached=hit, detail="cached")
            if not breaker.allow():
                return self._result(p, ProviderStatus.UNAVAILABLE, started, detail="circuit open")
            if limiter is not None and not limiter.try_acquire():
                breaker.cancel_trial()
                return self._result(p, ProviderStatus.RATE_LIMITED, started, detail="limit reached")
            try:
                answer = await asyncio.wait_for(p.lookup(q), p.timeout)
            except TimeoutError:
                breaker.failure()
                return self._result(p, ProviderStatus.TIMEOUT, started, detail="no answer in time")
            except ProviderRateLimited as e:
                breaker.cancel_trial()
                if limiter is not None:
                    limiter.pause(e.retry_after or 60.0)
                return self._result(p, ProviderStatus.RATE_LIMITED, started, detail="told to wait")
            except ProviderUnavailable as e:
                breaker.cancel_trial()
                return self._result(p, ProviderStatus.UNAVAILABLE, started, detail=e.reason)
            except ProviderError as e:
                breaker.failure()
                return self._result(p, ProviderStatus.ERROR, started, detail=e.reason)
            except Exception as e:  # noqa: BLE001  (the message may hold a URL or a key: type only)
                log.warning("provider %s failed: %s", p.name, type(e).__name__)
                breaker.failure()
                return self._result(p, ProviderStatus.ERROR, started, detail=type(e).__name__)
            if (
                not isinstance(answer, Answer)
                or answer.state not in ANSWER_STATES
                or not isinstance(answer.provenance, str)
                or not answer.provenance.strip()
            ):
                breaker.failure()
                return self._result(p, ProviderStatus.ERROR, started, detail="invalid answer")
            breaker.success()
            outcome = self._result(p, ProviderStatus.OK, started, answer)
            if p.sends is Sends.HOST and q.name:
                value = Cached(answer, outcome.result.queried_at, outcome.result.latency_ms)
                self.cache.put(p.name, q.name, value, p.ttl)
            return outcome
        except asyncio.CancelledError:
            breaker.cancel_trial()
            raise
        except Exception as e:  # noqa: BLE001  (a bug here must not take the caller down)
            log.warning("intel bookkeeping failed for %s: %s", p.name, type(e).__name__)
            return self._result(p, ProviderStatus.ERROR, started, detail="internal error")

    # ---- all providers -------------------------------------------------------------------------

    async def query(self, subject: Subject, source: str = "url") -> IntelOutcome:
        started = self.clock()
        tasks: dict[str, asyncio.Future[IntelResult]] = {}
        skipped: list[tuple[str, str]] = []
        for p in self.providers:
            q, why = self._query_for(p, subject, source)
            if q is None:
                skipped.append((p.name, why))
            else:
                tasks[p.name] = asyncio.ensure_future(self._ask(p, q))
        if tasks:
            await asyncio.wait(tasks.values(), timeout=self.deadline)
        results: list[IntelResult] = []
        for p in self.providers:
            task = tasks.get(p.name)
            if task is None:
                continue
            if task.done() and not task.cancelled():
                results.append(task.result())
            else:  # still running: report the wait, let it finish and warm the cache
                self._late.add(task)
                task.add_done_callback(self._late.discard)
                results.append(
                    self._result(p, ProviderStatus.TIMEOUT, started, detail="deadline exceeded")
                )
        return IntelOutcome(tuple(results), tuple(skipped))

    def query_sync(self, subject: Subject, source: str = "url") -> IntelOutcome:
        """For a worker thread with no event loop (message links are analysed in one)."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.query(subject, source))
        raise RuntimeError("query_sync was called inside an event loop: use query()")

    async def settle(self) -> None:
        """Wait for answers that missed their deadline (tests and shutdown)."""
        if self._late:
            await asyncio.gather(*self._late, return_exceptions=True)

    async def aclose(self) -> None:
        """Close the HTTP clients of providers that own one (application shutdown)."""
        await self.settle()
        for p in self.providers:
            close = getattr(p, "aclose", None)
            if close is not None:
                await close()

    def health(self) -> list[dict[str, Any]]:
        out = []
        for p in self.providers:
            state = self.breakers[p.name].state
            out.append(
                {"provider": p.name, "sends": p.sends.value, "breaker": state.value,
                 "usable": state is not BreakerState.OPEN}
            )  # fmt: skip
        return out
