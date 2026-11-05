"""The intelligence core: egress gate, breaker, limiter, cache and orchestrator, with fake providers
and fault injection. No network and no sleeping beyond a few tens of milliseconds."""

import asyncio
import logging
from collections.abc import Awaitable
from datetime import UTC, datetime
from typing import Any

import pytest

from core.contracts import ProviderStatus, VerdictState
from core.intel.base import (
    Answer,
    IntelOutcome,
    Limit,
    ProviderError,
    ProviderRateLimited,
    Query,
    Sends,
    Subject,
)
from core.intel.egress import public_name
from core.intel.orchestrator import Intel
from core.intel.resilience import Breaker, BreakerState, Cache, Cached, RateLimiter
from core.urls.parse import ParsedUrl, parse_url

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


def parsed(url: str) -> ParsedUrl:
    u = parse_url(url)
    assert isinstance(u, ParsedUrl), url
    return u


def subject(url: str) -> Subject:
    return Subject.from_parsed(parsed(url))


def run[T](coro: Awaitable[T]) -> T:
    return asyncio.run(coro)  # type: ignore[arg-type]


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class Fake:
    """A provider that does what it is told: `how` is an Answer, an exception or a callable."""

    source = "fake feed"

    def __init__(
        self,
        name: str = "fake",
        how: Any = None,
        *,
        sends: Sends = Sends.NOTHING,
        timeout: float = 1.0,
        limit: Limit | None = None,
        ttl: float = 0.0,
    ) -> None:
        self.name, self.sends, self.timeout, self.limit, self.ttl = name, sends, timeout, limit, ttl
        self.how = how if how is not None else Answer(VerdictState.UNKNOWN, "fake v1")
        self.queries: list[Query] = []

    @property
    def calls(self) -> int:
        return len(self.queries)

    async def lookup(self, q: Query) -> Answer:
        self.queries.append(q)
        how = self.how
        if isinstance(how, BaseException):
            raise how
        if callable(how):
            result = how(q)
            return await result if asyncio.iscoroutine(result) else result  # type: ignore[no-any-return]
        return how  # type: ignore[no-any-return]


def ask(intel: Intel, url: str = "https://www.example.com/a", source: str = "url") -> IntelOutcome:
    async def go() -> IntelOutcome:
        outcome = await intel.query(subject(url), source)
        await intel.settle()
        return outcome

    return run(go())


def statuses(outcome: IntelOutcome) -> dict[str, ProviderStatus]:
    return {r.result.provider: r.result.status for r in outcome.results}


# ---- the egress gate -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "name"),
    [
        ("https://www.example.com/path?token=SECRET#frag", "example.com"),
        ("http://user:pw@login.example.org:8443/x", "example.org"),  # pragma: allowlist secret
        ("https://a.b.c.example.co.uk/", "example.co.uk"),
        ("https://xn--mnchen-3ya.example.de/", "example.de"),
        ("https://someone.github.io/page", "someone.github.io"),
    ],
)
def test_a_public_name_is_the_registered_domain_and_nothing_else(url: str, name: str) -> None:
    assert public_name(parsed(url)) == name


@pytest.mark.parametrize(
    "url",
    [
        "https://paypal-login.test/",  # the synthetic corpus can never be sent
        "https://host.invalid/",
        "https://printer.local/",
        "https://intranet/",
        "https://nas.lan/",
        "https://203.0.113.5/",
        "https://[2001:db8::1]/",
        "http://localhost:8080/",
        "https://app.internal/",
        "ftp://files.example.com/",
        "javascript:alert(1)",
        "data:text/html,x",
        "mailto:a@example.com",
        "file:///etc/hosts",
    ],
)
def test_nothing_else_is_ever_a_public_name(url: str) -> None:
    parsed_url = parse_url(url)
    if isinstance(parsed_url, ParsedUrl):
        assert public_name(parsed_url) is None


def test_a_query_for_an_outside_service_cannot_carry_a_url() -> None:
    s = subject("https://www.example.com/reset?token=SECRET#x")
    fake = Fake(sends=Sends.HOST)
    ask(Intel([fake]), "https://www.example.com/reset?token=SECRET#x")
    assert fake.queries == [Query(name="example.com")]
    assert s.url_sha256 not in repr(fake.queries)


def test_a_local_list_provider_gets_the_host_and_hash_only() -> None:
    fake = Fake(sends=Sends.NOTHING)
    ask(Intel([fake]), "https://www.example.com/reset?token=SECRET#x")
    (q,) = fake.queries
    assert (q.name, q.host) == ("example.com", "www.example.com") and len(q.url_sha256) == 64
    assert "SECRET" not in repr(q)


# ---- breaker -------------------------------------------------------------------------------------


def test_the_breaker_opens_after_repeated_failures_and_recovers_through_one_trial() -> None:
    clock = Clock()
    b = Breaker(failures=3, window=60, cooldown=30, clock=clock)
    assert b.state is BreakerState.CLOSED and b.allow()
    for _ in range(3):
        b.failure()
    assert b.state is BreakerState.OPEN and not b.allow()
    clock.t += 31
    assert b.state is BreakerState.HALF_OPEN
    assert b.allow() and not b.allow()  # exactly one trial at a time
    b.failure()  # the trial failed: open again for a full cooldown
    assert b.state is BreakerState.OPEN
    clock.t += 31
    assert b.allow()
    b.success()
    assert b.state is BreakerState.CLOSED and b.allow()


def test_a_failed_trial_reopens_even_when_the_old_failures_have_aged_out() -> None:
    clock = Clock()
    b = Breaker(failures=3, window=5, cooldown=30, clock=clock)
    for _ in range(3):
        b.failure()
    clock.t += 31  # the failures are older than the window now
    assert b.allow()
    b.failure()
    assert b.state is BreakerState.OPEN and not b.allow()


def test_old_failures_do_not_count() -> None:
    clock = Clock()
    b = Breaker(failures=3, window=60, clock=clock)
    b.failure()
    b.failure()
    clock.t += 61
    b.failure()
    assert b.state is BreakerState.CLOSED


# ---- limiter -------------------------------------------------------------------------------------


def test_the_limiter_enforces_minute_and_day_windows_and_a_pause() -> None:
    clock = Clock()
    lim = RateLimiter(Limit(per_minute=4, per_day=6), clock=clock)
    assert [lim.try_acquire() for _ in range(5)] == [True, True, True, True, False]
    clock.t += 61
    assert [lim.try_acquire() for _ in range(3)] == [True, True, False]  # day limit of 6
    clock.t += 86_400
    assert lim.try_acquire()
    lim.pause(120)
    clock.t += 60
    assert not lim.try_acquire()
    clock.t += 61
    assert lim.try_acquire()


# ---- cache ---------------------------------------------------------------------------------------


def test_the_cache_expires_evicts_and_stores_no_host_in_clear() -> None:
    clock = Clock()
    cache = Cache(max_entries=2, clock=clock)
    value = Cached(Answer(VerdictState.UNKNOWN, "x"), NOW, 5)
    cache.put("p", "a.example.com", value, ttl=10)
    assert cache.get("p", "a.example.com") is value
    clock.t += 11
    assert cache.get("p", "a.example.com") is None
    for name in ("one", "two", "three"):
        cache.put("p", name, value, ttl=100)
    assert cache.get("p", "one") is None and cache.get("p", "three") is value
    assert all("example" not in k and "three" not in k for k in cache._items)
    cache.put("p", "zero", value, ttl=0)
    assert cache.get("p", "zero") is None


# ---- the orchestrator ----------------------------------------------------------------------------


def test_providers_answer_independently_and_in_order() -> None:
    a = Fake("a", Answer(VerdictState.MALICIOUS, "feed 1", "listed", {"listed": True}))
    b = Fake("b", Answer(VerdictState.UNKNOWN, "feed 2"))
    out = ask(Intel([a, b]))
    assert [r.result.provider for r in out.results] == ["a", "b"]
    assert [r.result.state for r in out.results] == [VerdictState.MALICIOUS, VerdictState.UNKNOWN]
    assert out.results[0].facts == {"listed": True} and out.results[0].result.provenance == "feed 1"


FAILURES: dict[str, tuple[Any, ProviderStatus]] = {
    "timeout": (TimeoutError(), ProviderStatus.TIMEOUT),
    "hang": (lambda q: asyncio.sleep(5), ProviderStatus.TIMEOUT),
    "error": (ProviderError("http 500"), ProviderStatus.ERROR),
    "crash": (RuntimeError("secret-key-123 in https://x/?k=secret-key-123"), ProviderStatus.ERROR),
    "rate": (ProviderRateLimited(30), ProviderStatus.RATE_LIMITED),
    "garbage": (Answer(VerdictState.BENIGN, "x"), ProviderStatus.ERROR),  # never BENIGN
    "not-an-answer": ({"state": "MALICIOUS"}, ProviderStatus.ERROR),
    "no-provenance": (Answer(VerdictState.MALICIOUS, "  "), ProviderStatus.ERROR),
}


@pytest.mark.parametrize("name", sorted(FAILURES))
def test_every_failure_is_a_stated_status_with_no_opinion(name: str) -> None:
    how, status = FAILURES[name]
    fake = Fake("p", how, timeout=0.05)
    (r,) = ask(Intel([fake])).results
    assert r.result.status is status and r.result.state is None and r.facts == {}
    assert r.result.provenance == "fake feed"  # a failure still cites its source


def test_an_exception_text_never_reaches_the_result_or_the_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    fake = Fake("p", RuntimeError("secret-key-123 https://x/?k=secret-key-123"))
    (r,) = ask(Intel([fake])).results
    assert r.result.detail == "RuntimeError"
    assert "secret-key-123" not in caplog.text and "secret-key-123" not in repr(r)


def test_all_providers_failing_still_returns_an_outcome_with_no_opinions() -> None:
    fakes = [Fake(str(i), how, timeout=0.05) for i, (how, _) in enumerate(FAILURES.values())]
    out = ask(Intel(fakes))
    assert len(out.results) == len(fakes)
    assert all(
        r.result.state is None and r.result.status is not ProviderStatus.OK for r in out.results
    )


def test_detail_is_cleaned_and_bounded() -> None:
    fake = Fake("p", Answer(VerdictState.SUSPICIOUS, "feed", "line1\nline2\x00" + "x" * 1000))
    (r,) = ask(Intel([fake])).results
    assert r.result.detail is not None and len(r.result.detail) <= 300
    assert "\n" not in r.result.detail and "\x00" not in r.result.detail


def test_the_deadline_bounds_the_wait_and_the_late_answer_warms_the_cache() -> None:
    async def slow(q: Query) -> Answer:
        await asyncio.sleep(0.15)
        return Answer(VerdictState.SUSPICIOUS, "slow feed")

    slow_p = Fake("slow", slow, sends=Sends.HOST, timeout=1.0, ttl=60)
    fast_p = Fake("fast", Answer(VerdictState.UNKNOWN, "fast"))
    intel = Intel([slow_p, fast_p], deadline=0.03)

    async def go() -> tuple[IntelOutcome, IntelOutcome]:
        first = await intel.query(subject("https://www.example.com/"))
        await intel.settle()  # the late answer lands
        second = await intel.query(subject("https://www.example.com/other"))
        return first, second

    first, second = run(go())
    assert statuses(first) == {"slow": ProviderStatus.TIMEOUT, "fast": ProviderStatus.OK}
    assert first.results[0].result.detail == "deadline exceeded"
    assert statuses(second)["slow"] is ProviderStatus.OK and second.results[0].cached
    assert slow_p.calls == 1


def test_a_cached_answer_avoids_the_call_and_a_failure_is_never_cached() -> None:
    ok = Fake("ok", Answer(VerdictState.SUSPICIOUS, "feed"), sends=Sends.HOST, ttl=60)
    bad = Fake("bad", ProviderError("http 500"), sends=Sends.HOST, ttl=60)
    intel = Intel([ok, bad])
    ask(intel)
    second = ask(intel, "https://other.example.com/x")  # same registered domain
    assert (ok.calls, bad.calls) == (1, 2)
    assert second.results[0].cached and not second.results[1].cached
    assert second.results[1].result.status is ProviderStatus.ERROR


def test_the_breaker_stops_calls_to_a_failing_provider_then_lets_one_through() -> None:
    clock = Clock()
    bad = Fake("bad", ProviderError("http 503"))
    intel = Intel([bad], clock=clock)
    for _ in range(5):
        ask(intel)
    assert bad.calls == 5
    out = ask(intel)
    assert statuses(out) == {"bad": ProviderStatus.UNAVAILABLE} and bad.calls == 5
    assert out.results[0].result.detail == "circuit open" and out.results[0].result.state is None
    clock.t += 31
    bad.how = Answer(VerdictState.UNKNOWN, "feed")
    assert statuses(ask(intel)) == {"bad": ProviderStatus.OK} and bad.calls == 6
    assert statuses(ask(intel)) == {"bad": ProviderStatus.OK}


def test_the_limiter_refuses_without_calling_and_a_429_pauses_the_provider() -> None:
    clock = Clock()
    p = Fake("p", Answer(VerdictState.UNKNOWN, "feed"), limit=Limit(per_minute=2))
    intel = Intel([p], clock=clock)
    assert [statuses(ask(intel))["p"] for _ in range(3)] == [
        ProviderStatus.OK, ProviderStatus.OK, ProviderStatus.RATE_LIMITED,
    ]  # fmt: skip
    assert p.calls == 2
    clock.t += 61
    p.how = ProviderRateLimited(90)
    assert statuses(ask(intel))["p"] is ProviderStatus.RATE_LIMITED and p.calls == 3
    p.how = Answer(VerdictState.UNKNOWN, "feed")
    clock.t += 30
    assert statuses(ask(intel))["p"] is ProviderStatus.RATE_LIMITED and p.calls == 3  # still paused
    clock.t += 61
    assert statuses(ask(intel))["p"] is ProviderStatus.OK


def test_a_429_does_not_open_the_breaker() -> None:
    p = Fake("p", ProviderRateLimited(1))
    intel = Intel([p], clock=Clock())
    for _ in range(10):
        ask(intel)
    assert intel.breakers["p"].state is BreakerState.CLOSED


def test_an_outside_provider_is_skipped_for_names_that_are_not_public() -> None:
    outside = Fake("outside", sends=Sends.HOST)
    local = Fake("local", sends=Sends.NOTHING)
    out = ask(Intel([outside, local]), "https://login.paypal-secure.test/a?x=1")
    assert outside.calls == 0 and local.calls == 1
    assert out.skipped == (("outside", "not a public name"),)
    assert [r.result.provider for r in out.results] == ["local"]


def test_message_links_reach_outside_services_only_when_the_operator_allows_it() -> None:
    outside = Fake("outside", sends=Sends.HOST)
    local = Fake("local", sends=Sends.NOTHING)
    out = ask(Intel([outside, local]), source="email")
    assert outside.calls == 0 and local.calls == 1 and out.skipped[0][0] == "outside"
    allowed = ask(Intel([outside, local], email_links=True), source="email")
    assert outside.calls == 1 and not allowed.skipped


def test_providers_run_concurrently() -> None:
    async def nap(q: Query) -> Answer:
        await asyncio.sleep(0.1)
        return Answer(VerdictState.UNKNOWN, "feed")

    fakes = [Fake(str(i), nap) for i in range(5)]

    async def go() -> float:
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        await Intel(fakes, deadline=2).query(subject("https://www.example.com/"))
        return loop.time() - t0

    assert run(go()) < 0.4  # five 0.1 s providers in well under 0.5 s


def test_no_providers_is_an_empty_outcome() -> None:
    out = ask(Intel([]))
    assert out.results == () and out.skipped == () and out.provider_results == []


def test_health_reports_breaker_state_and_what_each_provider_sends() -> None:
    health = Intel([Fake("a", sends=Sends.HOST), Fake("b")]).health()
    assert health == [
        {"provider": "a", "sends": "host", "breaker": "closed", "usable": True},
        {"provider": "b", "sends": "nothing", "breaker": "closed", "usable": True},
    ]
