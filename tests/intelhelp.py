"""Shared fakes for the intelligence tests: a scripted provider and a settable clock."""

import asyncio
from collections.abc import Awaitable
from typing import Any

from core.contracts import VerdictState
from core.intel.base import Answer, Limit, Query, Sends, Subject
from core.urls.parse import ParsedUrl, parse_url


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
