"""Circuit breaker, rate limiter and answer cache. Pure: the clock is injected.

A breaker that is open, a limiter that says no and a cache miss all end in a stated provider status
(UNAVAILABLE, RATE_LIMITED, or a real call): none of them is ever read as "safe". Each class takes
a lock because message links are checked from worker threads, each with its own event loop.
"""

import hashlib
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from core.intel.base import Answer, Limit

Clock = Callable[[], float]


class BreakerState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class Breaker:
    """Opens after `failures` failures inside `window` seconds; after `cooldown` it lets one trial
    call through (half-open): success closes it, failure opens it again."""

    def __init__(
        self,
        failures: int = 5,
        window: float = 60.0,
        cooldown: float = 30.0,
        clock: Clock = time.monotonic,
    ) -> None:
        self.failures, self.window, self.cooldown, self.clock = failures, window, cooldown, clock
        self._recent: deque[float] = deque()
        self._opened_at: float | None = None
        self._trial = False
        self._lock = threading.Lock()

    def _state(self) -> BreakerState:
        if self._opened_at is None:
            return BreakerState.CLOSED
        if self.clock() - self._opened_at >= self.cooldown:
            return BreakerState.HALF_OPEN
        return BreakerState.OPEN

    @property
    def state(self) -> BreakerState:
        with self._lock:
            return self._state()

    def allow(self) -> bool:
        with self._lock:
            state = self._state()
            if state is BreakerState.CLOSED:
                return True
            if state is BreakerState.HALF_OPEN and not self._trial:
                self._trial = True  # exactly one call tests the provider
                return True
            return False

    def cancel_trial(self) -> None:
        """A permitted call was not made after all (for example the rate limiter said no)."""
        with self._lock:
            self._trial = False

    def success(self) -> None:
        with self._lock:
            self._recent.clear()
            self._opened_at, self._trial = None, False

    def failure(self) -> None:
        with self._lock:
            now = self.clock()
            self._trial = False
            if self._opened_at is not None:  # a failed trial: open again for a full cooldown
                self._opened_at = now
                return
            self._recent.append(now)
            while self._recent and now - self._recent[0] > self.window:
                self._recent.popleft()
            if len(self._recent) >= self.failures:
                self._opened_at = now


class RateLimiter:
    """Sliding windows for the documented per-minute and per-day limits, plus a hard pause after a
    429. State is in memory: a restart forgets the day's count (documented limitation)."""

    def __init__(self, limit: Limit, clock: Clock = time.monotonic) -> None:
        self.limit, self.clock = limit, clock
        self._minute: deque[float] = deque()
        self._day: deque[float] = deque()
        self._paused_until = 0.0
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        with self._lock:
            now = self.clock()
            if now < self._paused_until:
                return False
            for window, span in ((self._minute, 60.0), (self._day, 86_400.0)):
                while window and now - window[0] >= span:
                    window.popleft()
            per_minute, per_day = self.limit
            if per_minute is not None and len(self._minute) >= per_minute:
                return False
            if per_day is not None and len(self._day) >= per_day:
                return False
            self._minute.append(now)
            self._day.append(now)
            return True

    def pause(self, seconds: float) -> None:
        with self._lock:
            until = self.clock() + min(max(seconds, 1.0), 86_400.0)
            self._paused_until = max(self._paused_until, until)


@dataclass(frozen=True)
class Cached:
    answer: Answer
    queried_at: datetime
    latency_ms: int


class Cache:
    """Bounded LRU with expiry. Keys are hashes of (provider, name): no host is stored in clear.
    Only OK answers are ever put here; a failure is never cached as if it were an answer."""

    def __init__(self, max_entries: int = 10_000, clock: Clock = time.monotonic) -> None:
        self.max_entries, self.clock = max_entries, clock
        self._items: OrderedDict[str, tuple[float, Cached]] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def key(provider: str, name: str) -> str:
        return hashlib.sha256(f"{provider}\0{name}".encode()).hexdigest()

    def get(self, provider: str, name: str) -> Cached | None:
        k = self.key(provider, name)
        with self._lock:
            item = self._items.get(k)
            if item is None:
                return None
            if self.clock() >= item[0]:
                del self._items[k]
                return None
            self._items.move_to_end(k)
            return item[1]

    def put(self, provider: str, name: str, value: Cached, ttl: float) -> None:
        if ttl <= 0:
            return
        k = self.key(provider, name)
        with self._lock:
            self._items[k] = (self.clock() + ttl, value)
            self._items.move_to_end(k)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)
