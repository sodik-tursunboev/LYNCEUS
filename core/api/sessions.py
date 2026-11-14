"""Console sign-in (H1 A1): the console never holds the API token.

The agent, which holds the API token, asks for a one-time code; the console trades it, once and
within a minute, for a session token of its own. A person who types the API token at the sign-in
screen gets a session the same way, and the console forgets the API token at once. A session acts
only as the person at the console: it is always the actor `user`, never `policy`, never the agent.
Sessions live in memory, so restarting the core signs the console out. Only SHA-256 digests of
codes and sessions are kept.
"""

import hashlib
import secrets
import threading
import time
from collections.abc import Callable
from typing import Literal

Caller = Literal["agent", "console"]
CODE_SECONDS = 60
SESSION_SECONDS = 12 * 3600
MAX_LIVE = 256  # codes or sessions at once; a flood is refused, not stored


def _key(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


class ConsoleSessions:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._codes: dict[str, float] = {}
        self._sessions: dict[str, float] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        for table in (self._codes, self._sessions):
            for k in [k for k, t in table.items() if t <= now]:
                del table[k]

    def _add(self, table: dict[str, float], seconds: int) -> str | None:
        now = self._clock()
        self._prune(now)
        if len(table) >= MAX_LIVE:
            return None
        secret = secrets.token_urlsafe(32)
        table[_key(secret)] = now + seconds
        return secret

    def new_code(self) -> str | None:
        with self._lock:
            return self._add(self._codes, CODE_SECONDS)

    def redeem(self, code: str) -> str | None:
        """A session for a valid code; the code is spent either way."""
        with self._lock:
            expiry = self._codes.pop(_key(code), None)
            if expiry is None or expiry <= self._clock():
                return None
            return self._add(self._sessions, SESSION_SECONDS)

    def open(self) -> str | None:
        """A session for a caller that has just shown the API token."""
        with self._lock:
            return self._add(self._sessions, SESSION_SECONDS)

    def valid(self, session: str) -> bool:
        with self._lock:
            expiry = self._sessions.get(_key(session))
            return expiry is not None and expiry > self._clock()

    def close(self, session: str) -> None:
        with self._lock:
            self._sessions.pop(_key(session), None)
