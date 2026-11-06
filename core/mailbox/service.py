"""Runs the mailbox poller inside the API process, on its own thread, and reports on it."""

import logging
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from core.email.engine import EmailAnalysis
from core.mailbox.oauth import TokenSource
from core.mailbox.sync import Mailbox, MailSource, State
from core.mailbox.tokens import TokenFile

log = logging.getLogger(__name__)


class MailboxService:
    def __init__(
        self,
        mailbox: Mailbox,
        tokens: TokenFile,
        source: TokenSource | None,
        poll_seconds: float,
        wait: Callable[[float], bool] | None = None,
        name: str = "gmail",
    ) -> None:
        self.name = name
        self.mailbox, self.tokens, self.source, self.poll_seconds = (
            mailbox,
            tokens,
            source,
            poll_seconds,
        )
        self._stop = threading.Event()
        self._wait = wait or self._stop.wait
        self._thread: threading.Thread | None = None

    @classmethod
    def build(
        cls,
        client: MailSource,
        source: TokenSource | None,
        tokens: TokenFile,
        directory: Path,
        analyze: Callable[[bytes], EmailAnalysis],
        store: Callable[[EmailAnalysis], None],
        lookback_days: int,
        poll_seconds: float,
        fetch_gap: float = 0.7,
        name: str = "gmail",
    ) -> "MailboxService":
        state = State(directory / f"{name}-state.json")
        mailbox = Mailbox(client, analyze, store, state, lookback_days, fetch_gap)
        return cls(mailbox, tokens, source, poll_seconds, name=name)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="mailbox", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def poll_once(self) -> None:
        if self.tokens.load() is None:
            return
        self.mailbox.poll()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:  # noqa: BLE001  (the loop must outlive any one failure; it is logged by class)
                log.exception("mailbox poll failed unexpectedly")
            if self._wait(self.poll_seconds):
                return

    def status(self) -> dict[str, object]:
        s = self.mailbox.stats
        connected = self.tokens.load() is not None
        if not connected:
            state = "disconnected"
        elif self.source is not None and self.source.last_error == "revoked":
            state = "reauth_needed"  # revoked, expired ("Testing": 7 days) or password changed
        elif s.last_error:
            state = "error"
        else:
            state = "connected"
        return {
            "provider": self.name,
            "state": state,
            "last_poll": datetime.fromtimestamp(s.last_poll, UTC).isoformat()
            if s.last_poll
            else None,
            "last_error": s.last_error,
            "analysed": s.analysed,
            "vanished": s.vanished,
            "too_large": s.too_large,
            "gave_up": s.gave_up,
            "recoveries": s.recoveries,
            "backlog": s.backlog,
            "flagged": s.flagged[-20:],
        }


def combined_status(services: list[MailboxService]) -> dict[str, object]:
    """One answer for the console and the agent: a problem wins (sign-in needed, then error),
    otherwise connected if any provider is; flagged mail is merged. With one provider it is that
    provider's own status."""
    if not services:
        return {"state": "off"}
    each = {s.name: s.status() for s in services}
    if len(services) == 1:
        return next(iter(each.values())) | {"providers": each}
    states = [str(v["state"]) for v in each.values()]
    for worst in ("reauth_needed", "error", "connected", "disconnected"):
        if worst in states:
            state = worst
            break
    else:
        state = "disconnected"
    flagged = sorted((f for v in each.values() for f in v["flagged"]), key=lambda f: f["at"])  # type: ignore[attr-defined]
    return {"state": state, "flagged": flagged[-20:], "providers": each}


def now() -> float:
    return time.time()
