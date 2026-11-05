"""Runs the mailbox poller inside the API process, on its own thread, and reports on it."""

import logging
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from core.email.engine import EmailAnalysis
from core.mailbox.gmail import GmailClient
from core.mailbox.oauth import TokenSource
from core.mailbox.sync import Mailbox, State
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
    ) -> None:
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
        client: GmailClient,
        source: TokenSource | None,
        tokens: TokenFile,
        directory: Path,
        analyze: Callable[[bytes], EmailAnalysis],
        store: Callable[[EmailAnalysis], None],
        lookback_days: int,
        poll_seconds: float,
        fetch_gap: float = 0.7,
    ) -> "MailboxService":
        state = State(directory / "gmail-state.json")
        mailbox = Mailbox(client, analyze, store, state, lookback_days, fetch_gap)
        return cls(mailbox, tokens, source, poll_seconds)

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
            "flagged": s.flagged[-20:],
        }


def now() -> float:
    return time.time()
