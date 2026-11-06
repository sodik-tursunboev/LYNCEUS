"""Carries out what you approved for email (M6b): move a flagged message out of the inbox, or back.

It runs inside the core because the core holds the mailbox tokens (the agent never sees email). It
acts only on actions the response engine has marked APPROVED (by your click; `auto` never approves
mail) or RESTORE_REQUESTED, one at a time, and reports every outcome through the same state machine
and audit log as files. A failure that will not go away becomes a stated FAILED with a reason; a
failure that may pass (throttling, a server error, the network) leaves the action where it is and
tries again later, up to a limit. Nothing here deletes, sends or edits a message.
"""

import logging
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Protocol

from sqlalchemy import Engine

from core.mailbox.gmail import GmailError
from core.response import service
from core.response.machine import Event

log = logging.getLogger(__name__)

TRANSIENT = frozenset({"rate", "server", "network"})
MAX_TRANSIENT = 10  # tries in a row before a passing failure is called a failure
REASON = {
    "not_found": "message_gone",
    "auth": "mail_auth",
    "forbidden": "mail_forbidden",
    "bad_response": "mail_bad_reply",
    "too_large": "mail_bad_reply",
    "history_gone": "mail_bad_reply",
    "rate": "mail_unavailable",
    "server": "mail_unavailable",
    "network": "mail_unavailable",
}


class Mover(Protocol):
    def quarantine(self, ref: str) -> str: ...

    def restore(self, ref: str) -> str: ...


class MailQuarantineRunner:
    def __init__(
        self,
        engine: Engine,
        movers: Mapping[str, Mover],
        interval: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._engine, self._movers, self._interval, self._clock = engine, movers, interval, clock
        self._tries: dict[uuid.UUID, int] = {}
        self._wait_until = 0.0
        self.last_error: str | None = None
        self.handled = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def providers(self) -> list[str]:
        return sorted(self._movers)

    def poll_once(self) -> int:
        """One round. Returns how many actions reached a final outcome. Never raises."""
        if self._clock() < self._wait_until:
            return 0
        done = 0
        for work in service.mail_work(self._engine):
            mover = self._movers.get(work.provider)
            restoring = work.state == "RESTORE_REQUESTED"
            if mover is None:
                done += self._finish(work.id, restoring, "no_write_access")
                continue
            if work.mail_ref is None:  # the id is gone: nothing to find the message with
                done += self._finish(work.id, restoring, "message_gone")
                continue
            try:
                new_ref = (
                    mover.restore(work.mail_ref) if restoring else mover.quarantine(work.mail_ref)
                )
            except GmailError as e:
                self.last_error = e.kind
                if e.kind in TRANSIENT and self._tries.get(work.id, 0) + 1 < MAX_TRANSIENT:
                    self._tries[work.id] = self._tries.get(work.id, 0) + 1
                    self._wait_until = self._clock() + min(e.retry_after or 30.0, 300.0)
                    log.warning("a mail move is waiting: %s", e.kind)
                    return done  # the whole mailbox is slow or throttled: stop this round
                done += self._finish(work.id, restoring, REASON.get(e.kind, "mail_error"))
                continue
            except Exception:  # noqa: BLE001  (one message must not stop the others; logged by class)
                log.exception("a mail move failed unexpectedly")
                done += self._finish(work.id, restoring, "mail_error")
                continue
            self._tries.pop(work.id, None)
            self.last_error = None
            event = Event.RESTORED if restoring else Event.APPLIED
            # the new id (Outlook changes it on a move) is saved in the same commit as the outcome;
            # a restore clears it (the service does that, in the same commit)
            service.transition(self._engine, work.id, event, "core", mail_ref=new_ref)
            self.handled += 1
            done += 1
        return done

    def _finish(self, action_id: uuid.UUID, restoring: bool, reason: str) -> int:
        self._tries.pop(action_id, None)
        event = Event.RESTORE_FAILED if restoring else Event.FAILED
        service.transition(self._engine, action_id, event, "core", reason)
        return 1

    # ---- the background thread ---------------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="mail-quarantine", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self.poll_once()
            except Exception:  # noqa: BLE001  (the loop must outlive any one failure)
                log.exception("the mail quarantine step failed unexpectedly")
