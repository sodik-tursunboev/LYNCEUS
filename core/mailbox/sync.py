"""Keep up with a mailbox: new mail is analysed once, missed mail is found again (M5, ADR-017).

The loop is "connect, look back a few days, then follow the history". Everything that can go wrong
has a stated outcome: an expired history position (HTTP 404) triggers a bounded re-list, a message
deleted before it was fetched is counted as vanished, a failed analysis is retried a few times and
then recorded, and Gmail being unreachable or throttling us only delays the next poll. Nothing is
ever turned into "no phishing found". Message ids are kept as SHA-256 hashes; the raw message
lives in memory for one analysis.
"""

import hashlib
import json
import logging
import os
import time
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from core.contracts import VerdictState
from core.email.engine import EmailAnalysis, unscored
from core.mailbox.gmail import GmailError, HistoryPage, ListPage

log = logging.getLogger(__name__)
SEEN_LIMIT = 5000
MAX_ATTEMPTS = 3
MAX_PER_POLL = 200  # a burst is queued for the next poll, not dropped


class MailSource(Protocol):
    """What the sync needs from a mailbox, whoever provides it (Gmail, Microsoft Graph)."""

    def profile_history_id(self) -> str: ...

    def list_recent(self, days: int, page: str | None = None) -> ListPage: ...

    def history(self, start_history_id: str, page: str | None = None) -> HistoryPage: ...

    def get_raw(self, message_id: str) -> bytes: ...


def message_key(message_id: str) -> str:
    return hashlib.sha256(message_id.encode()).hexdigest()


@dataclass
class Stats:
    analysed: int = 0
    vanished: int = 0
    too_large: int = 0
    gave_up: int = 0
    unfinished: int = 0  # stored UNKNOWN or ERROR because the parser could not finish (H1 A6)
    recoveries: int = 0
    backlog: bool = False  # the last poll stopped at its limit with mail still to read
    polls: int = 0
    last_poll: float | None = None
    last_error: str | None = None
    flagged: list[dict[str, object]] = field(
        default_factory=list
    )  # newest last, no addresses or subjects


class State:
    """What survives a restart: the history position, analysed ids (as hashes), retries."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.history_id: str | None = None
        self.seen: deque[str] = deque(maxlen=SEEN_LIMIT)
        self.attempts: dict[str, int] = {}
        self._seen_set: set[str] = set()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            hid = data.get("history_id")
            self.history_id = (
                hid if isinstance(hid, str) and 0 < len(hid) <= 4096 and hid.isprintable() else None
            )
            for k in data.get("seen", []):
                if isinstance(k, str) and len(k) == 64:
                    self._remember(k)
            self.attempts = {
                k: int(v) for k, v in data.get("attempts", {}).items() if isinstance(v, int)
            }
        except (OSError, ValueError, AttributeError):
            pass  # no file yet, or damaged: start "not connected"; the look-back covers the gap

    def _remember(self, key: str) -> None:
        if key in self._seen_set:
            return
        if len(self.seen) == SEEN_LIMIT:
            self._seen_set.discard(self.seen[0])
        self.seen.append(key)
        self._seen_set.add(key)

    def has(self, key: str) -> bool:
        return key in self._seen_set

    def mark(self, key: str) -> None:
        self._remember(key)
        self.attempts.pop(key, None)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        body = {"history_id": self.history_id, "seen": list(self.seen), "attempts": self.attempts}
        tmp.write_text(json.dumps(body), encoding="utf-8")
        os.replace(tmp, self.path)


class Mailbox:
    def __init__(
        self,
        client: MailSource,
        analyze: Callable[[bytes], EmailAnalysis],
        store: Callable[[EmailAnalysis], None],
        state: State,
        lookback_days: int = 2,
        fetch_gap: float = 0.7,  # a raw fetch costs 60 of 6,000 units a minute
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
        on_malicious: Callable[[str, uuid.UUID], None] | None = None,
    ) -> None:
        self.client, self.analyze, self.store, self.state = client, analyze, store, state
        self.on_malicious = on_malicious  # M6b: proposes (never performs) a quarantine
        self.lookback_days, self.fetch_gap, self._sleep, self._clock = (
            lookback_days, fetch_gap, sleep, clock,
        )  # fmt: skip
        self.stats = Stats()
        self.backoff_until = 0.0
        self._deferred = (
            False  # a message must be tried again, so the history position must not move on
        )
        self._truncated = False  # the per-poll limit left unread mail: same rule, position stays

    def poll(self) -> None:
        """One round. Never raises for a Gmail problem: it records it and waits."""
        if self._clock() < self.backoff_until:
            return
        self.stats.polls += 1
        try:
            if self.state.history_id is None:
                self._connect()
            else:
                self._follow()
            self.stats.last_error = None
        except GmailError as e:
            self.stats.last_error = e.kind
            wait = (
                e.retry_after if e.retry_after is not None else 60.0 if e.kind != "auth" else 300.0
            )
            self.backoff_until = self._clock() + min(wait, 900.0)
            log.warning("mailbox poll stopped: %s", e.kind)
        self.stats.last_poll = self._clock()

    # ---- the three situations -------------------------------------------------------------

    def _connect(self) -> None:
        """First time, or after losing the position: note where "now" is, then read recent days."""
        start = (
            self.client.profile_history_id()
        )  # before listing, so mail arriving meanwhile is not missed
        self._deferred = False
        self._truncated = False
        self.stats.backlog = False
        self._relist()
        if self._deferred:
            return  # stay "not connected": the next poll lists again and skips what is done
        self.state.history_id = start
        self.state.save()

    def _follow(self) -> None:
        if self.state.history_id is None:
            return self._connect()
        page: str | None = None
        done = 0
        self._deferred = False
        self._truncated = False
        self.stats.backlog = False
        while True:
            try:
                h = self.client.history(self.state.history_id, page)
            except GmailError as e:
                if e.kind != "history_gone":
                    raise
                self.stats.recoveries += 1
                log.warning(
                    "the saved history position expired; reading the last %d days",
                    self.lookback_days,
                )
                self.state.history_id = None
                self._connect()
                return
            done += self._process(h.ids, MAX_PER_POLL - done)
            if self._truncated:
                # unread mail is left on this very page: moving the position now would lose it
                self.stats.backlog = True
                return
            if h.next_page and done < MAX_PER_POLL:
                page = h.next_page
                continue
            if h.next_page:
                self.stats.backlog = True
                return  # keep the old position; the rest is read next poll (seen ids are skipped)
            if self._deferred:
                self._deferred = False
                return  # a message is waiting for a retry: read this range again next time
            self.state.history_id = h.history_id
            self.state.save()
            return

    def _relist(self) -> None:
        if self.lookback_days <= 0:
            return
        page: str | None = None
        done = 0
        while True:
            listing = self.client.list_recent(self.lookback_days, page)
            done += self._process(listing.ids, MAX_PER_POLL - done)
            if self._truncated or (listing.next_page and done >= MAX_PER_POLL):
                # mail is left over: do not call this connected yet; the next poll lists again
                # and skips what is already done
                self._deferred = True
                self.stats.backlog = True
                return
            if not listing.next_page:
                return
            page = listing.next_page

    # ---- one message -----------------------------------------------------------------------

    def _process(self, ids: list[str], budget: int) -> int:
        taken = 0
        for mid in ids:
            key = message_key(mid)
            if self.state.has(key):
                continue
            if taken >= budget:
                self._truncated = True  # an unread message is left behind
                break
            taken += 1
            self._one(mid, key)
            self._sleep(self.fetch_gap)
        return taken

    def _not_analysed(self, reason: str) -> None:
        """A message the parser could not finish is never silent (H1 A6): it joins the flagged list
        as NOT_ANALYSED with its reason code, so the agent and the console say so. Not safe."""
        self.stats.unfinished += 1
        self.stats.flagged.append(
            {"at": self._clock(), "state": "NOT_ANALYSED", "score": None, "rules": [reason]}
        )
        del self.stats.flagged[:-50]

    def _one(self, mid: str, key: str) -> None:
        try:
            raw = self.client.get_raw(mid)
        except GmailError as e:
            if e.kind == "not_found":  # deleted or moved before we got to it
                self.stats.vanished += 1
                self.state.mark(key)
                self.state.save()
                return
            if e.kind == "too_large":
                self.stats.too_large += 1
                analysis = unscored(
                    uuid.uuid4(), key, VerdictState.UNKNOWN,
                    "The message is over the size limit and was not opened.", "too_large",
                )  # fmt: skip
                self.store(analysis)
                self.state.mark(key)
                self.state.save()
                self._not_analysed("too_large")
                return
            raise
        analysis = self.analyze(raw)
        verdict = analysis.report.verdict
        if verdict.state is VerdictState.ERROR:
            n = self.state.attempts.get(key, 0) + 1
            if n < MAX_ATTEMPTS:
                self.state.attempts[key] = n
                self.state.save()
                self._deferred = True
                return
            self.stats.gave_up += 1
        self.store(analysis)
        self.state.mark(key)
        self.state.save()
        self.stats.analysed += 1
        reason = analysis.report.reason
        if verdict.state is VerdictState.ERROR or (reason or "").startswith("parser_"):
            self._not_analysed(reason or "error")
        if verdict.state in (VerdictState.MALICIOUS, VerdictState.SUSPICIOUS):
            self.stats.flagged.append(
                {
                    "at": self._clock(),
                    "state": verdict.state.value,
                    "score": verdict.risk_score,
                    "rules": [s.rule_id for s in verdict.signals][:5],
                }
            )
            del self.stats.flagged[:-50]
        if verdict.state is VerdictState.MALICIOUS and self.on_malicious is not None:
            try:
                self.on_malicious(mid, verdict.id)
            except Exception as e:  # noqa: BLE001  (a proposal must never stop the poll)
                # only the class is logged: a database error can carry the statement's parameters,
                # and the message id must never reach a log
                log.warning("proposing a quarantine failed: %s", type(e).__name__)
