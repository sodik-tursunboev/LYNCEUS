r"""The life of one response action, as a table. Nothing else decides what may happen next.

    PENDING -approve-> APPROVED -applied-> APPLIED -restore-> RESTORE_REQUESTED -restored-> RESTORED
       |                    |  \-failed-> FAILED -approve (retry)-> APPROVED
       \-dismiss-> DISMISSED <-dismiss- (APPROVED, FAILED);  DISMISSED -approve-> APPROVED
    RESTORE_REQUESTED -restore_failed-> APPLIED (the file is still in quarantine; reason kept)

Every event is idempotent: asking again for something already true is a no-op that says so, and
asking for something that cannot happen from here is refused, never forced.
"""

from enum import StrEnum
from typing import NamedTuple


class Event(StrEnum):
    APPROVE = "approve"
    DISMISS = "dismiss"
    RESTORE = "restore"
    APPLIED = "applied"
    FAILED = "failed"
    RESTORED = "restored"
    RESTORE_FAILED = "restore_failed"


NEXT: dict[tuple[str, Event], str] = {
    ("PENDING", Event.APPROVE): "APPROVED",
    ("PENDING", Event.DISMISS): "DISMISSED",
    ("APPROVED", Event.APPLIED): "APPLIED",
    ("APPROVED", Event.FAILED): "FAILED",
    ("APPROVED", Event.DISMISS): "DISMISSED",
    ("FAILED", Event.APPROVE): "APPROVED",
    ("FAILED", Event.DISMISS): "DISMISSED",
    ("DISMISSED", Event.APPROVE): "APPROVED",
    ("APPLIED", Event.RESTORE): "RESTORE_REQUESTED",
    ("RESTORE_REQUESTED", Event.RESTORED): "RESTORED",
    ("RESTORE_REQUESTED", Event.RESTORE_FAILED): "APPLIED",
}

# states in which an event has, in effect, already happened (so repeating it changes nothing)
ALREADY: dict[Event, frozenset[str]] = {
    Event.APPROVE: frozenset({"APPROVED", "APPLIED", "RESTORE_REQUESTED", "RESTORED"}),
    Event.DISMISS: frozenset({"DISMISSED"}),
    Event.RESTORE: frozenset({"RESTORE_REQUESTED", "RESTORED"}),
    Event.APPLIED: frozenset({"APPLIED", "RESTORE_REQUESTED", "RESTORED"}),
    Event.FAILED: frozenset({"FAILED"}),
    Event.RESTORED: frozenset({"RESTORED"}),
    Event.RESTORE_FAILED: frozenset({"APPLIED"}),
}


class Step(NamedTuple):
    new_state: str
    changed: bool
    legal: bool


def step(state: str, event: Event) -> Step:
    target = NEXT.get((state, event))
    if target is not None:
        return Step(target, True, True)
    if state in ALREADY[event]:
        return Step(state, False, True)
    return Step(state, False, False)
