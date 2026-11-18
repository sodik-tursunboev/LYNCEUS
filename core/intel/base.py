"""Shared types for intelligence providers.

A provider is handed a `Query`, never a URL. A provider that asks an outside service gets only the
public registered domain; a list provider that matches on this machine gets the host and the hash
of the normalized URL. No type here can carry a path, query string, fragment, user name or token,
so a provider cannot send what it was never given (tests check the real requests as well).
"""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, NamedTuple, Protocol

from core.contracts import ProviderResult, VerdictState
from core.urls.parse import ParsedUrl


class Sends(StrEnum):
    NOTHING = "nothing"  # matches on this machine, or reads a file already downloaded
    HOST = "host"  # asks an outside service about one public registered domain


class Limit(NamedTuple):
    """A provider's documented request limits. None: no limit stated."""

    per_minute: int | None = None
    per_day: int | None = None


# What a provider may conclude. Never BENIGN: a name that is not on a list proves nothing.
ANSWER_STATES = frozenset({VerdictState.MALICIOUS, VerdictState.SUSPICIOUS, VerdictState.UNKNOWN})
MAX_DETAIL = 300


@dataclass(frozen=True)
class Query:
    name: str | None = None  # public registered domain: the only thing a HOST provider may send
    host: str = ""  # full ASCII host, for local list matching only
    url_sha256: str = ""  # hash of the normalized URL, for local list matching only


def match_hash(u: ParsedUrl) -> str:
    """The key a list is matched on: sha256 of the normalized URL without its fragment, which a
    server never receives and which list entries often carry or lack."""
    return hashlib.sha256(u.normalized.split("#", 1)[0].encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Subject:
    """What the engine knows about one URL. Providers never see this, only a `Query`."""

    host: str
    url_sha256: str  # match_hash(): see above
    name: str | None  # the public registered domain, or None when the host is not a public name
    registered_domain: str | None

    @classmethod
    def from_parsed(cls, u: ParsedUrl) -> "Subject":
        from core.intel.egress import public_name

        return cls(u.host or "", match_hash(u), public_name(u), u.registered_domain)


@dataclass(frozen=True)
class Answer:
    state: VerdictState
    provenance: str  # which feed, version or endpoint answered
    detail: str | None = None  # human-readable, no attacker text
    facts: Mapping[str, Any] = field(default_factory=dict)  # structured, for correlation
    # (a provider's `ttl` says how long an answer may be reused; an Answer is per query)


@dataclass(frozen=True)
class FileRep:
    """DA2: what an antivirus aggregator's engines say about a file's SHA-256 (data only: the lookup
    itself is core/intel/filerep.py)."""

    malicious: int  # engines that flag the file
    suspicious: int
    harmless: int
    undetected: int
    analysed: datetime | None

    @property
    def engines(self) -> int:
        """Engines that gave an opinion (timeouts, failures and unsupported types left out)."""
        return self.malicious + self.suspicious + self.harmless + self.undetected


class ProviderError(Exception):
    """A provider failed in a way worth recording. `reason` must not contain URLs or keys."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ProviderUnavailable(Exception):
    """The provider cannot answer for a local reason (no feed downloaded, feed stale). It is not
    a fault of the provider, so it never counts against its circuit breaker."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ProviderRateLimited(Exception):
    def __init__(self, retry_after: float | None = None) -> None:
        super().__init__("rate limited")
        self.retry_after = retry_after


class Provider(Protocol):
    name: str
    source: str  # what answers, for provenance when there is no answer (a failure still cites it)
    sends: Sends
    timeout: float  # seconds allowed for one lookup
    limit: Limit | None
    ttl: float  # seconds an OK answer may be reused; 0 means never

    async def lookup(self, q: Query) -> Answer: ...


@dataclass(frozen=True)
class IntelResult:
    result: ProviderResult
    facts: Mapping[str, Any]
    cached: bool = False


@dataclass(frozen=True)
class IntelOutcome:
    results: tuple[IntelResult, ...]
    skipped: tuple[tuple[str, str], ...]  # (provider, why it was not asked)

    @property
    def provider_results(self) -> list[ProviderResult]:
        return [r.result for r in self.results]
