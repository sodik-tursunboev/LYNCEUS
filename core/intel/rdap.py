"""RDAP: how old is this domain? (a young registration is the cheapest strong phishing signal)

Asks the registry that runs the domain's top-level domain, found through IANA's bootstrap file
(RFC 9224), for the domain record (RFC 9082/9083) and reads its `registration` event. Sends one
public registered domain name and nothing else; off unless the operator enables `rdap`. A registry
may omit the date (privacy redaction): then there is no answer, which is not the same as "old".

Facts as read from the RFCs on 2026-11-05. Unverified: any registry's rate limits and whether it
logs queries. A server named by the bootstrap file is treated as untrusted input (https, a public
name, no IP literal, no credentials); a name that resolves to a private address is not blocked here
(documented limitation, ADR-015).
"""

import asyncio
import ipaddress
import json
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

from core.contracts import VerdictState
from core.intel.base import (
    Answer,
    Limit,
    ProviderError,
    ProviderUnavailable,
    Query,
    Sends,
)
from core.intel.http import Client, check_status, fetch
from core.urls import psl

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_TTL = 24 * 3600.0
MAX_BOOTSTRAP = 2 * 1024 * 1024
MAX_REPLY = 256 * 1024
YOUNG_DAYS = 30  # younger than this the answer's own state is SUSPICIOUS
_ENTRY = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)*$")


def _server(url: object) -> str | None:
    """A base URL from the bootstrap file, or None if it is not safe to talk to."""
    if not isinstance(url, str):
        return None
    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        ipaddress.ip_address(host)
        return None  # an IP literal
    except ValueError:
        pass
    if (
        parts.scheme != "https"
        or parts.username
        or parts.password
        or parts.port not in (None, 443)
        or parts.query
        or parts.fragment
        or "." not in host
        or not psl.known_suffix(host)
    ):
        return None
    return url if url.endswith("/") else url + "/"


def parse_bootstrap(raw: bytes) -> dict[str, str]:
    """TLD (or longer suffix) -> base URL, https servers only."""
    try:
        data = json.loads(raw)
        services = data["services"]
    except (ValueError, KeyError, TypeError, RecursionError):
        raise ProviderError("bootstrap file is not valid") from None
    table: dict[str, str] = {}
    if not isinstance(services, list):
        raise ProviderError("bootstrap file is not valid")
    for service in services:
        if not (isinstance(service, list) and len(service) == 2):
            continue
        entries, urls = service
        if not (isinstance(entries, list) and isinstance(urls, list)):
            continue
        base = next((s for u in urls if (s := _server(u))), None)  # first usable, https first
        if base is None:
            continue
        for entry in entries:
            if isinstance(entry, str) and _ENTRY.match(entry.lower()):
                table[entry.lower()] = base
    if not table:
        raise ProviderError("bootstrap file has no usable servers")
    return table


def registration_date(reply: Any) -> datetime | None:
    events = reply.get("events") if isinstance(reply, dict) else None
    if not isinstance(events, list):
        return None
    for event in events:
        if (
            not isinstance(event, dict)
            or str(event.get("eventAction", "")).lower() != "registration"
        ):
            continue
        raw = event.get("eventDate")
        if not isinstance(raw, str):
            continue
        try:
            date = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
        except ValueError:
            continue
        return date if date.tzinfo else date.replace(tzinfo=UTC)
    return None


class Rdap:
    name = "rdap"
    source = "RDAP (the registry of the domain's top-level domain)"
    sends = Sends.HOST
    timeout = 6.0
    limit: Limit | None = Limit(
        per_minute=30
    )  # conservative: registries publish no number we found
    ttl = 24 * 3600.0

    def __init__(
        self,
        client: Client,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        clock: Callable[[], float] = time.monotonic,
        bootstrap_url: str = BOOTSTRAP_URL,
    ) -> None:
        self.client, self.now, self.clock, self.bootstrap_url = client, now, clock, bootstrap_url
        self._table: dict[str, str] = {}
        self._expires = 0.0
        self._lock = asyncio.Lock()

    async def _servers(self) -> dict[str, str]:
        async with self._lock:
            if self._table and self.clock() < self._expires:
                return self._table
            got = await fetch(self.client, "GET", self.bootstrap_url, max_bytes=MAX_BOOTSTRAP)
            check_status(got)
            self._table = parse_bootstrap(got.body)
            self._expires = self.clock() + BOOTSTRAP_TTL
            return self._table

    async def lookup(self, q: Query) -> Answer:
        name = q.name
        if not name:
            raise ProviderUnavailable("no public name to ask about")
        table = await self._servers()
        labels = name.split(".")
        base = next(
            (table[s] for i in range(len(labels)) if (s := ".".join(labels[i:])) in table), None
        )
        if base is None:
            raise ProviderUnavailable("no RDAP server is listed for this top-level domain")
        provenance = f"RDAP via {urlsplit(base).hostname}"
        got = await fetch(
            self.client, "GET", f"{base}domain/{quote(name, safe='')}",
            max_bytes=MAX_REPLY, headers={"Accept": "application/rdap+json"},
        )  # fmt: skip
        if got.status == 404:
            return Answer(
                VerdictState.UNKNOWN, provenance, "the registry has no record of this domain"
            )
        check_status(got)
        try:
            reply = json.loads(got.body)
        except (ValueError, RecursionError):
            raise ProviderError("reply is not JSON") from None
        registered = registration_date(reply)
        if registered is None:
            return Answer(
                VerdictState.UNKNOWN, provenance, "the registry publishes no registration date"
            )
        age = (self.now() - registered).days
        if age < 0:
            return Answer(
                VerdictState.UNKNOWN, provenance, "the registration date is in the future"
            )
        state = VerdictState.SUSPICIOUS if age < YOUNG_DAYS else VerdictState.UNKNOWN
        return Answer(state, provenance, f"registered {age} days ago", {"age_days": age})

    async def aclose(self) -> None:
        await self.client.aclose()
