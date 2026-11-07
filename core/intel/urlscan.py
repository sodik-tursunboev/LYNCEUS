"""urlscan.io: what did its scanner conclude about this domain? (opt-in; sends one domain name)

It only READS scans that already exist (public ones, searched by registered domain). It never
submits a scan: a submission makes urlscan fetch the page, which leaks that you looked and can burn
a one-time link (ADR-015). Two calls: search for the newest public scan of the domain, then read
that scan's verdicts. A domain nobody has scanned is simply UNKNOWN, which proves nothing.

Verified against the live service (2026-11-07, no key): the search endpoint and the fields used
here. NOT verified: the result endpoint's `verdicts` block, because it answers "not logged in"
without a key and none was available; its shape is taken from urlscan's documentation, and a reply
that does not match it is an error (never a verdict). The free key goes in the `API-Key` header.
Terms: free for personal, non-commercial use (decision D1).
"""

import re
from datetime import UTC, datetime
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from core.contracts import VerdictState
from core.intel.base import Answer, Limit, ProviderError, ProviderRateLimited, Query, Sends
from core.intel.http import Client, check_status, fetch

SEARCH = "https://urlscan.io/api/v1/search/"
RESULT = "https://urlscan.io/api/v1/result/"
MAX_REPLY = 2 * 1024 * 1024
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
SUSPICIOUS_SCORE = (
    50  # urlscan's overall score (-100 to 100) at or above which a scan is "suspicious"
)


class _Hit(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(alias="_id")


class _Search(BaseModel):
    model_config = ConfigDict(extra="ignore")

    results: list[_Hit] = Field(default_factory=list, max_length=100)


class _Overall(BaseModel):
    model_config = ConfigDict(extra="ignore")

    malicious: bool = False
    score: int = Field(default=0, ge=-1000, le=1000)
    categories: list[str] = Field(default_factory=list, max_length=50)
    brands: list[str] = Field(default_factory=list, max_length=50)


class _Verdicts(BaseModel):
    model_config = ConfigDict(extra="ignore")

    overall: _Overall


class _Task(BaseModel):
    model_config = ConfigDict(extra="ignore")

    time: str | None = None


class _Result(BaseModel):
    model_config = ConfigDict(extra="ignore")

    verdicts: _Verdicts
    task: _Task = Field(default_factory=_Task)


def _clean(words: list[str]) -> list[str]:
    """Category and brand names are the service's words, not ours: keep short plain ones only."""
    return [
        w for w in (x.strip().lower() for x in words) if re.fullmatch(r"[a-z0-9 ._-]{1,40}", w)
    ][:5]


class UrlScan:
    name = "urlscan"
    source = "urlscan.io public scans"
    sends = Sends.HOST
    timeout = 8.0
    # the documented free quotas are far above this; two requests are made per lookup
    limit: Limit | None = Limit(per_minute=10, per_day=400)
    ttl = 6 * 3600.0

    def __init__(self, client: Client, api_key: str) -> None:
        self.client, self._key = client, api_key

    def __repr__(self) -> str:
        return "UrlScan(key=********)"

    async def _get(self, url: str) -> bytes:
        got = await fetch(
            self.client, "GET", url, max_bytes=MAX_REPLY, headers={"API-Key": self._key}
        )
        if got.status == 429:
            raise ProviderRateLimited(None)
        check_status(got)
        return got.body

    async def lookup(self, q: Query) -> Answer:
        if not q.name:
            raise ProviderError("no public name to ask about")
        search = f"{SEARCH}?q={quote('page.apexDomain:' + q.name, safe='')}&size=1"
        try:
            hits = _Search.model_validate_json(await self._get(search)).results
        except ValidationError:
            raise ProviderError("search reply has an unexpected shape") from None
        if not hits:
            return Answer(
                VerdictState.UNKNOWN, self.source, "urlscan has no public scan of this domain"
            )
        scan_id = hits[0].id
        if not _UUID.fullmatch(scan_id):
            raise ProviderError("search reply has an unexpected scan id")
        try:
            result = _Result.model_validate_json(await self._get(RESULT + scan_id + "/"))
        except ValidationError:
            raise ProviderError("result reply has an unexpected shape") from None
        overall = result.verdicts.overall
        scanned = None
        if result.task.time:
            try:
                scanned = datetime.fromisoformat(
                    result.task.time.replace("Z", "+00:00")
                ).astimezone(UTC)
            except ValueError:
                scanned = None
        provenance = self.source + (f", scanned {scanned:%Y-%m-%d}" if scanned else "")
        cats = ", ".join(_clean(overall.categories))
        brands = ", ".join(_clean(overall.brands))
        facts = {"score": overall.score}
        if overall.malicious:
            detail = "urlscan's verdict for the newest scan: malicious"
            return Answer(
                VerdictState.MALICIOUS,
                provenance,
                detail
                + (f" ({cats})" if cats else "")
                + (f", impersonating {brands}" if brands else ""),
                {**facts, "urlscan": "malicious"},
            )
        if overall.score >= SUSPICIOUS_SCORE:
            return Answer(
                VerdictState.SUSPICIOUS,
                provenance,
                f"urlscan scored the newest scan {overall.score}/100",
                {**facts, "urlscan": "suspicious"},
            )
        return Answer(
            VerdictState.UNKNOWN,
            provenance,
            "urlscan's newest scan has no malicious verdict: this proves nothing",
            facts,
        )

    async def aclose(self) -> None:
        await self.client.aclose()
