"""VirusTotal: what do the engines say about this domain? (opt-in; sends one public domain name)

Reads the domain report (`GET /api/v3/domains/{domain}`, key in the `x-apikey` header). VirusTotal's
documentation says an indicator queried through the API is added to its dataset and visible to the
community, which is why this provider is off until the operator names it, and why only a public
registered domain is ever sent (never a URL, path or token). The public API is limited to 4 requests
a minute and 500 a day and may not be used in commercial products (decision D1).

Unverified: the domain object's field names are taken from the URL-object documentation and general
knowledge; the Terms of Service page could not be read. The count of engines that flag a domain is
evidence, not a verdict: clean results from 70 engines still prove nothing.
"""

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from core.contracts import VerdictState
from core.intel.base import Answer, Limit, ProviderError, ProviderRateLimited, Query, Sends
from core.intel.http import Client, Fetched, check_status, fetch

BASE = "https://www.virustotal.com/api/v3/domains/"
MAX_REPLY = 1024 * 1024
MANY = 3  # engines flagging a domain: SUSPICIOUS below, MALICIOUS from here


class _Stats(BaseModel):
    model_config = ConfigDict(extra="ignore")

    malicious: int = Field(ge=0, le=1000)
    suspicious: int = Field(default=0, ge=0, le=1000)
    harmless: int = Field(default=0, ge=0, le=1000)
    undetected: int = Field(default=0, ge=0, le=1000)


class _Attributes(BaseModel):
    model_config = ConfigDict(extra="ignore")

    last_analysis_stats: _Stats
    last_analysis_date: int | None = Field(default=None, ge=0, le=4_102_444_800)


class _Data(BaseModel):
    model_config = ConfigDict(extra="ignore")

    attributes: _Attributes


class _Report(BaseModel):
    model_config = ConfigDict(extra="ignore")

    data: _Data


def _seconds_to_utc_midnight(now: datetime) -> float:
    tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return (tomorrow - now).total_seconds()


class VirusTotal:
    name = "virustotal"
    source = "VirusTotal domain report"
    sends = Sends.HOST
    timeout = 6.0
    limit: Limit | None = Limit(per_minute=4, per_day=500)  # the documented public API limits
    ttl = 6 * 3600.0  # the day's quota is small: reuse an answer for hours

    def __init__(
        self,
        client: Client,
        api_key: str,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.client, self._key, self.now = client, api_key, now

    def __repr__(self) -> str:
        return "VirusTotal(key=********)"

    def _quota_pause(self, got: Fetched) -> float | None:
        """A daily-quota 429 waits for the UTC midnight reset the documentation describes."""
        try:
            message = str(json.loads(got.body)["error"]["message"]).lower()
        except (ValueError, KeyError, TypeError):
            return None
        return _seconds_to_utc_midnight(self.now()) if "daily" in message else None

    async def lookup(self, q: Query) -> Answer:
        if not q.name:
            raise ProviderError("no public name to ask about")
        got = await fetch(
            self.client, "GET", BASE + quote(q.name, safe=""),
            max_bytes=MAX_REPLY, headers={"x-apikey": self._key},
        )  # fmt: skip
        if got.status == 404:
            return Answer(
                VerdictState.UNKNOWN, self.source, "VirusTotal has no report for this domain"
            )
        if got.status == 429:
            raise ProviderRateLimited(self._quota_pause(got))
        check_status(got)
        try:
            attrs = _Report.model_validate_json(got.body).data.attributes
        except ValidationError:
            raise ProviderError("reply has an unexpected shape") from None
        stats = attrs.last_analysis_stats
        when = (
            datetime.fromtimestamp(attrs.last_analysis_date, UTC)
            if attrs.last_analysis_date
            else None
        )
        provenance = self.source + (f", analysed {when:%Y-%m-%d}" if when else "")
        facts = {
            "detections": stats.malicious, "suspicious": stats.suspicious,
            "harmless": stats.harmless, "undetected": stats.undetected,
        }  # fmt: skip
        if stats.malicious >= MANY:
            state, detail = VerdictState.MALICIOUS, f"{stats.malicious} engines flag this domain"
        elif stats.malicious >= 1:
            state, detail = VerdictState.SUSPICIOUS, f"{stats.malicious} engine(s) flag this domain"
        else:
            state, detail = VerdictState.UNKNOWN, "no engine flags this domain: this proves nothing"
        return Answer(state, provenance, detail, facts)

    async def aclose(self) -> None:
        await self.client.aclose()
