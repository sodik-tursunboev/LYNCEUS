"""File reputation (DA2): what do VirusTotal's engines say about a file with this SHA-256?

Only the hash leaves this computer: never the file, its name, its folder or anything about the user.
VirusTotal's documentation says an indicator queried through its API is added to its dataset and
visible to the community, so this is off until `LYNCEUS_FILE_REPUTATION=true` and is asked only for
program-like downloads (see `core.files.engine.wants_reputation`). The request is a GET to
`/api/v3/files/<sha256>` with the key in the `x-apikey` header. The public key is limited to 4
requests a minute and 500 a day and may not be used in commercial products.

Unverified: VirusTotal's pages do not state what an unknown file returns; a 404 is read as "no
report" (as for domains). "No report" and every failure leave the verdict exactly as it was, and no
answer is ever read as safe: a file nobody has seen proves nothing.
"""

import asyncio
import logging
import re
import time
from collections import OrderedDict
from collections.abc import Callable
from datetime import UTC, datetime

from pydantic import ValidationError

from core.intel.base import FileRep, Limit, ProviderError, ProviderRateLimited
from core.intel.http import Client, check_status, fetch
from core.intel.resilience import RateLimiter
from core.intel.virustotal import Report

log = logging.getLogger(__name__)

BASE = "https://www.virustotal.com/api/v3/files/"
MAX_REPLY = 1024 * 1024
WAIT = 6.0  # seconds a download's verdict may wait for this lookup
FRESH = 6 * 3600.0  # an answer is reused this long
NO_REPORT = 3600.0  # "VirusTotal has not seen it" is asked again after this long
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
Clock = Callable[[], float]


class FileReputation:
    """One question at a time about a SHA-256, cached and kept inside the documented limits."""

    def __init__(self, client: Client, api_key: str, *, clock: Clock = time.monotonic) -> None:
        self.client, self._key, self._clock = client, api_key, clock
        self._limiter = RateLimiter(Limit(per_minute=4, per_day=500), clock=clock)
        self._cache: OrderedDict[str, tuple[float, FileRep | None]] = OrderedDict()

    def __repr__(self) -> str:
        return "FileReputation(key=********)"

    def _remember(self, digest: str, rep: FileRep | None, ttl: float) -> None:
        self._cache[digest] = (self._clock() + ttl, rep)
        while len(self._cache) > 2000:
            self._cache.popitem(last=False)

    async def lookup(self, sha256: str) -> FileRep | None:
        """The report (None: VirusTotal has none); raises ProviderError or ProviderRateLimited."""
        digest = sha256.lower()
        if not _SHA256.match(digest):
            raise ProviderError("not a SHA-256")
        hit = self._cache.get(digest)
        if hit is not None and hit[0] > self._clock():
            return hit[1]
        if not self._limiter.try_acquire():
            raise ProviderRateLimited(None)
        got = await fetch(
            self.client, "GET", BASE + digest, max_bytes=MAX_REPLY, headers={"x-apikey": self._key}
        )
        if got.status == 404:
            self._remember(digest, None, NO_REPORT)
            return None
        if got.status == 429:
            self._limiter.pause(300.0)
            raise ProviderRateLimited(None)
        check_status(got)
        try:
            attrs = Report.model_validate_json(got.body).data.attributes
        except ValidationError:
            raise ProviderError("reply has an unexpected shape") from None
        stats = attrs.last_analysis_stats
        when = (
            datetime.fromtimestamp(attrs.last_analysis_date, UTC)
            if attrs.last_analysis_date
            else None
        )
        rep = FileRep(stats.malicious, stats.suspicious, stats.harmless, stats.undetected, when)
        self._remember(digest, rep, FRESH)
        return rep

    async def ask(self, sha256: str) -> tuple[FileRep | None, str]:
        """For a download's verdict: never raises, never waits long. The second part says what
        happened, for the audit log: `report`, `no_report` or `failed`."""
        try:
            rep = await asyncio.wait_for(self.lookup(sha256), WAIT)
        except (TimeoutError, ProviderError, ProviderRateLimited) as e:
            log.info("file reputation: no answer (%s)", type(e).__name__)
            return None, "failed"
        except Exception as e:  # noqa: BLE001  (the message may hold a key: type only)
            log.warning("file reputation failed: %s", type(e).__name__)
            return None, "failed"
        return rep, "report" if rep is not None else "no_report"

    async def aclose(self) -> None:
        await self.client.aclose()
