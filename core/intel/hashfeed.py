"""Known-malware hashes from MalwareBazaar's "recent additions" export, into the local hash lists.

Opt-in and operator-run (`python -m core.intel hashes sync`): nothing downloads unless you run it
with your own free abuse.ch Auth-Key set (the same key URLhaus uses: MIRAGE_URLHAUS_AUTH_KEY).
Only a download: the key travels in the address (as abuse.ch's own example shows), no hash and
nothing about your files is sent. The export lists the hashes of the last 48 hours and is
regenerated every five minutes, so each run is merged into the local list, which therefore grows
over time (capped); abuse.ch asks not to fetch more often than every five minutes, which is
enforced here.

Unverified (the documentation behind the login was not readable without a key): the CSV's column
names, and whether the key belongs in the path (abuse.ch's example) or a query parameter (its
text). This reads any hash-shaped word in the file, so the layout does not matter, and it reports
a clear error rather than guessing if the answer is not a list of hashes.
"""

import time
from pathlib import Path

from core import hashlists
from core.intel.base import ProviderError, ProviderRateLimited
from core.intel.http import Client, FetchError, check_status, fetch

NAME = "malwarebazaar"
URL = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv"
HOST = "mb-api.abuse.ch"
MIN_INTERVAL = 300.0  # seconds: abuse.ch asks for no more often than every five minutes
MAX_DOWNLOAD = 64 * 1024 * 1024


async def sync(
    directory: Path,
    client: Client,
    key: str | None,
    *,
    force: bool = False,
    now: float | None = None,
) -> tuple[str, int, str]:
    """(status, hashes now in the list, detail). The previous list survives every failure."""
    if not key:
        return "error", 0, "an abuse.ch Auth-Key is required (MIRAGE_URLHAUS_AUTH_KEY)"
    target = directory / f"{NAME}.txt"
    clock = now if now is not None else time.time()
    existing = hashlists.read_list(directory, NAME)
    if not force and target.exists() and clock - target.stat().st_mtime < MIN_INTERVAL:
        return "fresh", len(existing), "downloaded in the last five minutes"
    url = URL.replace("{key}", key)
    try:
        got = await fetch(client, "GET", url, max_bytes=MAX_DOWNLOAD)
        check_status(got)
    except ProviderRateLimited:
        return "error", len(existing), "rate limited; try again later"
    except (ProviderError, FetchError) as e:
        return "error", len(existing), e.reason
    except TimeoutError:
        return "error", len(existing), "timeout"
    fresh = set(hashlists.tokens(got.body.decode("utf-8", "replace")))
    if not fresh:
        return "error", len(existing), "the answer held no hashes; kept the previous list"
    merged = existing | fresh
    count = hashlists.write_list(directory, NAME, sorted(merged))
    return "updated", count, f"{len(fresh)} hashes in this download"
