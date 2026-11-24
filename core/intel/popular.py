"""Download the popular-domain list (H1 B1): Tranco's latest top-1M, keep the top 100,000.

The only request is a GET of Tranco's public download; nothing about the user is sent. The zip is
bounded before and after unpacking, the result is written next to the old file and swapped in, and
the file says where and when it came from. See core/urls/popular.py for how it is used.
"""

import hashlib
import io
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from core.intel.http import Client, FetchError, check_status, fetch
from core.urls import popular

SOURCE = "https://tranco-list.eu/top-1m.csv.zip"
MAX_ZIP = 40 * 1024 * 1024
MAX_CSV = 64 * 1024 * 1024


async def sync(directory: Path, client: Client) -> tuple[int, str]:
    """(domains kept, the list's date and digest). Raises FetchError on a bad download."""
    got = await fetch(client, "GET", SOURCE, max_bytes=MAX_ZIP)
    if got.status in (301, 302, 303, 307, 308):  # the "latest" link may point at a dated file
        target = urljoin(SOURCE, got.headers.get("location", ""))  # it answers with a path
        if urlsplit(target).scheme != "https" or urlsplit(target).hostname != "tranco-list.eu":
            raise FetchError("redirect away from tranco-list.eu")
        got = await fetch(client, "GET", target, max_bytes=MAX_ZIP)
    check_status(got)
    try:
        with zipfile.ZipFile(io.BytesIO(got.body)) as z:
            member = next(i for i in z.infolist() if i.filename.endswith(".csv"))
            if member.file_size > MAX_CSV:
                raise FetchError("list too large")
            text = z.read(member).decode("ascii", "replace")
    except (zipfile.BadZipFile, StopIteration, KeyError):
        raise FetchError("not the expected zip") from None
    top = popular.top_from_csv(text)
    if len(top) < popular.TOP // 2:
        raise FetchError("list too short")
    digest = hashlib.sha256(got.body).hexdigest()
    when = datetime.now(UTC).isoformat(timespec="seconds")
    directory.mkdir(parents=True, exist_ok=True)
    tmp = directory / (popular.FILE + ".new")
    header = f"# Tranco top {len(top)} from {SOURCE}, downloaded {when}, zip sha256 {digest}\n"
    tmp.write_text(header + "\n".join(top) + "\n", encoding="ascii")
    tmp.replace(directory / popular.FILE)
    ranked = popular.ranked_from_csv(text)  # DA5: the same download's ranks 100,001 to 1,000,000
    if len(ranked) > 400_000:  # a short list is not kept: it would silence the model unevenly
        rtmp = directory / (popular.RANKED_FILE + ".new")
        rtmp.write_bytes(popular.ranked_bytes(ranked))
        rtmp.replace(directory / popular.RANKED_FILE)
    popular.configure(directory)  # reloaded on next use
    return len(top), f"{when} sha256 {digest[:16]}"
