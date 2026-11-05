"""A read-only Microsoft Graph mail client for an inbox (M5b, ADR-017).

Same promises as the Gmail client: only GET, only `graph.microsoft.com` (the shared transport
guard), every answer size-capped and strictly parsed, a failure is a stated error and never an
empty mailbox. Changes come from the folder's delta query: the opaque `@odata.deltaLink` is the
position, kept by the sync. A link Graph hands back (`nextLink`, `deltaLink`) is followed only if
it points at Graph over HTTPS.
"""

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from core.mailbox.gmail import (
    GRAPH_HOST,
    MAX_RESPONSE_BYTES,
    GmailError,
    HistoryPage,
    ListPage,
    _status_error,
    make_client,
)

BASE = "https://graph.microsoft.com/v1.0"
INBOX = "/me/mailFolders/inbox/messages"
PAGE = 100
MAX_ROUNDS = 100  # pages followed in one call before giving up


class _M(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class _Item(_M):
    id: str = Field(pattern=r"^[A-Za-z0-9_=+\-]{1,512}$")
    removed: dict[str, Any] | None = Field(default=None, alias="@removed")


class _Page(_M):
    value: list[_Item] = []
    next_link: str | None = Field(default=None, alias="@odata.nextLink", max_length=4096)
    delta_link: str | None = Field(default=None, alias="@odata.deltaLink", max_length=4096)


def safe_link(url: str) -> str:
    """Only an https link to Graph's own v1.0 API: anything else a server hands back is refused."""
    p = urlparse(url)
    if (
        p.scheme != "https"
        or p.hostname != GRAPH_HOST
        or p.port not in (None, 443)
        or not p.path.startswith("/v1.0/")
    ):
        raise GmailError("bad_response")
    return url


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class GraphClient:
    def __init__(
        self,
        access_token: Callable[[], str],
        http: httpx.Client | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._token = access_token
        self._http = http or make_client()
        self._clock = clock

    # ---- the interface the sync uses --------------------------------------------------------

    def profile_history_id(self) -> str:
        """A change position for "from now on": a delta round filtered to mail received from now."""
        url = BASE + INBOX + "/delta"
        params: dict[str, str] | None = {
            "$filter": f"receivedDateTime ge {_iso(self._clock())}",
            "$select": "id",
        }
        for _ in range(MAX_ROUNDS):
            page = self._page(url, params, "history_gone")
            if page.delta_link:
                return safe_link(page.delta_link)
            if not page.next_link:
                raise GmailError("bad_response")
            url, params = safe_link(page.next_link), None
        raise GmailError("bad_response")

    def list_recent(self, days: int, page: str | None = None) -> ListPage:
        if not 1 <= days <= 30:
            raise ValueError("days must be 1..30")
        if page:
            got = self._page(safe_link(page), None, "not_found")
        else:
            since = _iso(self._clock() - timedelta(days=days))
            params = {
                "$filter": f"receivedDateTime ge {since}", "$orderby": "receivedDateTime desc",
                "$select": "id", "$top": str(PAGE),
            }  # fmt: skip
            got = self._page(BASE + INBOX, params, "not_found")
        return ListPage(ids=[m.id for m in got.value if m.removed is None], next_page=got.next_link)

    def history(self, start_history_id: str, page: str | None = None) -> HistoryPage:
        """`start_history_id` is the delta link kept from the last round; `page` a next link."""
        got = self._page(safe_link(page or start_history_id), None, "history_gone")
        ids = list(dict.fromkeys(m.id for m in got.value if m.removed is None))
        return HistoryPage(
            history_id=safe_link(got.delta_link) if got.delta_link else start_history_id,
            ids=ids,
            next_page=safe_link(got.next_link) if got.next_link else None,
        )

    def get_raw(self, message_id: str) -> bytes:
        try:
            _Item(id=message_id)
        except ValidationError:
            raise ValueError("not a Graph message id") from None
        return self._fetch(
            f"{BASE}/me/messages/{quote(message_id, safe='')}/$value", None, "not_found"
        )

    # ---- plumbing ----------------------------------------------------------------------------

    def _page(self, url: str, params: dict[str, str] | None, missing: Any) -> _Page:
        body = self._fetch(url, params, missing, prefer="odata.maxpagesize=" + str(PAGE))
        try:
            return _Page.model_validate(json.loads(body))
        except (ValueError, ValidationError):
            raise GmailError("bad_response") from None

    def _fetch(
        self, url: str, params: dict[str, str] | None, missing: Any, prefer: str | None = None
    ) -> bytes:
        headers = {"Authorization": f"Bearer {self._token()}"}
        if prefer:
            headers["Prefer"] = prefer
        try:
            with self._http.stream("GET", url, params=params, headers=headers) as r:
                if r.status_code != 200:
                    raise _status_error(r, missing)
                declared = r.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                    raise GmailError("too_large")
                body = bytearray()
                for chunk in r.iter_bytes():
                    body += chunk
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise GmailError("too_large")
        except httpx.HTTPError:
            raise GmailError("network") from None
        return bytes(body)
