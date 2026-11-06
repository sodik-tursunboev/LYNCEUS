"""A read-only Gmail client (M5, ADR-017).

It can only reach three Google hosts over HTTPS, and only `gmail.googleapis.com` may be asked for
anything but a GET: a transport hook refuses everything else before a byte leaves, so "read-only"
is enforced here and not only promised. Every response is size-capped and strictly parsed; an
answer that does not fit is an error, never an empty mailbox.
"""

import base64
import binascii
import logging
from collections.abc import Callable
from typing import Literal, TypeVar

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

# httpx logs request URLs at INFO and the URL carries a message id: keep it quiet (tested).
for _noisy in ("httpx", "httpcore"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

API = "https://gmail.googleapis.com/gmail/v1/users/me"
SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
SCOPE_WRITE = "https://www.googleapis.com/auth/gmail.modify"  # M6b: separate, explicit consent
GMAIL_HOST = "gmail.googleapis.com"
GRAPH_HOST = "graph.microsoft.com"
READ_ONLY_HOSTS = frozenset({GMAIL_HOST, GRAPH_HOST})  # GET and nothing else, ever
ALLOWED_HOSTS = frozenset(
    {
        GMAIL_HOST, GRAPH_HOST, "oauth2.googleapis.com", "accounts.google.com",
        "login.microsoftonline.com",
    }
)  # fmt: skip
MAX_RESPONSE_BYTES = 16 * 1024 * 1024  # a 10 MiB message is about 14 MB as base64url JSON
PAGE = 100

ErrorKind = Literal[
    "auth", "forbidden", "rate", "server", "history_gone", "not_found", "too_large", "bad_response",
    "network",
]  # fmt: skip


class GmailError(Exception):
    """Something Gmail or the network did, named by kind. Carries no message id or content."""

    def __init__(self, kind: ErrorKind, retry_after: float | None = None) -> None:
        super().__init__(kind)
        self.kind: ErrorKind = kind
        self.retry_after = retry_after


class EgressRefused(Exception):
    """The request was not to an allowed Google host over HTTPS, or was not a GET to Gmail."""


def guard(request: httpx.Request) -> None:
    if request.url.scheme != "https" or request.url.host not in ALLOWED_HOSTS:
        raise EgressRefused(f"{request.url.scheme}://{request.url.host}")
    if request.url.host in READ_ONLY_HOSTS and request.method != "GET":
        raise EgressRefused(f"{request.method} to a mail host")


def make_client(
    transport: httpx.BaseTransport | None = None, timeout: float = 20.0
) -> httpx.Client:
    return httpx.Client(
        transport=transport,
        timeout=timeout,
        follow_redirects=False,  # a redirect would be a surprise; never followed
        event_hooks={"request": [guard]},
        headers={"User-Agent": "mirage/0.1"},
    )


class _M(BaseModel):
    model_config = ConfigDict(extra="ignore")


_Id = Field(pattern=r"^[0-9A-Za-z_-]{1,64}$")


class _Ref(_M):
    id: str = _Id


class _List(_M):
    messages: list[_Ref] = []
    nextPageToken: str | None = Field(default=None, max_length=2048)


class _Profile(_M):
    historyId: str = Field(pattern=r"^\d{1,32}$")


class _Added(_M):
    message: _Ref


class _HistoryItem(_M):
    messagesAdded: list[_Added] = []


class _History(_M):
    history: list[_HistoryItem] = []
    nextPageToken: str | None = Field(default=None, max_length=2048)
    historyId: str = Field(pattern=r"^\d{1,32}$")


class _Raw(_M):
    id: str = _Id
    raw: str


class HistoryPage(BaseModel):
    history_id: str
    ids: list[str]
    next_page: str | None


class ListPage(BaseModel):
    ids: list[str]
    next_page: str | None


M = TypeVar("M", bound=BaseModel)


class GmailClient:
    def __init__(self, access_token: Callable[[], str], http: httpx.Client | None = None) -> None:
        """`access_token` returns a current token, or raises GmailError("auth")."""
        self._token = access_token
        self._http = http or make_client()

    def profile_history_id(self) -> str:
        return self._get("/profile", _Profile, {}).historyId

    def list_recent(self, days: int, page: str | None = None) -> ListPage:
        if not 1 <= days <= 30:
            raise ValueError("days must be 1..30")
        params = {"q": f"newer_than:{days}d", "labelIds": "INBOX", "maxResults": str(PAGE)}
        if page:
            params["pageToken"] = page
        r = self._get("/messages", _List, params)
        return ListPage(ids=[m.id for m in r.messages], next_page=r.nextPageToken)

    def history(self, start_history_id: str, page: str | None = None) -> HistoryPage:
        params = {
            "startHistoryId": start_history_id, "historyTypes": "messageAdded",
            "labelId": "INBOX", "maxResults": "500",
        }  # fmt: skip
        if page:
            params["pageToken"] = page
        r = self._get("/history", _History, params, missing="history_gone")
        ids = list(dict.fromkeys(a.message.id for h in r.history for a in h.messagesAdded))
        return HistoryPage(history_id=r.historyId, ids=ids, next_page=r.nextPageToken)

    def get_raw(self, message_id: str) -> bytes:
        try:
            _Ref(id=message_id)
        except ValidationError:
            raise ValueError("not a Gmail message id") from None
        r = self._get(f"/messages/{message_id}", _Raw, {"format": "raw"}, missing="not_found")
        try:
            return base64.b64decode(r.raw + "=" * (-len(r.raw) % 4), altchars=b"-_", validate=True)
        except (binascii.Error, ValueError):
            raise GmailError("bad_response") from None

    def _get(
        self, path: str, model: type[M], params: dict[str, str], missing: ErrorKind = "not_found"
    ) -> M:
        headers = {"Authorization": f"Bearer {self._token()}"}
        try:
            with self._http.stream("GET", API + path, params=params, headers=headers) as r:
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
        try:
            return model.model_validate_json(bytes(body))
        except ValidationError:
            raise GmailError("bad_response") from None


def _status_error(r: httpx.Response, missing: ErrorKind) -> GmailError:
    code = r.status_code
    retry = r.headers.get("retry-after")
    after = float(retry) if retry and retry.replace(".", "", 1).isdigit() else None
    if code == 410:
        return GmailError("history_gone")  # a change token the provider no longer has
    if code == 404:
        return GmailError(missing)
    if code == 401:
        return GmailError("auth")
    if code == 403:
        try:
            text = r.read().decode("utf-8", "replace")[:2000]
        except httpx.HTTPError:
            text = ""
        return GmailError("rate" if "ateLimitExceeded" in text else "forbidden", after)
    if code in (408, 429):
        return GmailError("rate", after)
    if code >= 500:
        return GmailError("server", after)
    return GmailError("bad_response")
