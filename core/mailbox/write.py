"""Moving a flagged message out of the inbox, and back (M6b, ADR-017 addendum).

This is the only code that changes a mailbox, and it is held to a short list. The token it uses
can do far more than MIRAGE ever asks of it (Gmail's `gmail.modify` also composes and sends;
Microsoft's `Mail.ReadWrite` also deletes), so the limit is enforced HERE, before a byte leaves:
a transport hook refuses every request that is not one of a handful of exact shapes (method,
host, path, query and body). There is no code path for DELETE, send, draft, trash or any edit of
the message itself, and the tests try each of them against the guard.

What "quarantine" means: Gmail adds the label MIRAGE-Quarantine and removes INBOX; Outlook moves
the message to a folder named MIRAGE Quarantine. Restore reverses it. Both are checked before
and after (already in place: do nothing; result not as expected: say so), so repeating a call is
harmless.
"""

import json
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx

from core.mailbox.gmail import (
    GMAIL_HOST,
    GRAPH_HOST,
    MAX_RESPONSE_BYTES,
    EgressRefused,
    GmailError,
    _status_error,
)
from core.mailbox.graph import safe_link

QUARANTINE_LABEL = "MIRAGE-Quarantine"
QUARANTINE_FOLDER = "MIRAGE Quarantine"
GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me"
GRAPH_API = "https://graph.microsoft.com/v1.0/me"
MAX_FOLDER_PAGES = 20

_GMAIL_ID = r"[A-Za-z0-9_\-]{1,64}"
_GRAPH_ID = r"[A-Za-z0-9_=+\-]{1,512}"
_LABEL_ID = re.compile(r"^(INBOX|Label_[0-9]{1,12})$")
_GRAPH_ID_RE = re.compile(rf"^{_GRAPH_ID}$")
_GMAIL_ID_RE = re.compile(rf"^{_GMAIL_ID}$")
_GRAPH_PAGE_KEYS = frozenset({"$top", "$skip", "$skiptoken"})


def _json(request: httpx.Request) -> object:
    try:
        return json.loads(request.content or b"null")
    except ValueError:
        return None


def _label_list(value: object) -> bool:
    return (
        isinstance(value, list)
        and 1 <= len(value) <= 2
        and len(set(map(str, value))) == len(value)
        and all(isinstance(v, str) and _LABEL_ID.match(v) for v in value)
    )


def _gmail_allowed(request: httpx.Request) -> bool:
    path, method, query = request.url.path, request.method, request.url.query.decode()
    if path == "/gmail/v1/users/me/labels":
        if method == "GET":
            return query == ""
        return (
            method == "POST"
            and query == ""
            and _json(request)
            == {
                "name": QUARANTINE_LABEL,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            }
        )
    if re.fullmatch(rf"/gmail/v1/users/me/messages/{_GMAIL_ID}", path):
        return method == "GET" and query == "format=minimal"
    if re.fullmatch(rf"/gmail/v1/users/me/messages/{_GMAIL_ID}/modify", path):
        body = _json(request)
        return (
            method == "POST"
            and query == ""
            and isinstance(body, dict)
            and 1 <= len(body) <= 2
            and set(body) <= {"addLabelIds", "removeLabelIds"}
            and all(_label_list(v) for v in body.values())
        )
    return False


def _graph_allowed(request: httpx.Request) -> bool:
    path, method = request.url.path, request.method
    keys = {k for k, _ in request.url.params.multi_items()}
    if path == "/v1.0/me/mailFolders":
        if method == "GET":
            return keys <= _GRAPH_PAGE_KEYS
        return (
            method == "POST" and not keys and _json(request) == {"displayName": QUARANTINE_FOLDER}
        )
    if path == "/v1.0/me/mailFolders/inbox":
        return method == "GET" and not keys
    if re.fullmatch(rf"/v1\.0/me/messages/{_GRAPH_ID}", path):
        return method == "GET" and dict(request.url.params) == {"$select": "parentFolderId"}
    if re.fullmatch(rf"/v1\.0/me/messages/{_GRAPH_ID}/move", path):
        body = _json(request)
        return (
            method == "POST"
            and not keys
            and isinstance(body, dict)
            and set(body) == {"destinationId"}
            and isinstance(body["destinationId"], str)
            and _GRAPH_ID_RE.match(body["destinationId"]) is not None
        )
    return False


def write_guard(request: httpx.Request) -> None:
    """Allow only the exact requests the two movers make; refuse all else before it is sent."""
    if request.url.scheme != "https" or request.url.port not in (None, 443) or request.url.username:
        raise EgressRefused(f"{request.url.scheme}://{request.url.host}")
    host = request.url.host
    allowed = (
        _gmail_allowed(request)
        if host == GMAIL_HOST
        else _graph_allowed(request)
        if host == GRAPH_HOST
        else False
    )
    if not allowed:
        raise EgressRefused(f"{request.method} to {host} is not one of the moves MIRAGE makes")


def make_write_client(
    transport: httpx.BaseTransport | None = None, timeout: float = 20.0
) -> httpx.Client:
    return httpx.Client(
        transport=transport,
        timeout=timeout,
        follow_redirects=False,
        event_hooks={"request": [write_guard]},
        headers={"User-Agent": "mirage/0.1"},
    )


def _call(
    http: httpx.Client, token: Callable[[], str], method: str, url: str,
    *, params: dict[str, str] | None = None, body: dict[str, Any] | None = None,
) -> dict[str, Any]:  # fmt: skip
    headers = {"Authorization": f"Bearer {token()}"}
    try:
        r = http.request(method, url, params=params, json=body, headers=headers)
    except httpx.HTTPError:
        raise GmailError("network") from None
    if r.status_code not in (200, 201):
        raise _status_error(r, "not_found")
    if len(r.content) > MAX_RESPONSE_BYTES:
        raise GmailError("too_large")
    try:
        data = r.json()
    except ValueError:
        raise GmailError("bad_response") from None
    if not isinstance(data, dict):
        raise GmailError("bad_response")
    return data


def _check_ref(ref: str, pattern: re.Pattern[str]) -> None:
    """A message id is checked before ANY request: no label or folder is made for a bad one."""
    if not pattern.match(ref):
        raise ValueError("not a message id")


def _text(data: dict[str, Any], key: str, pattern: re.Pattern[str]) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not pattern.match(value):
        raise GmailError("bad_response")
    return value


class GmailMover:
    """Quarantine = add the label, take away INBOX. Restore = the reverse. Never trash or delete."""

    def __init__(self, access_token: Callable[[], str], http: httpx.Client | None = None) -> None:
        self._token, self._http = access_token, http or make_write_client()
        self._label_id: str | None = None

    def _find_label(self) -> str | None:
        data = _call(self._http, self._token, "GET", GMAIL_API + "/labels")
        labels = data.get("labels", [])
        if not isinstance(labels, list):
            raise GmailError("bad_response")
        for label in labels:
            if isinstance(label, dict) and label.get("name") == QUARANTINE_LABEL:
                return _text(label, "id", re.compile(r"^Label_[0-9]{1,12}$"))
        return None

    def _label(self, create: bool) -> str | None:
        if self._label_id is None:
            self._label_id = self._find_label()
            if self._label_id is None and create:
                try:
                    made = _call(
                        self._http, self._token, "POST", GMAIL_API + "/labels",
                        body={
                            "name": QUARANTINE_LABEL,
                            "labelListVisibility": "labelShow",
                            "messageListVisibility": "show",
                        },
                    )  # fmt: skip
                    self._label_id = _text(made, "id", re.compile(r"^Label_[0-9]{1,12}$"))
                except GmailError:
                    # What a duplicate name answers is not documented: look again, whatever it was.
                    self._label_id = self._find_label()
                    if self._label_id is None:
                        raise
        return self._label_id

    def _labels_of(self, ref: str) -> set[str]:
        data = _call(
            self._http, self._token, "GET", f"{GMAIL_API}/messages/{quote(ref, safe='')}",
            params={"format": "minimal"},
        )  # fmt: skip
        ids = data.get("labelIds", [])
        if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
            raise GmailError("bad_response")
        return set(ids)

    def _modify(self, ref: str, add: list[str], remove: list[str]) -> set[str]:
        body: dict[str, Any] = {}
        if add:
            body["addLabelIds"] = add
        if remove:
            body["removeLabelIds"] = remove
        data = _call(
            self._http, self._token, "POST", f"{GMAIL_API}/messages/{quote(ref, safe='')}/modify",
            body=body,
        )  # fmt: skip
        ids = data.get("labelIds", [])
        if not isinstance(ids, list):
            raise GmailError("bad_response")
        return {i for i in ids if isinstance(i, str)}

    def quarantine(self, ref: str) -> str:
        _check_ref(ref, _GMAIL_ID_RE)
        label = self._label(create=True)
        if label is None:  # create=True finds, makes, or raises; this cannot happen
            raise GmailError("bad_response")
        have = self._labels_of(ref)
        if label in have and "INBOX" not in have:
            return ref  # already there: nothing to do twice
        after = self._modify(ref, [label], ["INBOX"])
        if label not in after or "INBOX" in after:
            raise GmailError("bad_response")  # the reply does not show what was asked for
        return ref

    def restore(self, ref: str) -> str:
        _check_ref(ref, _GMAIL_ID_RE)
        label = self._label(create=False)
        have = self._labels_of(ref)
        if "INBOX" in have and (label is None or label not in have):
            return ref
        after = self._modify(ref, ["INBOX"], [label] if label else [])
        if "INBOX" not in after or (label is not None and label in after):
            raise GmailError("bad_response")
        return ref


class GraphMover:
    """Quarantine = move to the MIRAGE Quarantine folder; restore = move back to the inbox.

    A move makes a copy in the destination and removes the original, so the message gets a NEW id:
    quarantine returns it and the caller keeps it for the restore."""

    def __init__(self, access_token: Callable[[], str], http: httpx.Client | None = None) -> None:
        self._token, self._http = access_token, http or make_write_client()
        self._folder_id: str | None = None

    def _folder(self) -> str:
        if self._folder_id is not None:
            return self._folder_id
        url: str | None = GRAPH_API + "/mailFolders"
        params: dict[str, str] | None = {"$top": "100"}
        for _ in range(MAX_FOLDER_PAGES):
            if url is None:
                break
            data = _call(self._http, self._token, "GET", url, params=params)
            for item in data.get("value", []) if isinstance(data.get("value", []), list) else []:
                if (
                    isinstance(item, dict)
                    and str(item.get("displayName", "")).lower() == QUARANTINE_FOLDER.lower()
                ):
                    self._folder_id = _text(item, "id", _GRAPH_ID_RE)
                    return self._folder_id
            nxt = data.get("@odata.nextLink")
            url, params = (safe_link(nxt), None) if isinstance(nxt, str) and nxt else (None, None)
        made = _call(
            self._http, self._token, "POST", GRAPH_API + "/mailFolders",
            body={"displayName": QUARANTINE_FOLDER},
        )  # fmt: skip
        self._folder_id = _text(made, "id", _GRAPH_ID_RE)
        return self._folder_id

    def _parent(self, ref: str) -> str:
        data = _call(
            self._http, self._token, "GET", f"{GRAPH_API}/messages/{quote(ref, safe='')}",
            params={"$select": "parentFolderId"},
        )  # fmt: skip
        return _text(data, "parentFolderId", _GRAPH_ID_RE)

    def _move(self, ref: str, folder: str) -> str:
        data = _call(
            self._http, self._token, "POST", f"{GRAPH_API}/messages/{quote(ref, safe='')}/move",
            body={"destinationId": folder},
        )  # fmt: skip
        new = _text(data, "id", _GRAPH_ID_RE)
        parent = data.get("parentFolderId")
        if parent is not None and parent != folder:
            raise GmailError("bad_response")  # it did not land where it was asked to
        return new

    def quarantine(self, ref: str) -> str:
        _check_ref(ref, _GRAPH_ID_RE)
        folder = self._folder()
        if self._parent(ref) == folder:
            return ref
        return self._move(ref, folder)

    def restore(self, ref: str) -> str:
        _check_ref(ref, _GRAPH_ID_RE)
        inbox = _text(
            _call(self._http, self._token, "GET", GRAPH_API + "/mailFolders/inbox"),
            "id",
            _GRAPH_ID_RE,
        )
        if self._parent(ref) == inbox:
            return ref
        return self._move(ref, inbox)
