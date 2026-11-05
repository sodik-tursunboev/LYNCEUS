"""A fake Gmail that follows the documented shapes: profile, list, history (404 when old), raw get.

It records every request so tests can assert the client only sends GETs, and can be told to fail
(HTTP status, optional Retry-After) for the next matching request. It proves our logic, not that
Google accepts the requests (see docs/milestones/M5.md).
"""

import base64
import json
from urllib.parse import unquote

import httpx

PREFIX = "/gmail/v1/users/me"


class FakeGmail:
    def __init__(self, page_size: int = 100) -> None:
        self.messages: dict[str, bytes] = {}
        self.order: list[str] = []
        self.history: list[tuple[int, str]] = []
        self.current = 1000
        self.floor = 0
        self.page_size = page_size
        self.requests: list[tuple[str, str, str]] = []  # method, path, query
        self.failures: list[tuple[str, int, dict[str, str]]] = []

    def add(self, message_id: str, raw: bytes) -> None:
        self.current += 1
        self.messages[message_id] = raw
        self.order.append(message_id)
        self.history.append((self.current, message_id))

    def delete(self, message_id: str) -> None:
        self.messages.pop(message_id, None)

    def expire_history(self) -> None:
        self.floor = (
            self.current
        )  # positions older than "now" are gone; a fresh one from /profile is fine

    def fail_next(self, contains: str, status: int, **headers: str) -> None:
        self.failures.append((contains, status, headers))

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append((request.method, path, request.url.query.decode()))
        for i, (contains, status, headers) in enumerate(self.failures):
            if contains in path:
                del self.failures[i]
                return httpx.Response(status, headers=headers, json={"error": {"code": status}})
        if request.method != "GET" or not path.startswith(PREFIX):
            return httpx.Response(405)
        route = path[len(PREFIX) :]
        q = dict(request.url.params)
        if route == "/profile":
            return httpx.Response(200, json={"historyId": str(self.current), "emailAddress": "x"})
        if route == "/messages":
            ids = [m for m in reversed(self.order) if m in self.messages]
            return self._page(
                ids, q, lambda page, nxt: {"messages": [{"id": m} for m in page], **nxt}
            )
        if route == "/history":
            start = int(q["startHistoryId"])
            if start < self.floor:
                return httpx.Response(404, json={"error": {"code": 404}})
            ids = [m for (h, m) in self.history if h > start]
            return self._page(
                ids, q,
                lambda page, nxt: {
                    "history": [
                        {"id": "1", "messagesAdded": [{"message": {"id": m}}]} for m in page
                    ],
                    "historyId": str(self.current), **nxt,
                },
            )  # fmt: skip
        if route.startswith("/messages/"):
            mid = unquote(route.removeprefix("/messages/"))
            assert q.get("format") == "raw"
            if mid not in self.messages:
                return httpx.Response(404, json={"error": {"code": 404}})
            raw = base64.urlsafe_b64encode(self.messages[mid]).rstrip(b"=").decode()
            return httpx.Response(200, json={"id": mid, "raw": raw})
        return httpx.Response(404)

    def _page(self, ids: list[str], q: dict[str, str], build) -> httpx.Response:  # noqa: ANN001
        start = int(q.get("pageToken", "0"))
        page = ids[start : start + self.page_size]
        nxt = (
            {"nextPageToken": str(start + self.page_size)}
            if start + self.page_size < len(ids)
            else {}
        )
        return httpx.Response(200, content=json.dumps(build(page, nxt)).encode())
