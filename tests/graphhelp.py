"""A fake Microsoft Graph inbox that follows the documented shapes: a delta query whose rounds end
in an `@odata.deltaLink` (more pages as `@odata.nextLink`), `@removed` entries for deleted mail, a
message list, and the raw message at `/$value`. A change token older than `expire_delta()` answers
HTTP 410. It records every request so tests can assert the client only sends GETs. It proves our
logic, not that Microsoft accepts the requests (see docs/milestones/M5b.md)."""

import json
from urllib.parse import unquote

import httpx

BASE = "/v1.0/me"
HOST = "https://graph.microsoft.com"


class FakeGraph:
    def __init__(self, page_size: int = 100) -> None:
        self.messages: dict[str, bytes] = {}
        self.order: list[str] = []
        self.changes: list[tuple[int, str, bool]] = []  # sequence, id, removed
        self.seq = 100
        self.floor = 0
        self.page_size = page_size
        self.requests: list[
            tuple[str, str, str, dict[str, str]]
        ] = []  # method, path, query, headers
        self.failures: list[tuple[str, int, dict[str, str]]] = []
        self.override: dict[
            str, dict[str, object]
        ] = {}  # path fragment -> JSON body to send instead

    def add(self, message_id: str, raw: bytes) -> None:
        self.seq += 1
        self.messages[message_id] = raw
        self.order.append(message_id)
        self.changes.append((self.seq, message_id, False))

    def delete(self, message_id: str) -> None:
        """Deleted for real: it is gone and the next delta round says so."""
        self.seq += 1
        self.messages.pop(message_id, None)
        self.changes.append((self.seq, message_id, True))

    def vanish(self, message_id: str) -> None:
        """Gone without a change entry (it disappears between the round and the fetch)."""
        self.messages.pop(message_id, None)

    def expire_delta(self) -> None:
        self.floor = self.seq

    def fail_next(self, contains: str, status: int, **headers: str) -> None:
        self.failures.append((contains, status, headers))

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _json(self, body: dict[str, object], status: int = 200) -> httpx.Response:
        return httpx.Response(
            status, content=json.dumps(body).encode(), headers={"content-type": "application/json"}
        )

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        query = request.url.query.decode()
        self.requests.append((request.method, path, query, dict(request.headers)))
        for i, (contains, status, headers) in enumerate(self.failures):
            if contains in path or contains in query:
                del self.failures[i]
                return httpx.Response(
                    status, headers=headers, json={"error": {"code": "x", "message": "m"}}
                )
        for fragment, body in self.override.items():
            if fragment in path:
                return self._json(body)
        if request.method != "GET" or request.url.host != "graph.microsoft.com":
            return httpx.Response(405)
        q = dict(request.url.params)
        if path == f"/v1.0{BASE[5:]}/mailFolders/inbox/messages/delta" or path.endswith(
            "/mailFolders/inbox/messages/delta"
        ):
            return self._delta(q)
        if path.endswith("/mailFolders/inbox/messages"):
            ids = [m for m in reversed(self.order) if m in self.messages]
            start = int(q.get("$skiptoken", "0"))
            page = ids[start : start + self.page_size]
            body: dict[str, object] = {"value": [{"id": m} for m in page]}
            if start + self.page_size < len(ids):
                body["@odata.nextLink"] = (
                    f"{HOST}/v1.0/me/mailFolders/inbox/messages?$skiptoken={start + self.page_size}"
                )
            return self._json(body)
        if "/messages/" in path and path.endswith("/$value"):
            mid = unquote(path.split("/messages/")[1].removesuffix("/$value"))
            if mid not in self.messages:
                return self._json({"error": {"code": "ErrorItemNotFound"}}, 404)
            return httpx.Response(
                200, content=self.messages[mid], headers={"content-type": "message/rfc822"}
            )
        return httpx.Response(404)

    def _delta(self, q: dict[str, str]) -> httpx.Response:
        base = f"{HOST}/v1.0/me/mailFolders/inbox/messages/delta"
        if "$deltaToken" not in q:  # the first round, filtered to mail from now on: nothing yet
            return self._json({"value": [], "@odata.deltaLink": f"{base}?$deltaToken=T{self.seq}"})
        token = int(q["$deltaToken"].removeprefix("T"))
        if token < self.floor:
            return self._json({"error": {"code": "syncStateNotFound"}}, 410)
        latest: dict[str, tuple[int, str, bool]] = {}  # Graph reports an item's final state once
        for c in self.changes:
            if c[0] > token:
                latest[c[1]] = c
        mine = sorted(latest.values())
        start = int(q.get("$skiptoken", "0"))
        page = mine[start : start + self.page_size]
        items = [
            ({"id": i, "@removed": {"reason": "deleted"}} if removed else {"id": i})
            for (_s, i, removed) in page
        ]
        body: dict[str, object] = {"value": items}
        if start + self.page_size < len(mine):
            body["@odata.nextLink"] = (
                f"{base}?$deltaToken=T{token}&$skiptoken={start + self.page_size}"
            )
        else:
            body["@odata.deltaLink"] = f"{base}?$deltaToken=T{self.seq}"
        return self._json(body)
