"""Fakes for the WRITE side of the mailboxes (M6b): Gmail labels and `messages.modify`, Graph
folders and `message: move`. They follow the documented shapes and record every request, so
tests can assert exactly which calls were made. They prove our logic, not that Google or
Microsoft accept the requests (see docs/milestones/M6b.md). Behaviour the documentation does not
state is switchable: a duplicate label or folder name, an id that changes after a move."""

import json
from urllib.parse import unquote

import httpx

GMAIL = "/gmail/v1/users/me"
GRAPH = "/v1.0/me"


class FakeGmailWrite:
    def __init__(self) -> None:
        self.labels: dict[str, str] = {"INBOX": "INBOX", "UNREAD": "UNREAD"}  # name -> id
        self.messages: dict[str, set[str]] = {}  # message id -> label ids
        self.requests: list[tuple[str, str, str, bytes]] = []  # method, path, query, body
        self.failures: list[tuple[str, int, dict[str, str]]] = []
        self.duplicate_label_status = 409  # what creating an existing name answers (not documented)
        self.hide_labels_once = (
            False  # the label exists but the first list does not show it (a race)
        )
        self.ignore_modify = (
            False  # modify answers 200 but changes nothing (a reply that does not match)
        )
        self._next = 1

    def add(self, message_id: str, *labels: str) -> None:
        self.messages[message_id] = set(labels or ("INBOX",))

    def fail_next(self, contains: str, status: int, **headers: str) -> None:
        self.failures.append((contains, status, headers))

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def calls(self, method: str | None = None) -> list[tuple[str, str]]:
        return [(m, p) for (m, p, _q, _b) in self.requests if method is None or m == method]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path, body = request.url.path, request.content
        self.requests.append((request.method, path, request.url.query.decode(), body))
        for i, (contains, status, headers) in enumerate(self.failures):
            if contains in path:
                del self.failures[i]
                return httpx.Response(status, headers=headers, json={"error": {"code": status}})
        if not path.startswith(GMAIL):
            return httpx.Response(404)
        route = path[len(GMAIL) :]
        if route == "/labels" and request.method == "GET":
            hide = self.hide_labels_once
            self.hide_labels_once = False
            shown = {
                n: i for n, i in self.labels.items() if not (hide and n == "LYNCEUS-Quarantine")
            }
            return httpx.Response(
                200, json={"labels": [{"id": i, "name": n} for n, i in shown.items()]}
            )
        if route == "/labels" and request.method == "POST":
            name = json.loads(body)["name"]
            if name in self.labels:
                return httpx.Response(
                    self.duplicate_label_status,
                    json={"error": {"code": self.duplicate_label_status}},
                )
            self.labels[name] = f"Label_{self._next}"
            self._next += 1
            return httpx.Response(200, json={"id": self.labels[name], "name": name})
        if route.startswith("/messages/"):
            rest = route.removeprefix("/messages/")
            if rest.endswith("/modify") and request.method == "POST":
                mid = unquote(rest.removesuffix("/modify"))
                if mid not in self.messages:
                    return httpx.Response(404, json={"error": {"code": 404}})
                change = json.loads(body)
                if not self.ignore_modify:
                    self.messages[mid] |= set(change.get("addLabelIds", []))
                    self.messages[mid] -= set(change.get("removeLabelIds", []))
                return httpx.Response(200, json={"id": mid, "labelIds": sorted(self.messages[mid])})
            if request.method == "GET":
                mid = unquote(rest)
                if mid not in self.messages:
                    return httpx.Response(404, json={"error": {"code": 404}})
                return httpx.Response(200, json={"id": mid, "labelIds": sorted(self.messages[mid])})
        return httpx.Response(405)


class FakeGraphWrite:
    def __init__(self, id_changes_on_move: bool = True) -> None:
        self.folders: dict[str, str] = {"inbox": "AAInbox="}  # display name (lower) -> id
        self.messages: dict[str, str] = {}  # message id -> folder id
        self.requests: list[tuple[str, str, str, bytes]] = []
        self.failures: list[tuple[str, int, dict[str, str]]] = []
        self.id_changes = id_changes_on_move
        self.land_elsewhere = False  # a move that answers with another parent folder
        self.next_link: str | None = None  # make the first folder list claim there is more
        self._next = 1

    def add(self, message_id: str, folder: str = "AAInbox=") -> None:
        self.messages[message_id] = folder

    def fail_next(self, contains: str, status: int, **headers: str) -> None:
        self.failures.append((contains, status, headers))

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def calls(self, method: str | None = None) -> list[tuple[str, str]]:
        return [(m, p) for (m, p, _q, _b) in self.requests if method is None or m == method]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path, body = request.url.path, request.content
        self.requests.append((request.method, path, request.url.query.decode(), body))
        for i, (contains, status, headers) in enumerate(self.failures):
            if contains in path:
                del self.failures[i]
                return httpx.Response(status, headers=headers, json={"error": {"code": "x"}})
        if not path.startswith(GRAPH):
            return httpx.Response(404)
        route = path[len(GRAPH) :]
        if route == "/mailFolders" and request.method == "GET":
            extra = (
                {"@odata.nextLink": self.next_link}
                if self.next_link and not request.url.params.get("$skip")
                else {}
            )
            return httpx.Response(
                200,
                json={
                    "value": [
                        {"id": i, "displayName": n} for n, i in self.folders.items() if n != "inbox"
                    ],
                    **extra,
                },
            )
        if route == "/mailFolders/inbox" and request.method == "GET":
            return httpx.Response(200, json={"id": self.folders["inbox"], "displayName": "Inbox"})
        if route == "/mailFolders" and request.method == "POST":
            name = json.loads(body)["displayName"]
            self.folders[name.lower()] = f"AAFolder{self._next}="
            self._next += 1
            return httpx.Response(201, json={"id": self.folders[name.lower()], "displayName": name})
        if route.startswith("/messages/"):
            rest = route.removeprefix("/messages/")
            if rest.endswith("/move") and request.method == "POST":
                mid = unquote(rest.removesuffix("/move"))
                if mid not in self.messages:
                    return httpx.Response(404, json={"error": {"code": "ErrorItemNotFound"}})
                target = json.loads(body)["destinationId"]
                if target not in self.folders.values():
                    return httpx.Response(404, json={"error": {"code": "ErrorInvalidIdMalformed"}})
                new = mid
                if self.id_changes:
                    new = f"{mid}-m{self._next}"
                    self._next += 1
                    del self.messages[mid]
                self.messages[new] = target
                return httpx.Response(
                    201,
                    json={
                        "id": new,
                        "parentFolderId": "AAElsewhere=" if self.land_elsewhere else target,
                    },
                )
            if request.method == "GET":
                mid = unquote(rest)
                if mid not in self.messages:
                    return httpx.Response(404, json={"error": {"code": "ErrorItemNotFound"}})
                return httpx.Response(200, json={"id": mid, "parentFolderId": self.messages[mid]})
        return httpx.Response(405)
