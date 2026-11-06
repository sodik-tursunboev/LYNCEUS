"""Email quarantine, the write side (M6b): the request guard and the two movers, against fakes.

The token the movers use could send or delete mail; the guard is what stops MIRAGE's own code from
ever doing so, so most of these tests try the forbidden requests one by one and assert that nothing
reaches the (fake) server."""

from typing import Any

import httpx
import pytest
from mailwritehelp import FakeGmailWrite, FakeGraphWrite

from core.mailbox.gmail import EgressRefused, GmailError
from core.mailbox.write import (
    QUARANTINE_FOLDER,
    QUARANTINE_LABEL,
    GmailMover,
    GraphMover,
    make_write_client,
)

GM = "https://gmail.googleapis.com/gmail/v1/users/me"
GR = "https://graph.microsoft.com/v1.0/me"
LABEL = {
    "name": QUARANTINE_LABEL,
    "labelListVisibility": "labelShow",
    "messageListVisibility": "show",
}


def gmail(fake: FakeGmailWrite) -> GmailMover:
    return GmailMover(lambda: "tok", make_write_client(fake.transport()))


def graph(fake: FakeGraphWrite) -> GraphMover:
    return GraphMover(lambda: "tok", make_write_client(fake.transport()))


# ---- the guard: what is allowed is exact, everything else is refused before it is sent ----------


def refused(method: str, url: str, **kw: Any) -> None:
    sent: list[httpx.Request] = []
    client = make_write_client(
        httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200, json={}))
    )
    with pytest.raises(EgressRefused):
        client.request(method, url, **kw)
    assert sent == [], f"{method} {url} reached the network"


GMAIL_FORBIDDEN: list[tuple[str, str, dict[str, Any]]] = [
    ("DELETE", f"{GM}/messages/abc", {}),
    ("POST", f"{GM}/messages/abc/trash", {}),
    ("POST", f"{GM}/messages/abc/untrash", {}),
    ("POST", f"{GM}/messages/batchDelete", {"json": {"ids": ["abc"]}}),
    ("POST", f"{GM}/messages/batchModify", {"json": {"ids": ["abc"], "addLabelIds": ["INBOX"]}}),
    ("POST", f"{GM}/messages/send", {"json": {"raw": "x"}}),
    ("POST", f"{GM}/messages", {"json": {"raw": "x"}}),
    ("POST", f"{GM}/messages/import", {"json": {"raw": "x"}}),
    ("POST", f"{GM}/drafts", {"json": {}}),
    ("POST", f"{GM}/drafts/send", {"json": {"id": "d"}}),
    ("POST", f"{GM}/messages/abc/modify", {"json": {"addLabelIds": ["TRASH"]}}),
    ("POST", f"{GM}/messages/abc/modify", {"json": {"addLabelIds": ["SPAM"]}}),
    ("POST", f"{GM}/messages/abc/modify", {"json": {"addLabelIds": ["STARRED"]}}),
    ("POST", f"{GM}/messages/abc/modify", {"json": {"removeLabelIds": ["UNREAD"]}}),
    ("POST", f"{GM}/messages/abc/modify", {"json": {"addLabelIds": ["Label_1"], "extra": 1}}),
    ("POST", f"{GM}/messages/abc/modify", {"json": {"addClassificationLabels": [{}]}}),
    ("POST", f"{GM}/messages/abc/modify", {"json": {}}),
    ("POST", f"{GM}/messages/abc/modify", {"json": {"addLabelIds": []}}),
    (
        "POST",
        f"{GM}/messages/abc/modify",
        {"json": {"addLabelIds": ["Label_1", "INBOX", "Label_2"]}},
    ),
    ("POST", f"{GM}/messages/abc/modify", {"json": {"addLabelIds": ["Label_1", "Label_1"]}}),
    ("POST", f"{GM}/messages/abc/modify", {"json": {"addLabelIds": "Label_1"}}),
    ("POST", f"{GM}/messages/abc/modify", {"json": ["Label_1"]}),
    ("POST", f"{GM}/messages/abc/modify", {"content": b"not json"}),
    (
        "POST",
        f"{GM}/messages/abc/modify",
        {"json": {"addLabelIds": ["Label_1"]}, "params": {"x": "1"}},
    ),
    ("PUT", f"{GM}/messages/abc/modify", {"json": {"addLabelIds": ["Label_1"]}}),
    ("PATCH", f"{GM}/messages/abc", {"json": {}}),
    ("POST", f"{GM}/labels", {"json": {**LABEL, "name": "Other"}}),
    ("POST", f"{GM}/labels", {"json": {**LABEL, "color": {}}}),
    ("POST", f"{GM}/labels", {"json": {"name": QUARANTINE_LABEL}}),
    ("PATCH", f"{GM}/labels/Label_1", {"json": {"name": "x"}}),
    ("PUT", f"{GM}/labels/Label_1", {"json": {"name": "x"}}),
    ("DELETE", f"{GM}/labels/Label_1", {}),
    ("GET", f"{GM}/messages/abc", {"params": {"format": "raw"}}),  # reading the body is not its job
    ("GET", f"{GM}/messages/abc", {"params": {"format": "full"}}),
    ("GET", f"{GM}/messages/abc", {}),
    ("GET", f"{GM}/messages", {}),
    ("GET", f"{GM}/threads/abc", {}),
    ("GET", f"{GM}/settings/filters", {}),
    ("POST", f"{GM}/settings/forwardingAddresses", {"json": {"forwardingEmail": "x@y.test"}}),
    ("POST", f"{GM}/settings/filters", {"json": {}}),
    (
        "POST",
        "https://gmail.googleapis.com/gmail/v1/users/other@x.test/messages/abc/modify",
        {"json": {"addLabelIds": ["INBOX"]}},
    ),
    (
        "POST",
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/a%2Fb/modify",
        {"json": {"addLabelIds": ["INBOX"]}},
    ),
    (
        "POST",
        "http://gmail.googleapis.com/gmail/v1/users/me/messages/abc/modify",
        {"json": {"addLabelIds": ["INBOX"]}},
    ),
    (
        "POST",
        "https://gmail.googleapis.com:8443/gmail/v1/users/me/messages/abc/modify",
        {"json": {"addLabelIds": ["INBOX"]}},
    ),
    (
        "POST",
        "https://user@gmail.googleapis.com/gmail/v1/users/me/messages/abc/modify",
        {"json": {"addLabelIds": ["INBOX"]}},
    ),
    (
        "POST",
        "https://gmail.googleapis.com.evil.test/gmail/v1/users/me/messages/abc/modify",
        {"json": {"addLabelIds": ["INBOX"]}},
    ),
]

GRAPH_FORBIDDEN: list[tuple[str, str, dict[str, Any]]] = [
    ("POST", f"{GR}/sendMail", {"json": {}}),
    ("POST", f"{GR}/messages/abc/send", {}),
    ("POST", f"{GR}/messages/abc/reply", {"json": {}}),
    ("POST", f"{GR}/messages/abc/replyAll", {"json": {}}),
    ("POST", f"{GR}/messages/abc/forward", {"json": {}}),
    ("POST", f"{GR}/messages/abc/createForward", {"json": {}}),
    ("POST", f"{GR}/messages", {"json": {"subject": "x"}}),  # a draft
    ("PATCH", f"{GR}/messages/abc", {"json": {"isRead": True}}),
    ("DELETE", f"{GR}/messages/abc", {}),
    ("POST", f"{GR}/messages/abc/permanentDelete", {}),
    ("POST", f"{GR}/messages/abc/copy", {"json": {"destinationId": "AAx="}}),
    ("DELETE", f"{GR}/mailFolders/AAx=", {}),
    ("PATCH", f"{GR}/mailFolders/AAx=", {"json": {"displayName": "x"}}),
    ("POST", f"{GR}/mailFolders/AAx=/move", {"json": {"destinationId": "inbox"}}),
    ("POST", f"{GR}/mailFolders", {"json": {"displayName": "Something else"}}),
    ("POST", f"{GR}/mailFolders", {"json": {"displayName": QUARANTINE_FOLDER, "isHidden": True}}),
    ("POST", f"{GR}/mailFolders/inbox/childFolders", {"json": {"displayName": QUARANTINE_FOLDER}}),
    ("POST", f"{GR}/messages/abc/move", {"json": {"destinationId": "AAx=", "extra": 1}}),
    ("POST", f"{GR}/messages/abc/move", {"json": {"destinationId": ""}}),
    ("POST", f"{GR}/messages/abc/move", {"json": {"destinationId": "a/b"}}),
    ("POST", f"{GR}/messages/abc/move", {"json": {"destinationId": 5}}),
    ("POST", f"{GR}/messages/abc/move", {"json": {}}),
    ("POST", f"{GR}/messages/abc/move", {"json": {"destinationId": "AAx="}, "params": {"x": "1"}}),
    ("PUT", f"{GR}/messages/abc/move", {"json": {"destinationId": "AAx="}}),
    ("GET", f"{GR}/messages/abc/$value", {}),  # reading the message is not its job
    ("GET", f"{GR}/messages/abc", {}),
    ("GET", f"{GR}/messages/abc", {"params": {"$select": "body"}}),
    ("GET", f"{GR}/messages", {"params": {"$top": "5"}}),
    ("GET", f"{GR}/mailFolders/inbox/messages", {}),
    ("GET", f"{GR}/mailFolders/inbox/messages/delta", {}),
    ("GET", f"{GR}/mailFolders", {"params": {"$filter": "displayName eq 'x'"}}),
    (
        "GET",
        "https://graph.microsoft.com/v1.0/users/someone/messages/abc",
        {"params": {"$select": "parentFolderId"}},
    ),
    (
        "POST",
        "https://graph.microsoft.com/beta/me/messages/abc/move",
        {"json": {"destinationId": "AAx="}},
    ),
    (
        "POST",
        "http://graph.microsoft.com/v1.0/me/messages/abc/move",
        {"json": {"destinationId": "AAx="}},
    ),
    (
        "POST",
        "https://graph.microsoft.com:444/v1.0/me/messages/abc/move",
        {"json": {"destinationId": "AAx="}},
    ),
    (
        "POST",
        "https://graph.microsoft.com.evil.test/v1.0/me/messages/abc/move",
        {"json": {"destinationId": "AAx="}},
    ),
    ("POST", "https://login.microsoftonline.com/common/oauth2/v2.0/token", {"data": {"x": "y"}}),
    ("POST", "https://oauth2.googleapis.com/token", {"data": {"x": "y"}}),
    ("GET", "https://outlook.office.com/api/v2.0/me/messages", {}),
]


@pytest.mark.parametrize(("method", "url", "kw"), GMAIL_FORBIDDEN + GRAPH_FORBIDDEN)
def test_the_guard_refuses_everything_that_is_not_one_of_the_moves(
    method: str, url: str, kw: dict[str, Any]
) -> None:
    refused(method, url, **kw)


def test_the_requests_the_movers_really_make_are_exactly_the_ones_the_guard_allows() -> None:
    g, r = FakeGmailWrite(), FakeGraphWrite()
    g.add("m1")
    r.add("m1")
    for mover in (gmail(g), graph(r)):
        new = mover.quarantine("m1")
        mover.restore(new)  # no guard error means every request was one of the allowed shapes
    assert {m for m, _ in g.calls()} == {"GET", "POST"} and {m for m, _ in r.calls()} == {
        "GET",
        "POST",
    }


# ---- Gmail: label + out of the inbox, and back ------------------------------------------------


def test_gmail_quarantine_adds_the_label_takes_it_out_of_the_inbox_and_restore_reverses_it() -> (
    None
):
    fake = FakeGmailWrite()
    fake.add("m1", "INBOX", "UNREAD")
    mover = gmail(fake)
    assert mover.quarantine("m1") == "m1"
    label = fake.labels[QUARANTINE_LABEL]
    assert fake.messages["m1"] == {
        label,
        "UNREAD",
    }  # out of the inbox, still unread, nothing else touched
    assert mover.restore("m1") == "m1"
    assert fake.messages["m1"] == {"INBOX", "UNREAD"}
    assert [
        c for c in fake.calls("POST") if c[1].endswith("/labels")
    ] != []  # the label was created once
    assert len([c for c in fake.calls("POST") if c[1].endswith("/labels")]) == 1


def test_gmail_repeating_a_move_does_nothing_twice() -> None:
    fake = FakeGmailWrite()
    fake.add("m1")
    mover = gmail(fake)
    mover.quarantine("m1")
    modifies = len([c for c in fake.calls("POST") if c[1].endswith("/modify")])
    mover.quarantine("m1")
    assert (
        len([c for c in fake.calls("POST") if c[1].endswith("/modify")]) == modifies
    )  # already there
    mover.restore("m1")
    modifies = len([c for c in fake.calls("POST") if c[1].endswith("/modify")])
    mover.restore("m1")
    assert len([c for c in fake.calls("POST") if c[1].endswith("/modify")]) == modifies
    assert fake.messages["m1"] == {"INBOX"}


def test_gmail_uses_an_existing_label_and_survives_a_duplicate_label_race() -> None:
    fake = FakeGmailWrite()
    fake.labels[QUARANTINE_LABEL] = "Label_77"
    fake.add("m1")
    gmail(fake).quarantine("m1")
    assert [c for c in fake.calls("POST") if c[1].endswith("/labels")] == []  # found, not created
    assert "Label_77" in fake.messages["m1"]

    raced = FakeGmailWrite()
    raced.labels[QUARANTINE_LABEL] = "Label_9"
    raced.hide_labels_once = True  # the first list does not show it, the create then collides
    raced.add("m2")
    gmail(raced).quarantine("m2")
    assert "Label_9" in raced.messages["m2"] and "INBOX" not in raced.messages["m2"]


def test_gmail_a_message_that_is_gone_and_a_reply_that_does_not_match_are_stated() -> None:
    fake = FakeGmailWrite()
    with pytest.raises(GmailError) as gone:
        gmail(fake).quarantine("nope")
    assert gone.value.kind == "not_found"
    fake.add("m1")
    fake.ignore_modify = True  # 200, but the labels did not change
    with pytest.raises(GmailError) as odd:
        gmail(fake).quarantine("m1")
    assert odd.value.kind == "bad_response"
    assert "INBOX" in fake.messages["m1"]  # and nothing is claimed done


@pytest.mark.parametrize(
    ("status", "kind"),
    [(401, "auth"), (403, "forbidden"), (429, "rate"), (500, "server"), (503, "server")],
)
def test_gmail_provider_failures_are_stated_not_swallowed(status: int, kind: str) -> None:
    fake = FakeGmailWrite()
    fake.add("m1")
    fake.fail_next("/labels", status, **{"Retry-After": "30"})
    with pytest.raises(GmailError) as e:
        gmail(fake).quarantine("m1")
    assert e.value.kind == kind
    assert fake.messages["m1"] == {"INBOX"}  # untouched


def test_gmail_a_hostile_reply_is_a_bad_response() -> None:
    def respond(body: Any) -> GmailMover:
        return GmailMover(
            lambda: "t",
            make_write_client(httpx.MockTransport(lambda r: httpx.Response(200, json=body))),
        )

    for body in (
        [],
        "x",
        None,
        {"labels": "no"},
        {"labels": [{"name": QUARANTINE_LABEL, "id": "../x"}]},
    ):
        with pytest.raises(GmailError) as e:
            respond(body).quarantine("m1")
        assert e.value.kind == "bad_response", body


def test_gmail_a_message_id_that_cannot_be_trusted_never_reaches_a_url_or_makes_a_label() -> None:
    fake = FakeGmailWrite()
    for bad in ("../x", "a b", "", "x" * 65, "a/b", "a?b"):
        with pytest.raises(ValueError):
            gmail(fake).quarantine(bad)
        with pytest.raises(ValueError):
            gmail(fake).restore(bad)
    assert fake.requests == []


# ---- Outlook: into a folder and back; the id changes -----------------------------------------


def test_outlook_quarantine_moves_to_the_folder_returns_the_new_id_and_restore_goes_back() -> None:
    fake = FakeGraphWrite()
    fake.add("m1")
    mover = graph(fake)
    new = mover.quarantine("m1")
    folder = fake.folders[QUARANTINE_FOLDER.lower()]
    assert new != "m1" and fake.messages == {new: folder}  # one copy, in the folder, under a new id
    assert mover.quarantine(new) == new  # already there: nothing done twice
    back = mover.restore(new)
    assert fake.messages == {back: "AAInbox="}
    assert mover.restore(back) == back


def test_outlook_uses_an_existing_folder_whatever_its_case_and_creates_it_once_otherwise() -> None:
    fake = FakeGraphWrite()
    fake.folders["mirage quarantine"] = "AAMine="
    fake.add("m1")
    graph(fake).quarantine("m1")
    assert [c for c in fake.calls("POST") if c[1].endswith("/mailFolders")] == []
    assert list(fake.messages.values()) == ["AAMine="]

    fresh = FakeGraphWrite()
    fresh.add("a")
    fresh.add("b")
    mover = graph(fresh)
    mover.quarantine("a")
    mover.quarantine("b")
    assert len([c for c in fresh.calls("POST") if c[1].endswith("/mailFolders")]) == 1


def test_outlook_failures_and_odd_replies_are_stated() -> None:
    fake = FakeGraphWrite()
    with pytest.raises(GmailError) as gone:
        graph(fake).quarantine("nope")
    assert gone.value.kind == "not_found"
    fake.add("m1")
    fake.land_elsewhere = True
    with pytest.raises(GmailError) as odd:
        graph(fake).quarantine("m1")
    assert odd.value.kind == "bad_response"
    for status, kind in ((401, "auth"), (403, "forbidden"), (429, "rate"), (503, "server")):
        failing = FakeGraphWrite()
        failing.add("m1")
        failing.fail_next("/move", status)
        with pytest.raises(GmailError) as e:
            graph(failing).quarantine("m1")
        assert e.value.kind == kind


def test_outlook_a_folder_list_that_points_off_graph_is_refused() -> None:
    fake = FakeGraphWrite()
    fake.add("m1")
    fake.next_link = "https://evil.test/v1.0/me/mailFolders?$skip=10"
    with pytest.raises(GmailError) as e:
        graph(fake).quarantine("m1")
    assert e.value.kind == "bad_response"
    assert fake.messages == {"m1": "AAInbox="}  # nothing was moved


def test_outlook_a_message_id_that_cannot_be_trusted_never_reaches_a_url() -> None:
    fake = FakeGraphWrite()
    for bad in ("../x", "a b", "", "x" * 513, "a/b", "a?b"):
        with pytest.raises(ValueError):
            graph(fake).quarantine(bad)
        with pytest.raises(ValueError):
            graph(fake).restore(bad)
    assert fake.requests == []  # not even the folder was looked up or made for a bad id
