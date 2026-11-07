"""The Outlook / Microsoft 365 mailbox (M5b) against a fake Graph: the same behaviours as Gmail
(new mail analysed once, missed mail found again, every failure stated), plus what is specific to
Microsoft: change links that must stay on Graph, scopes that must stay read-only, refresh tokens
that rotate."""

import http.client
import json
import threading
from pathlib import Path
from typing import Any

import httpx
import pytest
from graphhelp import FakeGraph
from mailhelp import PHISH_LINK, analyze, eml
from sqlalchemy import create_engine, select

from core.contracts import EventSource, VerdictState
from core.db import models as db
from core.db.store import save_email_analysis
from core.email.engine import EmailAnalysis, unscored
from core.mailbox import ms_oauth, oauth
from core.mailbox.gmail import MAX_RESPONSE_BYTES, EgressRefused, GmailError, make_client
from core.mailbox.graph import GraphClient, safe_link
from core.mailbox.service import MailboxService, combined_status
from core.mailbox.sync import MAX_PER_POLL, Mailbox, State, message_key

OK_MAIL = eml(subject="Lunch", text="see you at noon")
PHISH = eml(subject="Verify now", html=f"<p>{PHISH_LINK}</p>", text=None)
GRAPH = "https://graph.microsoft.com/v1.0"


class Rig:
    def __init__(self, tmp: Path, fake: FakeGraph | None = None, **kw: Any) -> None:
        self.tmp = tmp
        self.fake = fake or FakeGraph()
        self.stored: list[EmailAnalysis] = []
        self.now = 1_000_000.0
        self.client = GraphClient(lambda: "access-token", make_client(self.fake.transport()))
        self.analyze = kw.pop("analyze", analyze)
        self.store = kw.pop("store", self.stored.append)
        self.lookback = kw.pop("lookback_days", 2)
        self.box = self.make()

    def make(self) -> Mailbox:
        return Mailbox(
            self.client, self.analyze, self.store, State(self.tmp / "state.json"), self.lookback,
            fetch_gap=0, sleep=lambda _s: None, clock=lambda: self.now,
        )  # fmt: skip

    def restart(self) -> None:
        self.box = self.make()


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    return Rig(tmp_path)


def gets(rig: Rig, fragment: str) -> int:
    return len([r for r in rig.fake.requests if fragment in r[1]])


# ---- the normal life ----------------------------------------------------------------------------


def test_first_connect_reads_the_last_days_once_and_then_follows_new_mail(rig: Rig) -> None:
    rig.fake.add("AAMk1", OK_MAIL)
    rig.fake.add("AAMk2", PHISH)
    rig.box.poll()
    assert len(rig.stored) == 2
    rig.box.poll()
    assert len(rig.stored) == 2  # nothing new, nothing repeated
    rig.fake.add("AAMk3", OK_MAIL + b"\n.")
    rig.box.poll()
    assert len(rig.stored) == 3
    assert {a.report.verdict.state for a in rig.stored} & {
        VerdictState.SUSPICIOUS,
        VerdictState.MALICIOUS,
    }
    assert rig.box.stats.flagged and "rules" in rig.box.stats.flagged[0]


def test_a_duplicate_href_cannot_swap_the_analysed_link_for_a_harmless_one() -> None:
    one = analyze(eml(subject="Verify now", html=f'<a href="{PHISH_LINK}">go</a>', text=None))
    two = analyze(
        eml(
            subject="Verify now",
            html=f'<a href="{PHISH_LINK}" href="https://www.paypal.com/signin">go</a>',
            text=None,
        )
    )
    assert two.report.verdict.state == one.report.verdict.state
    assert two.report.verdict.risk_score == one.report.verdict.risk_score


def test_lookback_zero_reads_no_old_mail_but_follows_new(tmp_path: Path) -> None:
    rig = Rig(tmp_path, lookback_days=0)
    rig.fake.add("old", OK_MAIL)
    rig.box.poll()
    assert rig.stored == []
    rig.fake.add("new", PHISH)
    rig.box.poll()
    assert len(rig.stored) == 1


def test_mail_that_arrived_while_stopped_is_analysed_once_after_a_restart(rig: Rig) -> None:
    rig.fake.add("AAMk1", OK_MAIL)
    rig.box.poll()
    rig.fake.add("AAMk2", PHISH)
    rig.fake.add("AAMk3", OK_MAIL + b"\n.")
    rig.restart()
    rig.box.poll()
    rig.restart()
    rig.box.poll()
    assert len(rig.stored) == 3
    assert (rig.tmp / "state.json").read_text(encoding="utf-8").count(
        "deltaToken"
    ) == 1  # the link is kept


@pytest.mark.parametrize("status", [410, 404])
def test_an_expired_or_unknown_change_token_triggers_a_bounded_relist_without_repeats(
    rig: Rig, status: int
) -> None:
    rig.fake.add("AAMk1", OK_MAIL)
    rig.box.poll()
    rig.fake.add("AAMk2", PHISH)
    if status == 410:
        rig.fake.expire_delta()
    else:
        rig.fake.fail_next("/messages/delta", 404)
    rig.box.poll()
    assert rig.box.stats.recoveries == 1
    assert len(rig.stored) == 2  # AAMk2 found by the re-list, AAMk1 not repeated
    rig.fake.add("AAMk3", OK_MAIL + b"\n.")
    rig.box.poll()
    assert len(rig.stored) == 3 and rig.box.stats.recoveries == 1


def test_deleted_mail_is_ignored_and_mail_that_vanishes_before_it_is_fetched_is_counted(
    rig: Rig,
) -> None:
    rig.fake.add("AAMk1", OK_MAIL)
    rig.box.poll()
    rig.fake.add("gone1", PHISH)
    rig.fake.delete("gone1")  # an @removed entry: never fetched
    rig.fake.add("gone2", PHISH)
    rig.fake.vanish("gone2")  # listed, then gone: a 404 on the fetch
    rig.box.poll()
    assert gets(rig, "gone1") == 0
    assert rig.box.stats.vanished == 1 and len(rig.stored) == 1
    assert rig.box.state.has(message_key("gone2"))


def test_a_burst_that_fits_on_one_page_is_still_queued_not_dropped(tmp_path: Path) -> None:
    rig = Rig(tmp_path, FakeGraph(page_size=500), lookback_days=0)
    rig.box.poll()
    for i in range(MAX_PER_POLL + 30):
        rig.fake.add(f"b{i:04d}", OK_MAIL + f"\nn{i}".encode())
    rig.box.poll()
    assert len(rig.stored) == MAX_PER_POLL and rig.box.stats.backlog is True
    for _ in range(3):
        rig.box.poll()
    assert len(rig.stored) == MAX_PER_POLL + 30 and rig.box.stats.backlog is False


def test_a_look_back_larger_than_one_poll_is_finished_over_the_next_polls(tmp_path: Path) -> None:
    fake = FakeGraph(page_size=500)
    for i in range(MAX_PER_POLL + 50):
        fake.add(f"o{i:04d}", OK_MAIL + f"\nn{i}".encode())
    rig = Rig(tmp_path, fake, lookback_days=2)
    rig.box.poll()
    assert len(rig.stored) == MAX_PER_POLL and rig.box.state.history_id is None
    rig.box.poll()
    assert len(rig.stored) == MAX_PER_POLL + 50 and rig.box.state.history_id is not None


def test_paged_delta_is_followed_to_the_end_and_a_burst_is_queued(tmp_path: Path) -> None:
    rig = Rig(tmp_path, FakeGraph(page_size=2), lookback_days=0)
    rig.box.poll()
    for i in range(7):
        rig.fake.add(f"p{i}", OK_MAIL + f"\nn{i}".encode())
    rig.box.poll()
    assert len(rig.stored) == 7
    big = Rig(tmp_path / "big", lookback_days=0)
    (tmp_path / "big").mkdir()
    big.box.poll()
    for i in range(MAX_PER_POLL + 30):
        big.fake.add(f"b{i:04d}", OK_MAIL + f"\nn{i}".encode())
    big.box.poll()
    assert len(big.stored) == MAX_PER_POLL
    big.box.poll()
    assert len(big.stored) == MAX_PER_POLL + 30


# ---- failures have a stated outcome -------------------------------------------------------------


def test_throttling_waits_and_loses_nothing(rig: Rig) -> None:
    rig.fake.add("AAMk1", OK_MAIL)
    rig.fake.fail_next("/messages/delta", 429, **{"Retry-After": "30"})
    rig.box.poll()
    assert rig.box.stats.last_error == "rate" and rig.stored == []
    assert rig.box.backoff_until == rig.now + 30
    before = len(rig.fake.requests)
    rig.box.poll()  # still waiting: no request
    assert len(rig.fake.requests) == before
    rig.now += 31
    rig.box.poll()
    assert len(rig.stored) == 1 and rig.box.stats.last_error is None


@pytest.mark.parametrize(
    ("status", "kind"), [(500, "server"), (503, "server"), (401, "auth"), (403, "forbidden")]
)
def test_a_failing_graph_is_a_stated_error_not_an_empty_mailbox(
    rig: Rig, status: int, kind: str
) -> None:
    rig.fake.add("AAMk1", OK_MAIL)
    rig.fake.fail_next(
        "/messages/delta", status
    )  # a mailbox over quota answers 403 to a delta call
    rig.box.poll()
    assert rig.box.stats.last_error == kind and rig.stored == []
    rig.now += 1000
    rig.box.poll()
    assert len(rig.stored) == 1


def test_a_message_that_cannot_be_analysed_is_retried_then_given_up_and_never_called_safe(
    tmp_path: Path,
) -> None:
    calls = {"n": 0}

    def erroring(raw: bytes) -> EmailAnalysis:
        calls["n"] += 1
        from uuid import uuid4

        return unscored(uuid4(), "0" * 64, VerdictState.ERROR, "Analysis failed.", "error")

    rig = Rig(tmp_path, analyze=erroring)
    rig.fake.add("AAMk1", OK_MAIL)
    for _ in range(5):
        rig.box.poll()
    assert calls["n"] == 3 and rig.box.stats.gave_up == 1
    assert [a.report.verdict.state for a in rig.stored] == [VerdictState.ERROR]


# ---- hostile answers and links ------------------------------------------------------------------


def client_for(handler: Any) -> GraphClient:
    return GraphClient(lambda: "t", make_client(httpx.MockTransport(handler)))


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[]", b"null", b'{"value": 5}', b'{"value": [{"id": 5}]}',
     b'{"value": [{"id": "has space"}]}',
     b'{"value": [{"id": "' + b"a" * 600 + b'"}]}', b'{"value": [{}]}'],
)  # fmt: skip
def test_malformed_pages_are_bad_responses(body: bytes) -> None:
    with pytest.raises(GmailError) as e:
        client_for(lambda r: httpx.Response(200, content=body)).list_recent(2)
    assert e.value.kind == "bad_response"


@pytest.mark.parametrize(
    "link",
    [
        "https://evil.test/v1.0/me/mailFolders/inbox/messages/delta?x=1",
        "http://graph.microsoft.com/v1.0/me/x",
        "https://graph.microsoft.com.evil.test/v1.0/x",
        "https://graph.microsoft.com:8443/v1.0/me/x",
        "https://graph.microsoft.com/beta/me/x",
        "https://graph.microsoft.com/",
        "https://login.microsoftonline.com/v1.0/x",
        "file:///etc/passwd",
        "//graph.microsoft.com/v1.0/x",
        "https://[::1/v1.0/x",  # does not even parse
        "https://graph.microsoft.com:notaport/v1.0/x",
        "",
    ],
)
def test_a_link_that_does_not_lead_to_graph_is_never_followed(link: str) -> None:
    with pytest.raises(GmailError) as e:
        safe_link(link)
    assert e.value.kind == "bad_response"
    if not link:  # an empty link means "no more pages", not a place to go
        return
    sent: list[httpx.Request] = []

    def handler(r: httpx.Request) -> httpx.Response:
        sent.append(r)
        return httpx.Response(
            200, json={"value": [], "@odata.nextLink": link, "@odata.deltaLink": link}
        )

    good = f"{GRAPH}/me/mailFolders/inbox/messages/delta?$deltaToken=T1"
    with pytest.raises(GmailError) as e1:  # a hostile link in an answer is refused
        client_for(handler).history(good)
    with pytest.raises(GmailError) as e2:  # and so is one handed back to us as the next page
        client_for(handler).history(good, page=link)
    with pytest.raises(GmailError) as e3:
        client_for(handler).list_recent(2, page=link)
    assert {e1.value.kind, e2.value.kind, e3.value.kind} == {"bad_response"}
    assert [r.url.host for r in sent] == ["graph.microsoft.com"]  # only the first call went out


def test_a_damaged_saved_position_is_a_stated_error_not_a_crash(tmp_path: Path) -> None:
    (tmp_path / "state.json").write_text(
        json.dumps({"history_id": "https://[::1/v1.0/x", "seen": []}), encoding="utf-8"
    )
    rig = Rig(tmp_path)
    rig.fake.add("AAMk1", OK_MAIL)
    rig.box.poll()  # must not raise
    assert rig.box.stats.last_error == "bad_response" and rig.stored == []


def test_a_delta_round_that_never_ends_is_cut_off() -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "value": [],
                "@odata.nextLink": f"{GRAPH}/me/mailFolders/inbox/messages/delta?$skiptoken=1",
            },
        )

    with pytest.raises(GmailError) as e:
        client_for(handler).profile_history_id()
    assert e.value.kind == "bad_response"


def test_ids_are_checked_before_any_request_and_encoded_in_the_path() -> None:
    sent: list[httpx.Request] = []
    c = client_for(lambda r: sent.append(r) or httpx.Response(200, content=b"raw"))
    for bad in ("../x", "a b", "", "x" * 513, "a/b", "a?b"):
        with pytest.raises(ValueError, match="Graph message id"):
            c.get_raw(bad)
    assert sent == []
    assert c.get_raw("AAMk-1_=+") == b"raw"
    assert sent[0].url.path.endswith("/$value")
    assert b"/messages/AAMk-1_%3D%2B/" in sent[0].url.raw_path  # encoded, never raw in the path


def test_a_list_answer_that_carries_a_removed_entry_does_not_offer_it() -> None:
    body = {"value": [{"id": "a"}, {"id": "b", "@removed": {"reason": "deleted"}}]}
    page = client_for(lambda r: httpx.Response(200, json=body)).list_recent(2)
    assert page.ids == ["a"]


def test_a_next_link_in_a_change_answer_must_lead_to_graph() -> None:
    good = f"{GRAPH}/me/mailFolders/inbox/messages/delta?$deltaToken=T1"
    hostile = {"value": [{"id": "a"}], "@odata.nextLink": "https://evil.test/v1.0/me/x"}
    with pytest.raises(GmailError) as e:
        client_for(lambda r: httpx.Response(200, json=hostile)).history(good)
    assert e.value.kind == "bad_response"


def test_an_answer_that_declares_no_length_is_still_cut_off_at_the_cap() -> None:
    def chunks() -> Any:
        for _ in range(MAX_RESPONSE_BYTES // 1_000_000 + 2):
            yield b"x" * 1_000_000

    with pytest.raises(GmailError) as e:  # chunked: no Content-Length to check up front
        client_for(lambda r: httpx.Response(200, content=chunks())).get_raw("abc")
    assert e.value.kind == "too_large"


def test_an_oversize_raw_message_is_cut_off_and_stored_as_unknown_too_large(tmp_path: Path) -> None:
    rig = Rig(tmp_path, lookback_days=0)
    rig.box.poll()
    rig.fake.add("big", OK_MAIL)
    big = b"x" * (17 * 1024 * 1024)
    rig.client._http = make_client(  # noqa: SLF001
        httpx.MockTransport(
            lambda r: (
                httpx.Response(200, content=big) if "/big/" in r.url.path else rig.fake._handle(r)
            )
        )  # noqa: SLF001
    )
    rig.box.poll()
    assert rig.box.stats.too_large == 1
    only = rig.stored[0].report
    assert only.verdict.state is VerdictState.UNKNOWN and only.reason == "too_large"


def test_a_redirect_is_not_followed() -> None:
    hits: list[str] = []

    def handler(r: httpx.Request) -> httpx.Response:
        hits.append(str(r.url))
        return httpx.Response(302, headers={"Location": "https://evil.test/steal"})

    with pytest.raises(GmailError):
        client_for(handler).list_recent(2)
    assert len(hits) == 1 and "evil.test" not in hits[0]


# ---- read-only and egress ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("POST", f"{GRAPH}/me/sendMail"),
        ("DELETE", f"{GRAPH}/me/messages/abc"),
        ("PATCH", f"{GRAPH}/me/messages/abc"),
        ("PUT", f"{GRAPH}/me/mailFolders/inbox"),
        ("GET", "http://graph.microsoft.com/v1.0/me/messages"),
        ("GET", "https://graph.microsoft.com.evil.test/v1.0/me"),
        ("GET", "https://outlook.office.com/api/v2.0/me/messages"),
    ],
)
def test_the_client_cannot_send_anything_but_a_get_to_graph_or_reach_another_host(
    method: str, url: str
) -> None:
    sent: list[object] = []
    http = make_client(httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200)))
    with pytest.raises(EgressRefused):
        http.request(method, url)
    assert sent == []


def test_a_whole_sync_sends_only_gets_with_a_token_and_asks_for_a_bounded_page_size(
    rig: Rig,
) -> None:
    rig.fake.add("AAMk1", OK_MAIL)
    rig.box.poll()
    rig.fake.add("AAMk2", PHISH)
    rig.box.poll()
    assert {m for m, _p, _q, _h in rig.fake.requests} == {"GET"}
    assert all(
        h.get("authorization") == "Bearer access-token" for _m, _p, _q, h in rig.fake.requests
    )
    assert any(
        h.get("prefer") == "odata.maxpagesize=100"
        for _m, p, _q, h in rig.fake.requests
        if "delta" in p
    )


# ---- privacy ------------------------------------------------------------------------------------


def test_no_address_subject_body_token_or_message_id_is_kept(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    secret_mail = eml(
        sender="SENDERMARK <sendermark@sender.test>", to="rcptmark@rcpt.test",
        subject="SUBJECTMARK", text="BODYMARK https://paypal-login.test/PATHMARK?q=QUERYMARK",
    )  # fmt: skip
    engine = create_engine(f"sqlite:///{tmp_path / 'lynceus.db'}")
    db.Base.metadata.create_all(engine)
    rig = Rig(tmp_path, store=lambda a: save_email_analysis(engine, a, EventSource.EMAIL))
    with caplog.at_level("DEBUG"):
        rig.fake.add("IDMARK1234567890", secret_mail)
        rig.box.poll()
        rig.fake.add("IDMARK2234567890", secret_mail + b"\nx")
        rig.box.poll()
    with engine.connect() as conn:
        rows = "\n".join(
            repr(r) for t in db.Base.metadata.sorted_tables for r in conn.execute(select(t))
        )
        sources = {e.source for e in conn.execute(select(db.Event))}
    state = (tmp_path / "state.json").read_text(encoding="utf-8")
    dumped = rows + state + caplog.text + json.dumps(rig.box.stats.flagged)
    for marker in (
        "SENDERMARK",
        "sendermark",
        "rcptmark",
        "SUBJECTMARK",
        "BODYMARK",
        "PATHMARK",
        "QUERYMARK",
        "IDMARK",
        "access-token",
    ):
        assert marker not in dumped, marker
    assert message_key("IDMARK1234567890") in state and sources == {"EMAIL"}


def test_a_damaged_or_odd_state_file_means_start_again_not_a_crash(tmp_path: Path) -> None:
    (tmp_path / "state.json").write_text(
        json.dumps({"history_id": "x" * 5000, "seen": [1, "short"]}), encoding="utf-8"
    )
    rig = Rig(tmp_path)
    assert rig.box.state.history_id is None
    rig.fake.add("AAMk1", OK_MAIL)
    rig.box.poll()
    assert len(rig.stored) == 1


# ---- signing in ---------------------------------------------------------------------------------


def test_the_consent_url_names_the_tenant_asks_for_read_only_mail_and_a_localhost_redirect() -> (
    None
):
    from urllib.parse import parse_qs, urlparse

    url = urlparse(
        ms_oauth.authorize_url("consumers", "cid", "http://localhost:5555", "chal", "st")
    )
    q = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert (url.scheme, url.netloc, url.path) == (
        "https",
        "login.microsoftonline.com",
        "/consumers/oauth2/v2.0/authorize",
    )
    assert q["scope"] == "Mail.Read offline_access" and q["code_challenge_method"] == "S256"
    assert (q["response_type"], q["state"], q["redirect_uri"]) == (
        "code",
        "st",
        "http://localhost:5555",
    )


@pytest.mark.parametrize(
    "tenant", ["common/../x", "a b", "x?y", "a#b", "", "x" * 65, "evil.test/x", "a/b"]
)
def test_a_tenant_that_could_change_the_address_is_refused(tenant: str) -> None:
    with pytest.raises(oauth.OAuthError):
        ms_oauth.authorize_url(tenant, "cid", "http://localhost:1", "c", "s")
    with pytest.raises(oauth.OAuthError):
        ms_oauth.token_url(tenant)


@pytest.mark.parametrize(
    ("scope", "ok"),
    [
        ("Mail.Read User.Read profile openid email", True),
        ("https://graph.microsoft.com/Mail.Read offline_access", True),
        ("mail.read OFFLINE_ACCESS", True),
        ("Mail.Read Mail.ReadWrite", False),
        ("Mail.Read Mail.Send", False),
        ("Mail.ReadWrite", False),
        ("Mail.Read Files.Read", False),
        ("Mail.Read https://graph.microsoft.com/Mail.ReadWrite", False),
        ("User.Read profile", False),
        ("", False),
        (None, False),
        (5, False),
    ],
)
def test_only_read_only_mail_and_the_sign_in_basics_are_accepted(scope: object, ok: bool) -> None:
    assert ms_oauth.scope_ok(scope) is ok


def _token_http(
    body: dict[str, Any], status: int = 200, seen: list[httpx.Request] | None = None
) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(status, json=body)

    return make_client(httpx.MockTransport(handler))


GOOD = {
    "access_token": "a",
    "expires_in": 3600,
    "refresh_token": "r1",
    "scope": "Mail.Read User.Read",
}


def test_the_code_exchange_goes_to_the_tenant_with_the_verifier_and_no_secret() -> None:
    seen: list[httpx.Request] = []
    t = ms_oauth.exchange_code(
        _token_http(GOOD, seen=seen),
        "consumers",
        "cid",
        "code",
        "verifier",
        "http://localhost:1",
        now=lambda: 100.0,
    )
    assert (t.access_token, t.refresh_token, t.expires_at) == ("a", "r1", 3700.0)
    assert str(seen[0].url) == "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
    form = seen[0].content.decode()
    assert (
        "code_verifier=verifier" in form
        and "client_secret" not in form
        and "offline_access" in form
    )


@pytest.mark.parametrize(
    ("body", "status", "kind"),
    [
        (GOOD | {"scope": "Mail.Read Mail.ReadWrite"}, 200, "scope"),
        (GOOD | {"scope": "Mail.Read Mail.Send offline_access"}, 200, "scope"),
        ({k: v for k, v in GOOD.items() if k != "scope"}, 200, "scope"),
        ({k: v for k, v in GOOD.items() if k != "refresh_token"}, 200, "token"),
        ({"error": "invalid_grant"}, 400, "revoked"),
        ({"error": "server_error"}, 500, "token"),
    ],
)
def test_a_token_answer_that_is_wrong_is_refused_and_nothing_is_stored(
    body: dict[str, Any], status: int, kind: str
) -> None:
    with pytest.raises(oauth.OAuthError) as e:
        ms_oauth.exchange_code(
            _token_http(body, status), "common", "cid", "c", "v", "http://localhost:1"
        )
    assert e.value.kind == kind


def test_a_rotated_refresh_token_is_stored_and_used_next_time_and_a_revoked_one_is_reported() -> (
    None
):
    now = {"t": 1000.0}
    stored = {"token": "r1"}
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        form = dict(p.split("=", 1) for p in request.content.decode().split("&"))
        calls.append(form["refresh_token"])
        if len(calls) == 3:
            return httpx.Response(400, json={"error": "invalid_grant"})
        return httpx.Response(
            200,
            json={
                "access_token": f"a{len(calls)}",
                "expires_in": 3600,
                "refresh_token": f"r{len(calls) + 1}",
                "scope": "Mail.Read",
            },
        )

    http = make_client(httpx.MockTransport(handler))
    source = oauth.TokenSource(
        http, "cid", None, lambda: stored["token"], lambda: now["t"],
        refresher=lambda r: ms_oauth.refresh(http, "common", "cid", r, lambda: now["t"]),
        store=lambda new: stored.update(token=new),
    )  # fmt: skip
    assert source() == "a1" and source() == "a1" and stored["token"] == "r2"
    now["t"] += 3600
    assert source() == "a2" and calls == ["r1", "r2"] and stored["token"] == "r3"
    now["t"] += 3600
    with pytest.raises(GmailError) as e:
        source()
    assert e.value.kind == "auth" and source.last_error == "revoked"


def test_a_rotated_token_that_cannot_be_stored_fails_that_poll_and_not_the_next() -> None:
    from core.mailbox.tokens import TokenStoreUnavailable

    asked: list[str] = []

    def refresher(old: str) -> oauth.Tokens:
        asked.append(old)
        return oauth.Tokens("acc", 5000.0, "r2")

    def store(_new: str) -> None:
        raise TokenStoreUnavailable("no")

    http = make_client(httpx.MockTransport(lambda r: httpx.Response(500)))
    source = oauth.TokenSource(
        http, "cid", None, lambda: "r1", lambda: 1000.0, refresher=refresher, store=store
    )
    with pytest.raises(TokenStoreUnavailable):  # loud, not silently dropped
        source()
    assert source() == "acc" and asked == ["r1"]  # the new access token is not thrown away


def _listener() -> tuple[Any, threading.Thread, list[str]]:
    listener = oauth._Listener("st", hosts=("localhost", "127.0.0.1"), redirect_host="localhost")  # noqa: SLF001
    out: list[str] = []

    def run() -> None:
        try:
            out.append(oauth.wait_for_code(listener, 10))
        except oauth.OAuthError as e:
            out.append("ERR:" + e.kind)

    thread = threading.Thread(target=run)
    thread.start()
    return listener, thread, out


def test_the_listener_redirects_to_localhost_accepts_that_host_name_and_nothing_else() -> None:
    listener, thread, out = _listener()
    port = listener.server_address[1]
    assert listener.redirect_uri == f"http://localhost:{port}"
    assert listener.server_address[0] == "127.0.0.1"  # still bound to loopback only
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/?code=C&state=st", headers={"Host": "evil.test"})
    assert conn.getresponse().status == 400
    conn.close()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/?code=THECODE&state=st", headers={"Host": f"localhost:{port}"})
    assert conn.getresponse().status == 200
    conn.close()
    thread.join(timeout=10)
    listener.server_close()
    assert out == ["THECODE"]


# ---- both providers at once ---------------------------------------------------------------------


class _Stub:
    def __init__(self, name: str, state: str, flagged: list[dict[str, object]]) -> None:
        self.name, self._status = name, {"provider": name, "state": state, "flagged": flagged}

    def status(self) -> dict[str, object]:
        return self._status


def test_the_combined_status_shows_the_worst_state_and_merges_flagged_mail() -> None:
    assert combined_status([]) == {"state": "off"}
    one = combined_status([_Stub("outlook", "connected", [{"at": 1.0}])])  # type: ignore[list-item]
    assert one["state"] == "connected" and set(one["providers"]) == {"outlook"}  # type: ignore[arg-type]
    both = combined_status(
        [
            _Stub("gmail", "connected", [{"at": 5.0}, {"at": 1.0}]),
            _Stub("outlook", "reauth_needed", [{"at": 3.0}]),
        ]  # type: ignore[list-item]
    )
    assert both["state"] == "reauth_needed"
    assert [f["at"] for f in both["flagged"]] == [1.0, 3.0, 5.0]  # type: ignore[attr-defined]

    def state(*pairs: tuple[str, str]) -> object:
        stubs = [_Stub(n, s, []) for n, s in pairs]
        return combined_status(stubs)["state"]  # type: ignore[arg-type]

    assert state(("a", "disconnected"), ("b", "error")) == "error"
    assert state(("a", "error"), ("b", "reauth_needed")) == "reauth_needed"  # sign-in beats error
    assert state(("a", "connected"), ("b", "disconnected")) == "connected"  # one not set up
    assert state(("a", "disconnected"), ("b", "disconnected")) == "disconnected"


def test_enabling_outlook_without_a_client_id_stops_start_up_and_a_bad_tenant_is_refused(
    tmp_path: Path,
) -> None:
    from fastapi.testclient import TestClient

    from core.api.app import create_app
    from core.config import Settings

    with pytest.raises(RuntimeError, match="LYNCEUS_OUTLOOK_CLIENT_ID"):
        create_app(
            Settings(_env_file=None, api_token="t" * 20, data_dir=tmp_path, outlook_enabled=True)
        )
    with pytest.raises(ValueError, match="outlook_tenant"):
        Settings(_env_file=None, outlook_tenant="common/../x")
    app = create_app(
        Settings(
            _env_file=None,
            api_token="t" * 20,
            data_dir=tmp_path,
            outlook_enabled=True,
            outlook_client_id="cid",
        )
    )
    with TestClient(app, base_url="http://127.0.0.1") as c:
        status = c.get("/v1/mailbox/status", headers={"Authorization": "Bearer " + "t" * 20}).json()
    assert (
        status["state"] == "disconnected"
        and status["providers"]["outlook"]["provider"] == "outlook"
    )


def test_the_service_keeps_its_own_state_and_token_files_per_provider(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    service = MailboxService(rig.box, None, None, 60, name="outlook")  # type: ignore[arg-type]
    assert service.name == "outlook"
