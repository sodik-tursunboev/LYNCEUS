"""The live-mailbox logic (M5) against a fake Gmail: new mail is analysed once, missed mail is
found,
every failure has a stated outcome, nothing is written that should not be, and the client cannot
send
anything but a GET to Gmail."""

import base64
import http.client
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest
from gmailhelp import FakeGmail
from mailhelp import PHISH_LINK, analyze, eml
from sqlalchemy import create_engine, select

from core.contracts import EventSource, VerdictState
from core.db import models as db
from core.db.store import save_email_analysis
from core.email.engine import EmailAnalysis, unscored
from core.mailbox import oauth
from core.mailbox.gmail import EgressRefused, GmailClient, GmailError, make_client
from core.mailbox.service import MailboxService
from core.mailbox.sync import MAX_ATTEMPTS, MAX_PER_POLL, Mailbox, State, message_key
from core.mailbox.tokens import TokenFile, protect, unprotect

OK_MAIL = eml(subject="Lunch", text="see you at noon")
PHISH = eml(subject="Verify now", html=f"<p>{PHISH_LINK}</p>", text=None)


class Rig:
    def __init__(self, tmp: Path, fake: FakeGmail | None = None, **kw: Any) -> None:
        self.tmp = tmp
        self.fake = fake or FakeGmail()
        self.stored: list[EmailAnalysis] = []
        self.now = 1_000_000.0
        self.client = GmailClient(lambda: "access-token", make_client(self.fake.transport()))
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


# ---- the normal life of a mailbox ----------------------------------------------------------------


def test_first_connect_reads_the_last_days_once_and_then_follows_new_mail(rig: Rig) -> None:
    rig.fake.add("m1", OK_MAIL)
    rig.fake.add("m2", PHISH)
    rig.box.poll()
    assert len(rig.stored) == 2 and rig.box.stats.analysed == 2
    rig.box.poll()
    assert len(rig.stored) == 2  # nothing new: nothing repeated
    rig.fake.add("m3", OK_MAIL + b"\n.")
    rig.box.poll()
    assert len(rig.stored) == 3
    states = {a.report.verdict.state for a in rig.stored}
    assert VerdictState.SUSPICIOUS in states or VerdictState.MALICIOUS in states
    assert rig.box.stats.flagged and "rules" in rig.box.stats.flagged[0]


def test_lookback_zero_reads_no_old_mail_but_follows_new(tmp_path: Path) -> None:
    rig = Rig(tmp_path, lookback_days=0)
    rig.fake.add("old", OK_MAIL)
    rig.box.poll()
    assert rig.stored == []
    rig.fake.add("new", PHISH)
    rig.box.poll()
    assert len(rig.stored) == 1


def test_mail_that_arrived_while_stopped_is_analysed_once_after_a_restart(rig: Rig) -> None:
    rig.fake.add("m1", OK_MAIL)
    rig.box.poll()
    rig.fake.add("m2", PHISH)
    rig.fake.add("m3", OK_MAIL + b"\n.")
    rig.restart()  # the process stopped and started again
    rig.box.poll()
    rig.restart()
    rig.box.poll()
    assert len(rig.stored) == 3


def test_an_expired_history_position_triggers_a_bounded_relist_without_repeats(rig: Rig) -> None:
    rig.fake.add("m1", OK_MAIL)
    rig.box.poll()
    rig.fake.add("m2", PHISH)
    rig.fake.expire_history()  # Gmail no longer has the records: HTTP 404
    rig.box.poll()
    assert rig.box.stats.recoveries == 1
    assert len(rig.stored) == 2  # m2 found by the re-list, m1 not repeated
    rig.fake.add("m3", OK_MAIL + b"\n.")
    rig.box.poll()
    assert len(rig.stored) == 3 and rig.box.stats.recoveries == 1


def test_a_message_deleted_before_it_is_fetched_is_counted_not_lost_or_retried(rig: Rig) -> None:
    rig.fake.add("m1", OK_MAIL)
    rig.box.poll()
    rig.fake.add("gone", PHISH)
    rig.fake.messages.pop("gone")
    rig.box.poll()
    assert rig.box.stats.vanished == 1
    rig.box.poll()
    assert rig.box.stats.vanished == 1 and len(rig.stored) == 1


def test_a_burst_larger_than_one_poll_is_queued_not_dropped(tmp_path: Path) -> None:
    rig = Rig(tmp_path, lookback_days=0)
    rig.box.poll()
    for i in range(MAX_PER_POLL + 30):
        rig.fake.add(f"b{i:04d}", OK_MAIL + f"\nn{i}".encode())
    rig.box.poll()
    assert len(rig.stored) == MAX_PER_POLL
    rig.box.poll()
    assert len(rig.stored) == MAX_PER_POLL + 30
    rig.box.poll()
    assert len(rig.stored) == MAX_PER_POLL + 30


def test_a_burst_that_fits_on_one_page_is_still_queued_not_dropped(tmp_path: Path) -> None:
    # the real client asks for 500 per page, so a mail bomb followed by a phishing mail is ONE page
    rig = Rig(tmp_path, FakeGmail(page_size=500), lookback_days=0)
    rig.box.poll()
    for i in range(MAX_PER_POLL + 30):
        rig.fake.add(f"b{i:04d}", OK_MAIL + f"\nn{i}".encode())
    rig.fake.add("last", PHISH)
    rig.box.poll()
    assert len(rig.stored) == MAX_PER_POLL and rig.box.stats.backlog is True
    for _ in range(3):
        rig.box.poll()
    assert len(rig.stored) == MAX_PER_POLL + 31  # nothing lost, the phishing mail included
    assert rig.box.stats.backlog is False
    assert VerdictState.SUSPICIOUS in {a.report.verdict.state for a in rig.stored} or any(
        a.report.verdict.state is VerdictState.MALICIOUS for a in rig.stored
    )


def test_a_look_back_larger_than_one_poll_is_finished_over_the_next_polls(tmp_path: Path) -> None:
    fake = FakeGmail(page_size=500)
    for i in range(MAX_PER_POLL + 50):
        fake.add(f"o{i:04d}", OK_MAIL + f"\nn{i}".encode())
    rig = Rig(tmp_path, fake, lookback_days=2)
    rig.box.poll()
    assert len(rig.stored) == MAX_PER_POLL and rig.box.state.history_id is None
    assert rig.box.stats.backlog is True
    rig.box.poll()
    assert len(rig.stored) == MAX_PER_POLL + 50 and rig.box.state.history_id is not None
    assert rig.box.stats.backlog is False


def test_paged_history_is_followed_to_the_end(tmp_path: Path) -> None:
    rig = Rig(tmp_path, FakeGmail(page_size=2), lookback_days=0)
    rig.box.poll()
    for i in range(7):
        rig.fake.add(f"p{i}", OK_MAIL + f"\nn{i}".encode())
    rig.box.poll()
    assert len(rig.stored) == 7


# ---- failures have a stated outcome --------------------------------------------------------------


def test_throttling_waits_and_loses_nothing(rig: Rig) -> None:
    rig.fake.add("m1", OK_MAIL)
    rig.fake.fail_next("/profile", 429, **{"Retry-After": "30"})
    rig.box.poll()
    assert rig.box.stats.last_error == "rate" and rig.stored == []
    assert rig.box.backoff_until == rig.now + 30
    rig.box.poll()  # still waiting: no request is made
    assert [r for r in rig.fake.requests if r[1].endswith("/profile")].__len__() == 1
    rig.now += 31
    rig.box.poll()
    assert len(rig.stored) == 1 and rig.box.stats.last_error is None


@pytest.mark.parametrize(
    ("status", "kind"), [(500, "server"), (503, "server"), (401, "auth"), (403, "forbidden")]
)
def test_a_failing_gmail_is_a_stated_error_not_an_empty_mailbox(
    rig: Rig, status: int, kind: str
) -> None:
    rig.fake.add("m1", OK_MAIL)
    rig.fake.fail_next("/profile", status)
    rig.box.poll()
    assert rig.box.stats.last_error == kind and rig.stored == []
    rig.now += 1000
    rig.box.poll()
    assert len(rig.stored) == 1


def test_a_403_that_means_rate_limit_is_treated_as_one(rig: Rig) -> None:
    rig.fake.failures.append(("/profile", 403, {}))
    rig.client._http = make_client(  # noqa: SLF001
        httpx.MockTransport(
            lambda r: httpx.Response(
                403, json={"error": {"errors": [{"reason": "rateLimitExceeded"}]}}
            )
        )
    )
    rig.box.poll()
    assert rig.box.stats.last_error == "rate"


def test_a_message_that_cannot_be_analysed_is_retried_then_given_up_and_never_called_safe(
    tmp_path: Path,
) -> None:
    calls = {"n": 0}

    def erroring(raw: bytes) -> EmailAnalysis:
        calls["n"] += 1
        return unscored(uuid4(), "0" * 64, VerdictState.ERROR, "Analysis failed.", "error")

    rig = Rig(tmp_path, analyze=erroring)
    rig.fake.add("m1", OK_MAIL)
    for _ in range(MAX_ATTEMPTS + 2):
        rig.box.poll()
    assert calls["n"] == MAX_ATTEMPTS
    assert rig.box.stats.gave_up == 1
    assert [a.report.verdict.state for a in rig.stored] == [VerdictState.ERROR]


def test_a_failed_save_is_retried_and_stored_exactly_once(tmp_path: Path) -> None:
    stored: list[EmailAnalysis] = []
    fail = {"once": True}

    def flaky(a: EmailAnalysis) -> None:
        if fail.pop("once", False):
            raise OSError("database is down")
        stored.append(a)

    rig = Rig(tmp_path, store=flaky)
    rig.fake.add("m1", OK_MAIL)
    with pytest.raises(OSError, match="database is down"):
        rig.box.poll()  # the process "crashes" between fetching and saving
    rig.restart()
    rig.box.poll()
    rig.box.poll()
    assert len(stored) == 1


def test_an_oversize_response_is_stored_as_unknown_too_large(tmp_path: Path) -> None:
    rig = Rig(tmp_path, lookback_days=0)
    rig.box.poll()
    rig.fake.add("big", OK_MAIL)
    big = b"x" * (17 * 1024 * 1024)
    rig.client._http = make_client(  # noqa: SLF001
        httpx.MockTransport(
            lambda r: (
                httpx.Response(200, content=big)
                if "/messages/big" in r.url.path
                else rig.fake._handle(r)
            )
        )  # noqa: SLF001
    )
    rig.box.poll()
    assert rig.box.stats.too_large == 1
    only = rig.stored[0].report
    assert only.verdict.state is VerdictState.UNKNOWN and only.reason == "too_large"


# ---- the client against hostile answers ----------------------------------------------------------


def client_for(handler: Any) -> GmailClient:
    return GmailClient(lambda: "t", make_client(httpx.MockTransport(handler)))


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        b"{}",
        b'{"historyId": 5}',
        b'{"historyId": "abc"}',
        b'{"historyId": "' + b"9" * 40 + b'"}',
    ],
)
def test_malformed_profile_answers_are_bad_responses(body: bytes) -> None:
    with pytest.raises(GmailError) as e:
        client_for(lambda r: httpx.Response(200, content=body)).profile_history_id()
    assert e.value.kind == "bad_response"


@pytest.mark.parametrize("raw", ["!!!", "a", "====", 5, None])
def test_invalid_raw_message_bodies_are_bad_responses(raw: object) -> None:
    with pytest.raises(GmailError) as e:
        client_for(lambda r: httpx.Response(200, json={"id": "m1", "raw": raw})).get_raw("m1")
    assert e.value.kind == "bad_response"


def test_a_message_id_that_is_not_a_gmail_id_is_refused_before_any_request() -> None:
    hits: list[object] = []
    c = client_for(lambda r: hits.append(r) or httpx.Response(200))
    for bad in ("../x", "a b", "", "x" * 65, "a/b"):
        with pytest.raises(ValueError, match="Gmail message id"):
            c.get_raw(bad)
    assert hits == []


def test_a_slow_declared_or_streamed_oversize_body_is_cut_off() -> None:
    with pytest.raises(GmailError) as e:
        client_for(
            lambda r: httpx.Response(200, headers={"content-length": str(10**9)}, content=b"{}")
        ).profile_history_id()
    assert e.value.kind == "too_large"


def test_a_network_error_is_a_stated_error() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    with pytest.raises(GmailError) as e:
        client_for(boom).profile_history_id()
    assert e.value.kind == "network"


def test_a_redirect_is_not_followed_and_is_an_error() -> None:
    hits: list[str] = []

    def handler(r: httpx.Request) -> httpx.Response:
        hits.append(str(r.url))
        return httpx.Response(302, headers={"Location": "https://evil.test/steal"})

    with pytest.raises(GmailError):
        client_for(handler).profile_history_id()
    assert hits == [hits[0]] and "evil.test" not in hits[0]


# ---- read-only and egress ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"),
        ("DELETE", "https://gmail.googleapis.com/gmail/v1/users/me/messages/abc"),
        ("PUT", "https://gmail.googleapis.com/gmail/v1/users/me/labels"),
        ("GET", "http://gmail.googleapis.com/gmail/v1/users/me/profile"),
        ("GET", "https://evil.test/gmail/v1/users/me/profile"),
        ("GET", "https://gmail.googleapis.com.evil.test/profile"),
        ("GET", "https://127.0.0.1/profile"),
    ],
)
def test_the_client_cannot_send_anything_but_a_get_to_gmail_or_reach_any_other_host(
    method: str, url: str
) -> None:
    sent: list[object] = []
    http = make_client(httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200)))
    with pytest.raises(EgressRefused):
        http.request(method, url)
    assert sent == []


def test_a_whole_sync_sends_only_gets_to_gmail(rig: Rig) -> None:
    rig.fake.add("m1", OK_MAIL)
    rig.box.poll()
    rig.fake.add("m2", PHISH)
    rig.box.poll()
    assert rig.fake.requests and {m for m, _p, _q in rig.fake.requests} == {"GET"}


# ---- privacy -------------------------------------------------------------------------------------


def test_no_address_subject_body_token_or_message_id_is_kept(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    secret_mail = eml(
        sender="SENDERMARK <sendermark@sender.test>", to="rcptmark@rcpt.test",
        subject="SUBJECTMARK",
        text="BODYMARK https://paypal-login.test/PATHMARK?q=QUERYMARK",
    )  # fmt: skip
    url = f"sqlite:///{tmp_path / 'mirage.db'}"
    engine = create_engine(url)
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
        kinds = {a.kind for a in conn.execute(select(db.Artifact))}
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
    assert message_key("IDMARK1234567890") in state
    assert (sources, kinds) == ({"EMAIL"}, {"EMAIL"}) and "paypal-login.test" in rows


def test_a_damaged_state_file_means_start_again_not_a_crash(tmp_path: Path) -> None:
    (tmp_path / "state.json").write_text("{not json", encoding="utf-8")
    rig = Rig(tmp_path)
    rig.fake.add("m1", OK_MAIL)
    rig.box.poll()
    assert len(rig.stored) == 1


# ---- signing in ----------------------------------------------------------------------------------


def test_the_challenge_is_the_s256_of_the_verifier() -> None:
    verifier, challenge = oauth.pkce()
    import hashlib

    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    assert challenge == expected and len(verifier) >= 43


def test_the_consent_url_asks_for_read_only_mail_and_nothing_else() -> None:
    from urllib.parse import parse_qs, urlparse

    url = urlparse(oauth.authorize_url("cid", "http://127.0.0.1:5555", "chal", "st"))
    q = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert (url.scheme, url.netloc) == ("https", "accounts.google.com")
    assert q["scope"] == "https://www.googleapis.com/auth/gmail.readonly"
    assert (q["code_challenge_method"], q["response_type"], q["state"]) == ("S256", "code", "st")
    assert q["redirect_uri"].startswith("http://127.0.0.1:")


def _token_http(
    body: dict[str, Any], status: int = 200, seen: list[httpx.Request] | None = None
) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(status, json=body)

    return make_client(httpx.MockTransport(handler))


SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


def test_the_code_exchange_sends_the_verifier_and_no_secret_when_there_is_none() -> None:
    seen: list[httpx.Request] = []
    http = _token_http(
        {"access_token": "a", "expires_in": 3600, "refresh_token": "r", "scope": SCOPE}, seen=seen
    )
    t = oauth.exchange_code(
        http, "cid", None, "code", "verifier", "http://127.0.0.1:1", now=lambda: 100.0
    )
    assert (t.access_token, t.refresh_token, t.expires_at) == ("a", "r", 3700.0)
    form = seen[0].content.decode()
    assert "code_verifier=verifier" in form and "client_secret" not in form


@pytest.mark.parametrize(
    ("body", "status", "kind"),
    [
        (
            {
                "access_token": "a",
                "expires_in": 3600,
                "refresh_token": "r",
                "scope": SCOPE + " https://mail.google.com/",
            },
            200,
            "scope",
        ),
        (
            {
                "access_token": "a",
                "expires_in": 3600,
                "refresh_token": "r",
                "scope": "https://mail.google.com/",
            },
            200,
            "scope",
        ),
        ({"access_token": "a", "expires_in": 3600, "scope": SCOPE}, 200, "token"),
        ({"expires_in": 3600, "refresh_token": "r"}, 200, "token"),
        ({"error": "invalid_grant"}, 400, "revoked"),
        ({"error": "server_error"}, 500, "token"),
    ],
)
def test_a_token_answer_that_is_wrong_is_refused_and_nothing_is_stored(
    body: dict[str, Any], status: int, kind: str
) -> None:
    with pytest.raises(oauth.OAuthError) as e:
        oauth.exchange_code(_token_http(body, status), "cid", "s", "c", "v", "http://127.0.0.1:1")
    assert e.value.kind == kind


def test_the_token_source_refreshes_once_and_reports_a_revoked_token() -> None:
    now = {"t": 1000.0}
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 3:
            return httpx.Response(400, json={"error": "invalid_grant"})
        return httpx.Response(
            200, json={"access_token": f"a{calls['n']}", "expires_in": 3600, "scope": SCOPE}
        )

    source = oauth.TokenSource(
        make_client(httpx.MockTransport(handler)), "cid", None, lambda: "refresh", lambda: now["t"]
    )
    assert source() == "a1" and source() == "a1" and calls["n"] == 1
    now["t"] += 3600  # expired
    assert source() == "a2"
    now["t"] += 3600
    with pytest.raises(GmailError) as e:
        source()
    assert e.value.kind == "auth" and source.last_error == "revoked"


def _listener(state: str) -> tuple[Any, threading.Thread, list[str]]:
    listener = oauth._Listener(state)  # noqa: SLF001
    out: list[str] = []

    def run() -> None:
        try:
            out.append(oauth.wait_for_code(listener, 10))
        except oauth.OAuthError as e:
            out.append("ERR:" + e.kind)

    thread = threading.Thread(target=run)
    thread.start()
    return listener, thread, out


def _get(url: str) -> int:
    try:
        return urllib.request.urlopen(url, timeout=5).status  # noqa: S310
    except urllib.error.HTTPError as e:
        return e.code


def test_an_idle_connection_cannot_hold_the_sign_in_hostage_and_an_odd_state_is_only_a_stray() -> (
    None
):
    listener = oauth._Listener("st")  # noqa: SLF001
    port = listener.server_address[1]
    idle = socket.create_connection(("127.0.0.1", port))  # connects and says nothing
    out: list[str] = []
    thread = threading.Thread(target=lambda: out.append(oauth.wait_for_code(listener, 20)))
    thread.start()
    time.sleep(0.3)
    for state in ("%C3%A9", "x" * 10):  # a non-ASCII state used to raise inside the handler
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", f"/?code=EVIL&state={state}", headers={"Host": f"127.0.0.1:{port}"})
        assert conn.getresponse().status == 400
        conn.close()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", "/?code=THECODE&state=st", headers={"Host": f"127.0.0.1:{port}"})
    assert conn.getresponse().status == 200
    conn.close()
    thread.join(timeout=20)
    idle.close()
    listener.server_close()
    assert out == ["THECODE"]


def test_the_loopback_listener_takes_only_the_right_state_and_closes() -> None:
    listener, thread, out = _listener("good-state")
    base = listener.redirect_uri
    assert base.startswith("http://127.0.0.1:")
    assert _get(f"{base}/?code=stolen&state=wrong") == 400
    assert _get(f"{base}/other?code=stolen&state=good-state") == 400
    assert _get(f"{base}/?code=THECODE&state=good-state") == 200
    thread.join(timeout=10)
    listener.server_close()
    assert out == ["THECODE"]


def test_a_denied_consent_and_a_flood_of_wrong_states_end_cleanly() -> None:
    listener, thread, out = _listener("s")
    assert _get(f"{listener.redirect_uri}/?error=access_denied&state=s") == 200
    thread.join(timeout=10)
    listener.server_close()
    assert out == ["ERR:denied"]
    listener, thread, out = _listener("s")
    for _ in range(5):
        assert _get(f"{listener.redirect_uri}/?code=x&state=bad") == 400
    thread.join(timeout=10)
    listener.server_close()
    assert out == ["ERR:state"]


# ---- the refresh token at rest -------------------------------------------------------------------


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="DPAPI is Windows-only")
def test_the_refresh_token_is_encrypted_at_rest_and_a_damaged_file_means_disconnected(
    tmp_path: Path,
) -> None:
    tf = TokenFile(tmp_path)
    assert tf.load() is None
    tf.save("1//refresh-token-value-ABC")
    raw = tf.path.read_bytes()
    assert (
        b"refresh-token-value" not in raw and "refresh-token-value".encode("utf-16-le") not in raw
    )
    assert tf.load() == "1//refresh-token-value-ABC"
    assert unprotect(protect(b"abc")) == b"abc"
    tf.path.write_bytes(b"garbage")
    assert tf.load() is None
    tf.delete()
    tf.delete()


# ---- the service ---------------------------------------------------------------------------------


class _Source:
    last_error: str | None = None


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="DPAPI is Windows-only")
def test_the_status_names_each_situation_and_carries_no_content(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    tokens = TokenFile(tmp_path / "tok")
    source = _Source()
    service = MailboxService(rig.box, tokens, source, poll_seconds=0.01)  # type: ignore[arg-type]
    assert service.status()["state"] == "disconnected"
    service.poll_once()  # not connected: nothing is read
    assert rig.fake.requests == []
    tokens.save("refresh-token-0123456789")
    rig.fake.add("m1", PHISH)
    service.poll_once()
    status = service.status()
    assert status["state"] == "connected" and status["analysed"] == 1
    assert "SUBJECT" not in json.dumps(status) and "Verify" not in json.dumps(status)
    source.last_error = "revoked"
    assert service.status()["state"] == "reauth_needed"
    source.last_error = None
    rig.box.stats.last_error = "server"
    assert service.status()["state"] == "error"


# ---- the API ----------------------------------------------------------------------------------


def _api(tmp_path: Path, **over: Any):  # noqa: ANN202
    from fastapi.testclient import TestClient

    from core.api.app import create_app
    from core.config import Settings

    settings = Settings(
        _env_file=None, api_token="t0k-for-tests-0123456789", data_dir=tmp_path, **over
    )
    return TestClient(create_app(settings), base_url="http://127.0.0.1")


AUTH = {"Authorization": "Bearer t0k-for-tests-0123456789"}


def test_the_status_endpoint_needs_the_token_and_says_off_when_not_enabled(tmp_path: Path) -> None:
    with _api(tmp_path) as c:
        assert c.get("/v1/mailbox/status").status_code == 401
        assert c.get("/v1/mailbox/status", headers=AUTH).json() == {"state": "off"}


def test_enabling_without_a_client_id_stops_start_up_instead_of_doing_nothing(
    tmp_path: Path,
) -> None:
    with pytest.raises(RuntimeError, match="MIRAGE_GMAIL_CLIENT_ID"):
        _api(tmp_path, gmail_enabled=True)


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="DPAPI is Windows-only")
def test_an_enabled_mailbox_that_was_never_connected_is_disconnected_and_reads_nothing(
    tmp_path: Path,
) -> None:
    with _api(tmp_path, gmail_enabled=True, gmail_client_id="cid.apps.test") as c:
        status = c.get("/v1/mailbox/status", headers=AUTH).json()
    assert status["state"] == "disconnected" and status["analysed"] == 0


# ---- gaps the mutation checks found -----------------------------------------------------------


def test_the_loopback_listener_refuses_a_request_addressed_to_another_host_name() -> None:
    import http.client

    listener, thread, out = _listener("s")
    port = listener.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/?code=C&state=s", headers={"Host": "evil.test"})
    assert conn.getresponse().status == 400
    conn.close()
    assert _get(f"{listener.redirect_uri}/?code=REAL&state=s") == 200
    thread.join(timeout=10)
    listener.server_close()
    assert out == ["REAL"]


def test_a_message_that_failed_once_is_tried_again_and_not_lost_by_the_history_moving_on(
    tmp_path: Path,
) -> None:
    calls = {"n": 0}

    def flaky(raw: bytes) -> EmailAnalysis:
        calls["n"] += 1
        if calls["n"] == 1:
            return unscored(uuid4(), "0" * 64, VerdictState.ERROR, "Analysis failed.", "error")
        return analyze(raw)

    rig = Rig(tmp_path, analyze=flaky, lookback_days=0)
    rig.box.poll()  # connected
    rig.fake.add("m1", PHISH)
    rig.box.poll()  # first try fails: nothing stored, position must stay put
    assert rig.stored == []
    rig.box.poll()
    assert len(rig.stored) == 1 and calls["n"] == 2
    rig.box.poll()
    assert len(rig.stored) == 1


def test_a_vanished_message_is_remembered_so_it_is_not_asked_for_again(rig: Rig) -> None:
    rig.fake.add("m1", OK_MAIL)
    rig.box.poll()
    rig.fake.add("gone", PHISH)
    rig.fake.messages.pop("gone")
    rig.box.poll()
    assert rig.box.state.has(message_key("gone"))
