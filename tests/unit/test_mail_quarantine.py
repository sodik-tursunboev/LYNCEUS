"""Email quarantine (M6b) against fakes: the separate write consent, the core's own mail actions,
the runner that carries out what you approved, the poller hook that only proposes, and the privacy
of the message id. Nothing here talks to Google or Microsoft; it proves our logic, not their
behaviour (see docs/milestones/M6b.md)."""

import json
import logging
import sys
import threading
import time
import urllib.request
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from gmailhelp import FakeGmail
from mailhelp import PHISH_LINK, analyze, eml
from mailwritehelp import FakeGmailWrite, FakeGraphWrite
from sqlalchemy import Engine, create_engine, select, text
from sqlalchemy.exc import IntegrityError

from core.api.app import create_app
from core.config import Settings
from core.contracts import EventSource, VerdictState
from core.db import models as db
from core.db.store import save_email_analysis
from core.email.engine import EmailAnalysis
from core.mailbox import __main__ as cli
from core.mailbox import ms_oauth, oauth
from core.mailbox.gmail import GmailClient, GmailError, make_client
from core.mailbox.quarantine import MAX_TRANSIENT, MailQuarantineRunner
from core.mailbox.sync import Mailbox, State
from core.mailbox.tokens import TokenFile
from core.mailbox.wiring import build_mailboxes, build_quarantine, proposer
from core.mailbox.write import GmailMover, GraphMover, make_write_client
from core.response import service

TOKEN = "test-token-for-unit-tests"  # pragma: allowlist secret
AUTH = {"Authorization": f"Bearer {TOKEN}"}
READ = "https://www.googleapis.com/auth/gmail.readonly"
MODIFY = "https://www.googleapis.com/auth/gmail.modify"
MSG_ID = "PRIVATEMSGID0123"  # a Gmail-shaped id; it must never appear outside the action row
GRAPH_ID = "AAMkPRIVATEGRAPHID0123="
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")


# ---- the write consent: Google ------------------------------------------------------------------


@pytest.mark.parametrize(
    "scope",
    [MODIFY, f"{MODIFY} {READ}", f"{MODIFY} openid email", f"{MODIFY} profile {READ} email"],
)
def test_google_write_consent_accepts_modify_with_only_the_basic_sign_in_scopes(scope: str) -> None:
    assert oauth.google_write_scope_ok(scope)


@pytest.mark.parametrize(
    "scope",
    [
        None,
        "",
        READ,  # the read-only grant is not the write consent
        "https://mail.google.com/",
        f"{MODIFY} https://mail.google.com/",
        f"{MODIFY} https://www.googleapis.com/auth/gmail.send",
        f"{MODIFY} https://www.googleapis.com/auth/gmail.compose",
        f"{MODIFY} https://www.googleapis.com/auth/gmail.settings.basic",
        f"{MODIFY} https://www.googleapis.com/auth/drive",
        42,
    ],
)
def test_google_write_consent_refuses_a_missing_narrow_or_wider_grant(scope: object) -> None:
    assert not oauth.google_write_scope_ok(scope)


def test_a_refresh_answer_may_omit_the_scope_but_not_widen_it() -> None:
    assert oauth.google_write_refresh_ok(None)
    assert oauth.google_write_refresh_ok(f"{MODIFY} {READ}")
    assert not oauth.google_write_refresh_ok(f"{MODIFY} https://mail.google.com/")
    assert not oauth.google_write_refresh_ok(READ)


def _token_http(
    body: dict[str, Any], seen: list[httpx.Request] | None = None, status: int = 200
) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(status, json=body)

    return make_client(httpx.MockTransport(handler))


def _grant(scope: str | None) -> dict[str, Any]:
    body: dict[str, Any] = {"access_token": "a", "expires_in": 3600, "refresh_token": "r"}
    if scope is not None:
        body["scope"] = scope
    return body


def test_the_write_code_exchange_accepts_modify_and_stores_the_refresh_token() -> None:
    t = oauth.exchange_code(
        _token_http(_grant(MODIFY)), "cid", None, "c", "v", "http://127.0.0.1:1", write=True
    )
    assert t.refresh_token == "r"  # noqa: S105


@pytest.mark.parametrize(
    "scope",
    [
        READ,
        None,
        f"{MODIFY} https://www.googleapis.com/auth/gmail.send",
        "https://mail.google.com/",
    ],
)
def test_the_write_code_exchange_refuses_anything_but_modify_and_stores_nothing(
    scope: str | None,
) -> None:
    with pytest.raises(oauth.OAuthError) as e:
        oauth.exchange_code(
            _token_http(_grant(scope)), "cid", None, "c", "v", "http://127.0.0.1:1", write=True
        )
    assert e.value.kind == "scope"


def test_the_read_consent_still_refuses_the_write_scope() -> None:
    with pytest.raises(oauth.OAuthError) as e:
        oauth.exchange_code(
            _token_http(_grant(MODIFY)), "cid", None, "c", "v", "http://127.0.0.1:1"
        )
    assert e.value.kind == "scope"  # a read-only sign-in that came back with modify is refused


def test_the_write_refresh_refuses_a_widened_grant() -> None:
    ok = oauth.refresh_access(
        _token_http({"access_token": "a", "expires_in": 3600, "scope": MODIFY}),
        "cid", None, "r", write=True,
    )  # fmt: skip
    assert ok.access_token == "a"  # noqa: S105
    with pytest.raises(oauth.OAuthError) as e:
        oauth.refresh_access(
            _token_http({"access_token": "a", "expires_in": 3600, "scope": "https://mail.google.com/"}),
            "cid", None, "r", write=True,
        )  # fmt: skip
    assert e.value.kind == "scope"


def test_the_google_consent_url_asks_for_the_write_scope_only_when_told_to() -> None:
    read = parse_qs(urlparse(oauth.authorize_url("cid", "http://127.0.0.1:1", "ch", "st")).query)
    write = parse_qs(
        urlparse(oauth.authorize_url("cid", "http://127.0.0.1:1", "ch", "st", MODIFY)).query
    )
    assert read["scope"] == [READ] and write["scope"] == [MODIFY]


# ---- the write consent: Microsoft ---------------------------------------------------------------


@pytest.mark.parametrize(
    "scope",
    [
        "Mail.ReadWrite offline_access",
        "https://graph.microsoft.com/Mail.ReadWrite openid profile offline_access",
        "Mail.ReadWrite Mail.Read User.Read email",
    ],
)
def test_microsoft_write_consent_accepts_readwrite_with_the_basics(scope: str) -> None:
    assert ms_oauth.scope_ok_write(scope)


@pytest.mark.parametrize(
    "scope",
    [
        None,
        "",
        "Mail.Read offline_access",
        "Mail.ReadWrite Mail.Send",
        "Mail.ReadWrite Files.ReadWrite",
        "Mail.ReadWrite.Shared",
        "Mail.ReadWrite Calendars.ReadWrite",
        7,
    ],
)
def test_microsoft_write_consent_refuses_a_missing_narrow_or_wider_grant(scope: object) -> None:
    assert not ms_oauth.scope_ok_write(scope)


def test_the_microsoft_read_consent_still_refuses_readwrite() -> None:
    assert not ms_oauth.scope_ok("Mail.ReadWrite offline_access")
    assert ms_oauth.scope_ok("Mail.Read offline_access")


def test_the_microsoft_write_exchange_and_refresh_ask_for_readwrite_and_check_the_grant() -> None:
    seen: list[httpx.Request] = []
    body = {
        "access_token": "a",
        "expires_in": 3600,
        "refresh_token": "r",
        "scope": "Mail.ReadWrite offline_access",
    }
    t = ms_oauth.exchange_code(
        _token_http(body, seen), "common", "cid", "code", "ver", "http://localhost:1", write=True
    )
    ms_oauth.refresh(_token_http(body, seen), "common", "cid", "r", write=True)
    assert t.refresh_token == "r"  # noqa: S105
    assert all("scope=Mail.ReadWrite+offline_access" in r.content.decode() for r in seen)
    bad = body | {"scope": "Mail.ReadWrite Mail.Send"}
    for call in (
        lambda: ms_oauth.exchange_code(
            _token_http(bad), "common", "cid", "code", "ver", "http://localhost:1", write=True
        ),
        lambda: ms_oauth.refresh(_token_http(bad), "common", "cid", "r", write=True),
    ):
        with pytest.raises(oauth.OAuthError) as e:
            call()
        assert e.value.kind == "scope"
    with pytest.raises(oauth.OAuthError):  # the read flow refuses a Mail.ReadWrite answer
        ms_oauth.exchange_code(
            _token_http(body), "common", "cid", "code", "ver", "http://localhost:1"
        )


def test_the_microsoft_consent_url_asks_for_readwrite_only_when_told_to() -> None:
    read = parse_qs(
        urlparse(ms_oauth.authorize_url("common", "cid", "http://localhost:1", "c", "s")).query
    )
    write = parse_qs(
        urlparse(
            ms_oauth.authorize_url(
                "common", "cid", "http://localhost:1", "c", "s", ms_oauth.SCOPES_WRITE
            )
        ).query
    )
    assert read["scope"] == ["Mail.Read offline_access"]
    assert write["scope"] == ["Mail.ReadWrite offline_access"]


# ---- the whole sign-in, with a browser that answers --------------------------------------------


def _browser(seen: list[str]) -> Callable[[str], None]:
    def open_(url: str) -> None:
        seen.append(url)
        q = parse_qs(urlparse(url).query)
        redirect, state = q["redirect_uri"][0], q["state"][0]

        def answer() -> None:
            urllib.request.urlopen(f"{redirect}/?code=CODE&state={state}", timeout=5).read()  # noqa: S310

        threading.Thread(target=answer, daemon=True).start()

    return open_


def test_connecting_the_write_permission_asks_google_for_modify_and_returns_the_token() -> None:
    urls: list[str] = []
    token = oauth.connect(
        "cid", None, _browser(urls), http=_token_http(_grant(MODIFY)), timeout=10, write=True
    )
    assert token == "r" and parse_qs(urlparse(urls[0]).query)["scope"] == [MODIFY]  # noqa: S105
    with pytest.raises(oauth.OAuthError) as e:  # a grant that came back wider stores nothing
        oauth.connect(
            "cid", None, _browser([]),
            http=_token_http(_grant(f"{MODIFY} https://mail.google.com/")), timeout=10, write=True,
        )  # fmt: skip
    assert e.value.kind == "scope"


def test_connecting_the_write_permission_asks_microsoft_for_readwrite_and_returns_the_token() -> (
    None
):
    urls: list[str] = []
    body = {
        "access_token": "a",
        "expires_in": 3600,
        "refresh_token": "r",
        "scope": "Mail.ReadWrite offline_access",
    }
    token = ms_oauth.connect(
        "common", "cid", _browser(urls), http=_token_http(body), timeout=10, write=True
    )
    assert token == "r"  # noqa: S105
    assert parse_qs(urlparse(urls[0]).query)["scope"] == ["Mail.ReadWrite offline_access"]


# ---- the command line ---------------------------------------------------------------------------


class Cli:
    """Runs `python -m core.mailbox` in a throwaway data directory with the sign-in replaced."""

    def __init__(self, tmp: Path, mp: pytest.MonkeyPatch) -> None:
        mp.chdir(tmp)  # no .env is read from the project
        mp.setenv("MIRAGE_DATA_DIR", str(tmp / "data"))
        mp.setenv("MIRAGE_GMAIL_CLIENT_ID", "cid.apps.test")
        mp.setenv("MIRAGE_OUTLOOK_CLIENT_ID", "outlook-cid")
        self.dir = tmp / "data" / "mailbox"
        self.connects: list[tuple[str, bool]] = []
        self.revoked: list[str] = []
        self.questions: list[str] = []

        def google(client_id: str, secret: object, opener: object, *, write: bool = False) -> str:
            self.connects.append(("gmail", write))
            return "google-write-refresh" if write else "google-read-refresh"

        def microsoft(tenant: str, client_id: str, opener: object, *, write: bool = False) -> str:
            self.connects.append(("outlook", write))
            return "ms-write-refresh" if write else "ms-read-refresh"

        mp.setattr(oauth, "connect", google)
        mp.setattr(ms_oauth, "connect", microsoft)
        mp.setattr(oauth, "revoke", lambda _http, token: self.revoked.append(token) or True)

    def run(self, *argv: str, answer: str = "YES") -> int:
        def ask(prompt: str) -> str:
            self.questions.append(prompt)
            return answer

        return cli.main(list(argv), ask=ask, opener=lambda _u: None)

    def token(self, name: str) -> str | None:
        return TokenFile(self.dir, name).load()


@pytest.fixture
def cl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Cli:
    return Cli(tmp_path, monkeypatch)


@windows_only
def test_a_plain_connect_stores_only_the_read_token(cl: Cli) -> None:
    assert cl.run("connect") == 0
    assert cl.connects == [("gmail", False)] and cl.questions == []
    assert cl.token("gmail.token") == "google-read-refresh"
    assert cl.token("gmail-write.token") is None


@windows_only
@pytest.mark.parametrize("provider", ["gmail", "outlook"])
def test_connect_write_asks_first_and_stores_the_separate_token(cl: Cli, provider: str) -> None:
    assert cl.run("connect", "--write", "--provider", provider) == 0
    assert len(cl.questions) == 1
    assert cl.connects == [(provider, True)]
    assert cl.token(f"{provider}-write.token") is not None
    assert cl.token(f"{provider}.token") is None  # the read token is untouched, never replaced


@windows_only
@pytest.mark.parametrize("answer", ["", "yes", "y", "NO", "YES please"])
def test_connect_write_without_a_clear_yes_changes_nothing(
    cl: Cli, answer: str, capsys: Any
) -> None:
    assert cl.run("connect", "--write", answer=answer) == 1
    assert cl.connects == [] and cl.token("gmail-write.token") is None
    assert "Cancelled" in capsys.readouterr().err


@windows_only
def test_connect_write_with_no_terminal_is_a_no(cl: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    def eof(_prompt: str) -> str:
        raise EOFError

    assert cli.main(["connect", "--write"], ask=eof, opener=lambda _u: None) == 1
    assert cl.connects == []


@windows_only
def test_yes_skips_the_question_but_the_notice_names_the_wider_permission(
    cl: Cli, capsys: Any
) -> None:
    assert cl.run("connect", "--write", "--yes") == 0
    assert cl.questions == []
    assert cl.token("gmail-write.token") == "google-write-refresh"
    out = capsys.readouterr().out
    assert "read the mailbox" in out  # the read token is missing: it says so
    assert cl.run("connect", "--write", "--provider", "outlook") == 0
    notice = capsys.readouterr().out
    assert "Mail.ReadWrite" in notice and "never sends, deletes" in notice


def test_the_notice_says_what_the_permission_can_do_and_what_mirage_will_not(
    cl: Cli, capsys: Any
) -> None:
    cl.run("connect", "--write", answer="no")
    shown = capsys.readouterr().out
    assert "gmail.modify" in shown and "send" in shown and "Approve" in shown
    assert "never sends, drafts, trashes or deletes" in shown


def test_connect_write_needs_the_client_id_before_anything_is_asked(
    cl: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MIRAGE_GMAIL_CLIENT_ID")
    assert cl.run("connect", "--write") == 2
    assert cl.questions == [] and cl.connects == []


@windows_only
def test_disconnect_write_removes_only_the_write_token_and_revokes_it(cl: Cli) -> None:
    cl.run("connect")
    cl.run("connect", "--write", "--yes")
    assert cl.run("disconnect", "--write") == 0
    assert cl.token("gmail-write.token") is None and cl.token("gmail.token") is not None
    assert cl.revoked == ["google-write-refresh"]


@windows_only
def test_a_plain_disconnect_removes_both_tokens_and_the_state(cl: Cli) -> None:
    cl.run("connect")
    cl.run("connect", "--write", "--yes")
    (cl.dir / "gmail-state.json").write_text("{}", encoding="utf-8")
    assert cl.run("disconnect") == 0
    assert cl.token("gmail.token") is None and cl.token("gmail-write.token") is None
    assert not (cl.dir / "gmail-state.json").exists()
    assert sorted(cl.revoked) == ["google-read-refresh", "google-write-refresh"]


# ---- a world: a database, the API, and flagged messages ----------------------------------------


def forced(raw: bytes, state: VerdictState) -> EmailAnalysis:
    """The real analysis with the verdict state forced: what is tested is the response to it."""
    a = analyze(raw)
    v = a.report.verdict.model_copy(update={"state": state})
    return a.model_copy(update={"report": a.report.model_copy(update={"verdict": v})})


def malicious(raw: bytes) -> EmailAnalysis:
    return forced(raw, VerdictState.MALICIOUS)


def mail(n: int) -> bytes:
    return eml(subject=f"Verify now {n}", html=f"<p>{PHISH_LINK}</p>", text=None)


class World:
    def __init__(self, tmp_path: Path) -> None:
        self.url = f"sqlite:///{tmp_path / 'mirage.db'}"
        self.engine: Engine = create_engine(self.url)
        db.Base.metadata.create_all(self.engine)
        settings = Settings(
            _env_file=None, api_token=TOKEN, database_url=self.url, data_dir=tmp_path / "data"
        )
        self.client = TestClient(create_app(settings), base_url="http://127.0.0.1")
        self.now = 1000.0

    def verdict(self, n: int = 0) -> uuid.UUID:
        a = malicious(mail(n))
        save_email_analysis(self.engine, a, EventSource.EMAIL)
        return a.report.verdict.id

    def propose(self, provider: str = "gmail", ref: str = MSG_ID, n: int = 0) -> uuid.UUID:
        return service.create_pending_mail(self.engine, self.verdict(n), provider, ref)

    def act(self, action_id: object, verb: str, actor: str | None = None) -> Any:
        headers = AUTH | ({"X-Mirage-Actor": actor} if actor else {})
        return self.client.post(f"/v1/actions/{action_id}/{verb}", headers=headers)

    def get(self, action_id: object) -> dict[str, Any]:
        r = self.client.get(f"/v1/actions/{action_id}", headers=AUTH)
        assert r.status_code == 200
        return dict(r.json())

    def state(self, action_id: object) -> str:
        return str(self.get(action_id)["state"])

    def mail_ref(self, action_id: object) -> str | None:
        with self.engine.connect() as c:
            return c.scalar(select(db.Action.mail_ref).where(db.Action.id == action_id))

    def runner(self, movers: dict[str, Any]) -> MailQuarantineRunner:
        return MailQuarantineRunner(self.engine, movers, 0.01, clock=lambda: self.now)

    def audit(self) -> list[dict[str, Any]]:
        rows = self.client.get("/v1/audit?limit=500", headers=AUTH).json()
        return list(reversed(rows))

    def dump(self, skip_mail_ref: bool = True) -> str:
        """Everything in the database as text (the mail_ref column is the one allowed place)."""
        out: list[Any] = []
        with self.engine.connect() as c:
            for table in db.Base.metadata.sorted_tables:
                for row in c.execute(select(table)).mappings():
                    out.append(
                        {k: v for k, v in row.items() if not (skip_mail_ref and k == "mail_ref")}
                    )
        return json.dumps(out, default=str)


@pytest.fixture
def w(tmp_path: Path) -> World:
    return World(tmp_path)


def gmail_mover(fake: FakeGmailWrite) -> GmailMover:
    return GmailMover(lambda: "access-token", make_write_client(fake.transport()))


def graph_mover(fake: FakeGraphWrite) -> GraphMover:
    return GraphMover(lambda: "access-token", make_write_client(fake.transport()))


# ---- proposing an email action -----------------------------------------------------------------


def test_a_proposal_is_a_pending_mail_action_that_never_shows_the_message_id(w: World) -> None:
    action_id = w.propose()
    got = w.get(action_id)
    assert (got["state"], got["kind"], got["provider"]) == ("PENDING", "MAIL_QUARANTINE", "gmail")
    assert MSG_ID not in json.dumps(got) and "mail_ref" not in got
    assert w.mail_ref(action_id) == MSG_ID  # kept on the action row, nowhere else
    assert MSG_ID not in json.dumps(w.audit()) and MSG_ID not in w.dump()
    created = [a for a in w.audit() if a["action"] == "action.create"][-1]
    assert created["actor"] == "policy" and created["detail"]["provider"] == "gmail"


def test_asking_again_for_the_same_message_returns_the_same_action(w: World) -> None:
    first = w.propose()
    again = w.propose(n=1)
    assert again == first
    other = w.propose(provider="outlook", n=2)  # another provider's id is another message
    assert other != first
    assert len(service.list_actions(w.engine, None, 50, "MAIL_QUARANTINE")) == 2


@pytest.mark.parametrize(
    ("provider", "ref"),
    [
        ("yahoo", MSG_ID),
        ("", MSG_ID),
        ("gmail", ""),
        ("gmail", "has space"),
        ("gmail", "a/b"),
        ("gmail", "x" * 513),
    ],
)
def test_a_proposal_for_an_unknown_provider_or_a_malformed_id_is_refused(
    w: World, provider: str, ref: str
) -> None:
    with pytest.raises(ValueError):  # noqa: PT011
        service.create_pending_mail(w.engine, w.verdict(), provider, ref)
    assert service.list_actions(w.engine, None, 50) == []


def test_the_database_refuses_a_mail_action_without_a_provider_and_a_file_action_with_one(
    w: World,
) -> None:
    v = w.verdict()
    base = {"verdict_id": v, "state": "PENDING", "file_ref": "f" * 32, "sha256": "e" * 64}
    bad = [
        {"kind": "MAIL_QUARANTINE"},
        {"kind": "MAIL_QUARANTINE", "provider": "yahoo"},
        {"kind": "FILE_QUARANTINE", "provider": "gmail"},
        {"kind": "FILE_QUARANTINE", "mail_ref": "x"},
        {"kind": "DELETE_EMAIL", "provider": "gmail"},
    ]
    for i, extra in enumerate(bad):
        row = base | {"id": uuid.uuid4(), "file_ref": f"{i:032d}"} | extra
        with pytest.raises(IntegrityError), w.engine.begin() as c:
            c.execute(db.Action.__table__.insert().values(**row))  # type: ignore[attr-defined]


def test_the_action_list_can_be_filtered_by_kind(w: World) -> None:
    mail_id = w.propose()
    with w.engine.begin() as c:  # a file action, as the file route would have made it
        c.execute(
            db.Action.__table__.insert().values(  # type: ignore[attr-defined]
                id=uuid.uuid4(), verdict_id=w.verdict(5), kind="FILE_QUARANTINE", state="PENDING",
                file_ref="a" * 32, sha256="b" * 64,
            )
        )  # fmt: skip

    def kinds(query: str) -> set[str]:
        r = w.client.get(f"/v1/actions{query}", headers=AUTH)
        assert r.status_code == 200
        return {a["kind"] for a in r.json()}

    assert kinds("") == {"MAIL_QUARANTINE", "FILE_QUARANTINE"}
    assert kinds("?kind=MAIL_QUARANTINE") == {"MAIL_QUARANTINE"}
    assert kinds("?kind=FILE_QUARANTINE") == {"FILE_QUARANTINE"}
    assert kinds("?kind=NOTHING") == set()
    assert w.client.get("/v1/actions?kind=bad-kind!", headers=AUTH).status_code == 422
    assert [
        a["id"] for a in w.client.get("/v1/actions?kind=MAIL_QUARANTINE", headers=AUTH).json()
    ] == [str(mail_id)]


# ---- who may approve, and who may report -------------------------------------------------------


def test_only_your_own_click_approves_a_mail_move_policy_never_does(w: World) -> None:
    action_id = w.propose()
    r = w.act(action_id, "approve", actor="policy")
    assert r.status_code == 409 and "yourself" in r.json()["detail"]
    assert w.state(action_id) == "PENDING"
    assert w.act(action_id, "approve", actor="user").status_code == 200
    assert w.state(action_id) == "APPROVED"
    assert w.act(action_id, "approve").json()["changed"] is False  # twice: the same, once


@pytest.mark.parametrize("outcome", ["applied", "failed", "restored", "restore_failed"])
def test_the_result_route_cannot_finish_a_mail_action(w: World, outcome: str) -> None:
    action_id = w.propose()
    w.act(action_id, "approve", actor="user")
    r = w.client.post(f"/v1/actions/{action_id}/result", json={"outcome": outcome}, headers=AUTH)
    assert r.status_code == 409 and w.state(action_id) == "APPROVED"


def test_a_mail_move_can_be_dismissed_and_cannot_be_restored_before_it_happened(w: World) -> None:
    action_id = w.propose()
    assert w.act(action_id, "restore").status_code == 409
    assert w.act(action_id, "dismiss").status_code == 200 and w.state(action_id) == "DISMISSED"
    runner = w.runner({"gmail": gmail_mover(FakeGmailWrite())})
    assert runner.poll_once() == 0  # a dismissed action is not work


# ---- the runner: Gmail -------------------------------------------------------------------------


def approved(w: World, provider: str = "gmail", ref: str = MSG_ID, n: int = 0) -> uuid.UUID:
    action_id = w.propose(provider, ref, n)
    assert w.act(action_id, "approve", actor="user").status_code == 200
    return action_id


def test_nothing_is_touched_until_you_approve(w: World) -> None:
    fake = FakeGmailWrite()
    fake.add(MSG_ID)
    w.propose()
    runner = w.runner({"gmail": gmail_mover(fake)})
    assert runner.poll_once() == 0
    assert fake.requests == [] and fake.messages[MSG_ID] == {"INBOX"}


def test_an_approved_gmail_message_is_moved_out_of_the_inbox_and_can_be_moved_back(
    w: World,
) -> None:
    fake = FakeGmailWrite()
    fake.add(MSG_ID)
    action_id = approved(w)
    runner = w.runner({"gmail": gmail_mover(fake)})

    assert runner.poll_once() == 1
    assert w.state(action_id) == "APPLIED"
    label = fake.labels["MIRAGE-Quarantine"]
    assert fake.messages[MSG_ID] == {
        label
    }  # out of the inbox, in the quarantine label, not deleted
    assert w.mail_ref(action_id) == MSG_ID  # still needed to find it again

    assert w.act(action_id, "restore", actor="user").status_code == 200
    assert runner.poll_once() == 1
    assert w.state(action_id) == "RESTORED"
    assert fake.messages[MSG_ID] == {"INBOX"}
    assert w.mail_ref(action_id) is None  # no longer needed: cleared
    steps = [a["action"] for a in w.audit() if a["target_id"] == str(action_id)]
    assert steps == [
        "action.create",
        "action.approve",
        "action.applied",
        "action.restore",
        "action.restored",
    ]
    actors = [a["actor"] for a in w.audit() if a["target_id"] == str(action_id)]
    assert actors == ["policy", "user", "core", "user", "core"]


def test_a_repeated_pass_changes_nothing_a_second_time(w: World) -> None:
    fake = FakeGmailWrite()
    fake.add(MSG_ID)
    action_id = approved(w)
    runner = w.runner({"gmail": gmail_mover(fake)})
    runner.poll_once()
    calls = len(fake.requests)
    assert runner.poll_once() == 0 and runner.poll_once() == 0
    assert len(fake.requests) == calls and w.state(action_id) == "APPLIED"
    assert w.act(action_id, "approve", actor="user").json()["changed"] is False


def test_a_message_that_is_already_in_quarantine_is_not_moved_again_and_still_ends_applied(
    w: World,
) -> None:
    fake = FakeGmailWrite()
    fake.add(MSG_ID)
    action_id = approved(w)
    runner = w.runner({"gmail": gmail_mover(fake)})
    runner.poll_once()
    # the action row is rolled back to APPROVED (a crash after the move, before the commit)
    with w.engine.begin() as c:
        c.execute(text("UPDATE actions SET state = 'APPROVED' WHERE id = :i"), {"i": action_id.hex})
    modifies = [c for c in fake.calls("POST") if c[1].endswith("/modify")]
    assert runner.poll_once() == 1 and w.state(action_id) == "APPLIED"
    assert [c for c in fake.calls("POST") if c[1].endswith("/modify")] == modifies


def test_one_failed_message_does_not_stop_the_others(w: World) -> None:
    fake = FakeGmailWrite()
    fake.add("SECONDMSG")  # the first approved message does not exist in the mailbox
    gone = approved(w, ref="GONEMSG", n=1)
    there = approved(w, ref="SECONDMSG", n=2)
    runner = w.runner({"gmail": gmail_mover(fake)})
    assert runner.poll_once() == 2
    assert (w.state(gone), w.state(there)) == ("FAILED", "APPLIED")
    assert w.get(gone)["reason"] == "message_gone"


@pytest.mark.parametrize(
    ("status", "reason"),
    [(404, "message_gone"), (401, "mail_auth"), (403, "mail_forbidden"), (400, "mail_bad_reply")],
)
def test_a_provider_refusal_is_a_stated_failure_with_a_reason_and_no_guess(
    w: World, status: int, reason: str
) -> None:
    fake = FakeGmailWrite()
    fake.add(MSG_ID)
    action_id = approved(w)
    fake.fail_next("/messages/", status)
    runner = w.runner({"gmail": gmail_mover(fake)})
    assert runner.poll_once() == 1
    assert (w.state(action_id), w.get(action_id)["reason"]) == ("FAILED", reason)
    assert fake.messages[MSG_ID] == {"INBOX"}  # nothing moved, and it was not called done
    # approving again is the retry, and then it works
    w.act(action_id, "approve", actor="user")
    assert runner.poll_once() == 1 and w.state(action_id) == "APPLIED"


def test_throttling_waits_and_then_succeeds_without_failing_the_action(w: World) -> None:
    fake = FakeGmailWrite()
    fake.add(MSG_ID)
    action_id = approved(w)
    fake.fail_next("/messages/", 429, **{"Retry-After": "7"})
    runner = w.runner({"gmail": gmail_mover(fake)})
    assert runner.poll_once() == 0
    assert w.state(action_id) == "APPROVED" and runner.last_error == "rate"
    calls = len(fake.requests)
    assert runner.poll_once() == 0 and len(fake.requests) == calls  # still waiting: no request
    w.now += 8
    assert runner.poll_once() == 1 and w.state(action_id) == "APPLIED"
    assert runner.last_error is None


def test_a_provider_that_keeps_failing_ends_as_unavailable_after_a_bounded_number_of_tries(
    w: World,
) -> None:
    fake = FakeGmailWrite()
    fake.add(MSG_ID)
    action_id = approved(w)
    runner = w.runner({"gmail": gmail_mover(fake)})
    for _ in range(MAX_TRANSIENT):
        fake.fail_next("/messages/", 503)
        runner.poll_once()
        w.now += 400
    assert w.state(action_id) == "FAILED" and w.get(action_id)["reason"] == "mail_unavailable"


def test_a_failed_restore_returns_to_applied_with_the_reason_and_can_be_tried_again(
    w: World,
) -> None:
    fake = FakeGmailWrite()
    fake.add(MSG_ID)
    action_id = approved(w)
    runner = w.runner({"gmail": gmail_mover(fake)})
    runner.poll_once()
    w.act(action_id, "restore", actor="user")
    fake.fail_next("/messages/", 403)
    runner.poll_once()
    got = w.get(action_id)
    assert (got["state"], got["reason"]) == ("APPLIED", "mail_forbidden")
    assert w.mail_ref(action_id) == MSG_ID  # the id is kept: the restore can be tried again
    w.act(action_id, "restore", actor="user")
    runner.poll_once()
    assert w.state(action_id) == "RESTORED" and fake.messages[MSG_ID] == {"INBOX"}


def test_a_provider_without_write_access_or_a_lost_id_is_a_stated_failure(w: World) -> None:
    no_mover = approved(w, provider="outlook", ref=GRAPH_ID, n=1)
    lost = approved(w, ref="LOSTMSG", n=2)
    with w.engine.begin() as c:
        c.execute(text("UPDATE actions SET mail_ref = NULL WHERE id = :i"), {"i": lost.hex})
    runner = w.runner({"gmail": gmail_mover(FakeGmailWrite())})
    assert runner.poll_once() == 2
    assert (w.state(no_mover), w.get(no_mover)["reason"]) == ("FAILED", "no_write_access")
    assert (w.state(lost), w.get(lost)["reason"]) == ("FAILED", "message_gone")


def test_an_unexpected_error_in_one_move_is_logged_by_class_and_does_not_stop_the_rest(
    w: World, caplog: pytest.LogCaptureFixture
) -> None:
    class Broken:
        def quarantine(self, ref: str) -> str:
            raise RuntimeError(f"boom with {ref}")

        def restore(self, ref: str) -> str:
            raise RuntimeError(ref)

    action_id = approved(w)
    with caplog.at_level(logging.DEBUG):
        runner = w.runner({"gmail": Broken()})
        assert runner.poll_once() == 1
    assert (w.state(action_id), w.get(action_id)["reason"]) == ("FAILED", "mail_error")


def test_the_runner_survives_a_move_that_raises_a_provider_error_of_an_unknown_kind(
    w: World,
) -> None:
    class Odd:
        def quarantine(self, ref: str) -> str:
            raise GmailError("something_new")  # type: ignore[arg-type]

        def restore(self, ref: str) -> str:
            raise GmailError("something_new")  # type: ignore[arg-type]

    action_id = approved(w)
    assert w.runner({"gmail": Odd()}).poll_once() == 1
    assert w.get(action_id)["reason"] == "mail_error"


def test_you_dismissing_while_a_move_is_in_flight_still_leaves_it_restorable(w: World) -> None:
    fake = FakeGmailWrite()
    fake.add(MSG_ID)
    action_id = approved(w)
    inner = gmail_mover(fake)

    class Racing:
        def quarantine(self, ref: str) -> str:
            w.act(action_id, "dismiss", actor="user")  # your click lands after the runner read it
            return inner.quarantine(ref)

        def restore(self, ref: str) -> str:
            return inner.restore(ref)

    w.runner({"gmail": Racing()}).poll_once()
    assert w.state(action_id) == "APPLIED"  # what happened is recorded, so it can be moved back
    assert w.act(action_id, "restore", actor="user").status_code == 200


# ---- the runner: Outlook, where the id changes on a move --------------------------------------


def test_outlook_saves_the_new_id_with_the_outcome_and_restores_with_it(w: World) -> None:
    fake = FakeGraphWrite()
    fake.add(GRAPH_ID)
    action_id = approved(w, provider="outlook", ref=GRAPH_ID)
    runner = w.runner({"outlook": graph_mover(fake)})
    assert runner.poll_once() == 1 and w.state(action_id) == "APPLIED"
    new_ref = w.mail_ref(action_id)
    assert new_ref and new_ref != GRAPH_ID and new_ref in fake.messages
    assert GRAPH_ID not in fake.messages  # the old id is gone, as Graph does on a move
    folder = fake.folders["mirage quarantine"]
    assert fake.messages[new_ref] == folder

    w.act(action_id, "restore", actor="user")
    assert runner.poll_once() == 1
    assert w.state(action_id) == "RESTORED" and w.mail_ref(action_id) is None
    assert list(fake.messages.values()) == [fake.folders["inbox"]]


def test_outlook_without_an_id_change_works_too(w: World) -> None:
    fake = FakeGraphWrite(id_changes_on_move=False)
    fake.add(GRAPH_ID)
    action_id = approved(w, provider="outlook", ref=GRAPH_ID)
    runner = w.runner({"outlook": graph_mover(fake)})
    runner.poll_once()
    assert w.mail_ref(action_id) == GRAPH_ID and w.state(action_id) == "APPLIED"


# ---- the poller hook: it proposes, it never moves ---------------------------------------------


class Rig:
    """A Gmail poller over the fake read-only Gmail, with a stored verdict per message."""

    def __init__(self, w: World, tmp: Path, hook: Callable[[str, uuid.UUID], None] | None) -> None:
        self.fake = FakeGmail()
        self.w = w
        self.analyses: dict[str, EmailAnalysis] = {}
        self.calls: list[str] = []

        def analyzer(raw: bytes) -> EmailAnalysis:
            if b"Maybe later" in raw:
                return forced(raw, VerdictState.SUSPICIOUS)
            return malicious(raw) if b"Verify now" in raw else analyze(raw)

        def store(a: EmailAnalysis) -> None:
            save_email_analysis(w.engine, a, EventSource.EMAIL)

        self.box = Mailbox(
            GmailClient(lambda: "access-token", make_client(self.fake.transport())),
            analyzer, store, State(tmp / "state.json"), 2,
            fetch_gap=0, sleep=lambda _s: None, clock=lambda: 5000.0, on_malicious=hook,
        )  # fmt: skip


class Token:
    """Stands in for the write token file."""

    def __init__(self, present: bool) -> None:
        self.present = present

    def load(self) -> str | None:
        return "write-refresh" if self.present else None


def test_only_a_malicious_message_is_proposed_and_only_once(w: World, tmp_path: Path) -> None:
    seen: list[str] = []
    rig = Rig(w, tmp_path, lambda mid, _vid: seen.append(mid))
    rig.fake.add("OKMSG1", eml(subject="Lunch", text="see you at noon"))
    rig.fake.add("MAYBE1", eml(subject="Maybe later", html=f"<p>{PHISH_LINK}</p>", text=None))
    rig.fake.add("BADMSG1", mail(1))
    rig.box.poll()
    rig.box.poll()
    assert seen == ["BADMSG1"]  # SUSPICIOUS and benign mail are never proposed
    assert rig.box.stats.analysed == 3 and len(rig.box.stats.flagged) == 2


def test_a_hook_failure_never_stops_the_poll_and_never_logs_the_message_id(
    w: World, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    def hook(mid: str, _vid: uuid.UUID) -> None:
        raise RuntimeError(f"database said no about {mid}")

    rig = Rig(w, tmp_path, hook)
    rig.fake.add("BADMSG2", mail(2))
    rig.fake.add("BADMSG3", mail(3))
    with caplog.at_level(logging.DEBUG):
        rig.box.poll()
    assert rig.box.stats.analysed == 2 and rig.box.stats.last_error is None
    assert "BADMSG2" not in caplog.text and "BADMSG3" not in caplog.text
    assert "RuntimeError" in caplog.text


def test_without_the_write_permission_nothing_is_proposed(w: World, tmp_path: Path) -> None:
    hook = proposer("gmail", Token(False), w.engine)  # type: ignore[arg-type]
    assert hook is not None
    rig = Rig(w, tmp_path, hook)
    rig.fake.add("BADMSG4", mail(4))
    rig.box.poll()
    assert service.list_actions(w.engine, None, 50) == []


def test_with_the_write_permission_a_malicious_message_becomes_a_pending_action_only(
    w: World, tmp_path: Path
) -> None:
    hook = proposer("gmail", Token(True), w.engine)  # type: ignore[arg-type]
    assert hook is not None
    rig = Rig(w, tmp_path, hook)
    rig.fake.add("BADMSG5", mail(5))
    rig.fake.add("OKMSG5", eml(subject="Lunch", text="see you at noon"))
    rig.box.poll()
    actions = service.list_actions(w.engine, None, 50)
    assert [(a["kind"], a["state"], a["provider"]) for a in actions] == [
        ("MAIL_QUARANTINE", "PENDING", "gmail")
    ]
    assert w.mail_ref(actions[0]["id"]) == "BADMSG5"
    assert [r for r in rig.fake.requests if r[0] != "GET"] == []  # the poller only ever reads


def test_there_is_no_proposer_without_a_database() -> None:
    assert proposer("gmail", Token(True), None) is None  # type: ignore[arg-type]


# ---- the whole flow, and where the message id is allowed to be --------------------------------


def test_flag_approve_move_restore_end_to_end_and_the_message_id_stays_on_one_row(
    w: World, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    write = FakeGmailWrite()
    write.add("PRIVATEMSG987")
    hook = proposer("gmail", Token(True), w.engine)  # type: ignore[arg-type]
    rig = Rig(w, tmp_path, hook)
    rig.fake.add("PRIVATEMSG987", mail(7))
    runner = w.runner({"gmail": gmail_mover(write)})
    with caplog.at_level(logging.DEBUG):
        rig.box.poll()
        (action,) = service.list_actions(w.engine, None, 50)
        action_id = action["id"]
        assert action["state"] == "PENDING" and write.requests == []
        assert w.act(action_id, "approve", actor="user").status_code == 200
        runner.poll_once()
        applied = w.get(action_id)
        events = w.client.get("/v1/events", headers=AUTH).json()
        listing = w.client.get("/v1/actions", headers=AUTH).json()
        audit_while_applied = json.dumps(w.audit())
        assert w.act(action_id, "restore", actor="user").status_code == 200
        runner.poll_once()
    assert applied["state"] == "APPLIED" and w.state(action_id) == "RESTORED"
    assert write.messages["PRIVATEMSG987"] == {"INBOX"}
    for text_ in (
        json.dumps(applied),
        json.dumps(events),
        json.dumps(listing),
        audit_while_applied,
    ):
        assert "PRIVATEMSG987" not in text_
    assert "PRIVATEMSG987" not in json.dumps(w.audit()) and "PRIVATEMSG987" not in caplog.text
    assert "PRIVATEMSG987" not in w.dump(skip_mail_ref=False)  # cleared once restored
    mutating = [c for c in write.calls() if c[0] not in ("GET",)]
    assert all(
        p.endswith(("/modify", "/labels")) for _m, p in mutating
    )  # no delete, no send, no trash


# ---- wiring ------------------------------------------------------------------------------------


def test_the_runner_exists_with_a_database_and_has_a_mover_only_for_a_signed_in_provider(
    tmp_path: Path,
) -> None:
    both = Settings(
        _env_file=None, data_dir=tmp_path, gmail_enabled=True, gmail_client_id="cid.apps.test",
        outlook_enabled=True, outlook_client_id="outlook-cid",
    )  # fmt: skip
    services = build_mailboxes(both, None, None)
    assert build_quarantine(services, None) is None  # no database: no actions exist
    engine = create_engine(f"sqlite:///{tmp_path / 'x.db'}")
    runner = build_quarantine(services, engine)
    assert runner is not None and runner.providers() == ["gmail", "outlook"]
    movers = runner._movers  # noqa: SLF001
    assert isinstance(movers["gmail"], GmailMover) and isinstance(movers["outlook"], GraphMover)
    only_gmail = build_mailboxes(both.model_copy(update={"outlook_enabled": False}), None, None)
    runner = build_quarantine(only_gmail, engine)
    assert runner is not None and runner.providers() == ["gmail"]
    off = build_quarantine([], engine)
    assert off is not None and off.providers() == []  # still there: approved actions end stated


def test_the_status_reports_whether_the_write_permission_was_given(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None, data_dir=tmp_path, gmail_enabled=True, gmail_client_id="cid.apps.test"
    )
    (service_,) = build_mailboxes(settings, None, None)
    assert service_.status()["quarantine"] == "none"  # also with no token file at all


@windows_only
def test_the_status_says_ready_then_reauth_needed(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None, data_dir=tmp_path, gmail_enabled=True, gmail_client_id="cid.apps.test"
    )
    (service_,) = build_mailboxes(settings, None, None)
    assert service_.write_tokens is not None and service_.write_source is not None
    service_.write_tokens.save("write-refresh-token")
    assert service_.quarantine_state() == "ready"
    service_.write_source.last_error = "revoked"
    assert service_.quarantine_state() == "reauth_needed"
    service_.write_tokens.delete()
    assert service_.quarantine_state() == "none"


def test_the_app_starts_and_stops_the_runner_and_it_finishes_an_approved_move(
    tmp_path: Path,
) -> None:
    url = f"sqlite:///{tmp_path / 'mirage.db'}"
    engine = create_engine(url)
    db.Base.metadata.create_all(engine)
    settings = Settings(_env_file=None, api_token=TOKEN, database_url=url, data_dir=tmp_path / "d")
    app = create_app(settings)
    names = lambda: {t.name for t in threading.enumerate()}  # noqa: E731
    with TestClient(app, base_url="http://127.0.0.1"):
        assert "mail-quarantine" in names()
    time.sleep(0.2)
    assert "mail-quarantine" not in names()  # stopped with the app


def test_the_runner_thread_carries_out_an_approved_move_by_itself(w: World) -> None:
    fake = FakeGmailWrite()
    fake.add(MSG_ID)
    action_id = approved(w)
    runner = MailQuarantineRunner(w.engine, {"gmail": gmail_mover(fake)}, interval=0.02)
    runner.start()
    runner.start()  # starting twice is harmless
    try:
        deadline = time.monotonic() + 10
        while w.state(action_id) != "APPLIED" and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        runner.stop()
    assert w.state(action_id) == "APPLIED"
