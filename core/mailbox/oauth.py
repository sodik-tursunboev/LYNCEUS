"""Signing in to Google as a desktop app: authorization code + PKCE over a loopback address (M5).

Steps (Google's "OAuth 2.0 for Mobile & Desktop Apps"): make a verifier and its S256
challenge, open the
consent page in the browser with a `state`, receive the redirect on `http://127.0.0.1:<port>` (one
listener, this machine only, closed after the answer), exchange the code at the token endpoint.
The only scope asked for is read-only Gmail; if Google reports anything else being granted, nothing
is stored.
"""

import base64
import hashlib
import http.server
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from core.mailbox.gmail import SCOPE, SCOPE_WRITE, GmailError, make_client

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105  (a public endpoint, not a secret)
REVOKE_URL = "https://oauth2.googleapis.com/revoke"


class OAuthError(Exception):
    """A sign-in step failed: denied, state, timeout, scope, token, revoked or network."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


@dataclass(frozen=True)
class Tokens:
    access_token: str
    expires_at: float
    refresh_token: str | None


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    return verifier, challenge.decode()


def authorize_url(
    client_id: str, redirect_uri: str, challenge: str, state: str, scope: str = SCOPE
) -> str:
    query = {
        "client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code",
        "scope": scope, "code_challenge": challenge, "code_challenge_method": "S256",
        "state": state,
    }  # fmt: skip
    return AUTH_URL + "?" + urlencode(query)


class _Handler(http.server.BaseHTTPRequestHandler):
    server: "_Listener"
    timeout = 3  # seconds: an idle connection (a speculative browser socket) must not block sign-in

    def do_GET(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        host = self.headers.get("Host", "")
        ok = url.path == "/" and host.split(":")[0] in self.server.hosts
        if (
            ok
            and secrets.compare_digest(q.get("state", "").encode(), self.server.state.encode())
            and ("code" in q or "error" in q)
        ):
            self.server.result = q
            body, code = b"MIRAGE is connected. You can close this tab.", 200
        else:
            self.server.strays += 1
            body, code = b"Not the expected sign-in response.", 400
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:  # the query holds the code: never log it
        return


class _Listener(http.server.HTTPServer):
    def __init__(
        self, state: str, hosts: tuple[str, ...] = ("127.0.0.1",), redirect_host: str = "127.0.0.1"
    ) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)  # always bound to loopback only
        self.hosts = (
            hosts  # the Host header names accepted (Microsoft wants "localhost" in the URI)
        )
        self.redirect_host = redirect_host
        self.state = state
        self.result: dict[str, str] | None = None
        self.strays = 0
        self.timeout = 1.0

    @property
    def redirect_uri(self) -> str:
        return f"http://{self.redirect_host}:{self.server_address[1]}"


def wait_for_code(
    listener: _Listener, timeout: float, clock: Callable[[], float] = time.monotonic
) -> str:
    deadline = clock() + timeout
    while listener.result is None and listener.strays < 5 and clock() < deadline:
        listener.handle_request()
    result = listener.result
    if result is None:
        raise OAuthError("timeout" if listener.strays < 5 else "state")
    if "error" in result:
        raise OAuthError("denied")
    return result["code"]


def exchange_code(
    http: httpx.Client, client_id: str, client_secret: str | None, code: str, verifier: str,
    redirect_uri: str, now: Callable[[], float] = time.time, *, write: bool = False,
) -> Tokens:  # fmt: skip
    form = {
        "grant_type": "authorization_code", "code": code, "client_id": client_id,
        "redirect_uri": redirect_uri, "code_verifier": verifier,
    }  # fmt: skip
    if client_secret:
        form["client_secret"] = client_secret
    return _token_request(
        http, form, now, require_refresh=True,
        scope_ok=google_write_scope_ok if write else _google_scope_ok,
    )  # fmt: skip


def refresh_access(
    http: httpx.Client, client_id: str, client_secret: str | None, refresh_token: str,
    now: Callable[[], float] = time.time, *, write: bool = False,
) -> Tokens:  # fmt: skip
    form = {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id}
    if client_secret:
        form["client_secret"] = client_secret
    return _token_request(
        http, form, now, require_refresh=False,
        scope_ok=google_write_refresh_ok if write else _google_scope_ok,
    )  # fmt: skip


def revoke(http: httpx.Client, token: str) -> bool:
    try:
        return http.post(REVOKE_URL, data={"token": token}).status_code == 200
    except httpx.HTTPError:
        return False


def _google_scope_ok(scope: object) -> bool:
    return scope is None or set(str(scope).split()) == {SCOPE}


_WRITE_EXTRAS = frozenset({SCOPE, "openid", "email", "profile"})


def google_write_scope_ok(scope: object) -> bool:
    """The write consent (M6b): gmail.modify must be granted and nothing wider. Sending
    (gmail.send, gmail.compose), full access (mail.google.com), settings and any other scope are
    refused, and so is a missing scope list."""
    if not isinstance(scope, str):
        return False
    granted = set(scope.split())
    return SCOPE_WRITE in granted and granted <= ({SCOPE_WRITE} | _WRITE_EXTRAS)


def google_write_refresh_ok(scope: object) -> bool:
    """A refresh answer may leave the scope out; if it names scopes they must still pass."""
    return scope is None or google_write_scope_ok(scope)


def _token_request(
    http: httpx.Client,
    form: dict[str, str],
    now: Callable[[], float],
    *,
    require_refresh: bool,
    url: str = TOKEN_URL,
    scope_ok: Callable[[object], bool] = _google_scope_ok,
) -> Tokens:
    try:
        r = http.post(url, data=form)
    except httpx.HTTPError:
        raise OAuthError("network") from None
    if r.status_code == 400 and b"invalid_grant" in r.content[:2000]:
        raise OAuthError(
            "revoked"
        )  # revoked, expired (7 days in "Testing"), or the password changed
    if r.status_code != 200 or len(r.content) > 16384:
        raise OAuthError("token")
    try:
        body = r.json()
        access, expires = str(body["access_token"]), float(body["expires_in"])
        refresh = body.get("refresh_token")
        scope = body.get("scope")
    except (ValueError, KeyError, TypeError):
        raise OAuthError("token") from None
    if require_refresh and not isinstance(refresh, str):
        raise OAuthError("token")
    if not scope_ok(scope):
        raise OAuthError("scope")  # asked for read-only mail; anything else is refused
    return Tokens(access, now() + expires, refresh if isinstance(refresh, str) else None)


class TokenSource:
    """A current access token, refreshed a minute before it runs out."""

    def __init__(
        self, http: httpx.Client, client_id: str, client_secret: str | None,
        refresh_token: Callable[[], str | None], now: Callable[[], float] = time.time,
        refresher: Callable[[str], Tokens] | None = None,
        store: Callable[[str], None] | None = None,
    ) -> None:  # fmt: skip
        self._http, self._id, self._secret, self._refresh = (
            http,
            client_id,
            client_secret,
            refresh_token,
        )
        self._now = now
        self._refresher = refresher  # None: Google's refresh
        self._store = store  # called with a NEW refresh token (Microsoft rotates it on every use)
        self._tokens: Tokens | None = None
        self._lock = threading.Lock()
        self.last_error: str | None = None  # "revoked" means the user has to connect again

    def __call__(self) -> str:
        with self._lock:
            if self._tokens is None or self._tokens.expires_at - 60 < self._now():
                try:
                    refresh = self._refresh()
                    if refresh is None:
                        raise OAuthError("revoked")
                    self._tokens = (
                        self._refresher(refresh)
                        if self._refresher
                        else refresh_access(self._http, self._id, self._secret, refresh, self._now)
                    )
                    if self._store and self._tokens.refresh_token not in (None, refresh):
                        self._store(self._tokens.refresh_token)
                except OAuthError as e:
                    self.last_error = e.kind
                    raise GmailError("auth") from None
                self.last_error = None
            return self._tokens.access_token


def connect(
    client_id: str, client_secret: str | None, open_browser: Callable[[str], object],
    http: httpx.Client | None = None, timeout: float = 300.0, *, write: bool = False,
) -> str:  # fmt: skip
    """Run the whole sign-in and return the refresh token (the caller stores it). With `write` it
    asks for the separate write permission (M6b) instead of the read-only one."""
    http = http or make_client()
    verifier, challenge = pkce()
    state = secrets.token_urlsafe(24)
    listener = _Listener(state)
    try:
        scope = SCOPE_WRITE if write else SCOPE
        open_browser(authorize_url(client_id, listener.redirect_uri, challenge, state, scope))
        code = wait_for_code(listener, timeout)
        tokens = exchange_code(
            http, client_id, client_secret, code, verifier, listener.redirect_uri, write=write
        )
    finally:
        listener.server_close()
    if tokens.refresh_token is None:
        raise OAuthError("token")
    return tokens.refresh_token
