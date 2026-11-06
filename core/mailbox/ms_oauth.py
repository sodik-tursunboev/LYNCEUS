"""Signing in to Microsoft as a desktop app (M5b): authorization code + PKCE, loopback redirect.

Differences from Google's flow, from Microsoft's documentation: the endpoints take a tenant
(`common` works for personal and work accounts when the registration allows it), a public
client sends
no secret, `offline_access` is what yields a refresh token, the registered redirect is
`http://localhost` (the port is ignored when matching, so ours is free), and **the refresh token is
replaced on every use**, so the new one must be stored each time (the token source does).

Read-only is enforced by checking what was actually granted: only `Mail.Read` plus the basic sign-in
scopes are accepted; any other scope, above all one that can write or send, is refused and nothing
stored.
"""

import re
import secrets
import time
from collections.abc import Callable
from urllib.parse import urlencode

import httpx

from core.mailbox.gmail import make_client
from core.mailbox.oauth import (
    OAuthError,
    Tokens,
    _Listener,
    _token_request,
    pkce,
    wait_for_code,
)

SCOPES = "Mail.Read offline_access"
SCOPES_WRITE = "Mail.ReadWrite offline_access"  # M6b: separate, explicit consent
ALLOWED_SCOPES = frozenset(
    {"mail.read", "offline_access", "openid", "profile", "email", "user.read"}
)
ALLOWED_WRITE_SCOPES = ALLOWED_SCOPES | {"mail.readwrite"}
_TENANT = re.compile(r"^[A-Za-z0-9.\-]{1,64}$")
_PREFIX = "https://graph.microsoft.com/"


def check_tenant(tenant: str) -> str:
    """`common`, `organizations`, `consumers` or a tenant id; nothing that could change the URL."""
    if not _TENANT.match(tenant):
        raise OAuthError("token")
    return tenant


def authorize_url(
    tenant: str, client_id: str, redirect_uri: str, challenge: str, state: str,
    scopes: str = SCOPES,
) -> str:  # fmt: skip
    query = {
        "client_id": client_id, "response_type": "code", "redirect_uri": redirect_uri,
        "response_mode": "query", "scope": scopes, "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }  # fmt: skip
    return (
        f"https://login.microsoftonline.com/{check_tenant(tenant)}/oauth2/v2.0/authorize?"
        + urlencode(query)
    )


def token_url(tenant: str) -> str:
    return f"https://login.microsoftonline.com/{check_tenant(tenant)}/oauth2/v2.0/token"


def scope_ok(scope: object) -> bool:
    """Mail.Read granted and nothing beyond the sign-in basics; an absent list is refused."""
    if not isinstance(scope, str):
        return False
    granted = {s.lower().removeprefix(_PREFIX.lower()) for s in scope.split()}
    return "mail.read" in granted and granted <= ALLOWED_SCOPES


def scope_ok_write(scope: object) -> bool:
    """The write consent (M6b): Mail.ReadWrite granted and nothing that sends or reaches files
    (Mail.Send, Files.*, ...). An absent list is refused."""
    if not isinstance(scope, str):
        return False
    granted = {s.lower().removeprefix(_PREFIX.lower()) for s in scope.split()}
    return "mail.readwrite" in granted and granted <= ALLOWED_WRITE_SCOPES


def exchange_code(
    http: httpx.Client, tenant: str, client_id: str, code: str, verifier: str, redirect_uri: str,
    now: Callable[[], float] = time.time, *, write: bool = False,
) -> Tokens:  # fmt: skip
    form = {
        "grant_type": "authorization_code", "code": code, "client_id": client_id,
        "redirect_uri": redirect_uri, "code_verifier": verifier,
        "scope": SCOPES_WRITE if write else SCOPES,
    }  # fmt: skip
    return _token_request(
        http, form, now, require_refresh=True, url=token_url(tenant),
        scope_ok=scope_ok_write if write else scope_ok,
    )  # fmt: skip


def refresh(
    http: httpx.Client, tenant: str, client_id: str, refresh_token: str,
    now: Callable[[], float] = time.time, *, write: bool = False,
) -> Tokens:  # fmt: skip
    form = {
        "grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id,
        "scope": SCOPES_WRITE if write else SCOPES,
    }  # fmt: skip
    return _token_request(
        http, form, now, require_refresh=False, url=token_url(tenant),
        scope_ok=scope_ok_write if write else scope_ok,
    )  # fmt: skip


def connect(
    tenant: str, client_id: str, open_browser: Callable[[str], object],
    http: httpx.Client | None = None, timeout: float = 300.0, *, write: bool = False,
) -> str:  # fmt: skip
    """Run the whole sign-in and return the refresh token (the caller stores it). With `write` it
    asks for the separate write permission (M6b) instead of the read-only one."""
    check_tenant(tenant)
    http = http or make_client()
    verifier, challenge = pkce()
    state = secrets.token_urlsafe(24)
    listener = _Listener(state, hosts=("localhost", "127.0.0.1"), redirect_host="localhost")
    try:
        scopes = SCOPES_WRITE if write else SCOPES
        open_browser(
            authorize_url(tenant, client_id, listener.redirect_uri, challenge, state, scopes)
        )
        code = wait_for_code(listener, timeout)
        tokens = exchange_code(
            http, tenant, client_id, code, verifier, listener.redirect_uri, write=write
        )
    finally:
        listener.server_close()
    if tokens.refresh_token is None:
        raise OAuthError("token")
    return tokens.refresh_token
