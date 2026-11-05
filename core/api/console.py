"""Serve the built console (console/dist) at /console/, same origin as the API (M6, D1, D8).

The page and script hold no secrets; every API call still needs the token. Responses under /console
carry a strict Content-Security-Policy (own files only, no inline script or style, no framing, no
other origins to talk to), `nosniff`, `no-store` and no referrer.
"""

from pathlib import Path

from fastapi import FastAPI
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
    "object-src 'none'"
)
HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"cache-control", b"no-store"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
]


class ConsoleHeaders:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith("/console"):
            await self.app(scope, receive, send)
            return

        async def wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                have = {k.lower() for k, _ in message.get("headers", [])}
                message["headers"] = [
                    *message.get("headers", []),
                    *[h for h in HEADERS if h[0] not in have],
                ]
            await send(message)

        await self.app(scope, receive, wrapped)


def mount_console(app: FastAPI, directory: Path) -> bool:
    """Only if the console has been built; the API works without it."""
    if not (directory / "index.html").is_file():
        return False
    app.add_middleware(ConsoleHeaders)
    app.mount("/console", StaticFiles(directory=directory, html=True), name="console")
    return True
