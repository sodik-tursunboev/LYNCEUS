"""Bounded, redirect-free HTTP for providers.

A response is read in chunks and abandoned past `max_bytes`; redirects are never followed (a
provider URL is fixed, and a redirect is a surprise); and a failure carries a class name or a short
fixed reason, never the URL or the exception text, because some providers put an API key in the URL.
"""

import asyncio
import logging
import re
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from core.intel.base import ProviderError, ProviderRateLimited

Client = httpx.AsyncClient  # providers import this name, so httpx is imported in this file only
USER_AGENT = "lynceus-local/0.1"
# httpx logs every request URL at INFO, and some providers carry the API key in the URL path.
for _noisy in ("httpx", "httpcore"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
_RETRY_AFTER = re.compile(r"^\d{1,6}$")


class FetchError(ProviderError):
    """The request failed or the reply was unusable. `reason` is fixed text."""


@dataclass(frozen=True)
class Fetched:
    status: int
    headers: Mapping[str, str]  # lower-case names
    body: bytes


def make_client(transport: httpx.AsyncBaseTransport | None = None, timeout: float = 10.0) -> Client:
    return Client(
        transport=transport,
        follow_redirects=False,
        timeout=httpx.Timeout(timeout),
        headers={"User-Agent": USER_AGENT},
        limits=httpx.Limits(max_connections=10, max_keepalive_connections=4),
    )


async def fetch(
    client: Client,
    method: str,
    url: str,
    *,
    max_bytes: int,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
    json_body: Any = None,
    extensions: Mapping[str, Any] | None = None,
) -> Fetched:
    try:
        async with client.stream(
            method, url, headers=headers, params=params, json=json_body, extensions=extensions
        ) as response:
            declared = response.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > max_bytes:
                raise FetchError("response too large")
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body += chunk
                if len(body) > max_bytes:
                    raise FetchError("response too large")
            lowered = {k.lower(): v for k, v in response.headers.items()}
            return Fetched(response.status_code, lowered, bytes(body))
    except FetchError:
        raise
    except httpx.TimeoutException:
        raise TimeoutError from None  # a stated TIMEOUT, with nothing of the request in it
    except httpx.HTTPError as e:
        raise FetchError(type(e).__name__) from None


async def resolve_host(host: str) -> list[str]:
    """Every address a provider's server name has, so the caller can check them all (H1 A3)."""
    loop = asyncio.get_running_loop()
    answers = await loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return [str(a[4][0]) for a in answers]


def check_status(f: Fetched, *, ok: tuple[int, ...] = (200,)) -> None:
    """Map an HTTP status to the provider's stated outcome."""
    if f.status in ok:
        return
    if f.status == 429:
        after = f.headers.get("retry-after", "")
        raise ProviderRateLimited(float(after) if _RETRY_AFTER.match(after) else None)
    if 300 <= f.status < 400:
        raise FetchError("redirect not followed")
    if f.status in (401, 403):
        raise FetchError("credentials rejected")
    raise FetchError(f"http {f.status}")
