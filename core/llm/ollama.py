"""A client for Ollama that can only talk to this computer.

The address must be a loopback one (127.0.0.1, ::1, localhost) over plain http with no credentials,
path or query: anything else is refused when the client is built, so a mistyped or malicious setting
can never send a macro to another machine. Responses are size-capped and redirects are never
followed (core/intel/http.py). Errors carry fixed text, never the request.
"""

import json
from typing import Any
from urllib.parse import urlsplit

from core.intel.http import Client, fetch, make_client  # httpx is imported there only

_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
_MAX_REPLY = 256 * 1024


class LocalModelError(Exception):
    """The local model could not answer. `reason` is fixed text."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def loopback_base(url: str) -> str:
    """The base address, or ValueError if it is not plain http to a loopback host."""
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    if (
        parts.scheme != "http"
        or host not in _LOOPBACK
        or parts.username
        or parts.password
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise ValueError(
            "LYNCEUS_LLM_URL must be plain http to this computer (127.0.0.1, ::1 or localhost)"
        )
    port = parts.port or 11434
    return f"http://[{host}]:{port}" if ":" in host else f"http://{host}:{port}"


class OllamaClient:
    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        timeout: float = 90.0,
        transport: Any = None,  # a test transport; never set in production
    ) -> None:
        self.base, self.model = loopback_base(base_url), model
        self.client: Client = make_client(transport, timeout=timeout)

    async def models(self) -> list[str]:
        """The model names installed locally (used by `status`)."""
        got = await self._call("GET", "/api/tags", None)
        listed = got.get("models")
        if not isinstance(listed, list):
            raise LocalModelError("unexpected reply")
        return [str(m.get("name")) for m in listed if isinstance(m, dict) and m.get("name")]

    async def generate(
        self, system: str, prompt: str, schema: dict[str, Any], images: list[str] | None = None
    ) -> str:
        """One answer, constrained to `schema`. Deterministic settings (temperature 0, a seed).
        `images` are base64 pictures for a vision model (AI1 P3), sent to this computer only."""
        body: dict[str, Any] = {
            "model": self.model, "system": system, "prompt": prompt, "stream": False,
            "format": schema, "keep_alive": "10m",
            "options": {"temperature": 0, "seed": 7, "num_ctx": 8192, "num_predict": 400},
        }  # fmt: skip
        if images:
            body["images"] = images
        got = await self._call("POST", "/api/generate", body)
        text = got.get("response")
        if not isinstance(text, str):
            raise LocalModelError("unexpected reply")
        return text

    async def _call(self, method: str, path: str, body: Any) -> dict[str, Any]:
        try:
            got = await fetch(
                self.client, method, self.base + path, max_bytes=_MAX_REPLY, json_body=body
            )
        except TimeoutError:
            raise LocalModelError("the local model took too long") from None
        except Exception:  # noqa: BLE001  (fixed text only: never the request or the reply)
            raise LocalModelError("the local model could not be reached") from None
        if got.status != 200:
            raise LocalModelError(f"the local model answered with status {got.status}")
        try:
            data = json.loads(got.body)
        except ValueError:
            raise LocalModelError("unexpected reply") from None
        if not isinstance(data, dict):
            raise LocalModelError("unexpected reply")
        return data

    async def aclose(self) -> None:
        await self.client.aclose()
