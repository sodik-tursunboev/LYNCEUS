"""Env-based settings (LYNCEUS_ prefix, optional .env). No secrets in code; see .env.example.

The product was called MIRAGE before it was Lynceus. The old MIRAGE_ names are still read, after the
new ones (a LYNCEUS_ value always wins), so an existing .env and an older agent keep working; the
start-up log names which old variables are still in use (names only, never values).
"""

import os
from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

LEGACY_PREFIX = "MIRAGE_"


def legacy_env_names(env_file: str | os.PathLike[str] | None = ".env") -> list[str]:
    """The old-style variable names in use, from the environment and the .env file."""
    found = {k for k in os.environ if k.upper().startswith(LEGACY_PREFIX)}
    if env_file:
        try:
            for line in Path(env_file).read_text(encoding="utf-8", errors="replace").splitlines():
                name = line.strip().split("=", 1)[0].strip()
                if name.upper().startswith(LEGACY_PREFIX) and "=" in line:
                    found.add(name)
        except OSError:
            pass
    return sorted(found)


class DpapiSource(PydanticBaseSettingsSource):
    """Secrets stored with `python -m core.secrets set` (DPAPI, H1 A4). Only secret fields."""

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        return None, field_name, False  # unused: __call__ answers for every field at once

    def __call__(self) -> dict[str, Any]:
        if os.name != "nt":
            return {}
        from core import secrets

        return {k: v for k, v in secrets.load().items() if k in SECRET_FIELDS}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LYNCEUS_", env_file=".env", extra="ignore")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        legacy: list[PydanticBaseSettingsSource] = [
            EnvSettingsSource(settings_cls, env_prefix=LEGACY_PREFIX)
        ]
        if isinstance(dotenv_settings, DotEnvSettingsSource):
            legacy.append(
                DotEnvSettingsSource(
                    settings_cls,
                    env_file=dotenv_settings.env_file,
                    env_file_encoding=dotenv_settings.env_file_encoding,
                    env_prefix=LEGACY_PREFIX,
                )
            )
        # the environment first, then the DPAPI store (H1 A4), then the plain .env file
        dpapi = (
            [DpapiSource(settings_cls)]
            if isinstance(dotenv_settings, DotEnvSettingsSource)
            and (dotenv_settings.env_file is not None)
            else []
        )  # fmt: skip  (`_env_file=None`, as in tests, reads no file of any kind)
        return (init_settings, env_settings, *dpapi, dotenv_settings, *legacy, file_secret_settings)

    log_level: str = "INFO"

    @field_validator("api_token", mode="after")
    @classmethod
    def _token_is_not_a_placeholder(cls, value: SecretStr | None) -> SecretStr | None:
        """A guessable token is no token: refuse the .env.example placeholder and short ones."""
        if value is None or not value.get_secret_value().strip():
            return None  # unset or empty: the analysis routes refuse to serve, as before
        text = value.get_secret_value().strip()
        if len(text) < 16 or text.upper().startswith("CHANGE_ME"):
            raise ValueError(
                "LYNCEUS_API_TOKEN is too short or still the placeholder: use at least 16 random "
                "characters (the installer generates one)"
            )
        return value

    database_url: SecretStr | None = None  # SecretStr: repr/logs show ********, not the password
    api_token: SecretStr | None = None  # analysis endpoints refuse to serve without one
    allowed_hosts: list[str] = ["127.0.0.1", "localhost"]  # Host header: stops DNS rebinding
    max_body_bytes: int = 65536  # raw request body, over this is HTTP 413
    max_message_bytes: int = 10 * 1024 * 1024  # the same cap for /v1/emails/analyze
    max_file_bytes: int = 16 * 1024 * 1024 - 4096  # a file body for /v1/files/analyze
    max_concurrent_parsers: int = 4  # sandboxes running at once; more get HTTP 503
    rate_limit_per_minute: int = 120  # files, overrides and everything else
    url_rate_limit_per_minute: int = (
        1200  # the browser's URL checks: their own lane, so a page that
    )
    # bounces through many URLs cannot use up the budget the agent's file checks need
    resolve_redirects: bool = False  # operator opt-in only; needs ADR-011 signed off

    # Threat intelligence (M3, ADR-015). Everything is off until the operator names a provider.
    data_dir: Path = Path(".data")  # downloaded feeds live here
    intel_providers: str = (
        ""  # comma-separated: phishtank,openphish,urlhaus,rdap,virustotal,urlscan
    )
    intel_deadline: float = 2.0  # seconds a caller waits for providers before moving on
    intel_email_links: bool = False  # let links found in messages reach outside services
    phishtank_key: SecretStr | None = None
    urlhaus_auth_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None
    urlscan_api_key: SecretStr | None = None
    # DA2: ask VirusTotal about the SHA-256 of a downloaded program-like file (the hash only leaves;
    # needs virustotal_api_key; off until the owner turns it on, docs/milestones/DA2.md)
    file_reputation: bool = False

    # A local language model that reads the recovered code of a macro and gives ADVICE (ADR-023).
    # Off until enabled. It only talks to this computer (a loopback address; anything else stops
    # start-up), and its answer can raise suspicion but never lower a verdict or decide one alone.
    llm_review: bool = False
    llm_url: str = "http://127.0.0.1:11434"  # Ollama's default address
    llm_model: str = "llama3.2:3b"
    # seconds the review of one verdict may take in all, waiting included, before the verdict goes
    # out without it (the agent waits 90 s for an answer, and the analysis itself comes first)
    llm_timeout: float = 45.0

    # Page detonation (D1, ADR-025): POST /v1/urls/detonate opens the page in the sandboxed browser
    # container, from this computer's internet connection. Off until enabled; only on request (the
    # Analyze page's button), never for the browser extension or mail by itself.
    detonation: bool = False
    detonation_per_minute: int = 6
    # DA1 P3: open risky links without a click, from the browser extension and/or mail ("browser",
    # "mail", "browser,mail"; empty = off). Needs `detonation` on and Docker running; see
    # core/detonate/auto.py for what is opened and how it is bounded.
    auto_detonation: str = ""

    # The brain (AI1, docs/milestones/AI1.md): a local model reads opened pages, their screenshots,
    # their scripts and mail, and only findings that code can check count. Off until enabled; it
    # uses LYNCEUS_LLM_URL (this computer only). Keep it off while another job needs the same
    # graphics card.
    brain: bool = False
    brain_model: str = "gemma3:4b"  # reads text and images
    brain_timeout: float = 60.0  # seconds for one verdict's questions, waiting included

    console_dir: Path = Path(
        "console/dist"
    )  # the built console, served at /console/ if it exists (M6)

    # Live mailbox (M5, ADR-017). Off until the operator connects a Google account.
    gmail_enabled: bool = False
    gmail_client_id: str | None = None  # an OAuth "Desktop app" client of the operator's own
    gmail_client_secret: SecretStr | None = None
    gmail_lookback_days: int = 2  # on first connect, and after a lost position
    gmail_poll_seconds: int = 60

    # Live Outlook / Microsoft 365 mailbox (M5b): the same rules as Gmail (read-only, off).
    outlook_enabled: bool = False
    outlook_client_id: str | None = (
        None  # an Azure app registration of the operator's own (public client)
    )
    outlook_tenant: str = Field(default="common", pattern=r"^[A-Za-z0-9.\-]{1,64}$")
    outlook_lookback_days: int = 2
    outlook_poll_seconds: int = 60

    def intel_enabled(self) -> frozenset[str]:
        return frozenset(n.strip().lower() for n in self.intel_providers.split(",") if n.strip())


# every setting that holds a secret (typed SecretStr): what the DPAPI store may hold
SECRET_FIELDS = frozenset(
    name for name, f in Settings.model_fields.items() if "SecretStr" in str(f.annotation)
)


def plaintext_secrets(env_file: str | os.PathLike[str] | None = ".env") -> list[str]:
    """Secret settings still written with a value in plain text in .env (names only, H1 A4)."""
    if not env_file:
        return []
    try:
        lines = Path(env_file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    found = set()
    for line in lines:
        name, sep, value = line.strip().partition("=")
        bare = name.strip().upper().removeprefix("LYNCEUS_").removeprefix(LEGACY_PREFIX).lower()
        if sep and value.strip() and not name.strip().startswith("#") and bare in SECRET_FIELDS:
            found.add(bare)
    return sorted(found)
