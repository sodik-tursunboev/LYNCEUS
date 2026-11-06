"""Env-based settings (MIRAGE_ prefix, optional .env). No secrets in code; see .env.example."""

from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MIRAGE_", env_file=".env", extra="ignore")

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
                "MIRAGE_API_TOKEN is too short or still the placeholder: use at least 16 random "
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
    intel_providers: str = ""  # comma-separated: phishtank,openphish,urlhaus,rdap,virustotal
    intel_deadline: float = 2.0  # seconds a caller waits for providers before moving on
    intel_email_links: bool = False  # let links found in messages reach outside services
    phishtank_key: SecretStr | None = None
    urlhaus_auth_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None

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
