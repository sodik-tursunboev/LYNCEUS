"""Env-based settings (MIRAGE_ prefix, optional .env). No secrets in code; see .env.example."""

from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MIRAGE_", env_file=".env", extra="ignore")

    log_level: str = "INFO"
    database_url: SecretStr | None = None  # SecretStr: repr/logs show ********, not the password
    api_token: SecretStr | None = None  # analysis endpoints refuse to serve without one
    allowed_hosts: list[str] = ["127.0.0.1", "localhost"]  # Host header: stops DNS rebinding
    max_body_bytes: int = 65536  # raw request body, over this is HTTP 413
    max_message_bytes: int = 10 * 1024 * 1024  # the same cap for /v1/emails/analyze
    max_file_bytes: int = 16 * 1024 * 1024 - 4096  # a file body for /v1/files/analyze
    max_concurrent_parsers: int = 4  # sandboxes running at once; more get HTTP 503
    rate_limit_per_minute: int = 120
    resolve_redirects: bool = False  # operator opt-in only; needs ADR-011 signed off

    # Threat intelligence (M3, ADR-015). Everything is off until the operator names a provider.
    data_dir: Path = Path(".data")  # downloaded feeds live here
    intel_providers: str = ""  # comma-separated: phishtank,openphish,urlhaus,rdap,virustotal
    intel_deadline: float = 2.0  # seconds a caller waits for providers before moving on
    intel_email_links: bool = False  # let links found in messages reach outside services
    phishtank_key: SecretStr | None = None
    urlhaus_auth_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None

    def intel_enabled(self) -> frozenset[str]:
        return frozenset(n.strip().lower() for n in self.intel_providers.split(",") if n.strip())
