"""Env-based settings (MIRAGE_ prefix, optional .env). No secrets in code; see .env.example."""

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MIRAGE_", env_file=".env", extra="ignore")

    log_level: str = "INFO"
    database_url: SecretStr | None = None  # SecretStr: repr/logs show ********, not the password
    api_token: SecretStr | None = None  # analysis endpoints refuse to serve without one
    allowed_hosts: list[str] = ["127.0.0.1", "localhost"]  # Host header: stops DNS rebinding
    max_body_bytes: int = 65536  # raw request body, over this is HTTP 413
    rate_limit_per_minute: int = 120
    resolve_redirects: bool = False  # operator opt-in only; needs ADR-011 signed off
