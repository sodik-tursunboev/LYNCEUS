"""Env-based settings (MIRAGE_ prefix, optional .env). No secrets in code; see .env.example."""

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MIRAGE_", env_file=".env", extra="ignore")

    log_level: str = "INFO"
    database_url: SecretStr | None = None  # SecretStr: repr/logs show ********, not the password
