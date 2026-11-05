"""Build the mailbox service from settings (used by the API at start-up and by the CLI)."""

from collections.abc import Callable
from functools import partial
from pathlib import Path

from sqlalchemy import Engine

from core.config import Settings
from core.contracts import EventSource
from core.db.store import save_email_analysis
from core.email.engine import EmailAnalysis, analyze_message
from core.intel.analyze import link_analyzer
from core.intel.orchestrator import Intel
from core.mailbox.gmail import GmailClient, make_client
from core.mailbox.oauth import TokenSource
from core.mailbox.service import MailboxService
from core.mailbox.tokens import TokenFile


def mailbox_dir(settings: Settings) -> Path:
    return settings.data_dir / "mailbox"


def build_mailbox(
    settings: Settings, db: Engine | None, intel: Intel | None
) -> MailboxService | None:
    """None unless turned on; a missing client id is an error, not a silent no-op."""
    if not settings.gmail_enabled:
        return None
    if not settings.gmail_client_id:
        raise RuntimeError("MIRAGE_GMAIL_CLIENT_ID is required when MIRAGE_GMAIL_ENABLED is true")
    directory = mailbox_dir(settings)
    tokens = TokenFile(directory)
    http = make_client()
    secret = (
        settings.gmail_client_secret.get_secret_value() if settings.gmail_client_secret else None
    )
    source = TokenSource(http, settings.gmail_client_id, secret, tokens.load)
    links = link_analyzer(intel) if intel is not None else None
    analyze: Callable[[bytes], EmailAnalysis] = partial(analyze_message, link_analyzer=links)

    def store(a: EmailAnalysis) -> None:
        if db is not None:
            save_email_analysis(db, a, EventSource.EMAIL)

    return MailboxService.build(
        GmailClient(source, http), source, tokens, directory, analyze, store,
        settings.gmail_lookback_days, settings.gmail_poll_seconds,
    )  # fmt: skip
