"""Build the mailbox service from settings (used by the API at start-up and by the CLI)."""

import uuid
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
from core.mailbox import ms_oauth, oauth
from core.mailbox.gmail import GmailClient, make_client
from core.mailbox.graph import GraphClient
from core.mailbox.oauth import TokenSource
from core.mailbox.quarantine import MailQuarantineRunner, Mover
from core.mailbox.service import MailboxService
from core.mailbox.tokens import TokenFile
from core.mailbox.write import GmailMover, GraphMover
from core.response.service import create_pending_mail


def mailbox_dir(settings: Settings) -> Path:
    return settings.data_dir / "mailbox"


def token_names(provider: str) -> tuple[str, str]:
    """(read token file, write token file): the write permission is a separate consent (M6b)."""
    return ("outlook.token", "outlook-write.token") if provider == "outlook" else (
        "gmail.token", "gmail-write.token",
    )  # fmt: skip


def write_source(settings: Settings, provider: str, write_tokens: TokenFile) -> TokenSource | None:
    """Access tokens for the write permission only; None if the provider has no client id."""
    http = make_client()  # the sign-in endpoints only; the moves use their own narrower client
    if provider == "outlook":
        tenant, client_id = settings.outlook_tenant, settings.outlook_client_id
        if not client_id:
            return None
        return TokenSource(
            http, client_id, None, write_tokens.load,
            refresher=lambda r: ms_oauth.refresh(http, tenant, client_id, r, write=True),
            store=write_tokens.save,
        )  # fmt: skip
    gmail_id = settings.gmail_client_id
    if not gmail_id:
        return None
    secret = (
        settings.gmail_client_secret.get_secret_value() if settings.gmail_client_secret else None
    )
    return TokenSource(
        http, gmail_id, secret, write_tokens.load,
        refresher=lambda r: oauth.refresh_access(http, gmail_id, secret, r, write=True),
    )  # fmt: skip


def proposer(
    provider: str, write_tokens: TokenFile, db: Engine | None
) -> Callable[[str, uuid.UUID], None] | None:
    """What the poller calls for a MALICIOUS message: it only adds a PENDING action, and only if you
    gave the write permission. It never moves anything: that needs your click."""
    if db is None:
        return None

    def propose(message_id: str, verdict_id: uuid.UUID) -> None:
        if write_tokens.load() is None:
            return
        create_pending_mail(db, verdict_id, provider, message_id)

    return propose


def build_mailbox(
    settings: Settings, db: Engine | None, intel: Intel | None
) -> MailboxService | None:
    """None unless turned on; a missing client id is an error, not a silent no-op."""
    if not settings.gmail_enabled:
        return None
    if not settings.gmail_client_id:
        raise RuntimeError("LYNCEUS_GMAIL_CLIENT_ID is required when LYNCEUS_GMAIL_ENABLED is true")
    directory = mailbox_dir(settings)
    read_name, write_name = token_names("gmail")
    tokens, write_tokens = TokenFile(directory, read_name), TokenFile(directory, write_name)
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
        on_malicious=proposer("gmail", write_tokens, db), write_tokens=write_tokens,
        write_source=write_source(settings, "gmail", write_tokens),
    )  # fmt: skip


def build_outlook(
    settings: Settings, db: Engine | None, intel: Intel | None
) -> MailboxService | None:
    """None unless turned on; a missing client id is an error, not a silent no-op."""
    if not settings.outlook_enabled:
        return None
    if not settings.outlook_client_id:
        raise RuntimeError(
            "LYNCEUS_OUTLOOK_CLIENT_ID is required when LYNCEUS_OUTLOOK_ENABLED is true"
        )
    directory = mailbox_dir(settings)
    read_name, write_name = token_names("outlook")
    tokens, write_tokens = TokenFile(directory, read_name), TokenFile(directory, write_name)
    http = make_client()
    tenant, client_id = settings.outlook_tenant, settings.outlook_client_id
    source = TokenSource(
        http, client_id, None, tokens.load,
        refresher=lambda r: ms_oauth.refresh(http, tenant, client_id, r),
        store=tokens.save,
    )  # fmt: skip
    links = link_analyzer(intel) if intel is not None else None
    analyze: Callable[[bytes], EmailAnalysis] = partial(analyze_message, link_analyzer=links)

    def store(a: EmailAnalysis) -> None:
        if db is not None:
            save_email_analysis(db, a, EventSource.EMAIL)

    return MailboxService.build(
        GraphClient(source, http), source, tokens, directory, analyze, store,
        settings.outlook_lookback_days, settings.outlook_poll_seconds, name="outlook",
        on_malicious=proposer("outlook", write_tokens, db), write_tokens=write_tokens,
        write_source=write_source(settings, "outlook", write_tokens),
    )  # fmt: skip


def build_mailboxes(
    settings: Settings, db: Engine | None, intel: Intel | None
) -> list[MailboxService]:
    """Every provider the operator turned on."""
    built = [build_mailbox(settings, db, intel), build_outlook(settings, db, intel)]
    return [s for s in built if s is not None]


def build_quarantine(
    services: list[MailboxService], db: Engine | None, interval: float = 5.0
) -> MailQuarantineRunner | None:
    """The runner that carries out approved email moves. It exists whenever there is a database, so
    an approved action never waits forever: with no mover for its provider it ends as FAILED with a
    stated reason. A mover is built only for a provider whose write permission can be refreshed."""
    if db is None:
        return None
    movers: dict[str, Mover] = {}
    for s in services:
        if s.write_source is None:
            continue
        movers[s.name] = (
            GraphMover(s.write_source) if s.name == "outlook" else GmailMover(s.write_source)
        )
    return MailQuarantineRunner(db, movers, interval)
