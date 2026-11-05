"""python -m core.mailbox connect | status | poll | disconnect  (Gmail, read-only; see ADR-017)."""

import argparse
import json
import sys
import webbrowser

from core.config import Settings
from core.db.store import save_email_analysis  # noqa: F401  (imported so a missing database driver shows up here)
from core.mailbox import oauth
from core.mailbox.gmail import make_client
from core.mailbox.tokens import TokenFile, TokenStoreUnavailable
from core.mailbox.wiring import build_mailbox, mailbox_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m core.mailbox")
    parser.add_argument("command", choices=["connect", "status", "poll", "disconnect"])
    args = parser.parse_args(argv)
    settings = Settings()
    tokens = TokenFile(mailbox_dir(settings))

    if args.command == "connect":
        if not settings.gmail_client_id:
            print(
                "Set MIRAGE_GMAIL_CLIENT_ID (an OAuth 'Desktop app' client of your own) first.",
                file=sys.stderr,
            )
            return 2
        secret = (
            settings.gmail_client_secret.get_secret_value()
            if settings.gmail_client_secret
            else None
        )
        try:
            token = oauth.connect(settings.gmail_client_id, secret, webbrowser.open)
            tokens.save(token)
        except oauth.OAuthError as e:
            print(f"Sign-in failed: {e.kind}", file=sys.stderr)
            return 1
        except TokenStoreUnavailable as e:
            print(f"The token could not be stored securely: {e}", file=sys.stderr)
            return 1
        print(
            "Connected (read-only). Set MIRAGE_GMAIL_ENABLED=true so the API follows the mailbox."
        )
        return 0

    if args.command == "disconnect":
        stored = tokens.load()
        revoked = oauth.revoke(make_client(), stored) if stored else False
        tokens.delete()
        (mailbox_dir(settings) / "gmail-state.json").unlink(missing_ok=True)
        print(f"Disconnected. Google revoked the token: {revoked}.")
        return 0

    settings = settings.model_copy(update={"gmail_enabled": True})
    service = build_mailbox(settings, None, None)
    if service is None:  # cannot happen: enabled above
        return 2
    if args.command == "poll":
        service.poll_once()
    print(json.dumps(service.status(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
