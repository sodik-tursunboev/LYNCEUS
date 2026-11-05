"""python -m core.mailbox connect|status|poll|disconnect [--provider gmail|outlook] (ADR-017)."""

import argparse
import json
import sys
import webbrowser

from core.config import Settings
from core.db.store import save_email_analysis  # noqa: F401  (imported so a missing database driver shows up here)
from core.mailbox import ms_oauth, oauth
from core.mailbox.gmail import make_client
from core.mailbox.tokens import TokenFile, TokenStoreUnavailable
from core.mailbox.wiring import build_mailbox, build_outlook, mailbox_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m core.mailbox")
    parser.add_argument("command", choices=["connect", "status", "poll", "disconnect"])
    parser.add_argument("--provider", choices=["gmail", "outlook"], default="gmail")
    args = parser.parse_args(argv)
    settings = Settings()
    outlook = args.provider == "outlook"
    tokens = TokenFile(mailbox_dir(settings), "outlook.token" if outlook else "gmail.token")
    flag = "MIRAGE_OUTLOOK_ENABLED" if outlook else "MIRAGE_GMAIL_ENABLED"

    if args.command == "connect":
        try:
            if outlook:
                if not settings.outlook_client_id:
                    print(
                        "Set MIRAGE_OUTLOOK_CLIENT_ID (an Azure app registration of your own: "
                        "public client, redirect http://localhost, delegated Mail.Read) first.",
                        file=sys.stderr,
                    )
                    return 2
                token = ms_oauth.connect(
                    settings.outlook_tenant, settings.outlook_client_id, webbrowser.open
                )
            else:
                if not settings.gmail_client_id:
                    print(
                        "Set MIRAGE_GMAIL_CLIENT_ID (an OAuth 'Desktop app' client of "
                        "your own) first.",
                        file=sys.stderr,
                    )
                    return 2
                secret = (
                    settings.gmail_client_secret.get_secret_value()
                    if settings.gmail_client_secret
                    else None
                )
                token = oauth.connect(settings.gmail_client_id, secret, webbrowser.open)
            tokens.save(token)
        except oauth.OAuthError as e:
            print(f"Sign-in failed: {e.kind}", file=sys.stderr)
            return 1
        except TokenStoreUnavailable as e:
            print(f"The token could not be stored securely: {e}", file=sys.stderr)
            return 1
        print(f"Connected (read-only). Set {flag}=true so the API follows the mailbox.")
        return 0

    if args.command == "disconnect":
        stored = tokens.load()
        # Google can revoke a token over the API; for Microsoft the user removes the app's access
        # in their account (there is no revoke call we use), so only the local copy goes.
        revoked = oauth.revoke(make_client(), stored) if stored and not outlook else False
        tokens.delete()
        name = "outlook" if outlook else "gmail"
        (mailbox_dir(settings) / f"{name}-state.json").unlink(missing_ok=True)
        if outlook:
            print(
                "Disconnected here. To remove the app's access, use your Microsoft "
                "account's app permissions page."
            )
        else:
            print(f"Disconnected. Google revoked the token: {revoked}.")
        return 0

    update = {"outlook_enabled": True} if outlook else {"gmail_enabled": True}
    settings = settings.model_copy(update=update)
    service = (
        build_outlook(settings, None, None) if outlook else build_mailbox(settings, None, None)
    )
    if service is None:  # cannot happen: enabled above
        return 2
    if args.command == "poll":
        service.poll_once()
    print(json.dumps(service.status(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
