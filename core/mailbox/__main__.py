"""python -m core.mailbox connect|status|poll|disconnect [--provider gmail|outlook] [--write].

`connect --write` is the separate, explicit consent for email quarantine (M6b, ADR-017 addendum): a
wider permission with its own token file. The reading poller never uses it.
"""

import argparse
import json
import sys
import webbrowser
from collections.abc import Callable

from core.config import Settings
from core.db.store import save_email_analysis  # noqa: F401  (imported so a missing database driver shows up here)
from core.mailbox import ms_oauth, oauth
from core.mailbox.gmail import make_client
from core.mailbox.tokens import TokenFile, TokenStoreUnavailable
from core.mailbox.wiring import build_mailbox, build_outlook, mailbox_dir, token_names

CONSENT = {
    "gmail": (
        "This asks Google for the permission 'gmail.modify'. Google describes it as: read, "
        "compose and send email. That is wider than the read-only access Lynceus normally has.\n"
        "What it does with it: when a message is judged MALICIOUS and you click Approve in the "
        "console, it adds the label LYNCEUS-Quarantine and takes the message out of the inbox "
        "(Restore puts it back). It never sends, drafts, trashes or deletes anything; a built-in "
        "filter refuses those requests. The token is stored encrypted for your Windows user only."
    ),
    "outlook": (
        "This asks Microsoft for the permission 'Mail.ReadWrite' (delegated). Microsoft "
        "describes it as: create, read, update and delete email; it does not include sending. "
        "That is wider than the read-only access Lynceus normally has.\n"
        "What it does with it: when a message is judged MALICIOUS and you click Approve in the "
        "console, it moves the message to a folder named Lynceus Quarantine (Restore moves it "
        "back). It never sends, deletes or edits anything; a built-in filter refuses those "
        "requests. The token is stored encrypted for your Windows user only."
    ),
}


def main(
    argv: list[str] | None = None,
    *,
    ask: Callable[[str], str] = input,
    opener: Callable[[str], object] = webbrowser.open,
) -> int:
    parser = argparse.ArgumentParser(prog="python -m core.mailbox")
    parser.add_argument("command", choices=["connect", "status", "poll", "disconnect"])
    parser.add_argument("--provider", choices=["gmail", "outlook"], default="gmail")
    parser.add_argument(
        "--write",
        action="store_true",
        help="connect/disconnect the separate email-quarantine permission (wider than read-only)",
    )
    parser.add_argument("--yes", action="store_true", help="skip the question before --write")
    args = parser.parse_args(argv)
    settings = Settings()
    outlook = args.provider == "outlook"
    read_name, write_name = token_names(args.provider)
    read_tokens = TokenFile(mailbox_dir(settings), read_name)
    write_tokens = TokenFile(mailbox_dir(settings), write_name)
    tokens = write_tokens if args.write else read_tokens
    flag = "LYNCEUS_OUTLOOK_ENABLED" if outlook else "LYNCEUS_GMAIL_ENABLED"

    if args.command != "disconnect" and not (
        settings.outlook_client_id if outlook else settings.gmail_client_id
    ):  # connect, status and poll all need it: say what to set instead of failing with a traceback
        print(
            "Set LYNCEUS_OUTLOOK_CLIENT_ID (an Azure app registration of your own: "
            "public client, redirect http://localhost, delegated "
            f"{'Mail.ReadWrite' if args.write else 'Mail.Read'}) first."
            if outlook
            else "Set LYNCEUS_GMAIL_CLIENT_ID (an OAuth 'Desktop app' client of your own) first; "
            "the steps are in docs/KEYS.md.",
            file=sys.stderr,
        )
        return 2

    if args.command == "connect":
        if args.write and not args.yes:
            print(CONSENT[args.provider])
            try:
                answer = ask("Type YES to give this permission: ")
            except EOFError:
                answer = ""
            if answer.strip() != "YES":
                print("Cancelled. Nothing was changed.", file=sys.stderr)
                return 1
        try:
            if outlook:
                token = ms_oauth.connect(
                    settings.outlook_tenant, settings.outlook_client_id or "", opener,
                    write=args.write,
                )  # fmt: skip
            else:
                secret = (
                    settings.gmail_client_secret.get_secret_value()
                    if settings.gmail_client_secret
                    else None
                )
                token = oauth.connect(
                    settings.gmail_client_id or "", secret, opener, write=args.write
                )
            tokens.save(token)
        except oauth.OAuthError as e:
            print(f"Sign-in failed: {e.kind}", file=sys.stderr)
            return 1
        except TokenStoreUnavailable as e:
            print(f"The token could not be stored securely: {e}", file=sys.stderr)
            return 1
        if args.write:
            print(
                "Email quarantine is allowed. Lynceus proposes it for MALICIOUS mail and moves "
                "a message only after you approve it."
            )
            if read_tokens.load() is None:
                print("Lynceus also needs to read the mailbox: run connect without --write.")
        else:
            print(f"Connected (read-only). Set {flag}=true so the API follows the mailbox.")
        return 0

    if args.command == "disconnect":
        # a plain disconnect removes both permissions; `--write` removes only the wider one
        removing = [write_tokens] if args.write else [read_tokens, write_tokens]
        revoked = False
        for t in removing:
            stored = t.load()
            # Google can revoke a token over the API; for Microsoft the user removes the app's
            # access in their account (there is no revoke call we use), so only the local copy goes.
            if stored and not outlook:
                revoked = oauth.revoke(make_client(), stored) or revoked
            t.delete()
        if not args.write:
            name = "outlook" if outlook else "gmail"
            (mailbox_dir(settings) / f"{name}-state.json").unlink(missing_ok=True)
        if outlook:
            print(
                "Disconnected here. To remove the app's access, use your Microsoft "
                "account's app permissions page."
            )
        else:
            print(f"Disconnected. Google revoked the token: {revoked}.")
            if args.write:
                print(
                    "If Google also ended the read access, `status` shows reauth_needed: "
                    "run connect again."
                )
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
