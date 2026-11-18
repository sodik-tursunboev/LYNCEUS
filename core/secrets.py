"""Secrets at rest, protected by Windows (DPAPI) instead of plain text in .env (H1 A4).

    python -m core.secrets set NAME        store one value, typed hidden or read from standard input
    python -m core.secrets list            the names stored (never the values)
    python -m core.secrets remove NAME
    python -m core.secrets plaintext       the secret names still written in plain text in .env

NAME is a setting's name without the prefix, e.g. `api_token`, `database_url`, `virustotal_api_key`.
Values are encrypted with CryptProtectData for the current Windows user: only this user on this
computer can read them back (another account, a copied disk or a backup cannot). A process running
as you still can; that is the same trust as before, minus the readable file. The store is a JSON
file next to .env (`secrets.dpapi.json`, git-ignored), read by the settings after the environment
and before .env, so a value here replaces one in .env.

Run `set` from a normal PowerShell, not from a terminal inside a packaged app (ADR-024): DPAPI may
create a new key in the user profile, and such an app writes the profile into a private copy.
"""

import base64
import ctypes
import getpass
import json
import os
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Any

STORE = Path(os.environ.get("LYNCEUS_SECRETS_FILE", "secrets.dpapi.json"))
_ENTROPY = b"lynceus-secrets-v1"  # binds a blob to this use: another app's DPAPI blob will not open


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> tuple[_Blob, Any]:
    buf = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def _call(name: str, data: bytes) -> bytes:
    if sys.platform != "win32":
        raise OSError("DPAPI needs Windows")
    crypt32, kernel32 = ctypes.WinDLL("crypt32"), ctypes.WinDLL("kernel32")
    source, keep = _blob(data)
    entropy, keep2 = _blob(_ENTROPY)
    out = _Blob()
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN: never show a prompt
    fn = getattr(crypt32, name)
    if not fn(
        ctypes.byref(source), None, ctypes.byref(entropy), None, None, flags, ctypes.byref(out)
    ):
        raise OSError(f"{name} failed ({ctypes.GetLastError()})")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)
        del keep, keep2


def protect(data: bytes) -> bytes:
    return _call("CryptProtectData", data)


def unprotect(blob: bytes) -> bytes:
    return _call("CryptUnprotectData", blob)


def _read(store: Path) -> dict[str, str]:
    try:
        raw = json.loads(store.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    found = raw.get("secrets") if isinstance(raw, dict) else None
    return {k: v for k, v in (found or {}).items() if isinstance(k, str) and isinstance(v, str)}


def _write(store: Path, secrets: dict[str, str]) -> None:
    tmp = store.with_name(store.name + ".new")
    tmp.write_text(json.dumps({"v": 1, "secrets": secrets}, indent=1, sort_keys=True), "utf-8")
    tmp.replace(store)


def load(store: Path | None = None) -> dict[str, str]:
    """name -> plain value, for every entry this user can open. One that cannot be opened (made by
    another account or another computer) is left out, never guessed."""
    out = {}
    for name, b64 in _read(store or STORE).items():
        try:
            out[name] = unprotect(base64.b64decode(b64)).decode("utf-8")
        except (OSError, ValueError):
            continue
    return out


def put(name: str, value: str, store: Path | None = None) -> None:
    store = store or STORE
    secrets = _read(store)
    secrets[name] = base64.b64encode(protect(value.encode("utf-8"))).decode("ascii")
    _write(store, secrets)


def remove(name: str, store: Path | None = None) -> bool:
    store = store or STORE
    secrets = _read(store)
    if secrets.pop(name, None) is None:
        return False
    _write(store, secrets)
    return True


def main(argv: list[str] | None = None) -> int:
    import argparse

    from core.config import SECRET_FIELDS, plaintext_secrets

    ap = argparse.ArgumentParser(
        prog="python -m core.secrets", description=__doc__.split("\n\n")[0]
    )
    sub = ap.add_subparsers(dest="command", required=True)
    for cmd in ("set", "remove"):
        sub.add_parser(cmd).add_argument("name", choices=sorted(SECRET_FIELDS))
    sub.add_parser("list")
    sub.add_parser("plaintext")
    args = ap.parse_args(argv)
    if args.command == "set":
        # at a terminal the value is typed hidden (no echo, nothing in shell history);
        # a script pipes it in
        typed = (
            getpass.getpass(f"{args.name} (hidden, then Enter): ") if sys.stdin.isatty() else None
        )
        # a byte-order mark is what Windows PowerShell puts in front of piped text; it is not part
        # of a key, and kept it would make every request with that key fail
        value = (typed if typed is not None else sys.stdin.readline()).lstrip("﻿").strip()
        if not value:
            print("no value given", file=sys.stderr)
            return 2
        put(args.name, value)
        print(f"stored {args.name} (DPAPI, this Windows user only) in {STORE}")
        return 0
    if args.command == "remove":
        print("removed" if remove(args.name) else "not stored")
        return 0
    if args.command == "list":
        for name in sorted(load()):
            print(name)
        return 0
    names = plaintext_secrets()
    for name in names:
        print(
            f"{name} is in plain text in .env: python -m core.secrets set {name}, "
            "then delete it there"
        )
    return 1 if names else 0


if __name__ == "__main__":
    raise SystemExit(main())
