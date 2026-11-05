"""The Gmail refresh token, kept encrypted for the current Windows user (DPAPI) and nowhere else.

No dependency: `ctypes` calls `CryptProtectData` / `CryptUnprotectData` directly. The token is never
written to the database, an env file, a log or git. Other users and machines cannot decrypt it;
programs running as you can, which is why `disconnect` also revokes it with Google.
"""

import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path

_ENTROPY = b"mirage.gmail.refresh-token.v1"


class TokenStoreUnavailable(Exception):
    """Not Windows, or DPAPI refused: the token is not stored; the mailbox stays disconnected."""


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]  # noqa: RUF012


def _blob(data: bytes) -> tuple[_Blob, ctypes.Array[ctypes.c_char]]:
    buf = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def _call(fn_name: str, data: bytes) -> bytes:
    if sys.platform != "win32":
        raise TokenStoreUnavailable("DPAPI is only available on Windows")
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    source, keep_source = _blob(data)
    entropy, keep_entropy = _blob(_ENTROPY)
    out = _Blob()
    fn = getattr(crypt32, fn_name)  # both calls take the same seven arguments
    ok = fn(ctypes.byref(source), None, ctypes.byref(entropy), None, None, 0, ctypes.byref(out))
    del keep_source, keep_entropy
    if not ok:
        raise TokenStoreUnavailable(f"{fn_name} failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def protect(data: bytes) -> bytes:
    return _call("CryptProtectData", data)


def unprotect(blob: bytes) -> bytes:
    return _call("CryptUnprotectData", blob)


class TokenFile:
    def __init__(self, directory: Path) -> None:
        self.path = directory / "gmail.token"

    def save(self, refresh_token: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(protect(refresh_token.encode()))
        os.replace(tmp, self.path)

    def load(self) -> str | None:
        try:
            return unprotect(self.path.read_bytes()).decode()
        except (OSError, TokenStoreUnavailable, UnicodeDecodeError):
            return (
                None  # missing, from another user, or damaged: the mailbox is simply not connected
            )

    def delete(self) -> None:
        self.path.unlink(missing_ok=True)
