"""Archive inspection by listing. Standard library only; runs inside the sandbox on hostile input.

Nothing is extracted or written to disk. Entry data is read only to learn its type (a few KB) or,
for an archive inside an archive, up to MAX_NESTED_BYTES; every byte read is charged to one budget,
so a bomb is reported (declared sizes, ratios, limits) and never expanded. It reports facts about
names, types and sizes; the host's rules decide what is dangerous.
"""

import bz2
import io
import lzma
import re
import tarfile
import zipfile
import zlib
from typing import Any

from filetype import detect_magic
from limits import (
    MAX_ARCHIVE_BUDGET,
    MAX_ARCHIVE_DEPTH,
    MAX_ENTRIES,
    MAX_EXTS,
    MAX_NAME_CHARS,
    MAX_NESTED_BYTES,
    MAX_SNIFF,
)

_EXT = re.compile(r"^[a-z0-9]{1,10}$")
_DRIVE = re.compile(r"^[A-Za-z]:")
_SPLIT = re.compile(r"[\\/]")
_ARCHIVES = {"zip", "gz", "bz2", "xz", "tar"}
_MAX_PAIRS = 10


class _State:
    def __init__(self) -> None:
        self.entries = 0
        self.total = 0
        self.ratio = 0.0
        self.encrypted = 0
        self.traversal = 0
        self.nested = 0
        self.depth = 0
        self.exts: dict[str, int] = {}
        self.magics: dict[str, int] = {}
        self.pairs: list[list[str]] = []
        self.limits: set[str] = set()
        self.left: int = MAX_ARCHIVE_BUDGET

    def charge(self, n: int) -> None:
        self.left -= n
        if self.left < 0:
            self.limits.add("decompressed_bytes")

    @property
    def spent(self) -> bool:
        return self.left < 0

    def entry(self, name: str, size: int, packed: int | None, encrypted: bool) -> None:
        self.entries += 1
        self.total = min(self.total + max(size, 0), 1 << 50)
        if packed is not None and size > 0:
            self.ratio = min(max(self.ratio, size / max(packed, 1)), 1e12)
        name = name[:MAX_NAME_CHARS]
        parts = _SPLIT.split(name)
        if ".." in parts or name.startswith(("/", "\\")) or _DRIVE.match(name) or "\x00" in name:
            self.traversal += 1
        if encrypted:
            self.encrypted += 1
        pieces = parts[-1].strip().lower().split(".")
        if len(pieces) < 2:
            return
        ext = pieces[-1].strip()
        key = ext if _EXT.match(ext) else "(odd)"
        if key in self.exts or len(self.exts) < MAX_EXTS:
            self.exts[key] = self.exts.get(key, 0) + 1
        inner = pieces[-2].strip()
        pair = [inner, ext]
        if (
            len(pieces) >= 3
            and _EXT.match(inner)
            and _EXT.match(ext)
            and pair not in self.pairs
            and len(self.pairs) < _MAX_PAIRS
        ):
            self.pairs.append(pair)

    def sniff(self, head: bytes) -> str | None:
        magic: str | None = detect_magic(head)
        if magic:
            self.magics[magic] = self.magics.get(magic, 0) + 1
        return magic


def _safe_read(reader: Any, n: int, st: _State) -> bytes:
    try:
        data = bytes(reader.read(n))
    except (MemoryError, RecursionError):
        raise
    except Exception:  # noqa: BLE001  (a hostile archive may raise anything; it just reads as empty)
        return b""
    st.charge(len(data))
    return data


def _open_nested(st: _State, depth: int, size: int, opener: Any) -> None:
    if depth + 1 > MAX_ARCHIVE_DEPTH:
        st.limits.add("depth")
        return
    if size > MAX_NESTED_BYTES or size > st.left:
        st.limits.add("nested_size")
        return
    try:
        with opener() as f:
            inner = _safe_read(f, MAX_NESTED_BYTES + 1, st)
    except (MemoryError, RecursionError):
        raise
    except Exception:  # noqa: BLE001
        return
    if len(inner) > MAX_NESTED_BYTES:
        st.limits.add("nested_size")
        return
    st.nested += 1
    _walk(inner, depth + 1, st)


def _zip(data: bytes, depth: int, st: _State) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (MemoryError, RecursionError):
        raise
    except Exception:  # noqa: BLE001
        st.limits.add("bad_archive")
        return
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            st.limits.add("entries")
            infos = infos[:MAX_ENTRIES]
        for info in infos:
            if st.spent:
                break
            encrypted = bool(info.flag_bits & 0x1)
            st.entry(info.filename, info.file_size, info.compress_size, encrypted)
            if info.is_dir() or encrypted or info.file_size == 0:
                continue
            try:
                with zf.open(info) as f:
                    head = _safe_read(f, MAX_SNIFF, st)
            except (MemoryError, RecursionError):
                raise
            except Exception:  # noqa: BLE001, S112
                continue
            magic = st.sniff(head)
            if magic in _ARCHIVES:
                _open_nested(st, depth, info.file_size, lambda i=info: zf.open(i))


def _tar(data: bytes, depth: int, st: _State) -> None:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")  # noqa: SIM115
    except (MemoryError, RecursionError):
        raise
    except Exception:  # noqa: BLE001
        st.limits.add("bad_archive")
        return
    with tf:
        try:
            for i, member in enumerate(tf):
                if st.spent:
                    break
                if i >= MAX_ENTRIES:
                    st.limits.add("entries")
                    break
                st.entry(member.name, member.size, None, False)
                if (member.issym() or member.islnk()) and member.linkname:
                    target = _SPLIT.split(member.linkname[:MAX_NAME_CHARS])
                    if ".." in target or member.linkname.startswith(("/", "\\")):
                        st.traversal += 1
                if not member.isfile() or member.size == 0:
                    continue
                stream = tf.extractfile(member)
                head = _safe_read(stream, MAX_SNIFF, st) if stream else b""
                magic = st.sniff(head)
                if magic in _ARCHIVES:
                    _open_nested(st, depth, member.size, lambda m=member: tf.extractfile(m))
        except (MemoryError, RecursionError):
            raise
        except Exception:  # noqa: BLE001  (truncated or corrupt tar)
            st.limits.add("bad_archive")


def _decompress(data: bytes, magic: str, st: _State) -> bytes | None:
    """At most the remaining budget; more than that is a bomb and is reported, not read."""
    cap = max(st.left, 0)
    try:
        if magic == "gz":
            out = zlib.decompressobj(31).decompress(data, cap + 1)
        elif magic == "bz2":
            out = bz2.BZ2Decompressor().decompress(data, cap + 1)
        else:
            out = lzma.LZMADecompressor().decompress(data, cap + 1)
    except (MemoryError, RecursionError):
        raise
    except Exception:  # noqa: BLE001
        st.limits.add("bad_archive")
        return None
    if len(out) > cap:
        st.limits.add("decompressed_bytes")
        out = out[:cap]
    st.charge(len(out))
    return out


def _walk(data: bytes, depth: int, st: _State) -> str | None:
    st.depth = max(st.depth, depth)
    magic: str | None = detect_magic(data[:600])
    if magic == "zip":
        _zip(data, depth, st)
    elif magic == "tar":
        _tar(data, depth, st)
    elif magic in ("gz", "bz2", "xz"):
        inner = _decompress(data, magic, st)
        if inner is not None:
            inner_magic = detect_magic(inner[:600])
            if inner_magic == "tar":
                _tar(inner, depth, st)
            else:
                st.entry("(stream)", len(inner), len(data), False)
                st.sniff(inner[:MAX_SNIFF])
                if inner_magic in _ARCHIVES:
                    if depth + 1 > MAX_ARCHIVE_DEPTH:
                        st.limits.add("depth")
                    else:
                        st.nested += 1
                        _walk(inner, depth + 1, st)
    else:
        st.limits.add("bad_archive")
    return magic


def scan_archive(data: bytes) -> dict[str, Any]:
    st = _State()
    fmt = _walk(data, 0, st)
    return {
        "kind": "archive",
        "format": fmt if fmt in _ARCHIVES else "zip",
        "entries": st.entries,
        "total_size": st.total,
        "ratio": round(st.ratio, 1),
        "encrypted": st.encrypted,
        "traversal": st.traversal,
        "nested": st.nested,
        "depth": st.depth,
        "exts": dict(sorted(st.exts.items())),
        "magics": dict(sorted(st.magics.items())),
        "double_pairs": st.pairs,
        "limits": sorted(st.limits),
    }
