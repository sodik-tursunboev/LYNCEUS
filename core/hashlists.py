"""Known-bad file hashes: exact matches against lists held on THIS machine (M8).

A file's hash is computed here, from the bytes the core already has, and looked up in plain text
lists in `<data dir>/hashes/`: one hash per line (SHA-256, SHA-1 or MD5, any case; `#` starts a
comment; a CSV export such as MalwareBazaar's works as it is, every hash-shaped word counts).
Nothing is sent anywhere: this is a lookup in a set. A hit names the list it came from, so the
verdict can say what vouches for it. The harmless EICAR antivirus test file is built in so the whole
path can be tried safely.

An exact hash match is the one kind of evidence strong enough to call a file malicious on its own
(see `certain` in rules/email/scoring.toml): the same bytes were already judged malicious by someone
whose list you chose to load. A list is only as good as its source; an entry that is wrong makes a
wrong verdict, which is why every hit carries its list's name.
"""

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from rules.email import HashHit

_TOKEN = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])"
)
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,40}$")
_ALGORITHM = {64: "sha256", 40: "sha1", 32: "md5"}
BUILTIN = "eicar-test-file"
_EICAR = {  # the 68-byte standard antivirus test string
    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # pragma: allowlist secret  # noqa: E501
    "sha1": "3395856ce81f2b7382dee72602f798b642f14140",  # pragma: allowlist secret
    "md5": "44d88612fea8a8f36de82e1278abb02f",  # pragma: allowlist secret
}  # public hashes of a public test file, not secrets
MAX_LINES_PER_LIST = 5_000_000


def digests(data: bytes) -> dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324  (a lookup key for lists, not security)
        "md5": hashlib.md5(data).hexdigest(),  # noqa: S324
    }


def tokens(text: str) -> Iterable[str]:
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        for m in _TOKEN.finditer(line):
            yield m.group(0).lower()


@dataclass(frozen=True)
class ListInfo:
    name: str
    hashes: int


class HashStore:
    """Hash sets loaded from a folder of lists; reloaded when a list changes."""

    def __init__(self, directory: Path | None) -> None:
        self.directory = directory
        self._sets: dict[str, dict[str, str]] = {a: {} for a in _ALGORITHM.values()}
        self._signature: tuple[tuple[str, int, int], ...] | None = None
        self.lists: list[ListInfo] = []

    def _files(self) -> list[Path]:
        if self.directory is None or not self.directory.is_dir():
            return []
        return sorted(
            p for p in self.directory.glob("*") if p.suffix in (".txt", ".csv") and p.is_file()
        )

    def _refresh(self) -> None:
        files = self._files()
        signature = tuple((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in files)
        if signature == self._signature:
            return
        sets: dict[str, dict[str, str]] = {a: {} for a in _ALGORITHM.values()}
        for algorithm, value in _EICAR.items():
            sets[algorithm][value] = BUILTIN
        lists = [ListInfo(BUILTIN, len(_EICAR))]
        for path in files:
            name = path.stem.lower()
            if not _NAME.match(name):
                continue
            count = 0
            try:
                with path.open(encoding="utf-8", errors="replace") as handle:
                    for number, line in enumerate(handle):
                        if number >= MAX_LINES_PER_LIST:
                            break
                        for token in tokens(line):
                            sets[_ALGORITHM[len(token)]].setdefault(token, name)
                            count += 1
            except OSError:
                continue  # an unreadable list is skipped; the others still work
            lists.append(ListInfo(name, count))
        self._sets, self._signature, self.lists = sets, signature, lists

    def lookup(self, found: dict[str, str]) -> list[tuple[str, str]]:
        """[(algorithm, list name)] for every one of these digests that is on a list."""
        self._refresh()
        return [(a, self._sets[a][v]) for a, v in found.items() if v in self._sets.get(a, {})]

    def status(self) -> list[ListInfo]:
        self._refresh()
        return list(self.lists)


_store = HashStore(None)


def configure(directory: Path | None) -> None:
    """Point the lookup at a folder of lists (the API does this once at start-up)."""
    global _store  # noqa: PLW0603
    _store = HashStore(directory)


def current() -> HashStore:
    return _store


def hits_for_file(part: str, found: dict[str, str]) -> list[HashHit]:
    return [HashHit(part, a, source, "file") for a, source in _store.lookup(found)]


def hits_for_members(part: str, members: Iterable[str]) -> list[HashHit]:
    """SHA-256 hits for the entries of an archive (the sandbox hashes them)."""
    out: list[HashHit] = []
    for sha in members:
        out += [HashHit(part, a, s, "archive entry") for a, s in _store.lookup({"sha256": sha})]
    return out


def digests_of_file(path: Path) -> dict[str, str]:
    """SHA-256, SHA-1 and MD5 of a file on disk, read in blocks (any size)."""
    hashers = {
        "sha256": hashlib.sha256(),
        "sha1": hashlib.sha1(),  # noqa: S324  (a lookup key for lists, not security)
        "md5": hashlib.md5(),  # noqa: S324
    }
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            for h in hashers.values():
                h.update(block)
    return {name: h.hexdigest() for name, h in hashers.items()}


def write_list(directory: Path, name: str, found: Iterable[str]) -> int:
    """Write `<directory>/<name>.txt` from hash-shaped words only, one per line, lowercase, no
    duplicates. Replaced atomically. Returns how many distinct hashes were written."""
    name = name.lower()
    if not _NAME.match(name):
        raise ValueError("a list name is letters, digits, dots, dashes and underscores")
    seen: dict[str, None] = {}
    for token in found:
        seen.setdefault(token)
        if len(seen) >= MAX_LINES_PER_LIST:
            break
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{name}.txt"
    temporary = target.with_suffix(".tmp")
    temporary.write_text("# hashes\n" + "\n".join(seen) + "\n", encoding="utf-8")
    temporary.replace(target)
    return len(seen)


def read_list(directory: Path, name: str) -> set[str]:
    try:
        text = (directory / f"{name.lower()}.txt").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    return set(tokens(text))


def import_list(source: Path, name: str, directory: Path) -> int:
    """Copy the hashes out of `source` into `<directory>/<name>.txt`. Only hash-shaped words are
    kept, so a list with other columns or odd content cannot carry anything else in."""
    with source.open(encoding="utf-8", errors="replace") as handle:
        lines = (line for number, line in enumerate(handle) if number < MAX_LINES_PER_LIST)
        return write_list(directory, name, (t for line in lines for t in tokens(line)))
