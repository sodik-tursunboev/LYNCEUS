"""Incidents: events that belong to one story, linked by keys they share (DA5 phase 3, item 2).

Every event is judged on its own; this view reads what storage already holds and joins them, so a
mail, the click on its link and the file that followed can be seen as one chain. It never edits a
verdict, an event or any other row (it only runs SELECTs) and it adds no table: an incident is
computed again from the existing ones whenever it is asked for.

Three joins, each an edge with a label that says why (nothing is linked without one):
  mail_link_is_this_url         a message's extracted link, and the URL artifact with the same
                                normalized-URL SHA-256 (the message, then the click)
  download_origin_is_this_host  a URL artifact and a file whose origin site has the same keyed host
                                tag, no further apart in time than `host_gap`
  same_file_hash                the same file SHA-256 seen again (a later download of the same file)

A key shared by more than `max_fanout` events, or a popular site, says nothing about one story (a
newsletter link, a big platform, the empty file) and links nothing. A chain whose every member is
BENIGN, or UNKNOWN or ERROR without a single signal, makes no incident: there is nothing in it to
warn about. A lone event is never an incident either.

`severity` is its own number in its own category, "chain": the noisy-OR of what the flagged members
said (their own score, or at most WEAK_CAP for a member with only weak signals) and one small
LINK_WEIGHT for every edge that touches a flagged member, capped below certainty. It is never
merged into a verdict and no verdict reads it.
"""

import math
import uuid
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Literal, NamedTuple

from pydantic import AwareDatetime, BaseModel, ConfigDict
from sqlalchemy import Engine, func, select

from core.contracts import ArtifactKind, VerdictState
from core.db import hosts
from core.db import models as db
from core.incidents.origin import popular_host

HOST_GAP = timedelta(minutes=30)  # a click and the download it led to
HASH_GAP = timedelta(days=7)  # a message and its click; one file seen again
MAX_FANOUT = 10  # a key joining more events than this is shared, not a story
WEAK_CAP = 0.3  # the most a member with only weak signals (UNKNOWN, no score) can count
LINK_WEIGHT = 0.15  # what an edge touching a flagged member adds
CHAIN_CAP = 0.95  # a chain is never certain on its own

Why = Literal["mail_link_is_this_url", "download_origin_is_this_host", "same_file_hash"]
KeyName = Literal["url_sha256", "host_tag", "file_sha256"]
LABELS: dict[Why, tuple[KeyName, str]] = {
    "mail_link_is_this_url": (
        "url_sha256",
        "the message has a link to this exact address (same URL hash)",
    ),
    "download_origin_is_this_host": (
        "host_tag",
        "the file came from the site this address is on (same site tag, close in time)",
    ),
    "same_file_hash": ("file_sha256", "the same file (same SHA-256) was seen again"),
}
_FLAGGED = (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)
_ORDER = {ArtifactKind.EMAIL: 0, ArtifactKind.URL: 1, ArtifactKind.FILE: 2}


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Member(_Frozen):
    """One event's artifact in a chain: what it is, when, and what its newest verdict said."""

    artifact_id: uuid.UUID
    event_id: uuid.UUID
    kind: ArtifactKind
    source: str
    at: AwareDatetime
    state: VerdictState | None  # None: no verdict is stored for it
    risk_score: int | None
    signals: int  # how many rules fired on it
    flagged: bool  # it carries something to warn about (see the module note)


class Edge(_Frozen):
    earlier: uuid.UUID  # artifact ids, the earlier member first
    later: uuid.UUID
    why: Why
    key: KeyName
    key_prefix: str  # the first 12 characters of the shared key: enough to see it is one key
    gap_seconds: int
    text: str


class Severity(_Frozen):
    category: Literal["chain"] = "chain"
    score: int  # 0 to 100; not a verdict's risk score
    flagged_members: int


class Incident(_Frozen):
    id: uuid.UUID  # stable: derived from the earliest member
    members: tuple[Member, ...]  # in time order
    edges: tuple[Edge, ...]
    severity: Severity


class _Row(NamedTuple):
    artifact_id: uuid.UUID
    event_id: uuid.UUID
    kind: ArtifactKind
    sha256: str
    host: str | None  # sealed; read only to ask whether the site is popular
    host_tag: str | None
    source: str
    at: datetime
    state: VerdictState | None
    risk: int | None
    signals: int
    strongest: float

    @property
    def sort_key(self) -> tuple[datetime, int, str]:
        return self.at, _ORDER[self.kind], str(self.artifact_id)


def _utc(when: datetime) -> datetime:
    return when.replace(tzinfo=UTC) if when.tzinfo is None else when.astimezone(UTC)


def _flagged(r: _Row) -> bool:
    if r.state in _FLAGGED:
        return True
    return r.state in (VerdictState.UNKNOWN, VerdictState.ERROR) and r.signals > 0


def _weight(r: _Row) -> float:
    if r.state in _FLAGGED:
        return (r.risk or 0) / 100
    return min(r.strongest, WEAK_CAP) if _flagged(r) else 0.0


def _noisy_or(weights: Iterable[float]) -> float:
    return 1 - math.prod(1 - w for w in weights)


def _load(
    engine: Engine, since: datetime, until: datetime
) -> tuple[list[_Row], list[tuple[uuid.UUID, str]]]:
    """Artifacts in the window with their newest verdict, and each message's link hashes."""
    a, e, v, d, x = db.Artifact, db.Event, db.Verdict, db.Detection, db.ExtractedUrl
    inside = (e.observed_at >= since, e.observed_at <= until)
    with engine.connect() as c:
        artifacts = c.execute(
            select(a.id, a.event_id, a.kind, a.sha256, a.host, a.host_tag, e.source, e.observed_at)
            .join(e, e.id == a.event_id)
            .where(*inside)
        ).all()
        newest: dict[uuid.UUID, tuple[uuid.UUID, str, int | None]] = {}
        for artifact_id, verdict_id, state, risk in c.execute(
            select(v.artifact_id, v.id, v.state, v.risk_score)
            .join(a, a.id == v.artifact_id)
            .join(e, e.id == a.event_id)
            .where(*inside)
            .order_by(v.created_at, v.id)
        ):
            newest[artifact_id] = (verdict_id, state, risk)  # the last one in order wins
        fired = {
            verdict_id: (int(n), float(top or 0.0))
            for verdict_id, n, top in c.execute(
                select(d.verdict_id, func.count(), func.max(d.weight))
                .join(a, a.id == d.artifact_id)
                .join(e, e.id == a.event_id)
                .where(*inside, d.verdict_id.is_not(None))
                .group_by(d.verdict_id)
            )
        }
        links = [
            (row.artifact_id, row.url_sha256)
            for row in c.execute(
                select(x.artifact_id, x.url_sha256)
                .join(a, a.id == x.artifact_id)
                .join(e, e.id == a.event_id)
                .where(*inside, a.kind == ArtifactKind.EMAIL.value)
            )
        ]
    rows: list[_Row] = []
    for art in artifacts:
        latest = newest.get(art.id)
        count, top = fired.get(latest[0], (0, 0.0)) if latest else (0, 0.0)
        rows.append(
            _Row(
                art.id, art.event_id, ArtifactKind(art.kind), art.sha256, art.host, art.host_tag,
                art.source, _utc(art.observed_at), VerdictState(latest[1]) if latest else None,
                latest[2] if latest else None, count, top,
            )
        )  # fmt: skip
    return rows, links


def _edge(a: _Row, b: _Row, why: Why, key: str) -> Edge:
    first, second = sorted((a, b), key=lambda r: r.sort_key)
    name, text = LABELS[why]
    return Edge(
        earlier=first.artifact_id, later=second.artifact_id, why=why, key=name,
        key_prefix=key[:12], gap_seconds=int((second.at - first.at).total_seconds()), text=text,
    )  # fmt: skip


def _by(rows: Iterable[_Row], key: Callable[[_Row], str | None]) -> dict[str, list[_Row]]:
    groups: dict[str, list[_Row]] = defaultdict(list)
    for r in rows:
        if (value := key(r)) is not None:
            groups[value].append(r)
    return groups


def _edges(
    rows: Sequence[_Row],
    links: Sequence[tuple[uuid.UUID, str]],
    host_gap: timedelta,
    hash_gap: timedelta,
    max_fanout: int,
) -> list[Edge]:
    found: dict[tuple[uuid.UUID, uuid.UUID, str], Edge] = {}

    def add(a: _Row, b: _Row, why: Why, key: str) -> None:
        edge = _edge(a, b, why, key)
        found[(edge.earlier, edge.later, why)] = edge

    by_id = {r.artifact_id: r for r in rows}
    urls = [r for r in rows if r.kind is ArtifactKind.URL]
    files = [r for r in rows if r.kind is ArtifactKind.FILE]

    # a message's link, and the click on that same address
    messages: dict[str, set[uuid.UUID]] = defaultdict(set)
    for artifact_id, digest in links:
        messages[digest].add(artifact_id)
    clicks = _by(urls, lambda r: r.sha256)
    for digest, sent in messages.items():
        hit = clicks.get(digest, [])
        if not hit or len(sent) + len(hit) > max_fanout:
            continue
        for artifact_id in sent:
            for click in hit:
                if abs(click.at - by_id[artifact_id].at) <= hash_gap:
                    add(by_id[artifact_id], click, "mail_link_is_this_url", digest)

    # a click, and a download from the same site a little later (or a little earlier: the page's
    # verdict can be stored after the download was reported)
    downloads = _by(files, lambda r: r.host_tag)
    asked: dict[str, bool] = {}
    for tag, pages in _by(urls, lambda r: r.host_tag).items():
        got = downloads.get(tag, [])
        if not got or len(pages) + len(got) > max_fanout:
            continue
        pairs = [(p, f) for p in pages for f in got if abs(f.at - p.at) <= host_gap]
        if not pairs:
            continue
        if tag not in asked:
            asked[tag] = popular_host(hosts.reveal(pairs[0][0].host))
        if not asked[tag]:
            for page, download in pairs:
                add(page, download, "download_origin_is_this_host", tag)

    # the same file again
    for same_file, same in _by(files, lambda r: r.sha256).items():
        if 1 < len(same) <= max_fanout:
            ordered = sorted(same, key=lambda r: r.sort_key)
            for before, after in zip(ordered, ordered[1:], strict=False):
                if after.at - before.at <= hash_gap:
                    add(before, after, "same_file_hash", same_file)
    return list(found.values())


def _components(edges: Iterable[Edge]) -> list[set[uuid.UUID]]:
    parent: dict[uuid.UUID, uuid.UUID] = {}

    def find(x: uuid.UUID) -> uuid.UUID:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for edge in edges:
        parent[find(edge.earlier)] = find(edge.later)
    groups: dict[uuid.UUID, set[uuid.UUID]] = defaultdict(set)
    for node in list(parent):
        groups[find(node)].add(node)
    return list(groups.values())


def _severity(members: Sequence[_Row], edges: Sequence[Edge]) -> Severity:
    """The chain's own number (category "chain"): see the module note."""
    flagged = {r.artifact_id: r for r in members if _flagged(r)}
    weights = [_weight(r) for r in flagged.values()]
    weights += [LINK_WEIGHT for e in edges if e.earlier in flagged or e.later in flagged]
    score = round(100 * min(_noisy_or(weights), CHAIN_CAP))
    return Severity(score=score, flagged_members=len(flagged))


def find_incidents(
    engine: Engine,
    since: datetime,
    until: datetime,
    *,
    host_gap: timedelta = HOST_GAP,
    hash_gap: timedelta = HASH_GAP,
    max_fanout: int = MAX_FANOUT,
) -> list[Incident]:
    """The incidents among the events observed from `since` to `until` (both inclusive), the most
    severe first. Read-only. A chain that continues past the window shows only what is inside it."""
    rows, links = _load(engine, _utc(since), _utc(until))
    edges = _edges(rows, links, host_gap, hash_gap, max_fanout)
    by_id = {r.artifact_id: r for r in rows}
    out: list[Incident] = []
    for ids in _components(edges):
        members = sorted((by_id[i] for i in ids), key=lambda r: r.sort_key)
        if not any(_flagged(r) for r in members):
            continue  # nothing in it to warn about
        mine = sorted(
            (e for e in edges if e.earlier in ids), key=lambda e: (by_id[e.later].sort_key, e.why)
        )
        out.append(
            Incident(
                id=uuid.uuid5(uuid.NAMESPACE_OID, f"lynceus.incident:{members[0].artifact_id}"),
                members=tuple(
                    Member(
                        artifact_id=r.artifact_id, event_id=r.event_id, kind=r.kind,
                        source=r.source, at=r.at, state=r.state, risk_score=r.risk,
                        signals=r.signals, flagged=_flagged(r),
                    )
                    for r in members
                ),
                edges=tuple(mine),
                severity=_severity(members, mine),
            )
        )  # fmt: skip
    return sorted(out, key=lambda i: (-i.severity.score, i.members[0].at, str(i.id)))
