"""DA5 phase 3, item 2: does the incident view find every scripted chain and invent none?

    python -m eval.incidents check [--docs docs/eval]

It writes scripted timelines into a throwaway SQLite database the way the core stores events (one
`store._write` per event, so hosts are sealed and tagged and message links become extracted URLs),
in a shuffled insertion order, and asks `core.incidents.find_incidents` for the incidents:
  chains   mail link, click, download, in eight different orders and shapes (the click stored before
           the mail, the download before the page's verdict, two pages on one site, a file seen
           again, a message with many links, an unflagged mail ahead of a flagged click, a link
           clicked twice): each must come back as exactly one incident holding exactly its members,
           with exactly its edges, every edge labelled;
  benign   chains whose members are BENIGN, or UNKNOWN and ERROR without a signal, linked by the
           same keys: no incident may come back;
  decoys   events close in time but unrelated, a site outside the time gap, a popular site, a shared
           site, a different address on a site, the same file after more than the gap: no link.
No row may change. `check` prints INCIDENT GATE MET only when all of that holds (otherwise what
failed, and a non-zero exit) and writes `docs/eval/incidents.md`, counts only.
"""

import argparse
import hashlib
import random
import tempfile
import uuid
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, select

from core.contracts import (
    ArtifactKind,
    Confidence,
    EventSource,
    ResponseAction,
    Signal,
    Verdict,
    VerdictState,
)
from core.db import models as db
from core.db import store
from core.email.engine import ExtractedRef
from core.incidents import LABELS, Incident, find_incidents
from core.incidents.chains import Why
from core.urls import popular
from core.urls.parse import ParsedUrl, parse_url

SEED = "lynceus-da5-incidents"
START = datetime(2026, 11, 2, 8, 0, tzinfo=UTC)
SPACING = timedelta(hours=3)  # between the starts of two timelines
DAY = 86_400
POPULAR = "popular-platform.test"  # a registered domain on the (pinned) popular list
SCORES = {
    VerdictState.MALICIOUS: 90, VerdictState.SUSPICIOUS: 60, VerdictState.BENIGN: 0,
}  # fmt: skip
WEAK = (("email.dangerous_attachment", 0.3),)
SIGN = (("url.combosquat", 0.6),)
Rules = tuple[tuple[str, float], ...]


class Seeder:
    """Writes events the way the core does, at a chosen time with a chosen verdict."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def _write(
        self, kind: ArtifactKind, at: datetime, digest: str, host: str | None,
        state: VerdictState, rules: Rules, source: EventSource, refs: Sequence[ExtractedRef] = (),
    ) -> uuid.UUID:  # fmt: skip
        artifact_id = uuid.uuid4()
        verdict = Verdict(
            artifact_id=artifact_id, state=state, risk_score=SCORES.get(state),
            confidence=Confidence.MEDIUM,
            signals=[
                Signal(rule_id=r, category="seed", weight=w, description="a seeded signal")
                for r, w in rules
            ],
            evidence_ids=[], provider_results=[], recommended_response=ResponseAction.NONE,
            applied_response=ResponseAction.NONE, explanation="seeded", engine_version="seed",
            ruleset_version="seed", created_at=at,
        )  # fmt: skip
        store._write(self.engine, verdict, [], kind, digest, host, source, refs)
        return artifact_id

    def mail(
        self, at: datetime, links: Sequence[str] = (), state: VerdictState = VerdictState.UNKNOWN,
        rules: Rules = (),
    ) -> uuid.UUID:  # fmt: skip
        refs: list[ExtractedRef] = []
        for url in links:
            parsed = parse_url(url)
            assert isinstance(parsed, ParsedUrl), url  # noqa: S101  (a seeding mistake)
            refs.append(ExtractedRef(
                url_sha256=parsed.url_sha256, host=parsed.host,
                registered_domain=parsed.registered_domain, position=len(refs),
            ))  # fmt: skip
        digest = hashlib.sha256(f"mail:{uuid.uuid4()}".encode()).hexdigest()
        return self._write(
            ArtifactKind.EMAIL, at, digest, None, state, rules, EventSource.EMAIL, refs
        )

    def click(
        self, at: datetime, url: str, state: VerdictState = VerdictState.UNKNOWN, rules: Rules = ()
    ) -> uuid.UUID:  # fmt: skip
        parsed = parse_url(url)
        assert isinstance(parsed, ParsedUrl), url  # noqa: S101  (a seeding mistake)
        return self._write(
            ArtifactKind.URL, at, parsed.url_sha256, parsed.host, state, rules, EventSource.BROWSER
        )

    def download(
        self, at: datetime, host: str, name: str, state: VerdictState = VerdictState.UNKNOWN,
        rules: Rules = (),
    ) -> uuid.UUID:  # fmt: skip
        digest = hashlib.sha256(f"file:{name}".encode()).hexdigest()
        return self._write(ArtifactKind.FILE, at, digest, host, state, rules, EventSource.AGENT)


@dataclass(frozen=True)
class Step:
    label: str
    kind: ArtifactKind
    at: int  # seconds after the timeline's start
    state: VerdictState = VerdictState.UNKNOWN
    rules: Rules = ()
    target: str = ""  # the address clicked, or the site a file came from
    links: tuple[str, ...] = ()  # a message's links
    file: str = ""  # a name standing for the file's bytes


@dataclass(frozen=True)
class Timeline:
    name: str
    steps: tuple[Step, ...]
    edges: tuple[tuple[str, str, Why], ...] = ()  # expected, by step label (a chain only)


U, S, M, B, E = (
    VerdictState.UNKNOWN, VerdictState.SUSPICIOUS, VerdictState.MALICIOUS, VerdictState.BENIGN,
    VerdictState.ERROR,
)  # fmt: skip


def mail(label: str, at: int, *links: str, state: VerdictState = U, rules: Rules = ()) -> Step:
    return Step(label, ArtifactKind.EMAIL, at, state, rules, links=links)


def click(label: str, at: int, url: str, state: VerdictState = U, rules: Rules = ()) -> Step:
    return Step(label, ArtifactKind.URL, at, state, rules, target=url)


def download(
    label: str, at: int, host: str, file: str, state: VerdictState = U, rules: Rules = ()
) -> Step:
    return Step(label, ArtifactKind.FILE, at, state, rules, target=host, file=file)


def chains() -> list[Timeline]:
    """Mail link, click, download: eight orders and shapes."""

    def site(n: int) -> str:
        return f"chain{n}.site.test"

    def at(n: int, path: str = "") -> str:
        return f"https://{site(n)}/{path}"

    link: Why = "mail_link_is_this_url"
    host: Why = "download_origin_is_this_host"
    return [
        Timeline(
            "canonical order",
            (
                mail("m", 0, at(1, "a"), state=S, rules=SIGN),
                click("c", 120, at(1, "a"), S, SIGN),
                download("f", 150, site(1), "setup-1", U, WEAK),
            ),
            (("m", "c", link), ("c", "f", host)),
        ),  # fmt: skip
        Timeline(
            "click stored before the mail",
            (
                click("c", 0, at(2, "a"), M, SIGN),
                download("f", 60, site(2), "setup-2", S, SIGN),
                mail("m", 400, at(2, "a"), rules=WEAK),
            ),
            (("m", "c", link), ("c", "f", host)),
        ),  # fmt: skip
        Timeline(
            "download before the page's verdict",
            (
                mail("m", 0, at(3, "a")),
                download("f", 7200, site(3), "setup-3", U, WEAK),
                click("c", 7220, at(3, "a"), M, SIGN),
            ),
            (("m", "c", link), ("c", "f", host)),
        ),  # fmt: skip
        Timeline(
            "two pages on one site",
            (
                mail("m", 0, at(4, "a"), state=S, rules=SIGN),
                click("a", 30, at(4, "a"), S, SIGN),
                click("b", 90, at(4, "b")),
                download("f", 100, site(4), "setup-4", S, SIGN),
            ),
            (("m", "a", link), ("a", "f", host), ("b", "f", host)),
        ),  # fmt: skip
        Timeline(
            "the same file again",
            (
                mail("m", 0, at(5, "a"), state=S, rules=SIGN),
                click("c", 60, at(5, "a"), S, SIGN),
                download("f1", 100, site(5), "setup-5", S, SIGN),
                download("f2", 2 * DAY, "elsewhere5.site.test", "setup-5", S, SIGN),
            ),
            (("m", "c", link), ("c", "f1", host), ("f1", "f2", "same_file_hash")),
        ),  # fmt: skip
        Timeline(
            "a message with many links, one clicked",
            (
                mail(
                    "m",
                    0,
                    at(6, "x"),
                    at(6, "y"),
                    "https://other6.site.test/z",
                    "https://more6.site.test/",
                    state=S,
                    rules=SIGN,
                ),
                click("c", 90, at(6, "y"), S, SIGN),
                download("f", 130, site(6), "setup-6", U, WEAK),
            ),
            (("m", "c", link), ("c", "f", host)),
        ),  # fmt: skip
        Timeline(
            "only the click is flagged",
            (
                mail("m", 0, at(7, "a")),
                click("c", 200, at(7, "a"), M, SIGN),
                download("f", 240, site(7), "setup-7"),
            ),
            (("m", "c", link), ("c", "f", host)),
        ),  # fmt: skip
        Timeline(
            "a link clicked twice",
            (
                mail("m", 0, at(8, "a"), state=S, rules=SIGN),
                click("c1", 60, at(8, "a"), S, SIGN),
                click("c2", 90, at(8, "a"), S, SIGN),
                download("f", 100, site(8), "setup-8", S, SIGN),
            ),
            (("m", "c1", link), ("m", "c2", link), ("c1", "f", host), ("c2", "f", host)),
        ),  # fmt: skip
    ]


def benign() -> list[Timeline]:
    """Linked by the same keys, and still nothing to warn about."""

    def at(n: int, path: str = "") -> str:
        return f"https://benign{n}.site.test/{path}"

    return [
        Timeline(
            "benign mail and click, unknown file",
            (
                mail("m", 0, at(1, "a"), state=B),
                click("c", 60, at(1, "a"), B),
                download("f", 90, "benign1.site.test", "ok-1"),
            ),
        ),  # fmt: skip
        Timeline(
            "all unknown, no signal",
            (
                mail("m", 0, at(2, "a")),
                click("c", 60, at(2, "a")),
                download("f", 90, "benign2.site.test", "ok-2"),
            ),
        ),  # fmt: skip
        Timeline(
            "the same unknown file twice",
            (
                click("c", 0, at(3, "a")),
                download("f1", 40, "benign3.site.test", "ok-3"),
                download("f2", DAY, "benign3.site.test", "ok-3"),
            ),
        ),  # fmt: skip
        Timeline(
            "a file that could not be read",
            (
                mail("m", 0, at(4, "a"), state=B),
                click("c", 60, at(4, "a"), B),
                download("f", 90, "benign4.site.test", "ok-4", E),
            ),
        ),  # fmt: skip
        Timeline(
            "benign with weak signals",
            (
                mail("m", 0, at(5, "a"), state=B, rules=WEAK),
                click("c", 60, at(5, "a"), B, WEAK),
                download("f", 90, "benign5.site.test", "ok-5", B, WEAK),
            ),
        ),  # fmt: skip
        Timeline(
            "three benign clicks and a download",
            (
                mail("m", 0, at(6, "a"), at(6, "b"), at(6, "c"), state=B),
                click("a", 20, at(6, "a"), B),
                click("b", 40, at(6, "b"), B),
                click("c", 60, at(6, "c"), B),
                download("f", 80, "benign6.site.test", "ok-6"),
            ),
        ),  # fmt: skip
    ]


def decoys() -> list[Timeline]:
    """Each is flagged enough to be an incident if it were linked; none may be."""
    return [
        Timeline(
            "same site, outside the time gap",
            (
                click("c", 0, "https://decoy1.site.test/a", S, SIGN),
                download("f", 2 * 3600, "decoy1.site.test", "decoy-1", U, WEAK),
            ),
        ),  # fmt: skip
        Timeline(
            "a popular site",
            (
                click("c", 0, f"https://files.{POPULAR}/a", S, SIGN),
                download("f", 60, f"files.{POPULAR}", "decoy-2", U, WEAK),
            ),
        ),  # fmt: skip
        Timeline(
            "a site shared by many events",
            (
                *(
                    click(
                        f"c{i}",
                        i * 5,
                        f"https://decoy3.site.test/p{i}",
                        S if i == 0 else U,
                        SIGN if i == 0 else (),
                    )
                    for i in range(12)
                ),
                download("f", 90, "decoy3.site.test", "decoy-3", U, WEAK),
            ),
        ),  # fmt: skip
        Timeline(
            "unrelated events close in time",
            (
                mail("m", 0, "https://decoy4.site.test/a", state=S, rules=SIGN),
                click("c", 10, "https://other4.site.test/a", S, SIGN),
                download("f", 20, "third4.site.test", "decoy-4", U, WEAK),
            ),
        ),  # fmt: skip
        Timeline(
            "another address on the same site",
            (
                mail("m", 0, "https://decoy5.site.test/a", state=S, rules=SIGN),
                click("c", 30, "https://decoy5.site.test/b", S, SIGN),
            ),
        ),  # fmt: skip
        Timeline(
            "the same file after more than the gap",
            (
                download("f1", 0, "first6.site.test", "decoy-6", S, SIGN),
                download("f2", 10 * DAY, "second6.site.test", "decoy-6", S, SIGN),
            ),
        ),  # fmt: skip
    ]


def snapshot(engine: Engine) -> dict[str, list[tuple[Any, ...]]]:
    """Every row of every table, to show that reading incidents changed nothing."""
    with engine.connect() as c:
        return {
            t.name: sorted((tuple(r) for r in c.execute(select(t)).all()), key=repr)
            for t in db.Base.metadata.sorted_tables
        }


def seed(
    engine: Engine, timelines: Iterable[tuple[str, int, Timeline]]
) -> dict[tuple[str, int, str], uuid.UUID]:
    """Write every step of every timeline in a shuffled order; ids by (group, index, label)."""
    seeder = Seeder(engine)
    writes = [
        (group, n, step, START + n * SPACING + timedelta(seconds=step.at))
        for group, n, t in timelines
        for step in t.steps
    ]
    random.Random(SEED).shuffle(writes)  # noqa: S311  (a reproducible order, not a secret)
    ids: dict[tuple[str, int, str], uuid.UUID] = {}
    for group, n, step, when in writes:
        if step.kind is ArtifactKind.EMAIL:
            made = seeder.mail(when, step.links, step.state, step.rules)
        elif step.kind is ArtifactKind.URL:
            made = seeder.click(when, step.target, step.state, step.rules)
        else:
            made = seeder.download(when, step.target, step.file, step.state, step.rules)
        ids[(group, n, step.label)] = made
    return ids


def evaluate(engine: Engine) -> tuple[list[str], dict[str, int]]:
    """Seed everything into `engine`, read the incidents, and say what is wrong (and the counts)."""
    groups = [("chain", c) for c in chains()] + [("benign", b) for b in benign()]
    groups += [("decoy", d) for d in decoys()]
    numbered = [(g, n, t) for n, (g, t) in enumerate(groups)]
    ids = seed(engine, numbered)
    before = snapshot(engine)
    window = (START - timedelta(days=1), START + 40 * SPACING + timedelta(days=30))
    found = find_incidents(engine, *window)
    failures: list[str] = []
    counts = Counter[str]()
    counts["reads_that_changed_a_row"] = int(snapshot(engine) != before)
    if counts["reads_that_changed_a_row"]:
        failures.append("reading incidents changed a stored row")
    if [i.model_dump() for i in find_incidents(engine, *window)] != [i.model_dump() for i in found]:
        failures.append("a second read gave different incidents")

    def holding(members: set[uuid.UUID]) -> list[Incident]:
        return [i for i in found if members & {m.artifact_id for m in i.members}]

    for group, n, t in numbered:
        mine = {ids[(group, n, s.label)] for s in t.steps}
        hit = holding(mine)
        if group != "chain":
            counts[f"{group}_timelines"] += 1
            counts[f"{group}_incidents"] += len(hit)
            if hit:
                failures.append(f"{group} timeline {t.name!r} made {len(hit)} incident(s)")
            continue
        counts["chains"] += 1
        if len(hit) != 1 or {m.artifact_id for m in hit[0].members} != mine:
            failures.append(f"chain {t.name!r} was not found as one incident with its members")
            continue
        counts["chains_found"] += 1
        want = {(frozenset({ids[(group, n, a)], ids[(group, n, b)]}), why) for a, b, why in t.edges}
        got = {(frozenset({e.earlier, e.later}), e.why) for e in hit[0].edges}
        counts["edges_expected"] += len(want)
        counts["edges_found"] += len(got & want)
        counts["edges_extra"] += len(got - want)
        if got != want:
            failures.append(f"chain {t.name!r} has the wrong edges")
        for e in hit[0].edges:
            labelled = e.why in LABELS and LABELS[e.why][0] == e.key and e.text and e.key_prefix
            counts["edges_unlabelled"] += 0 if labelled else 1
            counts[f"edges_{e.why}"] += 1
        times = [m.at for m in hit[0].members]
        if times != sorted(times):
            failures.append(f"chain {t.name!r} members are not in time order")
        if hit[0].severity.category != "chain" or hit[0].severity.score <= 0:
            failures.append(f"chain {t.name!r} has no chain severity")
    counts["incidents"] = len(found)
    counts["decoy_events"] = sum(len(t.steps) for g, _, t in numbered if g == "decoy")
    if counts["edges_unlabelled"]:
        failures.append(f"{counts['edges_unlabelled']} edge(s) without a label")
    if len(found) != counts["chains"]:
        failures.append(f"{len(found)} incidents for {counts['chains']} chains")
    return failures, dict(counts)


def report(counts: dict[str, int], failures: list[str]) -> str:
    rows = [
        ("chains seeded (mail link, click, download; eight orders and shapes)", "chains"),
        ("chains found as one incident with exactly their members", "chains_found"),
        ("labelled edges expected", "edges_expected"),
        ("labelled edges found", "edges_found"),
        ("edges found that were not expected", "edges_extra"),
        ("edges without a label", "edges_unlabelled"),
        ("  by mail link and click (same URL hash)", "edges_mail_link_is_this_url"),
        (
            "  by download origin (same host tag, inside the gap)",
            "edges_download_origin_is_this_host",
        ),
        ("  by the same file seen again (same SHA-256)", "edges_same_file_hash"),
        ("benign-only timelines seeded", "benign_timelines"),
        ("incidents made by them", "benign_incidents"),
        ("decoy timelines seeded", "decoy_timelines"),
        ("decoy events in them", "decoy_events"),
        ("incidents made by decoys", "decoy_incidents"),
        ("incidents returned in all", "incidents"),
        (
            "reads that changed a stored row (every table compared before and after)",
            "reads_that_changed_a_row",
        ),
    ]
    lines = [
        "# Incident view: gate (DA5 phase 3, item 2)",
        "",
        "Counts only, from `python -m eval.incidents check` on scripted timelines in a throwaway",
        "database, inserted in a shuffled order. No host, address or hash is recorded here.",
        "",
        "| What | Count |",
        "|---|---|",
        *(f"| {label} | {counts.get(key, 0)} |" for label, key in rows),
        "",
        "Result: " + ("INCIDENT GATE MET" if not failures else f"NOT MET ({len(failures)} failed)"),
        "",
    ]
    return "\n".join(lines)


def check(docs: Path) -> int:
    before = popular.domains()
    popular.use(frozenset({POPULAR}))  # pin the popular list: a synced one must not change this
    try:
        with tempfile.TemporaryDirectory() as tmp:
            engine = create_engine(f"sqlite:///{Path(tmp) / 'incidents.db'}")
            try:
                db.Base.metadata.create_all(engine)
                failures, counts = evaluate(engine)
            finally:
                engine.dispose()
    finally:
        popular.use(before)
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "incidents.md").write_text(report(counts, failures), encoding="utf-8", newline="\n")
    for what in failures:
        print(f"FAIL  {what}")
    if failures:
        print(f"INCIDENT GATE FAILED: {len(failures)}")
        return 1
    print("INCIDENT GATE MET")
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.incidents", description=__doc__)
    ap.add_argument("command", choices=["check"])
    ap.add_argument("--docs", type=Path, default=Path("docs/eval"))
    args = ap.parse_args(list(argv) if argv is not None else None)
    return check(args.docs)


if __name__ == "__main__":
    raise SystemExit(main())
