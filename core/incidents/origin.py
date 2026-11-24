"""What storage already knows about a site, read by its keyed host tag (ADR-007, DA5 phase 3).

`stored_origin(engine)` is the reader the file engine takes as `origin_lookup`: the latest verdict
of a URL artifact on the same host, so what the page, the lists or the sandbox said about a site is
not lost when a file comes from it. It only reads. The site's name is never revealed or stored: the
lookup is by the host's keyed hash, and the answer is a state and rule ids.

A popular site (the Tranco top list) is skipped: its stored verdicts belong to one page on it (one
bad document on a big platform), not to the site, and a download from it must not inherit them.
"""

from sqlalchemy import Engine, select

from core.contracts import ArtifactKind
from core.db import hosts
from core.db import models as db
from core.files.engine import OriginLookup, StoredVerdict
from core.urls import popular
from core.urls.parse import ParsedUrl, parse_url


def popular_host(host: str | None) -> bool:
    """True when the host's registered domain is on the popular list (not for an unreadable one)."""
    if not host or host == hosts.UNREADABLE:
        return False
    parsed = parse_url(f"https://{host}/")
    return isinstance(parsed, ParsedUrl) and popular.is_popular(parsed.registered_domain)


def stored_origin(engine: Engine) -> OriginLookup:
    """A lookup of the newest stored verdict for any URL on a host, for `analyze_file`."""

    def lookup(host: str) -> StoredVerdict | None:
        tag = hosts.tag(host)
        if tag is None or popular_host(host):
            return None
        with engine.connect() as c:
            latest = c.execute(
                select(db.Verdict.id, db.Verdict.state)
                .join(db.Artifact, db.Artifact.id == db.Verdict.artifact_id)
                .where(db.Artifact.host_tag == tag, db.Artifact.kind == ArtifactKind.URL.value)
                .order_by(db.Verdict.created_at.desc(), db.Verdict.id)
                .limit(1)
            ).first()
            if latest is None:
                return None
            rules = c.scalars(
                select(db.Detection.rule_id).where(db.Detection.verdict_id == latest.id).distinct()
            ).all()
        return StoredVerdict(state=latest.state, rules=tuple(sorted(rules)))

    return lookup
