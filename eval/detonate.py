# ruff: noqa: E501  (report rows are long literal lines)
"""Measure page detonation on live pages (D1).

    python -m eval.detonate [--refresh] [--phish 400] [--legit 400] [--out docs/eval]

Live, unlike E1: every URL is OPENED, in the detonator container only (docs/milestones/D1.md; the
owner allowed this on 2026-11-11). This module itself never fetches a page; it only downloads the
two public phishing lists (--refresh), from the same sources as E1. URLs and per-URL results stay in
.data/eval/d1/ (outside git); the reports hold counts only.

Phishing: today's OpenPhish feed and the newest PhishTank entries. Legitimate: a seeded sample of
the Tranco top 10,000 home pages, the home page of every brand on the brand list (a brand's own
sign-in page must not look like an impersonation of it), and /login on another seeded Tranco sample. Baseline: the URL rules alone, without the
lists (every phishing URL here IS on a list, so lists would trivially catch them all).
"""

import argparse
import bz2
import hashlib
import json
import random
import statistics
import threading
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from core.detection.engine import analyze_url
from core.detonate import detonate_url, runner
from core.detonate.auto import worth_opening
from core.detonate.judge import judge
from core.detonate.models import PageReport
from core.detonate.runner import ensure_ready
from core.urls import popular
from eval.metrics import wilson
from eval.realurl import LEGIT, PHISH, Sample, tranco
from rules.url.data import brands

SEED = "lynceus-d1-2026-11-11"  # fixed before any page was opened
SPLITS = ("dev", "test")  # rules may be tuned on dev only; the headline is the test half
FLAGGED = ("SUSPICIOUS", "MALICIOUS")
SOURCES = {
    "openphish.txt": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    "phishtank.json.bz2": "https://data.phishtank.com/data/online-valid.json.bz2",
}


def refresh(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    record = []
    with httpx.Client(
        timeout=120, follow_redirects=True, headers={"User-Agent": "lynceus-eval/1.0"}
    ) as c:
        for name, url in SOURCES.items():
            body = c.get(url).raise_for_status().content
            (folder / name).write_bytes(body)
            record.append({"file": name, "source": url, "bytes": len(body),
                           "sha256": hashlib.sha256(body).hexdigest(),
                           "downloaded": datetime.now(UTC).isoformat(timespec="seconds")})  # fmt: skip
    (folder / "sources.json").write_text(json.dumps(record, indent=2), encoding="utf-8")


def phishing(folder: Path, n: int) -> list[Sample]:
    """All of today's OpenPhish feed, then the newest verified PhishTank entries, up to n."""
    seen: set[str] = set()
    out: list[Sample] = []

    def add(s: Sample) -> None:
        if s.url not in seen and len(out) < n:
            seen.add(s.url)
            out.append(s)

    for line in (
        (folder / "openphish.txt").read_text(encoding="utf-8", errors="replace").splitlines()
    ):
        if line.startswith(("http://", "https://")):
            add(Sample("openphish", PHISH, line.strip()))
    entries = json.loads(bz2.decompress((folder / "phishtank.json.bz2").read_bytes()))
    entries = [e for e in entries if e.get("verified") == "yes" and isinstance(e.get("url"), str)]
    entries.sort(key=lambda e: str(e.get("submission_time") or ""), reverse=True)
    for e in entries:
        add(Sample("phishtank", PHISH, e["url"].strip()))
    return out


def legitimate(eval_data: Path, n: int) -> list[Sample]:
    rng = random.Random(SEED)  # noqa: S311  (a reproducible sample, not a secret)
    homes = [Sample("brand_home", LEGIT, f"https://{b.domains[0]}/") for b in brands()]
    top = list(tranco(eval_data / "tranco-top-1m.csv.zip", 10_000))
    picked = rng.sample(top, max(0, min(len(top), n - len(homes))))
    return homes + picked


def sign_in_pages(eval_data: Path, n: int) -> list[Sample]:
    """Real sign-in pages: /login on a seeded sample of the Tranco top 10,000 (many answer 404 or
    redirect; the ones that show a form are the fair false-alarm test for the credential rules)."""
    rng = random.Random(f"{SEED}|login")  # noqa: S311  (a reproducible sample, not a secret)
    top = list(tranco(eval_data / "tranco-top-1m.csv.zip", 10_000))
    return [
        Sample("tranco_login", LEGIT, s.url + "login") for s in rng.sample(top, min(n, len(top)))
    ]


def long_tail(eval_data: Path, n: int) -> list[Sample]:
    """DA1: legitimate sites the popular list does not cover, where rules about unknown domains
    actually fire: a seeded sample of Tranco ranks 100,001 to 1,000,000, at their home page. Being
    ranked is not proof of being harmless; the report says so."""
    rng = random.Random(f"{SEED}|tail")  # noqa: S311  (a reproducible sample, not a secret)
    ranked = list(tranco(eval_data / "tranco-top-1m.csv.zip", 1_000_000))[100_000:]
    return [Sample("tranco_tail", LEGIT, s.url) for s in rng.sample(ranked, min(n, len(ranked)))]


def split_of(url: str) -> str:
    return SPLITS[int(hashlib.sha256(f"{SEED}|{url}".encode()).hexdigest()[:8], 16) % 2]


def _key(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8", "surrogatepass")).hexdigest()[:24]


def row_for(s: Sample, page: PageReport) -> dict[str, Any]:
    """Judge a captured page with the rules as they are now (nothing is opened here)."""
    base = analyze_url(s.url)
    final = judge(base, page)
    page_rules = sorted({x.rule_id for x in final.verdict.signals if x.rule_id.startswith("page.")})
    landing = sorted(
        {x.rule_id for x in final.verdict.signals if x.description.startswith("landing page:")}
    )
    return {
        "source": s.source, "label": s.label, "url": s.url, "split": split_of(s.url),
        "url_state": base.verdict.state.value, "state": final.verdict.state.value,
        "status": page.status, "error": page.error, "http": page.http_status, "alive": page.alive,
        "page_rules": page_rules, "landing_rules": landing, "ms": page.elapsed_ms,
        "password": any(f.type == "password" for f in page.fields()),
        # DA1: the second look at a near-empty page, and whether automatic opening would pick it
        "second_look": page.second_look, "auto_open": worth_opening(base),
    }  # fmt: skip


def run_one(s: Sample, pages: Path) -> dict[str, Any]:
    """Open the page (in the detonator) once, keep what it showed (not the screenshot), judge it."""
    _, page = detonate_url(s.url, analyze_url(s.url))
    kept = page.model_copy(update={"screenshot": None})
    (pages / f"{_key(s.url)}.json").write_text(kept.model_dump_json(), encoding="utf-8")
    return row_for(s, kept)


def rescore(samples: Sequence[Sample], pages: Path) -> list[dict[str, Any]]:
    """Every captured page judged again with the current rules; nothing is reopened."""
    rows = []
    for s in samples:
        f = pages / f"{_key(s.url)}.json"
        if f.exists():
            rows.append(row_for(s, PageReport.model_validate_json(f.read_text(encoding="utf-8"))))
    return rows


def run(
    samples: Sequence[Sample], results: Path, pages: Path, parallel: int
) -> list[dict[str, Any]]:
    """Every sample once; resumable (already-measured URLs are read back, not reopened)."""
    done: dict[str, dict[str, Any]] = {}
    if results.exists():
        for line in results.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            done[row["url"]] = row
    todo = [s for s in samples if s.url not in done]
    print(f"{len(done)} already measured, {len(todo)} to open", flush=True)
    with results.open("a", encoding="utf-8") as out, ThreadPoolExecutor(parallel) as pool:
        futures = {pool.submit(run_one, s, pages): s for s in todo}
        for i, f in enumerate(as_completed(futures), 1):
            row = f.result()
            done[row["url"]] = row
            out.write(json.dumps(row) + "\n")
            out.flush()
            if i % 25 == 0:
                print(f"  {i}/{len(todo)}", flush=True)
    return [done[s.url] for s in samples if s.url in done]


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)  # None when n is 0
    return {"k": k, "n": n, "rate": k / n if n else None,
            "low": ci.low if ci else None, "high": ci.high if ci else None}  # fmt: skip


def _flagged(rows: Iterable[Mapping[str, Any]], key: str) -> int:
    return sum(r[key] in FLAGGED for r in rows)


def measure(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The headline is the test half; the dev half (the only one rules may be tuned on) apart."""
    return {
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "seed": SEED,
        "test": _measure([r for r in rows if r["split"] == "test"]),
        "dev": _measure([r for r in rows if r["split"] == "dev"]),
    }


def _measure(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    rep: dict[str, Any] = {}
    for label in (PHISH, LEGIT):
        group = [r for r in rows if r["label"] == label]
        alive = [r for r in group if r["alive"]]
        rep[label] = {
            "n": len(group),
            "alive": _rate(len(alive), len(group)),
            "status": dict(
                Counter(
                    r["status"] if r["alive"] or r["status"] != "ok" else f"http_{r['http']}"
                    for r in group
                )
            ),
            "url_only_all": _rate(_flagged(group, "url_state"), len(group)),
            "with_page_all": _rate(_flagged(group, "state"), len(group)),
            "url_only_alive": _rate(_flagged(alive, "url_state"), len(alive)),
            "with_page_alive": _rate(_flagged(alive, "state"), len(alive)),
            "malicious_alive": _rate(sum(r["state"] == "MALICIOUS" for r in alive), len(alive)),
            "password_pages": _rate(sum(r["password"] for r in alive), len(alive)),
            "by_source": {
                src: {
                    "n": sum(r["source"] == src for r in group),
                    "alive": sum(r["source"] == src and r["alive"] for r in group),
                    "with_page_alive": _rate(
                        _flagged([r for r in alive if r["source"] == src], "state"),
                        sum(r["source"] == src for r in alive),
                    ),
                }
                for src in sorted({r["source"] for r in group})
            },  # fmt: skip
            "rules": dict(Counter(x for r in alive for x in r["page_rules"]).most_common()),
            "landing_rules": dict(
                Counter(x for r in alive for x in r["landing_rules"]).most_common()
            ),
            "ms_p50": statistics.median([r["ms"] for r in group if r["ms"]] or [0]),
        }
    gained = [
        r
        for r in rows
        if r["label"] == PHISH
        and r["alive"]
        and r["state"] in FLAGGED
        and r["url_state"] not in FLAGGED
    ]
    for label in (PHISH, LEGIT):  # DA1
        group = [r for r in rows if r["label"] == label]
        alive = [r for r in group if r["alive"]]
        looked = [r for r in alive if r.get("second_look")]
        rep[label]["second_look"] = _rate(len(looked), len(alive))
        rep[label]["second_look_flagged"] = _rate(_flagged(looked, "state"), len(looked))
        rep[label]["fresh_certificate"] = _rate(
            sum("page.fresh_certificate" in r["page_rules"] for r in alive), len(alive)
        )
        rep[label]["auto_open"] = _rate(sum(bool(r.get("auto_open")) for r in group), len(group))
    rep["phish"]["caught_only_by_page"] = len(gained)
    rep["legit"]["false_alarms_from_page"] = sum(
        r["label"] == LEGIT and r["state"] in FLAGGED and r["url_state"] not in FLAGGED
        for r in rows
    )
    signin = [r for r in rows if r["label"] == LEGIT and r["alive"] and r["password"]]
    rep["legit"]["sign_in_pages_flagged"] = _rate(_flagged(signin, "state"), len(signin))
    return rep


def _pct(r: Mapping[str, Any]) -> str:
    if not r["n"]:
        return "n/a (n=0)"
    return f"{100 * r['rate']:.1f}% ({100 * r['low']:.1f} to {100 * r['high']:.1f}), {r['k']} of {r['n']}"


def render(full: Mapping[str, Any]) -> str:
    rep, dev = full["test"], full["dev"]
    p, g = rep["phish"], rep["legit"]
    lines = [
        "# Page detonation on live pages (D1)",
        "",
        f"{full['generated']}. Seed `{full['seed']}`. **The test half is shown.** The URLs were split in two by a hash fixed before any page was opened, and rules may be changed only by looking at the dev half (dev, for comparison: phishing caught with the page {_pct(dev['phish']['with_page_alive'])}; legitimate flagged {_pct(dev['legit']['with_page_alive'])}). Every page was opened in the detonator container only (`docs/milestones/D1.md`); nothing was typed or submitted. URLs and per-URL rows stay in `.data/eval/d1/`; this report holds counts only. Intervals are Wilson 95%.",
        "",
        "**Baseline = the URL rules alone, without the lists**: every phishing URL here comes from a list, so the lists would catch all of them by construction. The question is what the page adds for a phishing URL no list knows yet.",
        "",
        "## Phishing (today's OpenPhish feed and the newest PhishTank entries)",
        "",
        "| | Result |",
        "|---|---|",
        f"| pages still alive | {_pct(p['alive'])} |",
        f"| **caught, URL rules alone (alive pages)** | {_pct(p['url_only_alive'])} |",
        f"| **caught, URL rules + page (alive pages)** | {_pct(p['with_page_alive'])} |",
        f"| MALICIOUS with the page (alive pages) | {_pct(p['malicious_alive'])} |",
        f"| caught only because of the page | {p['caught_only_by_page']} |",
        f"| alive pages with a password field | {_pct(p['password_pages'])} |",
        f"| caught, all URLs (dead pages count as misses) | URL alone {_pct(p['url_only_all'])}; with page {_pct(p['with_page_all'])} |",
        "",
        "## Legitimate (brand home pages, a Tranco top-10,000 sample, and /login on another Tranco sample)",
        "",
        "| | Result |",
        "|---|---|",
        f"| pages alive | {_pct(g['alive'])} |",
        f"| flagged, URL rules alone (alive) | {_pct(g['url_only_alive'])} |",
        f"| **flagged, URL rules + page (alive)** | {_pct(g['with_page_alive'])} |",
        f"| false alarms added by the page | {g['false_alarms_from_page']} |",
        f"| **legitimate pages with a password form, flagged** | {_pct(g['sign_in_pages_flagged'])} |",
        "",
        "## By source (alive pages, URL rules + page)",
        "",
        "| Source | n | alive | flagged |",
        "|---|---|---|---|",
    ]
    for label in (PHISH, LEGIT):
        for src, row in rep[label]["by_source"].items():
            lines.append(
                f"| {src} ({label}) | {row['n']} | {row['alive']} | {_pct(row['with_page_alive'])} |"
            )
    lines += [
        "",
        "## DA1: what the deeper look adds, and what automatic opening would cost (test half)",
        "",
        "| | phishing | legitimate |",
        "|---|---|---|",
        f"| alive pages read on a second look (the first showed almost nothing) | {_pct(p['second_look'])} | {_pct(g['second_look'])} |",
        f"| ... of those, flagged | {_pct(p['second_look_flagged'])} | {_pct(g['second_look_flagged'])} |",
        f"| `page.fresh_certificate` (evidence only, no weight) | {_pct(p['fresh_certificate'])} | {_pct(g['fresh_certificate'])} |",
        f"| would be opened automatically (address SUSPICIOUS, or UNKNOWN with a sign, not popular) | {_pct(p['auto_open'])} | {_pct(g['auto_open'])} |",
        "",
        "## Page rules that fired (alive pages)",
        "",
        "| Rule | phishing | legitimate |",
        "|---|---|---|",
    ]
    for rule in sorted(set(p["rules"]) | set(g["rules"])):
        lines.append(f"| `{rule}` | {p['rules'].get(rule, 0)} | {g['rules'].get(rule, 0)} |")
    lines += ["", "Landing-address URL rules (the page moved to another site): "
              f"phishing {sum(p['landing_rules'].values())}, legitimate {sum(g['landing_rules'].values())}.",
              "", "## Page status", "",
              f"- phishing: {p['status']}", f"- legitimate: {g['status']}",
              f"- median time per page: phishing {p['ms_p50'] / 1000:.1f} s, legitimate {g['ms_p50'] / 1000:.1f} s"]  # fmt: skip
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.detonate")
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    ap.add_argument("--refresh", action="store_true", help="download today's phishing lists first")
    ap.add_argument("--phish", type=int, default=400)
    ap.add_argument("--legit", type=int, default=400)
    ap.add_argument("--logins", type=int, default=300, help="Tranco sites tried at /login")
    ap.add_argument(
        "--rescore", action="store_true", help="judge the kept pages again; open nothing"
    )
    ap.add_argument("--parallel", type=int, default=runner.MAX_PARALLEL, help="pages at once")
    ap.add_argument(
        "--folder", default="d1", help="the run's folder under --data (DA1: a new run, D1 kept)"
    )
    ap.add_argument("--tail", type=int, default=0, help="DA1: long-tail legitimate sites to open")
    ap.add_argument("--name", default="detonate", help="the report's file name in --out")
    args = ap.parse_args(argv)
    d1 = args.data / args.folder
    pages = d1 / "pages"
    popular.configure(args.data.parent / "popular")  # the list the core uses (H1 B1), if synced
    if not args.rescore and (args.refresh or not (d1 / "openphish.txt").exists()):
        refresh(d1)
    samples = (
        phishing(d1, args.phish)
        + legitimate(args.data, args.legit)
        + sign_in_pages(args.data, args.logins)
        + long_tail(args.data, args.tail)
    )
    if args.rescore:
        rows = rescore(samples, pages)
    else:
        ensure_ready()
        pages.mkdir(parents=True, exist_ok=True)
        runner._slots = threading.BoundedSemaphore(args.parallel)  # one container each
        rows = run(samples, d1 / "results.jsonl", pages, args.parallel)
    rep = measure(rows)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / f"{args.name}.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
    (args.out / f"{args.name}.md").write_text(render(rep), encoding="utf-8")
    print(render(rep))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
