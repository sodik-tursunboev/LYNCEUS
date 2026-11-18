# ruff: noqa: E501  (the report and sampling lines are long literals)
"""DA2: legitimate addresses WITH paths and queries, to measure false alarms where they really happen.

    python -m eval.deeplinks build   [--per-band 150,250,350,450] [--workers 4]   (resumable, slow)
    python -m eval.deeplinks measure [--out docs/eval] [--workers N]

Every other legitimate address in the evaluation data is a bare home page (E1: PhiUSIIL and Tranco),
so the rules that read paths and queries were never measured for false alarms outside your own 92
browsing URLs. `build` samples public Tranco domains in four rank bands and asks the Internet Archive's
public index (web.archive.org/cdx) for a few pages of each. What leaves this computer: one public
domain name per request, with an honest user agent, at most four requests in flight, backing off on
errors. Nothing about you. The URLs stay in `.data/eval/deeplinks/` (public data, git-ignored); the
report holds counts only. The archive holds some junk (crawler garbage, spam) even for good domains:
that is realistic web noise, and `measure` prints the rules behind every false alarm so it can be judged.

`measure` splits the domains in two by a hash fixed before anything was measured: rules may be tuned
only by looking at dev, and test is read once. It runs the whole address engine twice: as the product
runs (popular-domain list on) and as it treats an unknown site (list off), which is the view that
matters for small sites.
"""

import argparse
import hashlib
import json
import os
import random
import re
import threading
import time
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from eval import realurl as e1
from eval.metrics import wilson

SEED = "lynceus-da2-deeplinks"
FLAGGED = ("SUSPICIOUS", "MALICIOUS")
CDX = "https://web.archive.org/cdx/search/cdx"
UA = (
    "lynceus-research/0.1 (public-data false-alarm corpus; 4 requests at most in flight, backs off)"
)
BANDS = (
    ("rank 1 to 1,000", 0, 1_000),
    ("rank 1,001 to 10,000", 1_000, 10_000),
    ("rank 10,001 to 100,000", 10_000, 100_000),
    ("rank 100,001 to 1,000,000", 100_000, 1_000_000),
)
PER_BAND = (100, 100, 100, 100)
PER_DOMAIN = 5


def clean(url: str) -> str | None:
    """http(s) only, the archive's explicit default ports and fragments dropped, no junk lengths."""
    s = urlsplit(url.strip())
    if s.scheme not in ("http", "https") or not s.hostname or len(url) > 2000:
        return None
    if not s.hostname.isascii() or (s.port not in (None, 80, 443)):
        return None
    host = s.hostname.lower()
    netloc = host if s.port in (None, 80, 443) else f"{host}:{s.port}"
    path = s.path or "/"
    return f"{s.scheme}://{netloc}{path}" + (f"?{s.query}" if s.query else "")


def plan(data: Path, per_band: Sequence[int], draw: int = 1) -> list[dict[str, Any]]:
    """The domains to ask about: a seeded sample of each Tranco rank band. Draw 1 is the original
    sample; a later draw (a top-up) has its own seed, and domains already asked are skipped."""
    ranked = [
        s.url[len("https://") : -1] for s in e1.tranco(data / "tranco-top-1m.csv.zip", 1_000_000)
    ]
    rng = random.Random(SEED if draw == 1 else f"{SEED}|draw{draw}")  # noqa: S311  (not a secret)
    out: list[dict[str, Any]] = []
    for (name, lo, hi), n in zip(BANDS, per_band, strict=True):
        for domain in rng.sample(ranked[lo:hi], n):
            out.append({"domain": domain, "band": name})
    return out


_ASSET = re.compile(
    r"\.(css|js|json|xml|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|pdf|zip|txt|map)(\?|$)", re.I
)


def fetch(client: httpx.Client, domain: str, rng: random.Random) -> list[str]:
    """Archived HTML pages of one domain: a cheap page count, then one random page of the index
    (a couple of thousand lines, filtered here). [] when the archive has none or keeps failing."""
    for attempt in range(3):
        try:
            counted = client.get(
                CDX,
                params={
                    "url": domain,
                    "matchType": "domain",
                    "showNumPages": "true",
                    "output": "json",
                },
            )
            if counted.status_code in (429, 500, 502, 503, 504):
                time.sleep(30 * (attempt + 1))
                continue
            found = re.findall(r"\d+", counted.text)
            pages = int(found[-1]) if counted.status_code == 200 and found else 1
            r = client.get(
                CDX,
                params={
                    "url": domain, "matchType": "domain", "fl": "original,mimetype,statuscode",
                    "page": rng.randrange(max(1, pages)), "pageSize": 1,
                },
            )  # fmt: skip
        except httpx.HTTPError:
            time.sleep(15 * (attempt + 1))
            continue
        if r.status_code in (429, 500, 502, 503, 504):
            time.sleep(30 * (attempt + 1))
            continue
        if r.status_code != 200:
            return []
        out = []
        for line in r.text.splitlines():
            parts = line.rsplit(" ", 2)
            if (
                len(parts) == 3
                and parts[1] == "text/html"
                and parts[2] == "200"
                and not _ASSET.search(parts[0])
            ):
                out.append(parts[0])
        return out
    return []


def build(data: Path, per_band: Sequence[int], workers: int, draw: int = 1) -> int:
    folder = data / "deeplinks"
    folder.mkdir(parents=True, exist_ok=True)
    urls_file, done_file = folder / "urls.jsonl", folder / "domains_done.jsonl"
    done = (
        {json.loads(x)["domain"] for x in done_file.read_text("utf-8").splitlines()}
        if done_file.exists()
        else set()
    )
    todo = [d for d in plan(data, per_band, draw) if d["domain"] not in done]
    (folder / "sources.json").write_text(
        json.dumps({"source": CDX, "seed": SEED, "per_band": list(per_band), "built": datetime.now(UTC).isoformat()}),
        encoding="utf-8",
    )  # fmt: skip
    print(f"{len(done)} domains already asked, {len(todo)} to ask", flush=True)
    lock = threading.Lock()
    kept = 0
    with httpx.Client(timeout=90, headers={"User-Agent": UA}) as client, \
         urls_file.open("a", encoding="utf-8") as urls_out, done_file.open("a", encoding="utf-8") as done_out, \
         ThreadPoolExecutor(workers) as pool:  # fmt: skip
        futures = {
            pool.submit(fetch, client, d["domain"], random.Random(f"{SEED}|{d['domain']}")): d  # noqa: S311
            for d in todo
        }
        for i, f in enumerate(as_completed(futures), 1):
            d = futures[f]
            urls = list(dict.fromkeys(u for raw in f.result() if (u := clean(raw))))
            random.Random(f"{SEED}|pick|{d['domain']}").shuffle(urls)  # noqa: S311
            with lock:
                for u in urls[:PER_DOMAIN]:
                    urls_out.write(
                        json.dumps({"url": u, "domain": d["domain"], "band": d["band"]}) + "\n"
                    )
                done_out.write(
                    json.dumps({"domain": d["domain"], "n": len(urls[:PER_DOMAIN])}) + "\n"
                )
                urls_out.flush()
                done_out.flush()
                kept += len(urls[:PER_DOMAIN])
            if i % 25 == 0:
                print(f"  {i}/{len(todo)} domains, {kept} addresses kept", flush=True)
    print(f"done: {kept} addresses kept")
    return 0


def split_of(registered_domain: str) -> str:
    n = int(hashlib.sha256(f"{SEED}|{registered_domain}".encode()).hexdigest()[:8], 16)
    return "dev" if n % 2 == 0 else "test"


def setup(popular_on: bool, data: Path) -> None:
    """Runs once in each judging worker: the engine as the product runs (popular on) or as it sees an
    unknown site (popular off)."""
    from core.learn import model
    from core.urls import popular

    model.use(model.load(model.DEFAULT))
    if popular_on:
        popular.configure(data.parent / "popular")
    else:
        popular.configure(None)
        popular.use(frozenset())


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 5) if n else None,
            "ci": [round(ci.low, 5), round(ci.high, 5)] if ci else None}  # fmt: skip


def measure(data: Path, out: Path, workers: int, dev_only: bool = False) -> int:
    """`dev_only`: look at the dev half and nothing else (rules may be tuned on it); no report is
    written and the test half is not even computed. Without it, both halves are measured and the
    report written: do that once, after the tuning."""
    from eval.learn_url import parsed

    rows = [
        json.loads(x) for x in (data / "deeplinks" / "urls.jsonl").read_text("utf-8").splitlines()
    ]
    for r in rows:
        u = parsed(r["url"])
        r["registered"] = (u.registered_domain if u else None) or r["domain"]
        r["split"] = split_of(r["registered"])
    urls = [r["url"] for r in rows]
    batch = [e1.Sample("", "", u) for u in urls]
    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"), "seed": SEED,
        "addresses": len(rows), "domains": len({r["registered"] for r in rows}),
        "with_query": sum("?" in r["url"] for r in rows),
        "views": {},
    }  # fmt: skip
    for view, popular_on in (
        ("as the product runs (popular list on)", True),
        ("as an unknown site (list off)", False),
    ):
        judged = e1.judge(batch, workers, partial(setup, popular_on, data))
        by_url = dict(zip(urls, judged, strict=True))
        res: dict[str, Any] = {}
        if dev_only:
            dev = [r for r in rows if r["split"] == "dev"]
            flagged = [r for r in dev if by_url[r["url"]][0] in FLAGGED]
            print(f"\n=== DEV ONLY, {view}: {len(flagged)} of {len(dev)} flagged")
            print(
                "rules firing on ANY dev address:",
                dict(Counter(x for r in dev for x in by_url[r["url"]][2]).most_common(20)),
            )
            print(
                "rules on the FLAGGED dev addresses:",
                dict(Counter(x for r in flagged for x in by_url[r["url"]][2]).most_common(20)),
            )
            for r in flagged[:60]:
                print(
                    "  ",
                    by_url[r["url"]][0][:4],
                    sorted(by_url[r["url"]][2]),
                    r["band"][5:18],
                    r["url"][:100],
                )
            continue
        for split in ("dev", "test", "all"):
            sel = [r for r in rows if split == "all" or r["split"] == split]
            flagged = [r for r in sel if by_url[r["url"]][0] in FLAGGED]
            res[split] = {
                "overall": _rate(len(flagged), len(sel)),
                "bands": {b: _rate(sum(1 for r in flagged if r["band"] == b), sum(1 for r in sel if r["band"] == b))
                          for b, *_ in BANDS},
                "rules": dict(Counter(x for r in flagged for x in by_url[r["url"]][2]).most_common(12)),
            }  # fmt: skip
        report["views"][view] = res
    if dev_only:
        return 0
    out.mkdir(parents=True, exist_ok=True)
    (out / "deeplinks.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    text = render(report)
    (out / "deeplinks.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


def render(rep: Mapping[str, Any]) -> str:
    def pct(r: Mapping[str, Any]) -> str:
        if not r["n"]:
            return "n/a"
        return f"{100 * r['rate']:.2f}% ({100 * r['ci'][0]:.2f} to {100 * r['ci'][1]:.2f}), {r['k']} of {r['n']}"

    lines = [
        "# False alarms on legitimate addresses with paths and queries (DA2)", "",
        f"{rep['generated_at']}. {rep['addresses']:,} archived pages of {rep['domains']:,} public domains "
        f"({rep['with_query']:,} with a query string), sampled from four Tranco rank bands. Seed `{rep['seed']}`. "
        "Rules may be tuned only by looking at dev; test is read once. Counts only (the addresses stay in "
        ".data/eval/deeplinks). Intervals are Wilson 95%. Archived pages include some junk even from good "
        "domains, so a few flags may be real junk, not false alarms.", "",
    ]  # fmt: skip
    for view, res in rep["views"].items():
        lines += [f"## {view}", "", "| set | flagged (SUSPICIOUS or MALICIOUS) |", "|---|---|"]
        for split in ("dev", "test", "all"):
            lines.append(f"| {split} | {pct(res[split]['overall'])} |")
        lines += ["", "| rank band (all) | flagged |", "|---|---|"]
        lines += [f"| {b} | {pct(r)} |" for b, r in res["all"]["bands"].items()]
        lines += ["", "Rules on the flagged addresses (all): "
                  + ", ".join(f"`{k}` {v}" for k, v in res["all"]["rules"].items()), ""]  # fmt: skip
    return "\n".join(lines)


def check(data: Path, out: Path, report: bool) -> int:
    """Gate checks: the corpus is big enough (CORPUS READY), or the measurement was written
    (DEEPLINKS MEASURED)."""
    rows = [
        json.loads(x) for x in (data / "deeplinks" / "urls.jsonl").read_text("utf-8").splitlines()
    ]
    bands = Counter(r["band"] for r in rows)
    domains = len({r["domain"] for r in rows})
    print(f"{len(rows)} addresses from {domains} domains; per band: {dict(bands)}")
    if not report:
        ok = len(rows) >= 1500 and domains >= 300 and all(bands[b] >= 100 for b, *_ in BANDS)
        print("CORPUS READY" if ok else "CORPUS NOT READY")
        return 0 if ok else 1
    path = out / "deeplinks.json"
    rep = json.loads(path.read_text("utf-8")) if path.exists() else {}
    views = rep.get("views", {})
    ok = len(views) == 2 and all(
        v["dev"]["overall"]["n"] and v["test"]["overall"]["n"] for v in views.values()
    )
    print("DEEPLINKS MEASURED" if ok else "DEEPLINKS NOT MEASURED")
    return 0 if ok else 1


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.deeplinks", description=__doc__)
    ap.add_argument("command", choices=["build", "measure", "check"])
    ap.add_argument("--report", action="store_true", help="with check: was the measurement written")
    ap.add_argument(
        "--dev-only", action="store_true", help="with measure: the dev half only, nothing written"
    )
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    ap.add_argument("--per-band", default=",".join(map(str, PER_BAND)))
    ap.add_argument("--workers", type=int, default=0)
    ap.add_argument("--draw", type=int, default=1, help="2, 3, ...: a top-up sample, own seed")
    args = ap.parse_args(list(argv) if argv is not None else None)
    if args.command == "check":
        return check(args.data, args.out, args.report)
    if args.command == "build":
        sizes = [int(x) for x in args.per_band.split(",")]
        return build(args.data, sizes, args.workers or 4, args.draw)
    return measure(
        args.data, args.out, args.workers or max(1, (os.cpu_count() or 2) - 1), args.dev_only
    )


if __name__ == "__main__":
    raise SystemExit(main())
