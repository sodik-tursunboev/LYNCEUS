# ruff: noqa: E501  (report rows and the description below are long literal lines)
"""Measure the URL engine on real, labelled URLs that nobody on this project wrote (E1).

    python -m eval.realurl [--data .data/eval] [--out docs/eval] [--tranco 50000] [--workers N]

Offline: it reads the datasets downloaded once into .data/eval (their sources, licences and SHA-256
are in sources.json there) and never opens, fetches or resolves a URL: each one is only parsed as
text by the same engine the browser check uses. The reports hold counts only, never a URL.

What it measures (docs/milestones/E1.md): recall per source with Wilson intervals (UNKNOWN is a
miss, never "safe"); the false-alarm rate on legitimate URLs, split into home pages and URLs with a
path; per-rule hit rates; the lexical ceiling (real phishing URLs on which no URL rule fires at all);
and the misses by kind of host. Then (phase B) it fits the rule weights on the training split and
compares them with the hand-set weights on the test split. The reserve split is never evaluated.
"""

import argparse
import bz2
import csv
import hashlib
import io
import json
import math
import os
import sqlite3
import zipfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from eval.metrics import wilson

SEED = "lynceus-e1-2026-11-10"  # fixed before any number was looked at
PHISH, LEGIT = "phish", "legit"
FLAGGED = ("SUSPICIOUS", "MALICIOUS")

# Hosts where anyone can publish a page under a trusted name: a URL there carries no lexical tell.
PLATFORMS = (
    "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "github.io", "netlify.app",
    "vercel.app", "weebly.com", "weeblysite.com", "wixsite.com", "wixstudio.com", "blogspot.com",
    "sites.google.com", "docs.google.com", "forms.gle", "drive.google.com", "sharepoint.com",
    "onedrive.live.com", "1drv.ms", "dropbox.com", "ipfs.io", "dweb.link", "r2.dev", "glitch.me",
    "repl.co", "replit.app", "replit.dev", "webflow.io", "framer.app", "framer.website",
    "square.site", "godaddysites.com", "wordpress.com", "000webhostapp.com", "herokuapp.com",
    "azurewebsites.net", "appspot.com", "storage.googleapis.com", "firebasestorage.googleapis.com",
    "amazonaws.com", "cloudfront.net", "canva.site", "typeform.com", "jotform.com",
    "mailchimpsites.com", "ngrok-free.app", "trycloudflare.com", "translate.goog", "carrd.co",
    "notion.site", "yolasite.com", "strikingly.com", "mystrikingly.com", "jimdosite.com",
    "wix.com", "sharepoint-df.com", "linktr.ee", "telegra.ph", "gitbook.io", "vercel.com",
    "surge.sh", "render.com", "onrender.com", "fly.dev", "bubbleapps.io", "softr.app",
    "glide.page", "myshopify.com", "tilda.ws", "ukit.me", "webnode.page", "site123.me",
)  # fmt: skip
SHORTENERS = (
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rebrand.ly", "ow.ly", "buff.ly",
    "rb.gy", "shorturl.at", "t.ly", "tiny.cc", "s.id", "v.gd", "qrco.de", "goo.gl", "lnkd.in",
)  # fmt: skip


@dataclass(frozen=True)
class Sample:
    source: str
    label: str
    url: str


# ---- the datasets ---------------------------------------------------------------------------------
def phiusiil(path: Path) -> Iterator[Sample]:
    """UCI 967: label 1 is legitimate, 0 is phishing (as the dataset's description says)."""
    with zipfile.ZipFile(path) as z:
        name = next(i.filename for i in z.infolist() if i.filename.lower().endswith(".csv"))
        with z.open(name) as f:
            rows = csv.DictReader(io.TextIOWrapper(f, encoding="utf-8-sig", errors="replace"))
            for row in rows:
                url, label = (row.get("URL") or "").strip(), (row.get("label") or "").strip()
                if url and label in ("0", "1"):
                    yield Sample("phiusiil", LEGIT if label == "1" else PHISH, url)


def phishtank(path: Path) -> Iterator[Sample]:
    for entry in json.loads(bz2.decompress(path.read_bytes())):
        if entry.get("verified") == "yes" and isinstance(entry.get("url"), str):
            yield Sample("phishtank", PHISH, entry["url"].strip())


def openphish(path: Path) -> Iterator[Sample]:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith(("http://", "https://")):
            yield Sample("openphish", PHISH, line.strip())


def tranco(path: Path, top: int) -> Iterator[Sample]:
    """The most popular domains, as the home page a person would open."""
    with zipfile.ZipFile(path) as z, z.open(z.infolist()[0]) as f:
        for i, row in enumerate(csv.reader(io.TextIOWrapper(f, encoding="utf-8"))):
            if i >= top:
                return
            if len(row) == 2:
                yield Sample("tranco", LEGIT, f"https://{row[1].strip()}/")


def edge_history() -> Iterator[Sample]:
    """The owner's own Edge history (decision 2026-11-10): read in place, read-only, never copied,
    and never written anywhere: only counts reach the report. Local and private addresses are
    skipped (they are this computer's own pages, such as the Lynceus console)."""
    root = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data"
    for db in sorted(root.glob("*/History")):
        try:
            con = sqlite3.connect(db.as_uri() + "?mode=ro&immutable=1", uri=True)
            rows = con.execute("select url from urls where url like 'http%'").fetchall()
            con.close()
        except sqlite3.Error:
            continue
        for (url,) in rows:
            host = (urlsplit(url).hostname or "").lower()
            if host in ("localhost", "127.0.0.1", "::1") or host.endswith((".local", ".localhost")):
                continue
            yield Sample("edge_history", LEGIT, url)


def load(data: Path, tranco_top: int) -> list[Sample]:
    found: list[Sample] = []
    seen: set[tuple[str, str]] = set()
    sources: list[Iterable[Sample]] = [
        phiusiil(data / "phiusiil.zip"),
        phishtank(data / "phishtank.json.bz2"),
        openphish(data / "openphish.txt"),
        tranco(data / "tranco-top-1m.csv.zip", tranco_top),
        edge_history(),
    ]
    for source in sources:
        for s in source:
            if (s.source, s.url) not in seen and len(s.url) <= 8192:
                seen.add((s.source, s.url))
                found.append(s)
    return found


# ---- splits and kinds -----------------------------------------------------------------------------
def split_of(url: str) -> str:
    n = int(hashlib.sha256(f"{SEED}\n{url}".encode()).hexdigest()[:8], 16) % 100
    return "train" if n < 60 else "test" if n < 90 else "reserve"


def has_path(url: str) -> bool:
    parts = urlsplit(url)
    return parts.path not in ("", "/") or bool(parts.query)


def host_kind(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    if not host:
        return "unparsable"
    if host.replace(".", "").isdigit() or ":" in host:
        return "ip_address"
    if any(p.startswith("xn--") for p in host.split(".")):
        return "punycode"
    if any(host == s or host.endswith("." + s) for s in SHORTENERS):
        return "shortener"
    if any(host == p or host.endswith("." + p) for p in PLATFORMS):
        return "platform"
    return "own_domain"


# ---- judging (the real engine, in parallel) --------------------------------------------------------
Judged = tuple[str, int | None, tuple[str, ...]]  # state, risk, rule ids


def _judge_batch(urls: Sequence[str]) -> list[Judged]:
    from core.detection.engine import analyze_url

    out: list[Judged] = []
    for url in urls:
        try:
            v = analyze_url(url).verdict
            out.append((v.state.value, v.risk_score, tuple(sorted({s.rule_id for s in v.signals}))))
        except Exception:  # noqa: BLE001  (an engine failure on real data is a finding, counted)
            out.append(("ERROR", None, ()))
    return out


def judge(samples: Sequence[Sample], workers: int) -> list[Judged]:
    urls = [s.url for s in samples]
    chunks = [urls[i : i + 2000] for i in range(0, len(urls), 2000)]
    if workers <= 1:
        return [j for c in chunks for j in _judge_batch(c)]
    with ProcessPoolExecutor(max_workers=workers) as pool:
        return [j for part in pool.map(_judge_batch, chunks) for j in part]


# ---- measurements --------------------------------------------------------------------------------
def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None,
            "ci": [round(ci.low, 4), round(ci.high, 4)] if ci else None}  # fmt: skip


def measure(samples: Sequence[Sample], judged: Sequence[Judged]) -> dict[str, Any]:
    rows = [(s, j) for s, j in zip(samples, judged, strict=True) if split_of(s.url) != "reserve"]
    by_source: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for s, (state, _risk, _rules) in rows:
        by_source[(s.source, s.label)][state] += 1  # one source can hold both labels (PhiUSIIL)
        by_source[(s.source, s.label)]["n"] += 1
    sources = {}
    for (source, label), c in sorted(by_source.items()):
        n, hits = c["n"], c["SUSPICIOUS"] + c["MALICIOUS"]
        name = f"{source} {label}"
        entry: dict[str, Any] = {
            "label": label,
            "n": n,
            "states": {k: v for k, v in c.items() if k != "n"},
        }
        entry["flagged" if label == PHISH else "false_alarms"] = _rate(hits, n)
        if label == PHISH:
            entry["malicious"] = _rate(c["MALICIOUS"], n)
        sources[name] = entry

    phish = [(s, j) for s, j in rows if s.label == PHISH]
    legit = [(s, j) for s, j in rows if s.label == LEGIT]
    fresh = [(s, j) for s, j in phish if s.source in ("phishtank", "openphish")]

    def flagged(items: Sequence[tuple[Sample, Judged]]) -> dict[str, Any]:
        return _rate(sum(j[0] in FLAGGED for _, j in items), len(items))

    no_signal = sum(not j[2] for _, j in phish)
    weak = sum(bool(j[2]) and j[0] not in FLAGGED for _, j in phish)
    kinds: dict[str, Counter[str]] = defaultdict(Counter)
    for s, j in phish:
        k = host_kind(s.url)
        kinds[k]["n"] += 1
        kinds[k]["flagged"] += j[0] in FLAGGED
        kinds[k]["no_signal"] += not j[2]
    rule_hits: dict[str, Counter[str]] = defaultdict(Counter)
    for s, j in rows:
        for r in j[2]:
            rule_hits[r][s.label] += 1
    # Which rules raise the false alarms on real browsing (rule names and counts only, never a URL).
    browsing = Counter(r for s, j in legit if has_path(s.url) and j[0] in FLAGGED for r in j[2])
    n_phish, n_legit = len(phish), len(legit)
    rules = {
        r: {"on_phish": c[PHISH], "on_legit": c[LEGIT],
            "phish_rate": round(c[PHISH] / n_phish, 4) if n_phish else None,
            "legit_rate": round(c[LEGIT] / n_legit, 4) if n_legit else None}
        for r, c in sorted(rule_hits.items(), key=lambda kv: -sum(kv[1].values()))
    }  # fmt: skip
    return {
        "evaluated": len(rows),
        "sources": sources,
        "phishing": {
            "all": flagged(phish),
            "fresh_feeds": flagged(fresh),
            "historical_phiusiil": flagged([x for x in phish if x[0].source == "phiusiil"]),
            "on_home_pages": flagged([x for x in phish if not has_path(x[0].url)]),
            "with_a_path": flagged([x for x in phish if has_path(x[0].url)]),
            "malicious": _rate(sum(j[0] == "MALICIOUS" for _, j in phish), n_phish),
        },
        "legitimate": {
            "all": flagged(legit),
            "home_pages": flagged([x for x in legit if not has_path(x[0].url)]),
            "with_a_path": flagged([x for x in legit if has_path(x[0].url)]),
            "rules_on_flagged_urls_with_a_path": dict(browsing.most_common()),
        },
        "lexical_ceiling": {
            "no_rule_fired": _rate(no_signal, n_phish),
            "rules_fired_but_not_flagged": _rate(weak, n_phish),
        },
        "phishing_by_host_kind": {
            k: {
                "n": c["n"],
                "flagged": _rate(c["flagged"], c["n"]),
                "no_rule_fired": _rate(c["no_signal"], c["n"]),
            }
            for k, c in sorted(kinds.items(), key=lambda kv: -kv[1]["n"])
        },  # fmt: skip
        "rules": rules,
    }


# ---- phase B: fit the weights on train, compare on test -------------------------------------------
def _noisy_or(ws: Iterable[float]) -> float:
    return 1 - math.prod(1 - w for w in sorted(ws))


def fast_state(
    rules: Sequence[str],
    allowlisted: bool,
    weights: Mapping[str, float],
    cats: Mapping[str, str],
    cfg: Mapping[str, Any],
) -> str:
    """core.risk.scoring.score() for a set of rule ids, on plain numbers (checked equal to it)."""
    if not rules:
        return "BENIGN" if allowlisted else "UNKNOWN"
    t, caps = cfg["thresholds"], cfg["category_caps"]
    by: dict[str, list[float]] = defaultdict(list)
    for r in rules:
        by[cats[r]].append(weights[r])
    capped = [min(_noisy_or(ws), caps.get(c, 1.0)) for c, ws in sorted(by.items())]
    risk = round(100 * _noisy_or(capped))
    strong = sum(max(ws) >= t["high_weight"] for ws in by.values())
    if set(cfg.get("certain", {}).get("rules", ())) & set(rules):
        return "MALICIOUS"
    if risk >= t["malicious"] and strong >= t["min_categories"]:
        return "MALICIOUS"
    if risk >= t["suspicious"]:
        return "SUSPICIOUS"
    return "BENIGN" if allowlisted else "UNKNOWN"


def fit(samples: Sequence[Sample], judged: Sequence[Judged]) -> dict[str, Any]:
    from rules.url import RULES
    from rules.url.data import scoring

    cfg = scoring()
    base = dict(cfg["weights"])
    cats = {r.id: r.category for r in RULES}
    # Group identical outcomes: (rules fired, allowlisted) with counts per split and label.
    groups: dict[tuple[tuple[str, ...], bool], Counter[str]] = defaultdict(Counter)
    for s, (state, _risk, rules) in zip(samples, judged, strict=True):
        split = split_of(s.url)
        if split == "reserve" or state == "ERROR":
            continue
        groups[(rules, state == "BENIGN")][f"{split}:{s.label}"] += 1
    patterns = list(groups.items())
    # Every rule that fired must have a weight and a category, or the fit would be meaningless.
    for (rules, _allow), _ in patterns:
        if not all(r in cats and r in base for r in rules):
            raise ValueError(f"a rule without a weight or category: {rules}")

    def evaluate(weights: Mapping[str, float], split: str) -> tuple[int, int, int, int]:
        tp = fn = fp = tn = 0
        for (rules, allow), c in patterns:
            hit = fast_state(rules, allow, weights, cats, cfg) in FLAGGED
            p, n = c[f"{split}:{PHISH}"], c[f"{split}:{LEGIT}"]
            tp, fn, fp, tn = tp + hit * p, fn + (not hit) * p, fp + hit * n, tn + (not hit) * n
        return tp, fn, fp, tn

    _, _, base_fp, base_tn = evaluate(base, "train")
    budget = base_fp / max(base_fp + base_tn, 1)  # never more false alarms than today, on train

    def objective(weights: Mapping[str, float]) -> tuple[float, float]:
        tp, fn, fp, tn = evaluate(weights, "train")
        fpr = fp / max(fp + tn, 1)
        return (tp / max(tp + fn, 1) if fpr <= budget + 1e-12 else -1.0, -fpr)

    grid = [round(0.05 * i, 2) for i in range(1, 20)]
    weights, best = dict(base), objective(base)
    for _ in range(4):
        improved = False
        for rule in sorted(base):
            for w in grid:
                trial = {**weights, rule: w}
                score_ = objective(trial)
                if score_ > best:
                    weights, best, improved = trial, score_, True
        if not improved:
            break

    def report(w: Mapping[str, float]) -> dict[str, Any]:
        tp, fn, fp, tn = evaluate(w, "test")
        return {"recall": _rate(tp, tp + fn), "false_alarms": _rate(fp, fp + tn)}

    before, after = report(base), report(weights)
    r0, r1 = before["recall"]["ci"], after["recall"]["ci"]
    f0, f1 = before["false_alarms"]["ci"], after["false_alarms"]["ci"]
    clearly_better = bool(r0 and r1 and f0 and f1 and r1[0] > r0[1] and f1[1] <= f0[1])
    return {
        "method": "coordinate search over each rule's weight (0.05 to 0.95), thresholds, caps and "
        "the two-category rule unchanged; objective: recall on train without more false alarms "
        "on train than today's weights",
        "patterns": len(patterns),
        "test_hand_set": before,
        "test_fitted": after,
        "changed_weights": {r: [base[r], w] for r, w in sorted(weights.items()) if w != base[r]},
        "adopt": clearly_better,
        "rule_for_adopting": "fitted recall interval entirely above today's, and false alarms not worse",
    }


def check_fast_state(samples: Sequence[Sample], judged: Sequence[Judged]) -> int:
    """How many judged URLs the plain-number scorer disagrees with the engine on (must be 0)."""
    from rules.url import RULES
    from rules.url.data import scoring

    cfg = scoring()
    cats = {r.id: r.category for r in RULES}
    bad = 0
    for _s, (state, _risk, rules) in zip(samples, judged, strict=True):
        if state == "ERROR" or (state == "BENIGN" and rules):
            continue  # allow-listed with signals: the allow-list is not in the judged data
        if fast_state(rules, state == "BENIGN", cfg["weights"], cats, cfg) != state:
            bad += 1
    return bad


# ---- report ---------------------------------------------------------------------------------------
def _pct(r: Mapping[str, Any] | None) -> str:
    if not r or r.get("rate") is None:
        return "-"
    lo, hi = r["ci"]
    return f"{100 * r['rate']:.1f}% ({100 * lo:.1f} to {100 * hi:.1f}), n={r['n']:,}"


def render(rep: Mapping[str, Any]) -> str:
    m, f = rep["measure"], rep.get("fit")
    lines = [
        "# The URL engine on real data (E1)", "",
        f"{rep['generated_at']}. Engine {rep['engine_version']}, ruleset {rep['ruleset_version']}. "
        f"{m['evaluated']:,} URLs (train and test splits; the reserve split, about 10%, is sealed). "
        "Every URL was parsed as text only: none was opened. Sources and licences: "
        "`.data/eval/sources.json`. Intervals are Wilson 95%.", "",
        "**Real data, not written by this project.** UNKNOWN counts as a miss, never as safe.", "",
        "## Phishing caught (SUSPICIOUS or MALICIOUS)", "", "| Set | Caught |", "|---|---|",
    ]  # fmt: skip
    for k, v in m["phishing"].items():
        lines.append(f"| {k.replace('_', ' ')} | {_pct(v)} |")
    lines += ["", "## False alarms on legitimate URLs", "", "| Set | Flagged |", "|---|---|"]
    for k, v in m["legitimate"].items():
        if k != "rules_on_flagged_urls_with_a_path":
            lines.append(f"| {k.replace('_', ' ')} | {_pct(v)} |")
    raised = m["legitimate"].get("rules_on_flagged_urls_with_a_path") or {}
    lines += [
        "",
        "Rules behind the false alarms on legitimate URLs with a path: "
        + (", ".join(f"`{r}` {n}" for r, n in raised.items()) or "none")
        + ".",
    ]
    lines += ["", "## By source", "", "| Source | Label | n | Result |", "|---|---|---|---|"]
    for k, v in m["sources"].items():
        result = v.get("flagged") or v.get("false_alarms")
        lines.append(f"| {k} | {v['label']} | {v['n']:,} | {_pct(result)} |")
    c = m["lexical_ceiling"]
    lines += [
        "", "## The lexical ceiling", "",
        f"- Real phishing URLs on which **no URL rule fires at all**: {_pct(c['no_rule_fired'])}. "
        "Reading the address cannot catch these; only looking at the page (or a list) can.",
        f"- Rules fired but too weakly to flag: {_pct(c['rules_fired_but_not_flagged'])}.", "",
        "## Phishing by kind of host", "", "| Host | n | Caught | No rule fired |", "|---|---|---|---|",
    ]  # fmt: skip
    for k, v in m["phishing_by_host_kind"].items():
        lines.append(
            f"| {k.replace('_', ' ')} | {v['n']:,} | {_pct(v['flagged'])} | {_pct(v['no_rule_fired'])} |"
        )
    lines += ["", "## Rules on real data", "",
              "| Rule | On phishing | On legitimate | Phishing hit rate | Legitimate hit rate |",
              "|---|---|---|---|---|"]  # fmt: skip
    for r, v in m["rules"].items():
        lines.append(
            f"| `{r}` | {v['on_phish']:,} | {v['on_legit']:,} | {v['phish_rate']} | {v['legit_rate']} |"
        )
    if f:
        lines += [
            "", "## Fitted weights (phase B)", "", f"Method: {f['method']}.", "",
            "| On the test split | Caught | False alarms |", "|---|---|---|",
            f"| hand-set weights | {_pct(f['test_hand_set']['recall'])} | {_pct(f['test_hand_set']['false_alarms'])} |",
            f"| fitted weights | {_pct(f['test_fitted']['recall'])} | {_pct(f['test_fitted']['false_alarms'])} |",
            "", f"Changed: {', '.join(f'`{r}` {a} to {b}' for r, (a, b) in f['changed_weights'].items()) or 'none'}.",
            f"Adopt: **{'yes' if f['adopt'] else 'no'}** ({f['rule_for_adopting']}).",
        ]  # fmt: skip
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.realurl", description=__doc__)
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    ap.add_argument("--tranco", type=int, default=50_000)
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    args = ap.parse_args(argv)
    from core.detection.engine import ENGINE_VERSION
    from rules.url.data import ruleset_version

    samples = load(args.data, args.tranco)
    judged = judge(samples, args.workers)
    mismatch = check_fast_state(samples, judged)
    rep: dict[str, Any] = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"),
        "engine_version": ENGINE_VERSION,
        "ruleset_version": ruleset_version(),
        "seed": SEED,
        "scorer_mismatches": mismatch,
        "measure": measure(samples, judged),
        "fit": fit(samples, judged) if mismatch == 0 else None,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "url-real.json").write_text(json.dumps(rep, indent=1), encoding="utf-8")
    (args.out / "url-real.md").write_text(render(rep), encoding="utf-8")
    print(render(rep))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
