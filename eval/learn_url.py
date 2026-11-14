"""AI1 P1: train the learned domain model on E1 and measure it honestly.

    python -m eval.learn_url [--data .data/eval] [--out docs/eval] [--workers N] [--epochs 6]

Split by REGISTERED DOMAIN (crc32 % 10: 0-5 train, 6 calibration, 7-9 test), so one phishing
domain with a thousand URLs cannot sit on both sides. E1's sealed reserve stays out. Training uses
each host once. Your browsing (Edge history, as in E1) is never trained on: weights trained on it
would carry pieces of the sites you visit; it is only counted as a false-alarm check. The threshold
is chosen on the calibration domains (at most 0.5% of their legitimate hosts flagged). Results
are compared with the URL rules on the same test URLs, and checked on D1's live pages whose
domains the model never saw. Pure Python: no new dependency. Writes the weights to
`.data/eval/learned/url_host.{json,bin}` (local); copying them to `rules/learned/` is the
adoption step.
"""

import argparse
import hashlib
import json
import math
import os
import random
import zlib
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.learn.hostfeatures import BUCKETS, features
from core.learn.model import pack
from core.urls.parse import ParsedUrl, parse_url
from eval import realurl as e1
from eval.metrics import wilson

SEED = "lynceus-ai1-p1"
FLAGGED = ("SUSPICIOUS", "MALICIOUS")


def part(registered: str) -> str:
    n = zlib.crc32(f"{SEED}:{registered}".encode()) % 10
    return "train" if n < 6 else "calib" if n == 6 else "test"


def parsed(url: str) -> ParsedUrl | None:
    u = parse_url(url)
    return u if isinstance(u, ParsedUrl) and u.host else None


def train(rows: Sequence[tuple[list[int], int]], epochs: int) -> tuple[float, list[float]]:
    """Logistic regression by SGD with L2, classes weighted to balance."""
    w = [0.0] * BUCKETS
    bias = 0.0
    pos = sum(y for _, y in rows) or 1
    neg = (len(rows) - pos) or 1
    weight = {1: len(rows) / (2 * pos), 0: len(rows) / (2 * neg)}
    order = list(range(len(rows)))
    rng = random.Random(SEED)  # noqa: S311  (a fixed training order, not a secret)
    l2 = 1e-6
    for epoch in range(epochs):
        rng.shuffle(order)
        rate = 0.2 / (1 + epoch)
        for k in order:
            idx, y = rows[k]
            z = bias + sum(w[i] for i in idx)
            p = 1.0 / (1.0 + math.exp(-max(-40.0, min(40.0, z))))
            g = (p - y) * weight[y] * rate
            bias -= g
            for i in idx:
                w[i] -= g + l2 * w[i]
    return bias, w


def prob(bias: float, w: Sequence[float], idx: Iterable[int]) -> float:
    z = bias + sum(w[i] for i in idx)
    return 1.0 / (1.0 + math.exp(-max(-40.0, min(40.0, z))))


def write_model(out: Path, bias: float, w: Sequence[float], threshold: float) -> None:
    """`url_host.bin` (16-bit weights) and `url_host.json` (the header with their SHA-256)."""
    raw, scale = pack(list(w))
    (out / "url_host.bin").write_bytes(raw)
    header = {
        "version": f"domain-lr-1+{SEED}", "bias": bias, "scale": scale,
        "threshold": round(threshold, 4), "buckets": BUCKETS,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "trained_on": "E1 train domains (PhiUSIIL, PhishTank and OpenPhish of 2026-11-10, Tranco)",
    }  # fmt: skip
    (out / "url_host.json").write_text(json.dumps(header, indent=1), encoding="utf-8")


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None,
            "ci": [round(ci.low, 4), round(ci.high, 4)] if ci else None}  # fmt: skip


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.learn_url", description=__doc__)
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--epochs", type=int, default=6)
    args = ap.parse_args(list(argv) if argv is not None else None)

    samples = [s for s in e1.load(args.data, 50_000) if e1.split_of(s.url) != "reserve"]
    # (registered domain, label) -> (part, features): the model reads the registered domain only
    hosts: dict[tuple[str, int], tuple[str, list[int]]] = {}
    labels_of: dict[str, set[int]] = defaultdict(set)
    for s in samples:
        if s.source == "edge_history":
            continue  # never trained on (see the module text)
        u = parsed(s.url)
        if u is None or not u.registered_domain:
            continue
        y = 1 if s.label == e1.PHISH else 0
        labels_of[u.registered_domain].add(y)
        hosts.setdefault((u.registered_domain, y), (part(u.registered_domain), list(features(u))))
    clash = {h for h, ys in labels_of.items() if len(ys) > 1}
    rows = [(f, y) for (h, y), (p, f) in hosts.items() if p == "train" and h not in clash]
    bias, w = train(rows, args.epochs)

    calib_legit = sorted(
        prob(bias, w, f) for (h, y), (p, f) in hosts.items() if p == "calib" and y == 0
    )
    threshold = calib_legit[int(len(calib_legit) * 0.995)] if calib_legit else 0.5
    threshold = max(threshold, 0.5)

    test = [s for s in samples if (u := parsed(s.url)) and u.registered_domain
            and part(u.registered_domain) == "test"]  # fmt: skip
    browsing = [s for s in samples if s.source == "edge_history"]
    states = dict(zip([s.url for s in test], e1.judge(test, args.workers), strict=True))

    def model_flag(url: str) -> bool:
        u = parsed(url)
        return u is not None and prob(bias, w, features(u)) >= threshold

    by_source: dict[str, dict[str, Any]] = {}
    groups: dict[str, list[e1.Sample]] = defaultdict(list)
    for s in test:
        groups[f"{s.source} {s.label}"].append(s)
    for name, group in sorted(groups.items()):
        rules = [states[s.url][0] in FLAGGED for s in group]
        model = [model_flag(s.url) for s in group]
        by_source[name] = {
            "rules": _rate(sum(rules), len(group)),
            "model": _rate(sum(model), len(group)),
            "rules_or_model": _rate(
                sum(a or b for a, b in zip(rules, model, strict=True)), len(group)
            ),
        }
    seen_domains = {u.registered_domain for s in samples if (u := parsed(s.url))
                    and u.registered_domain and part(u.registered_domain) != "test"}  # fmt: skip
    d1_rows = [json.loads(line) for line in (args.data / "d1" / "results.jsonl").read_text(
        encoding="utf-8").splitlines()]  # fmt: skip
    d1: dict[str, dict[str, Any]] = {}
    for label in ("phish", "legit"):
        fresh = [r for r in d1_rows if r["label"] == label
                 and (u := parsed(r["url"]))
                 and u.registered_domain not in seen_domains]  # fmt: skip
        d1[f"D1 {label} (domains the model never saw)"] = {
            "url_rules": _rate(sum(r["url_state"] in FLAGGED for r in fresh), len(fresh)),
            "model": _rate(sum(model_flag(r["url"]) for r in fresh), len(fresh)),
        }
    report = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"),
        "seed": SEED, "epochs": args.epochs, "train_hosts": len(rows),
        "threshold": round(threshold, 4), "label_clashes_dropped": len(clash),
        "test_by_source": by_source, "d1": d1,
        "your_browsing_flagged": _rate(sum(model_flag(s.url) for s in browsing), len(browsing)),
        "nonzero_weights": sum(1 for x in w if abs(x) >= 0.002),
    }  # fmt: skip
    out = args.data / "learned"
    out.mkdir(parents=True, exist_ok=True)
    write_model(out, bias, w, threshold)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "learned-url.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    (args.out / "learned-url.md").write_text(render(report), encoding="utf-8")
    print(render(report))
    return 0


def render(rep: Mapping[str, Any]) -> str:
    def pct(r: Mapping[str, Any]) -> str:
        if not r["n"]:
            return "-"
        lo, hi = 100 * r["ci"][0], 100 * r["ci"][1]
        return f"{100 * r['rate']:.1f}% ({lo:.1f} to {hi:.1f}), {r['k']} of {r['n']}"

    lines = [
        "# Learned domain model (AI1 P1)", "",
        f"{rep['generated_at']}. Logistic regression on registered-domain features, "
        f"{rep['train_hosts']:,} training domains, {rep['epochs']} epochs, seed `{rep['seed']}`. "
        "Split by registered domain; "
        f"threshold {rep['threshold']} chosen on calibration domains (at most 0.5% of their "
        "legitimate hosts flagged). Test domains were never seen in training.", "",
        "## Test domains (E1): the URL rules, the model, and either", "",
        "| set | URL rules | model | rules or model |", "|---|---|---|---|",
    ]  # fmt: skip
    for name, r in rep["test_by_source"].items():
        lines.append(
            f"| {name} | {pct(r['rules'])} | {pct(r['model'])} | {pct(r['rules_or_model'])} |"
        )
    lines += ["", "## D1 live pages (2026-11-11), domains the model never saw", "",
              "| set | URL rules | model |", "|---|---|---|"]  # fmt: skip
    for name, r in rep["d1"].items():
        lines.append(f"| {name} | {pct(r['url_rules'])} | {pct(r['model'])} |")
    lines += ["", f"Your browsing (never trained on), flagged by the model: "
              f"{pct(rep['your_browsing_flagged'])}.", ""]  # fmt: skip
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
