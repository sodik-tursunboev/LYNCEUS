"""AI1 P1: train the learned domain model on E1 and measure it honestly.

    python -m eval.learn_url [--data .data/eval] [--out docs/eval] [--workers N] [--epochs 6]

Split by REGISTERED DOMAIN (crc32 % 10: 0-5 train, 6 calibration, 7-9 test), so one phishing
domain with a thousand URLs cannot sit on both sides. E1's sealed reserve stays out. Training uses
each host once. Your browsing (Edge history, as in E1) is never trained on: weights trained on it
would carry pieces of the sites you visit; it is only counted as a false-alarm check. The threshold
is chosen on the calibration domains (DA1: at most 0.4% of their legitimate hosts above it).
Results are compared with the URL rules alone and with the whole product on the same URLs: the
test domains, D1's live pages whose domains the model never saw, and (DA1) ordinary long-tail
sites, where rules about unknown domains really fire. Pure Python: no new dependency. Writes the
weights to
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
from functools import partial
from pathlib import Path
from typing import Any

from core.learn.hostfeatures import BUCKETS, features
from core.learn.model import pack
from core.urls.parse import ParsedUrl, parse_url
from eval import realurl as e1
from eval.metrics import wilson

SEED = "lynceus-ai1-p1"
TAIL = "lynceus-da1-tail-test"
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


def use_model(header: Path | None) -> None:
    """In each judging worker: the engine with no learned model (the rules alone) or this one."""
    from core.learn import model

    model.use(model.load(header) if header else None)


def tail_sample(data: Path, n: int) -> list[str]:
    """DA1: home pages of ordinary long-tail sites (Tranco ranks 100,001 to 1,000,000), which
    neither E1 (its top 50,000) nor the popular list (top 100,000) covers. A seeded sample."""
    ranked = [s.url for s in e1.tranco(data / "tranco-top-1m.csv.zip", 1_000_000)][100_000:]
    return random.Random(TAIL).sample(ranked, min(n, len(ranked)))  # noqa: S311  (not a secret)


def write_model(out: Path, bias: float, w: Sequence[float], threshold: float) -> None:
    """`url_host.bin` (16-bit weights) and `url_host.json` (the header with their SHA-256)."""
    raw, scale = pack(list(w))
    (out / "url_host.bin").write_bytes(raw)
    header = {
        "version": f"domain-lr-2+{SEED}", "bias": bias, "scale": scale,
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
    # DA1: 0.4% (was 0.5%), chosen on the calibration domains with model 2's features
    threshold = calib_legit[int(len(calib_legit) * 0.996)] if calib_legit else 0.5
    threshold = max(threshold, 0.5)
    out = args.data / "learned"
    out.mkdir(parents=True, exist_ok=True)
    write_model(out, bias, w, threshold)

    sets: dict[str, list[str]] = defaultdict(list)
    for s in samples:
        if (u := parsed(s.url)) and u.registered_domain and part(u.registered_domain) == "test":
            sets[f"{s.source} {s.label}"].append(s.url)
    sets["long-tail sites (Tranco 100,001 to 1M, home pages)"] = tail_sample(args.data, 3000)
    seen_domains = {u.registered_domain for s in samples if (u := parsed(s.url))
                    and u.registered_domain and part(u.registered_domain) != "test"}  # fmt: skip
    d1_rows = [json.loads(line) for line in (args.data / "d1" / "results.jsonl").read_text(
        encoding="utf-8").splitlines()]  # fmt: skip
    for label in ("phish", "legit"):
        sets[f"D1 live {label} pages, address only (domains never seen)"] = [
            r["url"] for r in d1_rows
            if r["label"] == label and (u := parsed(r["url"]))
            and u.registered_domain not in seen_domains
        ]  # fmt: skip
    sets["your browsing (never trained on)"] = [
        s.url for s in samples if s.source == "edge_history"
    ]
    urls = sorted({url for group in sets.values() for url in group})
    batch = [e1.Sample("", "", url) for url in urls]
    rules_alone = dict(
        zip(urls, e1.judge(batch, args.workers, partial(use_model, None)), strict=True)
    )
    product = dict(
        zip(urls, e1.judge(batch, args.workers, partial(use_model, out / "url_host.json")),
            strict=True)
    )  # fmt: skip

    def model_flag(url: str) -> bool:
        u = parsed(url)
        return u is not None and prob(bias, w, features(u)) >= threshold

    measured: dict[str, dict[str, Any]] = {}
    for name, group in sets.items():
        measured[name] = {
            "rules": _rate(sum(rules_alone[url][0] in FLAGGED for url in group), len(group)),
            "model": _rate(sum(model_flag(url) for url in group), len(group)),
            "product": _rate(sum(product[url][0] in FLAGGED for url in group), len(group)),
        }
    report = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"),
        "seed": SEED, "epochs": args.epochs, "train_hosts": len(rows),
        "threshold": round(threshold, 4),
        "label_clashes_dropped": len(clash), "sets": measured,
        "nonzero_weights": sum(1 for x in w if abs(x) >= 0.002),
    }  # fmt: skip
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
        "# Learned domain model (AI1 P1; model 2 since DA1)", "",
        f"{rep['generated_at']}. Logistic regression on registered-domain features, "
        f"{rep['train_hosts']:,} training domains, {rep['epochs']} epochs, seed `{rep['seed']}`. "
        "Split by registered domain; test domains were never seen in training. Threshold "
        f"{rep['threshold']}, chosen on the calibration domains (at most 0.4% of their legitimate "
        "hosts above it). Flagged means SUSPICIOUS or MALICIOUS from the address alone, without "
        "the popular-domain list. Intervals are Wilson 95%.", "",
        "| set | URL rules alone | model alone | the product with this model |",
        "|---|---|---|---|",
    ]  # fmt: skip
    for name, r in rep["sets"].items():
        lines.append(f"| {name} | {pct(r['rules'])} | {pct(r['model'])} | {pct(r['product'])} |")
    return "\n".join([*lines, ""])


if __name__ == "__main__":
    raise SystemExit(main())
