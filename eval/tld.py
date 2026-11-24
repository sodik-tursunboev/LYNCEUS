# ruff: noqa: E501  (report rows are long literals)
"""DA4: can the learned domain model be made less dependent on a cheap ending?

    python -m eval.tld [--data .data/eval] [--out docs/eval] [--epochs 6]

DA3 found that moving a caught phishing name to `.com` leaves only 35.0% of the addresses flagged:
the model leans on the ending (`.top`, `.cc`, `.xyz`). This fits variants of the model on E1's train
split only, each calibrated the same way as the shipped one (threshold at 0.4% of the calibration
domains' legitimate names), and reads the test split:

  shipped         the features as they are
  name only       every feature that names or depends on the ending removed
  swap to .com    the shipped features, and each phishing training name also seen under .com
  swap to common  the same, under one of .com .net .org .info chosen per name
  swap both ways  the above, and each legitimate training name also seen under one of the ten
                  endings most used by phishing, so an ending alone proves less in either direction

For each: phishing caught as it stands (PhishTank, OpenPhish, PhiUSIIL), phishing caught after the
same name is moved to `.com`, legitimate names flagged as they stand and after moving to a cheap
ending. Nothing is adopted by this tool: the numbers decide, in docs/milestones/DA5.md.
"""

import argparse
import json
import random
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.learn.hostfeatures import features
from eval import realurl as e1
from eval.learn_url import parsed, part, prob, train
from eval.metrics import wilson

ENDING_TOKENS = ("suffix:", "suffix_len:", "suffix+len:", "suffix+hyph:")
COMMON = ("com", "net", "org", "info")

Row = tuple[str, int, str, set[str], str, str]  # domain, label, split, sources, name, ending


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None,
            "ci": [round(ci.low, 4), round(ci.high, 4)] if ci else None}  # fmt: skip


def _feats(name: str, ending: str, drop_ending: bool = False) -> list[int] | None:
    u = parsed(f"http://{name}.{ending}/")
    if u is None or not u.registered_domain:
        return None
    return [
        b for b, tok in features(u).items() if not (drop_ending and tok.startswith(ENDING_TOKENS))
    ]


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.tld", description=__doc__)
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    ap.add_argument("--epochs", type=int, default=6)
    args = ap.parse_args(list(argv) if argv is not None else None)

    seen: dict[tuple[str, int], tuple[str, set[str], str, str]] = {}
    labels_of: dict[str, set[int]] = defaultdict(set)
    for s in e1.load(args.data, 50_000):
        if s.source == "edge_history" or e1.split_of(s.url) == "reserve":
            continue
        u = parsed(s.url)
        if u is None or not u.registered_domain:
            continue
        y = 1 if s.label == e1.PHISH else 0
        labels_of[u.registered_domain].add(y)
        key = (u.registered_domain, y)
        if key in seen:
            seen[key][1].add(s.source)
        else:
            name, _, ending = u.registered_domain.partition(".")
            seen[key] = (part(u.registered_domain), {s.source}, name, ending)
    clash = {d for d, ys in labels_of.items() if len(ys) > 1}
    rows: list[Row] = [
        (d, y, p, src, name, ending)
        for (d, y), (p, src, name, ending) in seen.items()
        if d not in clash
    ]
    cheap = [
        e for e, _ in Counter(r[5] for r in rows if r[1] == 1 and r[2] == "train").most_common(10)
    ]
    rng = random.Random("lynceus-da4-tld")  # noqa: S311  (a seeded sample, not a secret)

    def fit(variant: str, quantile: float = 0.996) -> tuple[float, list[float], float]:
        drop = variant == "name only"
        fit_rows: list[tuple[list[int], int]] = []
        for _, y, p, _, name, ending in rows:
            if p != "train":
                continue
            f = _feats(name, ending, drop)
            if f is not None:
                fit_rows.append((f, y))
            extra: str | None = None
            if variant == "swap to .com" and y == 1:
                extra = "com"
            elif variant in ("swap to common", "swap both ways") and y == 1:
                extra = rng.choice(COMMON)
            elif variant == "swap both ways" and y == 0:
                extra = rng.choice(cheap)
            if extra is not None and extra != ending:
                g = _feats(name, extra)
                if g is not None:
                    fit_rows.append((g, y))
        bias, w = train(fit_rows, args.epochs)
        calib = sorted(
            prob(bias, w, f)
            for _, y, p, _, name, ending in rows
            if p == "calib" and y == 0 and (f := _feats(name, ending, drop)) is not None
        )
        return bias, w, max(calib[int(len(calib) * quantile)], 0.5)

    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"),
        "cheap_endings": cheap,
        "variants": {},
    }
    test = [r for r in rows if r[2] == "test"]
    either = "either shipped or swap to .com (each at 0.2%)"
    for variant in (
        "shipped",
        "name only",
        "swap to .com",
        "swap to common",
        "swap both ways",
        either,
    ):
        if (
            variant == either
        ):  # two models, each at half the false-alarm budget; flagged if either flags
            models = [fit("shipped", 0.998), fit("swap to .com", 0.998)]
        else:
            models = [fit(variant)]
        thr = models[0][2]
        drop = variant == "name only"

        def flagged(
            sel: Sequence[Row],
            ending: str | None,
            drop: bool = drop,
            models: list[tuple[float, list[float], float]] = models,
        ) -> tuple[int, int]:
            k = n = 0
            for _, _, _, _, name, own in sel:
                f = _feats(name, ending or own, drop)
                if f is None:
                    continue
                n += 1
                k += any(prob(b, w, f) >= t for b, w, t in models)
            return k, n

        def pick(y: int, source: str | None = None) -> list[Row]:
            return [r for r in test if r[1] == y and (source is None or source in r[3])]

        out: dict[str, Any] = {"threshold": round(thr, 4)}
        for label, source in (
            ("PhishTank", "phishtank"),
            ("OpenPhish", "openphish"),
            ("PhiUSIIL", "phiusiil"),
        ):
            out[f"{label} phishing, as it stands"] = _rate(*flagged(pick(1, source), None))
        out["all test phishing, as it stands"] = _rate(*flagged(pick(1), None))
        out["all test phishing, moved to .com"] = _rate(*flagged(pick(1), "com"))
        out["legitimate, as it stands"] = _rate(*flagged(pick(0), None))
        sample = rng.sample(pick(0), min(8000, len(pick(0))))
        out["legitimate (8,000), moved to a cheap ending"] = _rate(
            *[sum(x) for x in zip(*(flagged([r], rng.choice(cheap)) for r in sample), strict=True)]
        )
        report["variants"][variant] = out
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "tld.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    text = render(report)
    (args.out / "tld.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


def render(rep: Mapping[str, Any]) -> str:
    def pct(r: Mapping[str, Any]) -> str:
        return (
            "n/a"
            if not r["n"]
            else f"{100 * r['rate']:.1f}% ({100 * r['ci'][0]:.1f} to {100 * r['ci'][1]:.1f}), {r['k']} of {r['n']}"
        )

    names = list(rep["variants"])
    sets = [k for k in rep["variants"][names[0]] if k != "threshold"]
    lines = [
        "# Less dependence on a cheap ending? (DA4)", "",
        f"{rep['generated_at']}. Domain-name model only (no URL rules), fitted on E1's train split, threshold at 0.4% of the calibration domains' legitimate names for each variant, read on the test split. The ten endings most used by phishing in the train split: {', '.join('.' + e for e in rep['cheap_endings'])}. Intervals are Wilson 95%.", "",
        "| test set | " + " | ".join(f"{n} (threshold {rep['variants'][n]['threshold']})" for n in names) + " |",
        "|---|" + "---|" * len(names),
    ]  # fmt: skip
    lines += [
        f"| {s} | " + " | ".join(pct(rep["variants"][n][s]) for n in names) + " |" for s in sets
    ]
    return "\n".join([*lines, ""])


if __name__ == "__main__":
    raise SystemExit(main())
