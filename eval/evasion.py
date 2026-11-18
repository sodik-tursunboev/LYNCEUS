# ruff: noqa: E501  (report rows are long literals)
"""DA3: how easily can a phishing address the engine catches be made to slip past?

    python -m eval.evasion [--data .data/eval] [--out docs/eval] [--workers N]

Takes the phishing addresses of E1's test split that the whole address engine flags (the popular list
on, as the product runs) and changes each in one cheap, mechanical way a kit author could: another
ending, no hyphens, a digit on the name, a neutral subdomain, a harmless query, a longer path,
plain http. For each change it counts how many of the caught addresses are still flagged. A low number
means the engine leans on that feature. No new rule is added by this tool: it only measures.
"""

import argparse
import json
import os
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from eval import da1_rules
from eval import realurl as e1
from eval.learn_url import parsed
from eval.metrics import wilson

FLAGGED = ("SUSPICIOUS", "MALICIOUS")


def _swap(url: str, edit: Callable[[str, str], str], scheme: str | None = None) -> str | None:
    """`edit(label, suffix)` returns the new registered domain's text; the rest of the host is kept."""
    u = parsed(url)
    if u is None or not u.registered_domain or not u.host:
        return None
    label, _, suffix = u.registered_domain.partition(".")
    s = urlsplit(url)
    new = edit(label, suffix)
    host = u.host[: -len(u.registered_domain)] + new
    return f"{scheme or s.scheme}://{host}{s.path or '/'}" + (f"?{s.query}" if s.query else "")


MUTATIONS: dict[str, Callable[[str], str | None]] = {
    "another ending (.com)": lambda u: _swap(u, lambda label, suffix: f"{label}.com"),
    "no hyphens in the name": lambda u: _swap(u, lambda label, suffix: f"{label.replace('-', '')}.{suffix}"),
    "a digit on the name": lambda u: _swap(u, lambda label, suffix: f"{label}7.{suffix}"),
    "plain http": lambda u: _swap(u, lambda label, suffix: f"{label}.{suffix}", scheme="http"),
    "a neutral subdomain (www)": lambda u: (lambda s: f"{s.scheme}://www.{s.netloc}{s.path or '/'}" + (f"?{s.query}" if s.query else ""))(urlsplit(u)),
    "a harmless query (?utm_source=news)": lambda u: (u.split("#")[0] + ("&" if "?" in u else "?") + "utm_source=news"),
    "a longer path (/blog/2024/ first)": lambda u: (lambda s: f"{s.scheme}://{s.netloc}/blog/2024{s.path or '/'}" + (f"?{s.query}" if s.query else ""))(urlsplit(u)),
}  # fmt: skip


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None,
            "ci": [round(ci.low, 4), round(ci.high, 4)] if ci else None}  # fmt: skip


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.evasion", description=__doc__)
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    args = ap.parse_args(list(argv) if argv is not None else None)
    init = partial(da1_rules.setup, "C", args.data)
    test = [
        s
        for s in e1.load(args.data, 50_000)
        if e1.split_of(s.url) == "test" and s.label == e1.PHISH
    ]
    judged = e1.judge(test, args.workers, init)
    caught = [s.url for s, j in zip(test, judged, strict=True) if j[0] in FLAGGED]
    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"),
        "caught": len(caught),
        "of": len(test),
        "mutations": {},
    }
    for name, mutate in MUTATIONS.items():
        changed = [(u, m) for u in caught if (m := mutate(u)) and m != u]
        again = e1.judge([e1.Sample("", "", m) for _, m in changed], args.workers, init)
        report["mutations"][name] = _rate(sum(j[0] in FLAGGED for j in again), len(changed))
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "evasion.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    text = render(report)
    (args.out / "evasion.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


def render(rep: Mapping[str, Any]) -> str:
    def pct(r: Mapping[str, Any]) -> str:
        return (
            "n/a"
            if not r["n"]
            else f"{100 * r['rate']:.1f}% ({100 * r['ci'][0]:.1f} to {100 * r['ci'][1]:.1f}), {r['k']} of {r['n']}"
        )

    lines = [
        "# Evasion test (DA3)", "",
        f"{rep['generated_at']}. The {rep['caught']:,} phishing addresses of E1's test split that the whole address engine flags (of {rep['of']:,}); each is changed in one cheap way and judged again. The share still flagged shows how much the engine leans on the changed feature. Intervals are Wilson 95%.", "",
        "| one change | still flagged |", "|---|---|",
    ]  # fmt: skip
    lines += [f"| {n} | {pct(r)} |" for n, r in rep["mutations"].items()]
    return "\n".join([*lines, ""])


if __name__ == "__main__":
    raise SystemExit(main())
