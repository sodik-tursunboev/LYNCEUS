# ruff: noqa: E501  (report rows are long literal lines)
"""Calibrate the verdict's bands as LIKELIHOODS (DA5 phase 3, item 4).

    python -m eval.calibrate [--data .data/eval] [--out docs/eval] [--workers 3] [--refresh]
    python -m eval.calibrate check [--out docs/eval]

Offline: E1 (the address engine over real labelled URLs, parsed as text, never opened) and D1 (the
pages kept from the live runs, judged again with today's rules; nothing is opened). Per score band
and per state/confidence tier it measures, on a FITTING half and again on a HELD-OUT half the fit
never saw, two rates with Wilson 95% intervals:

  detection    the share of PHISHING samples that land in the band
  false alarm  the share of LEGITIMATE samples that land in the band

Both are likelihoods. They are not "the chance a page in this band is phishing": E1 and D1 are about
half phishing and a person's traffic is a tiny fraction, so that number measured here would mean
nothing. `posterior` shows it only as an illustration at a stated prevalence.

Splits are the evaluation sets' own: E1 `split_of` (train fits, test is held out, the sealed reserve
is never read) and D1 `split_of` (dev fits, test is held out). Nothing is fitted on a held-out half.
`check` prints CALIBRATION MET only if, for every band with at least 30 samples in both halves, both
rates measured on the fitting half reproduce on the held-out half within 0.05 absolute.
"""

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ProcessPoolExecutor
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any, NamedTuple

from core.risk import calibration as cal
from eval import detonate as d1
from eval import realurl as e1
from eval.metrics import wilson

TOLERANCE = 0.05  # the criterion: |rate on the fitting half - rate on the held-out half|
MIN_SAMPLES = 30  # a band is checked when it holds at least this many samples in BOTH halves
PREVALENCE = 0.001  # the illustration only: 1 phishing page in 1,000
HALVES = ("fit", "held")
LABELS = (e1.PHISH, e1.LEGIT)
FAMILIES = ("score", "tier")
SEVERITY = ("MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN", "ERROR")
D1_FOLDERS = ("da1-2026-11-16", "d1")  # the newer run first: a URL in both is judged once


class Row(NamedTuple):
    ds: str  # e1 | d1
    half: str  # fit | held
    label: str  # phish | legit
    state: str
    risk: int | None
    conf: str
    dom: str  # short hash of the registered domain ("" if none): only to measure split overlap


def _dom(registered: str | None) -> str:
    return hashlib.sha256(registered.encode()).hexdigest()[:12] if registered else ""


# ---- judging --------------------------------------------------------------------------------------
def _setup(data: Path) -> None:
    from core.urls import popular

    popular.configure(data.parent / "popular")  # the list the core uses, as the product runs


def _batch(urls: Sequence[str]) -> list[tuple[str, int | None, str, str]]:
    from core.detection.engine import analyze_url

    out = []
    for u in urls:
        a = analyze_url(u)
        v = a.verdict
        out.append(
            (
                v.state.value,
                v.risk_score,
                v.confidence.value,
                _dom(a.url.registered_domain if a.url else None),
            )
        )
    return out


def e1_rows(data: Path, workers: int) -> list[Row]:
    """The address engine over E1's train and test splits (the reserve is dropped before judging)."""
    samples = [s for s in e1.load(data, 50_000) if e1.split_of(s.url) != "reserve"]
    urls = [s.url for s in samples]
    chunks = [urls[i : i + 2000] for i in range(0, len(urls), 2000)]
    judged: list[tuple[str, int | None, str, str]] = []
    with ProcessPoolExecutor(max_workers=workers, initializer=partial(_setup, data)) as pool:
        for i, part in enumerate(pool.map(_batch, chunks), 1):
            judged += part
            if i % 10 == 0:
                print(f"  e1 {i}/{len(chunks)} chunks", flush=True)
    return [
        Row("e1", "fit" if e1.split_of(s.url) == "train" else "held", s.label, *j)
        for s, j in zip(samples, judged, strict=True)
    ]


def d1_rows(data: Path) -> list[Row]:
    """The address plus the opened page, as the product judges a live page: the kept pages of both
    live runs, judged again with today's rules (dead pages add nothing and stay in)."""
    from core.detection.engine import analyze_url
    from core.detonate.judge import judge
    from core.detonate.models import PageReport

    _setup(data)
    rows: dict[str, Row] = {}
    for folder in D1_FOLDERS:
        for line in (data / folder / "results.jsonl").read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            kept = data / folder / "pages" / f"{d1._key(r['url'])}.json"
            if r["url"] in rows or not kept.exists():
                continue
            start = analyze_url(r["url"])
            v = judge(
                start, PageReport.model_validate_json(kept.read_text(encoding="utf-8"))
            ).verdict
            rows[r["url"]] = Row(
                "d1", "fit" if d1.split_of(r["url"]) == "dev" else "held", r["label"],
                v.state.value, v.risk_score, v.confidence.value,
                _dom(start.url.registered_domain if start.url else None),
            )  # fmt: skip
    return list(rows.values())


def _stamp(data: Path) -> str:
    """What the cached rows depend on: the engine, the rules, the learned model, the popular list."""
    from core.detection.engine import ENGINE_VERSION
    from core.learn import model
    from rules.url.data import ruleset_version

    m = model.current()
    listed = data.parent / "popular" / "tranco-top.txt"
    popular = hashlib.sha256(listed.read_bytes()).hexdigest()[:8] if listed.exists() else "none"
    return f"{ENGINE_VERSION}|{ruleset_version()}|{m.version if m else 'none'}|{popular}"


def _cached(path: Path, stamp: str, build: Callable[[], list[Row]], refresh: bool) -> list[Row]:
    if path.exists() and not refresh:
        head, *lines = path.read_text(encoding="utf-8").splitlines()
        if head == stamp:
            return [Row(*json.loads(x)) for x in lines]
    rows = build()
    path.parent.mkdir(parents=True, exist_ok=True)
    body = [stamp, *(json.dumps(list(r)) for r in rows)]
    path.write_text("\n".join(body) + "\n", encoding="utf-8")
    return rows


# ---- measurement ----------------------------------------------------------------------------------
def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 6) if n else None,
            "ci": [round(ci.low, 6), round(ci.high, 6)] if ci else None}  # fmt: skip


def _order(family: str, band: str) -> tuple[int, str]:
    return (SEVERITY.index(band.split()[0]) if family == "tier" else 0, band)


def measure(rows: Sequence[Row]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for ds in sorted({r.ds for r in rows}):
        sub = [r for r in rows if r.ds == ds]
        total = Counter((r.half, r.label) for r in sub)
        seen: Counter[tuple[str, str, str, str]] = Counter()
        for r in sub:
            for fam, band in zip(FAMILIES, cal.bands_of(r.state, r.risk, r.conf), strict=True):
                seen[(fam, band, r.half, r.label)] += 1
        bands: dict[str, Any] = {}
        for fam in FAMILIES:
            names = sorted({b for f, b, _, _ in seen if f == fam}, key=lambda b: _order(fam, b))
            bands[fam] = {b: _band(seen, total, fam, b) for b in names}
        fit_doms = {r.dom for r in sub if r.half == "fit" and r.dom}
        held = [r for r in sub if r.half == "held" and r.dom]
        out[ds] = {
            "n": {h: {x: total[(h, x)] for x in LABELS} for h in HALVES},
            "bands": bands,
            # the splits cut by address, not by registered domain: how many held-out samples share a domain with the fit half
            "domain_overlap": {
                x: _rate(
                    sum(r.dom in fit_doms for r in held if r.label == x),
                    sum(r.label == x for r in held),
                )
                for x in LABELS
            },
        }
    return out


def _band(
    seen: Mapping[tuple[str, str, str, str], int],
    total: Mapping[tuple[str, str], int],
    fam: str,
    band: str,
) -> dict[str, Any]:
    b: dict[str, Any] = {}
    for h in HALVES:
        k = {x: seen.get((fam, band, h, x), 0) for x in LABELS}
        b[h] = {
            "samples": sum(k.values()),
            "detection": _rate(k[e1.PHISH], total[(h, e1.PHISH)]),
            "false_alarm": _rate(k[e1.LEGIT], total[(h, e1.LEGIT)]),
        }
    b["checked"] = min(b["fit"]["samples"], b["held"]["samples"]) >= MIN_SAMPLES
    return b


def disjoint(rows: Sequence[Row]) -> list[Row]:
    """The rows without the held-out ones whose registered domain is also in the fitting half."""
    fit = {(r.ds, r.dom) for r in rows if r.half == "fit" and r.dom}
    return [r for r in rows if not (r.half == "held" and (r.ds, r.dom) in fit)]


def failures(rep: Mapping[str, Any]) -> list[str]:
    """The criterion, recomputed from the stored counts: one line per band and rate that fails."""
    bad = []
    for ds, d in rep["sets"].items():
        for fam, bands in d["bands"].items():
            for band, b in bands.items():
                if min(b["fit"]["samples"], b["held"]["samples"]) < MIN_SAMPLES:
                    continue
                for what in ("detection", "false_alarm"):
                    f, h = b["fit"][what], b["held"][what]
                    if not f["n"] or not h["n"]:
                        bad.append(f"{ds} {fam} '{band}' {what}: a half has none of that class")
                        continue
                    a, c = f["k"] / f["n"], h["k"] / h["n"]
                    if abs(a - c) > TOLERANCE:
                        bad.append(
                            f"{ds} {fam} '{band}' {what}: fit {a:.4f}, held-out {c:.4f}, gap {abs(a - c):.4f}"
                        )
    return bad


# ---- outputs --------------------------------------------------------------------------------------
def _pct(r: Mapping[str, Any]) -> str:
    if r["rate"] is None:
        return "n/a"
    digits = 1 if r["rate"] >= 0.1 else 2 if r["rate"] >= 0.01 else 3
    lo, hi = 100 * r["ci"][0], 100 * r["ci"][1]
    return f"{100 * r['rate']:.{digits}f}% ({lo:.{digits}f} to {hi:.{digits}f})"


def _gap(b: Mapping[str, Any], what: str) -> str:
    f, h = b["fit"][what], b["held"][what]
    if f["rate"] is None or h["rate"] is None:
        return "n/a"
    return f"{abs(f['rate'] - h['rate']):.3f}"


def render(rep: Mapping[str, Any]) -> str:
    from core.risk.asktable import TABLE

    bad = rep["check"]["failures"]
    names = {"e1": ("E1: the address engine alone", "train", "test"),
             "d1": ("D1: the address plus the opened page", "dev", "test")}  # fmt: skip
    lines = [
        "# Calibration of the verdict bands (DA5 phase 3, item 4)", "",
        f"{rep['generated']}. Engine and rules: `{rep['stamp']}`. Offline: nothing was opened or fetched. "
        "**Likelihoods, not probabilities.** For each band the table gives the *detection rate* (the share of "
        "phishing samples that land in the band) and the *false-alarm rate* (the share of legitimate samples that "
        "land in it), each with its Wilson 95% interval, measured on a fitting half and again on a held-out half "
        "that the fit never saw. The sets are about half phishing and a person's traffic is a tiny fraction, so "
        "\"how often is a page in this band phishing\" measured here would mean nothing; it is shown only as an "
        f"illustration at an assumed prevalence of 1 in {round(1 / PREVALENCE):,}.", "",
        f"**Criterion** (fixed before measuring, not loosened): for every band with at least {MIN_SAMPLES} samples "
        f"(phishing and legitimate together) in both halves, both rates on the fitting half must reproduce on the "
        f"held-out half within {TOLERANCE} absolute. `python -m eval.calibrate check` re-computes it from "
        "`calibration.json`.", "",
        "**Result: CALIBRATION MET.**" if not bad else f"**Result: CALIBRATION NOT MET** ({len(bad)} failing):",
    ]  # fmt: skip
    lines += [f"- {x}" for x in bad] + [""]
    for ds, d in rep["sets"].items():
        title, fit, held = names[ds]
        n = d["n"]
        lines += [
            f"## {title}", "",
            f"Fitting half = {fit} split ({n['fit']['phish']:,} phishing, {n['fit']['legit']:,} legitimate); "
            f"held-out half = {held} split ({n['held']['phish']:,} phishing, {n['held']['legit']:,} legitimate).", "",
        ]  # fmt: skip
        for fam, heading in (("tier", "By state and confidence tier"), ("score", "By score band")):
            lines += [
                f"### {heading}",
                "",
                "| band | samples fit / held | detection, fit | detection, held-out | gap | false alarm, fit | false alarm, held-out | gap | checked |",
                "|---|---|---|---|---|---|---|---|---|",
            ]
            for band, b in d["bands"][fam].items():
                lines.append(
                    f"| {band} | {b['fit']['samples']:,} / {b['held']['samples']:,} | {_pct(b['fit']['detection'])} "
                    f"| {_pct(b['held']['detection'])} | {_gap(b, 'detection')} | {_pct(b['fit']['false_alarm'])} "
                    f"| {_pct(b['held']['false_alarm'])} | {_gap(b, 'false_alarm')} | {'yes' if b['checked'] else 'no, under ' + str(MIN_SAMPLES)} |"
                )
            lines.append("")
        lines += [
            f"### Illustration: P(phishing | tier) at an assumed 1 in {round(1 / PREVALENCE):,} (fitting half)", "",
            "Bayes from the two likelihoods above; **an illustration, not a measurement**: the prevalence is "
            "assumed, and the legitimate samples are not a person's real traffic. The conservative column uses the "
            "low end of the detection interval and the high end of the false-alarm interval.", "",
            "| tier | likelihood ratio (detection / false alarm) | P(phishing) at the assumed prevalence | conservative |",
            "|---|---|---|---|",
        ]  # fmt: skip
        for band, b in d["bands"]["tier"].items():
            dr, fa = b["fit"]["detection"], b["fit"]["false_alarm"]
            if not dr["n"] or not fa["n"] or not dr["k"]:
                lines.append(f"| {band} | n/a (no phishing in the band) | 0 | 0 |")
                continue
            ratio = (
                f"{dr['rate'] / fa['rate']:,.1f}"
                if fa["rate"]
                else "no legitimate sample (unbounded)"
            )
            point = (
                f"{100 * cal.posterior(PREVALENCE, dr['rate'], fa['rate']):.2f}%"
                if fa["rate"]
                else "undefined (no legitimate sample)"
            )
            lines.append(
                f"| {band} | {ratio} | {point} "
                f"| {100 * cal.posterior(PREVALENCE, dr['ci'][0], fa['ci'][1]):.2f}% |"
            )
        ov = d["domain_overlap"]
        lines += [
            "", "### Split overlap", "",
            "The splits cut by address, not by registered domain, so one domain can sit in both halves. Held-out "
            f"samples whose registered domain is also in the fitting half: phishing {_pct(ov['phish'])}, "
            f"legitimate {_pct(ov['legit'])}. The more of this, the kinder the held-out half is to the fit.", "",
        ]  # fmt: skip
    strict = rep["domain_disjoint"]
    left = ", ".join(
        f"{ds.upper()} {d['n']['held']['phish']:,} phishing and {d['n']['held']['legit']:,} legitimate"
        for ds, d in strict["sets"].items()
    )
    lines += [
        "## Robustness: held-out samples on domains the fitting half never saw", "",
        "The same criterion with every held-out sample that shares a registered domain with the fitting half removed "
        f"(left: {left}). It is not the criterion above and `check` does not read it; it shows how much the "
        "address-level split flatters the result. Dropping the overlap also drops the repeat domains (shared "
        "hosts, mass-made names), so what remains is a different mix and not only an unseen one: a gap here "
        "means the rates depend on which domains a half holds, not necessarily that the engine is worse on a "
        "domain it has not met.",
        "",
        "**Same criterion on those: MET.**"
        if not strict["failures"]
        else f"**Same criterion on those: NOT MET** ({len(strict['failures'])} failing):",
    ]  # fmt: skip
    lines += [f"- {x}" for x in strict["failures"]] + [""]
    lines += [
        "## What this does not show", "",
        "- In this table \"false alarm\" is only the share of legitimate samples in the band. In a SUSPICIOUS or "
        "MALICIOUS band that is a false alarm; in BENIGN or UNKNOWN it is the share of legitimate samples that got "
        "that answer, which is what a legitimate page should get.",
        "- A 0.05 absolute gap is wide for a band holding a small share of a class (under 5%): such a band passes the "
        "criterion by construction. Only the large bands (the UNKNOWN tier, SUSPICIOUS LOW, the 45-59 score band) "
        "are tested hard; for the others read the intervals.",
        "- The legitimate sets are not a person's traffic: E1's are home pages of popular sites, an older dataset and "
        "92 pages of one person's history; D1's are popular home pages and /login. A person's deep links are warned "
        "more often (DA2, `docs/eval/deeplinks.md`). The false-alarm rates are those of these sets only.",
        "- D1 is small and live; its halves are noisy, so a band can miss the 0.05 criterion from sampling noise "
        "alone. The intervals show how much. Read the gap against them.",
        "- UNKNOWN and ERROR carry no score; they are their own tier and the `unscored` band, never a low score.",
        "- Mail and downloaded files are not in these sets (the mail corpus has 73 phishing and no legitimate "
        "false alarm, too few for bands); the ask table below treats them by rule, not by measurement.", "",
        "## The ask table (`core/risk/asktable.py`)", "",
        "**Not wired into the agent, the extension or the API in this version.** It is the table, its rules and its "
        "tests: a pure function (state, confidence tier, source, whether every provider answered, familiarity fixed "
        "to `unknown`) to a loudness (`interrupt`, `ask_once`, `banner`, `log`). Only loudness changes, never a "
        "state or a score. Hard rules, enforced by `tests/unit/test_ask_table.py`: a MALICIOUS verdict with two "
        "strong categories is never quieter than a banner (browser: interrupt); automatic responses never apply to "
        "mail or to SUSPICIOUS; UNKNOWN is logged at least and, when a provider did not answer, shown. SUSPICIOUS at "
        "LOW confidence (one strong category, the tier where the false alarms sit in the tables above) gets a banner "
        "and the two-category tiers a question; the numbers inform the table, they do not drive it at run time. An "
        "incomplete provider answer raises UNKNOWN and ERROR to at least a banner. The table (provider answers "
        "complete; confidence LOW / MEDIUM / HIGH):", "",
        "| state | source | LOW | MEDIUM | HIGH |", "|---|---|---|---|---|",
    ]  # fmt: skip
    lines += [
        f"| {s.value} | {src} | {lo.value} | {mid.value} | {hi.value} |"
        for (s, src), (lo, mid, hi) in TABLE.items()
    ]
    return "\n".join([*lines, ""])


def _toml_float(x: float) -> str:
    return repr(float(x))


def render_toml(rep: Mapping[str, Any]) -> str:
    lines = [
        "# Written by `python -m eval.calibrate`; do not edit by hand.",
        "# detection = share of PHISHING samples in the band; false_alarm = share of LEGITIMATE samples in it.",
        "# They are likelihoods, NOT the probability that a page in the band is phishing (see docs/eval/calibration.md).",
        "[meta]",
        f'generated = "{rep["generated"]}"',
        f'stamp = "{rep["stamp"]}"',
        f"tolerance = {TOLERANCE}",
        f"min_samples = {MIN_SAMPLES}",
        f"met = {str(not rep['check']['failures']).lower()}",
    ]
    for ds, d in rep["sets"].items():
        for fam, bands in d["bands"].items():
            for band, b in bands.items():
                lines += ["", "[[band]]", f'set = "{ds}"', f'family = "{fam}"', f"band = {json.dumps(band)}",
                          f"checked = {str(b['checked']).lower()}"]  # fmt: skip
                for h in HALVES:
                    lines.append(f"{h}_samples = {b[h]['samples']}")
                    for what in ("detection", "false_alarm"):
                        r = b[h][what]
                        if r["rate"] is not None:
                            lines.append(f"{h}_{what} = {_toml_float(r['rate'])}")
                            lines.append(
                                f"{h}_{what}_ci = [{_toml_float(r['ci'][0])}, {_toml_float(r['ci'][1])}]"
                            )
    return "\n".join([*lines, ""])


def check(out: Path) -> int:
    rep = json.loads((out / "calibration.json").read_text(encoding="utf-8"))
    bad = failures(rep)
    if not cal.PATH.exists() or cal.load()["meta"]["generated"] != rep["generated"]:
        bad.append(
            "core/risk/calibration.toml is missing or not from the same run as calibration.json"
        )
    if bad:
        print("\n".join(bad))
        print("CALIBRATION NOT MET")
        return 1
    print("CALIBRATION MET")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.calibrate", description=__doc__)
    ap.add_argument("cmd", nargs="?", choices=("run", "check"), default="run")
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    ap.add_argument("--workers", type=int, default=min(3, max(1, (os.cpu_count() or 2) - 1)))
    ap.add_argument(
        "--refresh", action="store_true", help="judge again even if the cache is current"
    )
    args = ap.parse_args(argv)
    if args.cmd == "check":
        return check(args.out)
    cache = args.data / "calibration"
    stamp = _stamp(args.data)
    rows = _cached(
        cache / "e1.jsonl", stamp, lambda: e1_rows(args.data, args.workers), args.refresh
    )
    rows += _cached(cache / "d1.jsonl", stamp, lambda: d1_rows(args.data), args.refresh)
    rep: dict[str, Any] = {
        "generated": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"),
        "stamp": stamp,
        "criterion": {"tolerance": TOLERANCE, "min_samples": MIN_SAMPLES, "halves": "e1 train/test, d1 dev/test"},
        "prevalence_illustration": PREVALENCE,
        "sets": measure(rows),
    }  # fmt: skip
    rep["check"] = {"failures": failures(rep)}
    strict = measure(disjoint(rows))
    rep["domain_disjoint"] = {"sets": strict, "failures": failures({"sets": strict})}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "calibration.json").write_text(json.dumps(rep, indent=1), encoding="utf-8")
    (args.out / "calibration.md").write_text(render(rep), encoding="utf-8")
    cal.PATH.write_text(render_toml(rep), encoding="utf-8")
    print(
        f"wrote calibration.json, calibration.md and {cal.PATH.name}; run `check` for the verdict"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
