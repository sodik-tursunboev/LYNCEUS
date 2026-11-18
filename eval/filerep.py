# ruff: noqa: E501  (report rows and messages are long literals)
"""DA2: how well does VirusTotal's answer about a file's hash separate clean programs from malware?

    python -m eval.filerep run   [--n 100]    (slow: VirusTotal's free key allows 4 questions a minute)
    python -m eval.filerep check [--docs docs/eval]

`run` asks about two sets, each of N SHA-256 hashes, and nothing else leaves this computer:
  clean    a seeded sample of Microsoft-made programs from this computer's Windows folders. Their hashes
           are the same on every Windows computer of that version, so they say nothing about the owner.
  malware  a seeded sample of the recent MalwareBazaar hashes already in the local known-bad list
           (`python -m core.intel hashes sync`), public data.
It records, per hash, whether VirusTotal had a report and how many engines flagged it, and writes
counts to `docs/eval/filerep.{json,md}`. The tiers in `rules/email/scoring.toml` (`vt_certain`,
`vt_flagged`) were chosen from the clean set (no clean program may reach the flagged tier) and are
reported against both sets. `check` prints FILEREP MEASURED only when at least 90 of each set got a
report and none of the clean ones reaches the flagged tier.
"""

import argparse
import asyncio
import hashlib
import json
import random
import re
import subprocess
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.config import Settings
from core.intel.registry import build_file_reputation
from eval.metrics import wilson
from rules.email.data import scoring

SEED = "lynceus-da2-filerep"
WINDOWS_FOLDERS = (r"C:\Windows\System32", r"C:\Windows\SysWOW64")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
PACE = 16.0  # seconds between questions: under 4 a minute with room to spare


def microsoft_programs(n: int) -> list[Path]:
    """`n` programs from the Windows folders whose maker (version info) is Microsoft."""
    pool = [
        p for folder in WINDOWS_FOLDERS if Path(folder).is_dir()
        for p in Path(folder).iterdir() if p.suffix.lower() in (".exe", ".dll")
    ]  # fmt: skip
    random.Random(SEED).shuffle(pool)  # noqa: S311  (a reproducible sample, not a secret)
    keep: list[Path] = []
    for i in range(0, min(len(pool), 1500), 100):
        batch = pool[i : i + 100]
        paths = ",".join("'" + str(p).replace("'", "''") + "'" for p in batch)
        script = (
            "$ErrorActionPreference='SilentlyContinue'; "
            f"foreach ($p in @({paths})) {{ if ((Get-Item -LiteralPath $p).VersionInfo.CompanyName -like 'Microsoft*') {{ $p }} }}"
        )
        done = subprocess.run(  # noqa: S603  (a fixed PowerShell command over Windows folder paths)
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=300, check=False,
        )  # fmt: skip
        keep += [Path(x.strip()) for x in done.stdout.splitlines() if x.strip()]
        if len(keep) >= n:
            break
    return keep[:n]


def sha256_of(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            while block := f.read(1 << 20):
                h.update(block)
        return h.hexdigest()
    except OSError:
        return None


def malware_hashes(data: Path, n: int) -> list[str]:
    listing = data.parent / "hashes" / "malwarebazaar.txt"
    found = sorted({t for t in re.findall(r"[0-9a-f]{64}", listing.read_text("utf-8").lower())})
    random.Random(f"{SEED}|malware").shuffle(found)  # noqa: S311
    return found[:n]


def run(data: Path, n: int) -> int:
    folder = data / "filerep"
    folder.mkdir(parents=True, exist_ok=True)
    rows_file = folder / "rows.jsonl"
    done = (
        {(r["set"], r["sha"]) for r in map(json.loads, rows_file.read_text("utf-8").splitlines())}
        if rows_file.exists()
        else set()
    )
    clean = [h for p in microsoft_programs(n + 20) if (h := sha256_of(p))][:n]
    todo = [("clean", h) for h in clean] + [("malware", h) for h in malware_hashes(data, n)]
    todo = [t for t in todo if t not in done]
    print(
        f"{len(done)} already asked, {len(todo)} to ask (about {len(todo) * PACE / 60:.0f} minutes)",
        flush=True,
    )
    rep = build_file_reputation(Settings(file_reputation=True))
    if rep is None:
        raise SystemExit("no VirusTotal key stored")

    async def go() -> None:
        with rows_file.open("a", encoding="utf-8") as out:
            for i, (which, sha) in enumerate(todo, 1):
                answer, outcome = await rep.ask(sha)
                row = {"set": which, "sha": sha, "status": outcome,
                       "malicious": answer.malicious if answer else None,
                       "engines": answer.engines if answer else None}  # fmt: skip
                out.write(json.dumps(row) + "\n")
                out.flush()
                if outcome == "failed":
                    await asyncio.sleep(60)  # told to wait, or a bad moment: breathe
                await asyncio.sleep(PACE)
                if i % 20 == 0:
                    print(f"  {i}/{len(todo)}", flush=True)
        await rep.aclose()

    asyncio.run(go())
    return report(data, Path("docs/eval"))


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None,
            "ci": [round(ci.low, 4), round(ci.high, 4)] if ci else None}  # fmt: skip


def load(data: Path) -> list[dict[str, Any]]:
    f = data / "filerep" / "rows.jsonl"
    return [json.loads(x) for x in f.read_text("utf-8").splitlines()] if f.exists() else []


def tiers(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    cfg = scoring()["file"]
    rows = list(rows)
    got = [r for r in rows if r["status"] == "report"]
    bands = Counter(
        "malicious tier" if r["malicious"] >= cfg["vt_certain"] else
        "flagged tier" if r["malicious"] >= cfg["vt_flagged"] else
        "weak (1 to 3)" if r["malicious"] >= 1 else "0 engines"
        for r in got
    )  # fmt: skip
    return {
        "asked": len(rows), "report": len(got),
        "no_report": sum(r["status"] == "no_report" for r in rows),
        "failed": sum(r["status"] == "failed" for r in rows),
        "bands": dict(bands),
        "flagged_or_worse": _rate(sum(r["malicious"] >= cfg["vt_flagged"] for r in got), len(got)),
        "malicious_tier": _rate(sum(r["malicious"] >= cfg["vt_certain"] for r in got), len(got)),
        "max_engines_clean": max((r["malicious"] for r in got), default=0),
    }  # fmt: skip


def report(data: Path, out: Path) -> int:
    rows = load(data)
    rep = {"generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"), "seed": SEED,
           "thresholds": {k: v for k, v in scoring()["file"].items() if k.startswith("vt_")},
           "clean": tiers(r for r in rows if r["set"] == "clean"),
           "malware": tiers(r for r in rows if r["set"] == "malware")}  # fmt: skip
    out.mkdir(parents=True, exist_ok=True)
    (out / "filerep.json").write_text(json.dumps(rep, indent=1), encoding="utf-8")
    (out / "filerep.md").write_text(render(rep), encoding="utf-8")
    print(render(rep))
    return 0


def render(rep: Mapping[str, Any]) -> str:
    def pct(r: Mapping[str, Any]) -> str:
        return (
            "n/a"
            if not r["n"]
            else f"{100 * r['rate']:.1f}% ({100 * r['ci'][0]:.1f} to {100 * r['ci'][1]:.1f}), {r['k']} of {r['n']}"
        )

    c, m = rep["clean"], rep["malware"]
    return "\n".join([
        "# File reputation at VirusTotal (DA2)", "",
        f"{rep['generated_at']}. Seed `{rep['seed']}`. Thresholds in force: {rep['thresholds']}. Only SHA-256 hashes were "
        "asked about: clean = Microsoft-made programs from this computer's Windows folders (the same on every Windows "
        "computer of that version); malware = a sample of the recent MalwareBazaar hashes in the local known-bad list. "
        "Intervals are Wilson 95%.", "",
        "| | clean programs | recent malware hashes |", "|---|---|---|",
        f"| hashes asked | {c['asked']} | {m['asked']} |",
        f"| VirusTotal had a report | {c['report']} | {m['report']} |",
        f"| no report (never seen) | {c['no_report']} | {m['no_report']} |",
        f"| lookup failed | {c['failed']} | {m['failed']} |",
        f"| engines flagging: breakdown (of reports) | {c['bands']} | {m['bands']} |",
        f"| at or above the flagged tier | {pct(c['flagged_or_worse'])} | {pct(m['flagged_or_worse'])} |",
        f"| at or above the malicious tier | {pct(c['malicious_tier'])} | {pct(m['malicious_tier'])} |",
        f"| most engines flagging any one clean program | {c['max_engines_clean']} | |", "",
    ])  # fmt: skip


def check(data: Path) -> int:
    rows = load(data)
    clean = tiers(r for r in rows if r["set"] == "clean")
    bad = tiers(r for r in rows if r["set"] == "malware")
    print(
        f"clean: {clean['report']} reports of {clean['asked']}, {clean['flagged_or_worse']['k']} at or above the flagged tier"
    )
    print(
        f"malware: {bad['report']} reports of {bad['asked']}, {bad['flagged_or_worse']['k']} at or above the flagged tier ({bad['malicious_tier']['k']} malicious tier)"
    )
    ok = clean["report"] >= 90 and bad["report"] >= 90 and clean["flagged_or_worse"]["k"] == 0
    print("FILEREP MEASURED" if ok else "FILEREP NOT MEASURED YET")
    return 0 if ok else 1


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.filerep", description=__doc__)
    ap.add_argument("command", choices=["run", "check"])
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--n", type=int, default=100)
    args = ap.parse_args(list(argv) if argv is not None else None)
    return run(args.data, args.n) if args.command == "run" else check(args.data)


if __name__ == "__main__":
    raise SystemExit(main())
