"""Command line: python -m core.cli analyze-url <url> [--json]. Offline, no database, no API."""

import argparse
import sys

from core.contracts import VerdictState
from core.detection.engine import UrlReport, analyze_url


def _text(r: UrlReport) -> str:
    v = r.verdict
    score = "n/a" if v.risk_score is None else str(v.risk_score)
    lines = [f"{v.state.value}  score {score}  confidence {v.confidence.value}"]
    if r.normalized_url:
        lines.append(f"URL:      {r.normalized_url}")
    lines.append(f"Why:      {v.explanation}")
    lines.append(f"Response: recommended {v.recommended_response.value}, applied none")
    for s in v.signals:
        lines.append(f"  [{s.weight:.2f}] {s.rule_id} ({s.attack}): {s.description}")
    lines.append(f"Versions: engine {v.engine_version}, ruleset {v.ruleset_version}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m core.cli")
    commands = ap.add_subparsers(dest="command", required=True)
    cmd = commands.add_parser("analyze-url", help="analyze one URL, offline")
    cmd.add_argument("url")
    cmd.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = ap.parse_args(argv)

    report = analyze_url(args.url).report()
    if sys.stdout.encoding.lower().replace("-", "") != "utf8":  # a Windows console is often cp1252
        sys.stdout.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]
    print(report.model_dump_json(indent=2) if args.json else _text(report))
    return 1 if report.verdict.state is VerdictState.ERROR else 0


if __name__ == "__main__":
    raise SystemExit(main())
