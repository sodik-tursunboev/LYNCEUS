"""Command line, offline: no API, no database.

python -m core.cli analyze-url <url> [--json]
python -m core.cli analyze-eml <path> [--json]
python -m core.cli detonate <url> [--json] [--screenshot FILE]
    (D1: opens the page in the sandbox container from this computer's internet connection;
    needs Docker and `python tasks.py detonator`)
python -m core.cli investigate <url | .eml | file> [--json] [--html FILE] [--page-report FILE]
    (DA5 1a: the evidence dossier; offline, opens no socket; docs/INVESTIGATE.md)
"""

import argparse
import sys
from pathlib import Path

from core.contracts import Verdict, VerdictState
from core.detection.engine import UrlReport, analyze_url
from core.email.engine import MAX_MESSAGE_BYTES, EmailReport, analyze_message


def _head(v: Verdict) -> list[str]:
    score = "n/a" if v.risk_score is None else str(v.risk_score)
    return [f"{v.state.value}  score {score}  confidence {v.confidence.value}"]


def _tail(v: Verdict) -> list[str]:
    lines = [f"Why:      {v.explanation}"]
    lines.append(f"Response: recommended {v.recommended_response.value}, applied none")
    for s in v.signals:
        lines.append(f"  [{s.weight:.2f}] {s.rule_id} ({s.attack}): {s.description}")
    lines.append(f"Versions: engine {v.engine_version}, ruleset {v.ruleset_version}")
    return lines


def _text(r: UrlReport) -> str:
    lines = _head(r.verdict)
    if r.normalized_url:
        lines.append(f"URL:      {r.normalized_url}")
    return "\n".join(lines + _tail(r.verdict))


def _email_text(r: EmailReport) -> str:
    lines = _head(r.verdict)
    if r.reason:
        lines.append(f"Reason:   {r.reason}")
    if r.summary:
        s = r.summary
        lines.append(
            f"Message:  {s.size} bytes, {s.parts} parts, {s.attachments} attachments, "
            f"{s.links} links ({s.links_analyzed} analysed)"
        )
    lines += _tail(r.verdict)
    for link in r.links:
        shown = link.normalized_url or "(unresolved)"
        verdict = f"{link.state.value} {link.risk_score}" if link.state else "not analysed"
        lines.append(f"  link [{link.kind}] {shown}: {verdict}")
    return "\n".join(lines)


def _read(path: Path) -> bytes | None:
    """The file's bytes, or None when it is unreadable or over the message cap."""
    try:
        with path.open("rb") as f:
            raw = f.read(MAX_MESSAGE_BYTES + 1)  # never pull a huge file into memory
    except OSError as e:
        print(f"cannot read {path}: {e.strerror}", file=sys.stderr)
        return None
    return raw


def _detonate(url: str, as_json: bool, shot: Path | None) -> int:
    import base64

    from core.detonate import detonate_url, safe_screenshot

    analysis, page = detonate_url(url)
    report = analysis.report()
    if shot is not None and (jpeg := safe_screenshot(page.screenshot)):
        shot.write_bytes(base64.b64decode(jpeg))
    if as_json:
        print(report.model_dump_json(indent=2))
    else:
        print(_text(report))
        where = page.final_url or "-"
        print(
            f"Page:     {page.status} {page.http_status or ''} -> {where}  ({page.elapsed_ms} ms)"
        )
        if page.error:
            print(f"          not analysed: {page.error}")
    return 1 if report.verdict.state is VerdictState.ERROR else 0


def _investigate(target: str, as_json: bool, html: Path | None, page_report: Path | None) -> int:
    from core import hashlists
    from core.config import Settings
    from core.investigate import (
        investigate,
        load_page_report,
        render_html,
        render_json,
        render_text,
    )

    hashlists.configure(Settings().data_dir / "hashes")  # the known-bad lists on this machine
    try:
        page = load_page_report(page_report) if page_report else None
        dossier = investigate(target, page_report=page)
    except OSError as e:
        print(f"cannot read {e.filename or target}: {e.strerror}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
    if html is not None:
        html.write_text(render_html(dossier), encoding="utf-8")
        print(f"wrote {html}", file=sys.stderr)
    print(render_json(dossier) if as_json else render_text(dossier))
    return 1 if dossier["verdict"]["state"] == VerdictState.ERROR.value else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m core.cli")
    commands = ap.add_subparsers(dest="command", required=True)
    url_cmd = commands.add_parser("analyze-url", help="analyze one URL, offline")
    url_cmd.add_argument("url")
    eml_cmd = commands.add_parser("analyze-eml", help="analyze one .eml file in the sandbox")
    eml_cmd.add_argument("path", type=Path)
    det_cmd = commands.add_parser("detonate", help="open one URL in the sandboxed browser (D1)")
    det_cmd.add_argument("url")
    det_cmd.add_argument("--screenshot", type=Path, help="save the page's screenshot (JPEG) here")
    inv_cmd = commands.add_parser(
        "investigate", help="the evidence dossier for a URL, an .eml or a file, offline"
    )
    inv_cmd.add_argument("target", help="a web address, or the path of an .eml or another file")
    inv_cmd.add_argument("--html", type=Path, help="also write the dossier as one HTML file")
    inv_cmd.add_argument(
        "--page-report", type=Path, help="a saved page report (JSON) to read the page from"
    )
    for cmd in (url_cmd, eml_cmd, det_cmd, inv_cmd):
        cmd.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = ap.parse_args(argv)

    if sys.stdout.encoding.lower().replace("-", "") != "utf8":  # a Windows console is often cp1252
        sys.stdout.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]
    from core.config import Settings
    from core.urls import popular

    popular.configure(Settings().data_dir / "popular")  # the same list the running core uses
    if args.command == "analyze-url":
        report = analyze_url(args.url).report()
        print(report.model_dump_json(indent=2) if args.json else _text(report))
        return 1 if report.verdict.state is VerdictState.ERROR else 0
    if args.command == "detonate":
        return _detonate(args.url, args.json, args.screenshot)
    if args.command == "investigate":
        return _investigate(args.target, args.json, args.html, args.page_report)

    raw = _read(args.path)
    if raw is None:
        return 2
    email = analyze_message(raw).report
    print(email.model_dump_json(indent=2) if args.json else _email_text(email))
    return 1 if email.verdict.state is VerdictState.ERROR else 0


if __name__ == "__main__":
    raise SystemExit(main())
