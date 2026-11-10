"""Command line for the local model reviewer (ADR-023).

    python -m core.llm status          is the local model reachable, and is it installed?
    python -m core.llm review <file>   read one Office file's macro with the local model
    python -m core.llm check           ask the model about the labelled macro corpus and report how
                                       often it answers validly and agrees (needs a checkout)

Everything talks to this computer only. `check` measures the model, not Lynceus: the verdict never
depends on it.
"""

import argparse
import asyncio
import sys
import time
from pathlib import Path

from core.config import Settings
from core.llm.build import file_excerpt
from core.llm.ollama import LocalModelError, OllamaClient
from core.llm.review import review_excerpt

ROOT = Path(__file__).resolve().parents[2]


def _client(settings: Settings) -> OllamaClient:
    return OllamaClient(settings.llm_url, settings.llm_model, timeout=settings.llm_timeout)


async def _status(settings: Settings) -> int:
    client = _client(settings)
    try:
        names = await client.models()
    except LocalModelError as e:
        print(f"not reachable: {e.reason} ({client.base})")
        return 1
    finally:
        await client.aclose()
    mine = settings.llm_model in names or f"{settings.llm_model}:latest" in names
    print(f"reachable at {client.base}; models: {', '.join(names) or '(none)'}")
    print(f"configured model {settings.llm_model}: {'installed' if mine else 'NOT installed'}")
    print(f"review is {'ON' if settings.llm_review else 'off'} (LYNCEUS_LLM_REVIEW)")
    return 0 if mine else 1


async def _review(settings: Settings, path: Path) -> int:
    text = file_excerpt(path.read_bytes())
    if not text:
        print("no macro code found in this file (or it could not be read)")
        return 1
    client = _client(settings)
    try:
        review = await review_excerpt(client, text)
    finally:
        await client.aclose()
    if review is None:
        print("the local model gave no valid answer")
        return 1
    print(f"{review.assessment} (confidence {review.confidence}): {', '.join(review.behaviors)}")
    print(review.plain_reason())
    return 0


async def _check(settings: Settings) -> int:
    sys.path[:0] = [str(ROOT / "tests"), str(ROOT / "core" / "sandbox" / "guest")]
    try:
        import macrosamples as ms
        import vbaanalyze
    except ImportError:
        print("check needs a checkout (tests/macrosamples.py); nothing was asked of the model")
        return 2
    samples = [(n, "malicious", s, False) for n, s in ms.MALICIOUS_UNKNOWN.items()]
    samples += [(n, "benign", s, False) for n, s in ms.BENIGN.items()]
    samples += [(n, label, s, True) for n, (label, s) in ms.HELDOUT.items()]
    client = _client(settings)
    valid, right, held, held_right, rows = 0, 0, 0, 0, []
    try:
        for name, label, source, heldout in samples:
            started = time.monotonic()
            review = await review_excerpt(client, vbaanalyze.excerpt([source]))
            took = time.monotonic() - started
            agrees = False
            if review is not None:
                valid += 1
                said = "malicious" if review.assessment in ("malicious", "suspicious") else "benign"
                agrees = said == label
            right += agrees
            held += heldout
            held_right += agrees and heldout
            rows.append((name, label, review.assessment if review else "NO ANSWER", took, heldout))
    finally:
        await client.aclose()
    for name, label, said, took, heldout in rows:
        mark = "held-out" if heldout else ""
        print(f"{name:20} expected {label:9} model said {said:10} {took:5.1f}s {mark}")
    n = len(samples)
    flagging = ("malicious", "suspicious")
    missed = sum(
        1 for _, label, said, _, _ in rows if label == "malicious" and said not in flagging
    )
    alarms = sum(1 for _, label, said, _, _ in rows if label == "benign" and said in flagging)
    print(f"  hostile macros it did not flag: {missed}; ordinary macros it flagged: {alarms}")
    print(
        f"model {settings.llm_model}: valid answers {valid}/{n}; agrees with the label {right}/{n}"
    )
    print(f"  held-out macros (unlike the briefing's examples): agrees {held_right}/{held}")
    print(
        "(a measurement of the model on a small synthetic corpus: it is advice, never the verdict)"
    )
    if valid == n:
        print("LLM LIVE CHECK OK")
        return 0
    print("LLM LIVE CHECK FAILED: some answers were missing or not in the fixed form")
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m core.llm", description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    rv = sub.add_parser("review")
    rv.add_argument("file", type=Path)
    sub.add_parser("check")
    args = ap.parse_args(argv)
    settings = Settings()
    if args.command == "status":
        return asyncio.run(_status(settings))
    if args.command == "review":
        return asyncio.run(_review(settings, args.file))
    return asyncio.run(_check(settings))


if __name__ == "__main__":
    raise SystemExit(main())
