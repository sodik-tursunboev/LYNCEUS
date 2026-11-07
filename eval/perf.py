"""Measure what the engines and the API cost on THIS machine (M7).

`python -m eval.perf` prints a report; `--write` also saves it as docs/PERFORMANCE.md. These are
wall-clock numbers on a shared development machine: they say what to expect here, not what any
other machine will do. The random numbers only choose test inputs, so a plain PRNG is right.
"""

import argparse
import hashlib
import io
import json
import os
import platform
import random
import statistics
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from email.message import EmailMessage
from functools import partial
from pathlib import Path

from core import sandbox
from core.detection.engine import analyze_url
from core.email.engine import analyze_message
from core.files.engine import analyze_file

TOKEN = "perf-token-0123456789"  # noqa: S105  (a throwaway token for a local server)
URLS = [
    "https://www.example.com/",
    "https://github.com/anthropics/claude-code/issues/12345?tab=comments",
    "https://paypal-login.test/signin/login.php?email=jane%40example.test",
    "http://xn--pypal-4ve.test/account/verify",
    "https://secure-update.example.net/bank/login?redirect=https%3A%2F%2Fevil.test%2Fx",
    "http://192.168.0.1:8080/admin",
    "https://bit.ly/3AbCdEf",
    "https://sub.domain.example.co.uk/a/b/c/d/e/f/g?x=1&y=2&z=3#frag",
    "https://login.microsoftonline.com.evil-host.test/common/oauth2/authorize",
    "https://user:pw@host.test/",  # pragma: allowlist secret
    "https://" + "a" * 60 + ".test/" + "b" * 300,
    "https://example.org/%E2%82%AC/%2e%2e/%2e%2e/etc/passwd",
]


def pct(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * p))]


def stats(ms: list[float]) -> dict[str, float]:
    return {"n": len(ms), "p50": round(statistics.median(ms), 3), "p95": round(pct(ms, 0.95), 3),
            "max": round(max(ms), 3)}  # fmt: skip


def timed(fn: Callable[[], object], n: int) -> list[float]:
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t0) * 1000)
    return out


def message(kind: str) -> bytes:
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "a@sender.test", "b@rcpt.test", "Hello"
    m["Date"], m["Message-ID"] = "Mon, 02 Nov 2026 10:00:00 +0000", "<p@sender.test>"
    if kind == "plain":
        m.set_content("Lunch on Friday?")
    elif kind == "html_links":
        m.set_content("see html")
        links = "".join(
            f'<a href="https://l{i}.example.test/x">https://www.paypal.com/l{i}</a>'
            for i in range(20)
        )
        m.add_alternative(f"<html><body>{links}</body></html>", subtype="html")
    else:  # attachment
        m.set_content("see attached")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("a.txt", "hello" * 200)
            z.writestr("b.scr", "x")
        m.add_attachment(buf.getvalue(), maintype="application", subtype="zip", filename="a.zip")
    return m.as_bytes()


def file_cases() -> dict[str, tuple[str, bytes]]:
    rng = random.Random(7)  # noqa: S311  (test inputs, not secrets)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(20):
            z.writestr(f"f{i}.txt", "data" * 500)
    pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
    return {
        "1 KB text": ("notes.txt", b"just words " * 90),
        "1 MiB random": ("blob.bin", rng.randbytes(1024 * 1024)),
        "small PDF": ("a.pdf", pdf),
        "zip with 20 entries": ("a.zip", buf.getvalue()),
        "8 MiB random": ("big.bin", rng.randbytes(8 * 1024 * 1024)),
    }


def api_load(seconds: float, workers: int) -> dict[str, float]:
    port = 18765 + os.getpid() % 1000
    # an empty database URL overrides the .env file: the load test must not write to a real database
    env = dict(
        os.environ,
        LYNCEUS_API_TOKEN=TOKEN,
        LYNCEUS_DATABASE_URL="",
        LYNCEUS_RATE_LIMIT_PER_MINUTE="100000000",
    )  # the default limiter is 120 a minute
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "uvicorn", "core.api.app:create_app", "--factory",
         "--host", "127.0.0.1", "--port", str(port), "--no-access-log"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)  # noqa: S310
                break
            except OSError:
                time.sleep(0.2)
        latencies: list[float] = []
        failures = 0
        lock = threading.Lock()
        stop = time.monotonic() + seconds

        def work(seed: int) -> None:
            nonlocal failures
            rng = random.Random(seed)  # noqa: S311  (test inputs, not secrets)
            while time.monotonic() < stop:
                body = json.dumps({"url": rng.choice(URLS)}).encode()
                req = urllib.request.Request(  # noqa: S310
                    f"http://127.0.0.1:{port}/v1/urls/analyze", data=body,
                    headers={"Authorization": f"Bearer {TOKEN}",
                             "Content-Type": "application/json"},
                )  # fmt: skip
                t0 = time.perf_counter()
                try:
                    urllib.request.urlopen(req, timeout=10).read()  # noqa: S310
                    ok = True
                except OSError:
                    ok = False
                with lock:
                    if ok:
                        latencies.append((time.perf_counter() - t0) * 1000)
                    else:
                        failures += 1

        threads = [threading.Thread(target=work, args=(i,)) for i in range(workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return {"workers": workers, "requests": len(latencies), "failures": failures,
                "requests_per_second": round(len(latencies) / seconds, 1),
                **{k: v for k, v in stats(latencies or [0.0]).items() if k != "n"}}  # fmt: skip
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def sizes() -> dict[str, int]:
    root = Path(__file__).parents[1]
    found = {}
    for label, rel in (
        ("console bundle", "console/dist/console.js"),
        ("extension service worker", "extension/dist/background.js"),
    ):
        p = root / rel
        if p.is_file():
            found[label + " (bytes)"] = p.stat().st_size
    return found


def build(quick: bool) -> dict[str, object]:
    n = 5 if quick else 30
    report: dict[str, object] = {
        "when": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "machine": (
            f"{platform.platform()}, {os.cpu_count()} logical CPUs, "
            f"Python {platform.python_version()}"
        ),
    }
    report["URL engine, in process (ms per URL)"] = stats(
        timed(lambda: [analyze_url(u) for u in URLS], 60 if not quick else 5)
    )
    report["URL engine note"] = f"each sample is {len(URLS)} URLs; divide by {len(URLS)} for one"
    if sandbox.available():
        msgs = {k: message(k) for k in ("plain", "html_links", "attachment")}
        report["message engine through the sandbox (ms per message)"] = {
            k: stats(timed(partial(analyze_message, raw), n)) for k, raw in msgs.items()
        }
        report["file engine through the sandbox (ms per file)"] = {
            label: stats(
                timed(
                    partial(analyze_file, name, len(data), hashlib.sha256(data).hexdigest(), data),
                    n,
                )
            )
            for label, (name, data) in file_cases().items()
        }
    else:
        report["sandbox"] = (
            "not built: run python tasks.py sandbox (message and file timings skipped)"
        )
    report["API, 8 concurrent clients, URL analysis, no database"] = api_load(3 if quick else 10, 8)
    report["sizes"] = sizes()
    return report


def markdown(r: dict[str, object]) -> str:
    lines = ["# Performance (measured, not promised)", "",
             f"Measured {r['when']} on: {r['machine']}.",
             "Wall-clock times on a shared development machine: an order of magnitude. "
             "Regenerate with `python -m eval.perf --write`.", ""]  # fmt: skip
    for key, value in r.items():
        if key in ("when", "machine"):
            continue
        lines += [f"## {key}", ""]
        if isinstance(value, dict) and value and all(isinstance(v, dict) for v in value.values()):
            lines += ["| case | n | p50 | p95 | max |", "|---|---|---|---|---|"]
            lines += [
                f"| {k} | {v['n']} | {v['p50']} | {v['p95']} | {v['max']} |"
                for k, v in value.items()
            ]
        elif isinstance(value, dict) and "n" in value and "p50" in value:
            lines.append(
                f"- n {value['n']}, p50 {value['p50']} ms, p95 {value['p95']} ms, "
                f"max {value['max']} ms"
            )
        elif isinstance(value, dict):
            lines += [f"- {k}: {v}" for k, v in value.items()]
        else:
            lines.append(str(value))
        lines.append("")
    notes = [
        "## Reading these numbers",
        "",
        "- A message or a file costs a third of a second or more, mostly because a fresh sandbox",
        "  process starts for each one (the 1 KB file is the floor); the work inside it is small.",
        "- A URL costs about a millisecond in process. The API figure is the ceiling with the rate",
        "  limiter lifted: by default the API allows 120 requests a minute per client",
        "  (`LYNCEUS_RATE_LIMIT_PER_MINUTE`).",
        "- The agent notices a finished download after its quiet period (one second by default)",
        "  and then pays the file cost above plus a local HTTP call. A browser check adds the",
        "  native-messaging round trip (M4 spike: p95 under a millisecond) plus the URL cost.",
        "- Nothing here measures a mailbox burst: Gmail quota (about 100 raw fetches a minute) is",
        "  the limit there.",
        "",
    ]
    lines += notes
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m eval.perf")
    parser.add_argument("--quick", action="store_true", help="few samples, for a smoke check")
    parser.add_argument("--write", action="store_true", help="save docs/PERFORMANCE.md")
    args = parser.parse_args()
    report = build(args.quick)
    text = markdown(report)
    print(text)
    if args.write:
        Path("docs/PERFORMANCE.md").write_text(text + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
