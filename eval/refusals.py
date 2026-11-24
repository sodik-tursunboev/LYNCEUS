"""Why do live pages refuse the sandbox? (DA5 Phase 0b and 0d)

    python -m eval.refusals            # writes docs/eval/refusals.{json,md}
    python -m eval.refusals check      # prints REFUSALS CLASSIFIED only if every condition holds

Nothing is opened here: it reads the pages D1 and DA1 kept (`.data/eval/<run>/pages`, read only) and
the rows beside them, the same way `eval.detonate --rescore` does. The reports hold counts only.

0b: every kept page whose fetch was refused (HTTP 4xx/5xx or an error) or that showed under 200
characters of text is put in one class from what was kept: status, title, text, final host.
0d: of the pages the page rules caught and the address rules did not, how many the automatic
opener's filter (`core.detonate.auto.worth_opening`) would have opened.
"""

import argparse
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from core.contracts import VerdictState
from core.detection.engine import _allowlisted, analyze_url
from core.detonate.models import PageReport
from core.urls import popular
from core.urls.popular import is_popular
from eval.detonate import FLAGGED, SPLITS, _key, _pct, _rate, row_for
from eval.realurl import LEGIT, PHISH, Sample

RUNS = {"d1": "d1", "da1": "da1-2026-11-16"}  # name in the report -> folder under --data
CLASSES = ("takedown", "challenge", "blocked", "empty_stub", "other", "unknown_no_body")
HALVES = (*SPLITS, "all")
SHORT = 200  # the detonator's own "nearly empty" line (NEARLY_EMPTY_CHARS)
MIN_CLASSIFIED = 150
_LOOK = 4000  # characters of title and text read; a hostile page cannot make this slow

# Phrase lists, lower case, matched as plain substrings (no regex on page text, so no backtracking).
# A host's or registrar's own notice: reported, suspended, removed, parked, for sale.
_NOTICE = (
    "suspected phishing", "suspected malware", "potential phishing", "deceptive site",
    "has been suspended", "account suspended", "account has been", "site suspended",
    "website suspended", "domain suspended", "has been disabled", "has been removed",
    "has been taken down", "has been deleted", "has been terminated", "no longer available",
    "no longer exists", "domain for sale", "domain is for sale", "domain name is for sale",
    "buy this domain", "domain parking", "parked domain", "this domain is parked", "parked free",
    "domain has expired", "deployment is blocked", "deployment is unavailable",
    "deployment_blocked", "deployment is disabled", "deployment is paused",
)  # fmt: skip
_PARKING_HOSTS = (
    "sedoparking.com", "parkingcrew.net", "hugedomains.com", "afternic.com", "dan.com",
    "bodis.com", "above.com", "undeveloped.com", "domainnamesales.com",
)  # fmt: skip
_CHALLENGE_TITLES = (
    "just a moment", "verify you are human", "checking your browser", "one more step",
    "security check", "access check", "human verification", "are you a robot", "ddos protection",
)  # fmt: skip
_CHALLENGE_TEXT = (
    "captcha", "verify you are human", "verifies you are not a bot", "verifying you are human",
    "checking your browser", "checking if the site connection is secure",
    "enable javascript and cookies", "are you a robot", "are you human", "press & hold",
    "not a robot", "performing security verification", "ddos protection",
)  # fmt: skip
_BLOCK_TEXT = (
    "access denied", "forbidden", "you have been blocked", "you are blocked", "has been blocked",
    "request blocked", "not authorized", "unauthorized", "permission to access",
    "don't have permission", "do not have permission", "not allowed", "error 1020",
    "not available in your", "unavailable in your", "your region", "your country",
)  # fmt: skip
_BLOCK_STATUS = (401, 403, 429, 451)
_ORIGIN_DOWN = (521, 522, 523)  # Cloudflare: the web server is down, timed out or unreachable
# The sandbox's own egress proxy answers a refused connection with this exact line and a 403
# (infra/detonator/egress.py); it says nothing about the site.
_PROXY = re.compile(r"refused: ([a-z_]{1,20})")
_PROXY_DEAD = ("dns", "connect")  # the name does not resolve, or nothing answered


@dataclass(frozen=True)
class Facts:
    """What a kept page lets us judge by. The body of an attacker's page is hostile text."""

    status: str = ""  # PageReport.status: ok, partial, dead, error
    http: int | None = None
    error: str = ""
    title: str = ""
    text: str = ""
    form: bool = False
    final_host: str = ""


def facts_of(page: PageReport) -> Facts:
    try:
        host = urlsplit(page.final_url).hostname or ""
    except ValueError:
        host = ""
    return Facts(page.status, page.http_status, page.error or "", page.title, page.text,
                 bool(page.fields()), host)  # fmt: skip


def _s(v: object) -> str:
    return v if isinstance(v, str) else ""


def refused(f: Facts) -> bool:
    return f.status in ("dead", "error") or (isinstance(f.http, int) and f.http >= 400)


def in_scope(f: Facts) -> bool:
    """Refused, or showed under SHORT characters of text."""
    return refused(f) or len(_s(f.text).strip()) < SHORT


def _has(haystack: str, phrases: Iterable[str]) -> bool:
    return any(p in haystack for p in phrases)


def _no_body_detail(error: str) -> str:
    e = _s(error).lower()
    if e == "err_tunnel_connection_failed":
        return "proxy_tunnel_failed"  # the proxy refused or failed; Chrome hides which
    if e.startswith(("err_cert", "err_ssl")):
        return "tls_error"
    if e in ("watchdog", "timeout"):
        return "sandbox_timeout"
    if e.startswith("err_connection") or e in ("err_empty_response", "err_aborted"):
        return "connection_dropped"
    return "other_error"


def classify(f: Facts) -> tuple[str, str]:
    """(class, detail). Never raises: every field is coerced, every phrase search is a plain
    substring test on at most _LOOK characters."""
    title = _s(f.title)[:_LOOK].lower()
    text = _s(f.text)
    body = bool(title.strip() or text.strip())
    low = (title + "\n" + text[:_LOOK]).lower().replace("’", "'")
    code = f.http if isinstance(f.http, int) and not isinstance(f.http, bool) else None
    status = _s(f.status)
    alive = status in ("ok", "partial") and (code is None or code < 400)
    host = _s(f.final_host).lower()

    m = _PROXY.fullmatch(text.strip().lower()) if code == 403 and len(text) <= 40 else None
    if m:  # the sandbox's own refusal, not the site's
        reason = m.group(1)
        return ("takedown" if reason in _PROXY_DEAD else "other"), f"proxy_{reason}"
    if _has(low, _NOTICE):
        return "takedown", "host_notice+form" if f.form else "host_notice"
    if host and any(host == h or host.endswith("." + h) for h in _PARKING_HOSTS):
        return "takedown", "parked_host"
    if "attention required" in title:  # Cloudflare's page for both a block and a check
        return ("blocked", "cloudflare_block") if _has(low, _BLOCK_TEXT) else ("challenge", "title")
    if _has(title, _CHALLENGE_TITLES):
        return "challenge", "title"
    if _has(low, _CHALLENGE_TEXT):
        return "challenge", "text"
    if code in (404, 410):
        return "takedown", f"http_{code}"
    if code in _ORIGIN_DOWN:
        return "takedown", "origin_down"
    if code in _BLOCK_STATUS:
        return "blocked", f"http_{code}" if body else f"http_{code}_no_body"
    if _has(low, _BLOCK_TEXT):
        return "blocked", "text"
    if not body and (status in ("dead", "error") or (status == "partial" and not f.form)):
        return "unknown_no_body", (
            _no_body_detail(f.error) if status in ("dead", "error") else "partial_blank"
        )
    if code is not None and code >= 400:
        return "other", f"http_{code}" if body else f"http_{code}_no_body"
    if alive and len(text.strip()) < SHORT:
        if f.form:
            return "other", "short_with_form"
        return "empty_stub", "short_text" if body else "blank"
    return "other", "no_match"


def why_not_opened(url: str) -> str:
    """Which condition of `worth_opening` an address fails (the same tests, in the same order)."""
    a = analyze_url(url)
    u = a.url
    if u is None or u.scheme not in ("http", "https") or not u.host:
        return "not a web address"
    if _allowlisted(u) or is_popular(u.registered_domain):
        return "official or popular host"
    if a.verdict.state is VerdictState.UNKNOWN:
        return "UNKNOWN with no sign" if not a.verdict.signals else "opened"
    return f"address {a.verdict.state.value}"


# ---- the kept data ---------------------------------------------------------------------------


def load(folder: Path) -> tuple[list[dict[str, Any]], dict[str, PageReport]]:
    """The run's rows and its kept pages by URL. Read only; a row with no kept page is left out of
    the pages and counted by the caller."""
    rows = [
        json.loads(line)
        for line in (folder / "results.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    pages: dict[str, PageReport] = {}
    for r in rows:
        f = folder / "pages" / f"{_key(r['url'])}.json"
        if f.is_file():
            pages[r["url"]] = PageReport.model_validate_json(f.read_text(encoding="utf-8"))
    return rows, pages


def page_only(rows: Sequence[Mapping[str, Any]], popular_loaded: bool) -> dict[str, Any]:
    """0d. Page-only catches (phishing, alive, flagged with the page, not by the address) against
    the automatic opener's filter, on rows judged with today's rules (`row_for`)."""
    out: dict[str, Any] = {}
    for half in HALVES:
        caught = [
            r for r in rows
            if half in ("all", r["split"]) and r["label"] == PHISH and r["alive"]
            and r["state"] in FLAGGED and r["url_state"] not in FLAGGED
        ]  # fmt: skip
        why: Counter[str] = Counter()
        failed: Counter[str] = Counter()
        passed = 0
        for r in caught:
            if not popular_loaded:
                why["the popular-domain list is not loaded, so 'not popular' cannot be judged"] += 1
            elif r["url_state"] == "ERROR":
                why["the address could not be analysed"] += 1
            elif r.get("auto_open") is None:
                why["no kept page to re-judge and no stored filter result"] += 1
            elif r["auto_open"]:
                passed += 1
            else:
                failed[str(r.get("why_not") or r["url_state"])] += 1
        out[half] = {
            "catches": len(caught), "pass": passed, "fail": sum(failed.values()),
            "cannot_tell": sum(why.values()),
            "pass_rate": _rate(passed, len(caught)),
            "fail_why": dict(failed), "cannot_tell_why": dict(why),
        }  # fmt: skip
    return out


def summarize(rows: Sequence[Mapping[str, Any]], pages: Mapping[str, PageReport]) -> dict[str, Any]:
    """0b for one run: the classes per half and label, with Wilson intervals."""
    kept: Counter[tuple[str, str]] = Counter()
    picked: list[tuple[str, str, str, str, int | None]] = []
    for r in rows:
        p = pages.get(r["url"])
        if p is None:
            continue
        kept[(r["label"], r["split"])] += 1
        f = facts_of(p)
        if in_scope(f):
            picked.append((r["label"], r["split"], *classify(f), f.http))
    groups: dict[str, Any] = {}
    for half in HALVES:
        groups[half] = {}
        for label in (PHISH, LEGIT):
            sel = [x for x in picked if x[0] == label and half in ("all", x[1])]
            n, counts = len(sel), Counter(x[2] for x in sel)
            seen = sum(v for (lab, s), v in kept.items() if lab == label and half in ("all", s))
            groups[half][label] = {
                "pages": seen,
                "classified": n,
                "classes": {c: _rate(counts[c], n) for c in CLASSES},
                "blocked_or_challenge": _rate(counts["blocked"] + counts["challenge"], n),
                "details": dict(sorted(Counter(f"{x[2]}/{x[3]}" for x in sel).items())),
                "http_403": dict(Counter(x[2] for x in sel if x[4] == 403)),
            }  # fmt: skip
    return {
        "rows": len(rows), "kept_pages": len(pages), "rows_without_page": len(rows) - len(pages),
        "classified": sum(groups["all"][lab]["classified"] for lab in (PHISH, LEGIT)),
        "groups": groups,
        # pages kept before DA1 carry no visit time, and D1 (11 November) predates the phone retry
        # (H1 C5): there it cannot have happened, so it is not measured
        "phone_view": {
            lab: _rate(
                sum(p.phone_view for r in rows if r["label"] == lab and (p := pages.get(r["url"]))),
                kept[(lab, "dev")] + kept[(lab, "test")],
            )
            for lab in (PHISH, LEGIT)
        }
        if any(p.visited_at is not None for p in pages.values())
        else None,
    }  # fmt: skip


def build(data: Path) -> dict[str, Any]:
    loaded = bool(popular.domains())
    runs: dict[str, Any] = {}
    for name, folder in RUNS.items():
        rows, pages = load(data / folder)
        judged = [
            row_for(Sample(r["source"], r["label"], r["url"]), p)
            if (p := pages.get(r["url"])) else {**r, "auto_open": r.get("auto_open")}
            for r in rows
        ]  # fmt: skip
        judged = [
            {**r, "why_not": why_not_opened(r["url"])}
            if r["label"] == PHISH and r.get("auto_open") is False else r
            for r in judged
        ]  # fmt: skip
        runs[name] = {
            "folder": folder,
            **summarize(rows, pages),
            "page_only": page_only(judged, loaded),
        }
    return {
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "popular_list_loaded": loaded, "runs": runs,
    }  # fmt: skip


# ---- the report ------------------------------------------------------------------------------


_METHOD = (
    "{generated}. Nothing was opened: this reads the pages D1 and DA1 kept (read only) and judges "
    "them with today's rules. Counts only, no addresses and no page text. Intervals are Wilson "
    "95%. The halves are each run's own dev and test halves; `both` is their sum.",
    "",
    "**Who is classified.** Every kept page that was refused (HTTP 4xx/5xx, or the sandbox could "
    "not load it) or showed under 200 characters of text. Each lands in the first class that "
    "fits, in this order: the sandbox's own proxy refusal (`refused: dns` and the like, a 403 "
    "that is not the site's; dns and connect count as takedown, the rest as other); a host or "
    "registrar notice (reported as phishing, suspended, removed, parked, for sale) is a "
    "**takedown**; a bot check (`just a moment`, captcha, `verify you are human`) is a "
    "**challenge**; HTTP 404, 410 or 521 to 523 is a **takedown**; HTTP 401, 403, 429, 451 or "
    "`access denied` text with no challenge is **blocked**; a page that loaded, shows under 200 "
    "characters and has no form is an **empty_stub**; a connection that failed before any page, "
    "with nothing kept, is **unknown_no_body**; the rest is **other**. Classes are phrase lists "
    "applied to the status, title, text and final host. There is no labelled truth set: they are "
    "a reading of the kept data, not ground truth.",
    "",
)
_CANNOT_SAY = (
    "## What the kept data cannot say",
    "",
    "- `proxy_tunnel_failed` (HTTPS): Chrome reports only that the sandbox's proxy could not "
    "connect. The proxy's reason (name does not resolve, nothing answered, a private address or "
    "an odd port) is hidden, so those pages stay `unknown_no_body`. On plain http the reason is "
    "visible (`proxy_dns`, `proxy_connect`, `proxy_<other>` in the detail table): the only "
    "evidence for how the hidden ones might split.",
    "- A host notice is the host's warning, not proof the page behind it is gone. The kept page "
    "does not show whether a continue button leads to a live page (`+form` only says the notice "
    "carries some form).",
    "- `blocked` is a refusal with no challenge text. Whether it is the sandbox's fingerprint, "
    "its region, its address range or a block of every visitor needs a second visit from "
    "elsewhere; the kept data holds at most one phone retry.",
    "- A challenge that drew no text, or a page waiting for a script, reads as `empty_stub` or "
    "`unknown_no_body`.",
    "- Pages that loaded and showed 200 characters or more are not examined, so a long parked "
    "page is not counted.",
    "- 0d assumes the address verdict without the feeds (every address here is on a feed), a "
    "link that arrives through an enabled channel (browser or mail), today's rules and today's "
    "popular-domain list.",
)
_SHOWN = {"dev": "dev", "test": "test", "all": "both"}


def _row(cells: Iterable[object]) -> str:
    return "| " + " | ".join(str(c) for c in cells) + " |"


def _sum_over_halves(po: Mapping[str, Any], key: str) -> Counter[str]:
    total: Counter[str] = Counter()
    for h in SPLITS:
        total.update(po[h][key])
    return total


def _n403(group: Mapping[str, Any]) -> int:
    return sum(group["http_403"].values())


def _phone_line(phone: Mapping[str, Any] | None) -> str:
    if phone is None:
        return (
            "Phone retry (desktop refused, phone then read): not measurable here. These pages were "
            "kept before DA1 and before the retry existed (H1 C5)."
        )
    return (
        "Pages the desktop visit was refused and the phone visit then read: phishing "
        f"{_pct(phone[PHISH])}; legitimate {_pct(phone[LEGIT])}."
    )


def _run_section(name: str, run: Mapping[str, Any]) -> list[str]:
    g, po = run["groups"], run["page_only"]
    lines = [f"## Run `{name}`: {run['kept_pages']} pages kept, {run['classified']} classified", ""]
    if run["rows_without_page"]:
        lines += [f"{run['rows_without_page']} rows have no kept page and are not classified.", ""]
    for label, title in ((PHISH, "Phishing"), (LEGIT, "Legitimate")):
        kept = ", ".join(f"{_SHOWN[h]} {g[h][label]['pages']}" for h in HALVES)
        done = ", ".join(f"{_SHOWN[h]} {g[h][label]['classified']}" for h in HALVES)
        lines += [
            f"### {title} (pages kept: {kept}; classified: {done})",
            "",
            _row(["class", *(_SHOWN[h] for h in HALVES)]),
            "|---|---|---|---|",
        ]
        for c in CLASSES:
            lines.append(_row([c, *(_pct(g[h][label]["classes"][c]) for h in HALVES)]))
        lines += [
            _row(
                [
                    "*blocked + challenge*",
                    *(_pct(g[h][label]["blocked_or_challenge"]) for h in HALVES),
                ]
            ),
            "",
        ]
    both = g["all"]
    keys = sorted(set(both[PHISH]["details"]) | set(both[LEGIT]["details"]))
    lines += [
        "### Detail inside each class (both halves)",
        "",
        _row(["class / detail", "phishing", "legitimate"]),
        "|---|---|---|",
        *(
            _row([k, both[PHISH]["details"].get(k, 0), both[LEGIT]["details"].get(k, 0)])
            for k in keys
        ),
        "",
        _phone_line(run["phone_view"]),
        "",
        "### Pages that answered HTTP 403 (the refusal most often named), by class",
        "",
        _row(["", *(f"{lab} {_SHOWN[h]}" for lab in (PHISH, LEGIT) for h in HALVES)]),
        "|---|---|---|---|---|---|---|",
        _row(["all 403 answers", *(_n403(g[h][lab]) for lab in (PHISH, LEGIT) for h in HALVES)]),
        *(
            _row([c, *(g[h][lab]["http_403"].get(c, 0) for lab in (PHISH, LEGIT) for h in HALVES)])
            for c in CLASSES
        ),
        "",
        "### 0d: would the automatic opener have opened the page-only catches?",
        "",
        _row(["", *(_SHOWN[h] for h in HALVES)]),
        "|---|---|---|---|",
    ]
    for key, what in (
        (
            "catches",
            "page-only catches (phishing, alive, flagged with the page, not by the address)",
        ),
        ("pass", "would pass `worth_opening`"),
        ("fail", "would fail"),
        ("cannot_tell", "cannot tell"),
    ):
        lines.append(_row([what, *(po[h][key] for h in HALVES)]))
    fails = _sum_over_halves(po, "fail_why")
    lines += [
        "",
        "Why the fails fail (`worth_opening` needs SUSPICIOUS, or UNKNOWN with a sign, off the "
        "official and popular hosts): "
        + (", ".join(f"{k} {v}" for k, v in sorted(fails.items())) or "none"),
        "",
    ]
    why = _sum_over_halves(po, "cannot_tell_why")
    if why:
        lines += ["Cannot tell, why: " + "; ".join(f"{k} ({v})" for k, v in why.items()), ""]
    return lines


def render(rep: Mapping[str, Any]) -> str:
    lines = ["# Why live pages refuse the sandbox (DA5 Phase 0b and 0d)", ""]
    lines += [s.format(generated=rep["generated"]) if "{generated}" in s else s for s in _METHOD]
    for name, run in rep["runs"].items():
        lines += _run_section(name, run)
    return "\n".join([*lines, *_CANNOT_SAY]) + "\n"


# ---- the gate --------------------------------------------------------------------------------


def verify(rep: Mapping[str, Any]) -> list[str]:
    """What is wrong with a report; empty when every condition holds."""
    problems: list[str] = []
    total = 0
    for name, run in rep["runs"].items():
        seen = 0
        for half in HALVES:
            for label in (PHISH, LEGIT):
                g = run["groups"][half][label]
                got = sum(g["classes"][c]["k"] for c in CLASSES)
                if got != g["classified"]:
                    problems.append(
                        f"{name} {half} {label}: classes sum to {got}, not {g['classified']}"
                    )
                if half != "all":
                    seen += g["classified"]
            po = run["page_only"][half]
            if po["pass"] + po["fail"] + po["cannot_tell"] != po["catches"]:
                problems.append(f"{name} {half}: 0d pass + fail + cannot tell != page-only catches")
        if seen != run["classified"]:
            problems.append(f"{name}: halves sum to {seen}, not {run['classified']}")
        if (
            sum(run["page_only"][h]["catches"] for h in SPLITS)
            != run["page_only"]["all"]["catches"]
        ):
            problems.append(f"{name}: 0d halves do not sum to both")
        total += run["classified"]
    if total < MIN_CLASSIFIED:
        problems.append(f"only {total} pages classified, need {MIN_CLASSIFIED}")
    return problems


def check(out: Path) -> int:
    files = [out / "refusals.json", out / "refusals.md"]
    problems = [f"missing {f}" for f in files if not f.is_file()]
    if not problems:
        try:
            problems = verify(json.loads(files[0].read_text(encoding="utf-8")))
        except (OSError, ValueError, KeyError, TypeError) as e:
            problems = [f"{files[0]} is unreadable or malformed ({type(e).__name__})"]
    for p in problems:
        print(f"FAILED: {p}")
    if problems:
        return 1
    print("REFUSALS CLASSIFIED")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.refusals", description=__doc__)
    ap.add_argument("command", nargs="?", choices=["run", "check"], default="run")
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    args = ap.parse_args(argv)
    if args.command == "check":
        return check(args.out)
    popular.configure(args.data.parent / "popular")  # the list the core uses, if synced
    rep = build(args.data)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "refusals.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
    text = render(rep)
    (args.out / "refusals.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
