"""DA1 P3: risky links are opened in the sandbox without a click, boundedly; nothing else is."""

import threading

import pytest

from core.contracts import VerdictState as V
from core.detection.engine import UrlAnalysis, analyze_url
from core.detonate.auto import AutoOpener, parse_sources, worth_opening
from core.urls import popular

RISKY = "https://paypal.com.secure-login.account-verify.test/signin?email=jane%40example.test"
SIGN = "https://account-review.test/login"  # a login path on an unknown domain: one weak sign


def raised(a: UrlAnalysis, state: V) -> UrlAnalysis:
    return a.model_copy(update={"verdict": a.verdict.model_copy(update={"state": state})})


def test_only_risky_unknown_or_suspicious_addresses_are_worth_opening() -> None:
    assert analyze_url(RISKY).verdict.state in (V.SUSPICIOUS, V.MALICIOUS)
    assert worth_opening(raised(analyze_url(RISKY), V.SUSPICIOUS))
    sign = analyze_url(SIGN)
    assert worth_opening(sign) == (sign.verdict.state is V.SUSPICIOUS or bool(sign.verdict.signals))
    assert not worth_opening(analyze_url("https://example.test/blog/notes"))  # no sign at all
    assert not worth_opening(raised(analyze_url(RISKY), V.MALICIOUS))  # already blocked
    assert not worth_opening(analyze_url("https://www.microsoft.com/"))  # a brand's own site
    assert not worth_opening(analyze_url("ftp://files.example.test/x"))  # not a web page


def test_a_popular_domain_is_never_opened() -> None:
    popular.use(frozenset({"account-review.test"}))
    try:
        assert not worth_opening(raised(analyze_url(SIGN), V.SUSPICIOUS))
    finally:
        popular.use(frozenset())


class Fake:
    def __init__(self, deeper_state: V = V.MALICIOUS, gate: threading.Event | None = None) -> None:
        self.opened: list[str] = []
        self.recorded: list[tuple[str, str]] = []
        self.deeper_state, self.gate = deeper_state, gate

    def open_page(self, raw: str, start: UrlAnalysis) -> tuple[UrlAnalysis, str]:
        if self.gate is not None:
            self.gate.wait(5)
        self.opened.append(raw)
        return raised(start, self.deeper_state), "ok"

    def record(self, deeper: UrlAnalysis, source: str, status: str) -> None:
        self.recorded.append((source, status))


def test_a_risky_address_is_opened_once_and_its_graver_verdict_is_given_back() -> None:
    fake, now = Fake(), [0.0]
    opener = AutoOpener(fake.open_page, fake.record, clock=lambda: now[0])
    start = raised(analyze_url(RISKY), V.SUSPICIOUS)
    assert opener.consider(RISKY, start, "browser")
    assert opener.wait_idle()
    assert fake.opened == [RISKY] and fake.recorded == [("browser", "ok")]
    deeper = opener.deeper(start)
    assert deeper is not None and deeper.verdict.state is V.MALICIOUS
    assert not opener.consider(RISKY, start, "browser")  # once per window: a one-time link survives
    now[0] = 3601.0
    assert opener.deeper(start) is None  # the window is over: the address is judged afresh
    assert opener.consider(RISKY, start, "browser")
    opener.close()


def test_an_opened_page_never_lowers_what_is_given_back() -> None:
    fake = Fake(deeper_state=V.UNKNOWN)
    opener = AutoOpener(fake.open_page, fake.record)
    start = raised(analyze_url(RISKY), V.SUSPICIOUS)
    opener.consider(RISKY, start, "browser")
    assert opener.wait_idle()
    assert fake.recorded  # the deeper look is still recorded as an event
    assert opener.deeper(start) is None  # but the browser keeps the graver address verdict
    opener.close()


def test_the_queue_is_bounded_and_a_source_not_chosen_is_ignored() -> None:
    gate = threading.Event()
    fake = Fake(gate=gate)
    opener = AutoOpener(
        fake.open_page, fake.record, workers=1, max_pending=2, sources=frozenset({"browser"})
    )
    base = raised(analyze_url(RISKY), V.SUSPICIOUS)
    queued = [
        opener.consider(
            f"{RISKY}&n={i}", raised(analyze_url(f"{RISKY}&n={i}"), V.SUSPICIOUS), "browser"
        )
        for i in range(4)
    ]
    assert queued == [True, True, False, False] and opener.dropped == 2
    assert not opener.consider(RISKY, base, "mail")  # mail was not chosen here
    gate.set()
    assert opener.wait_idle()
    assert len(fake.opened) == 2
    opener.close()


def test_a_failing_page_does_not_stop_the_next() -> None:
    calls: list[str] = []

    def open_page(raw: str, start: UrlAnalysis) -> tuple[UrlAnalysis, str]:
        calls.append(raw)
        if len(calls) == 1:
            raise RuntimeError("the container failed")
        return start, "ok"

    recorded: list[str] = []
    opener = AutoOpener(open_page, lambda d, s, st: recorded.append(st), workers=1)
    for i in range(2):
        url = f"{RISKY}&n={i}"
        opener.consider(url, raised(analyze_url(url), V.SUSPICIOUS), "browser")
    assert opener.wait_idle()
    assert len(calls) == 2 and recorded == ["ok"]
    opener.close()


def test_mail_links_are_judged_by_their_address_first() -> None:
    fake = Fake()
    opener = AutoOpener(fake.open_page, fake.record)
    assert not opener.consider_link(
        "https://example.test/blog/notes", "mail"
    )  # nothing wrong with it
    if worth_opening(analyze_url(RISKY)):
        assert opener.consider_link(RISKY, "mail")
        assert opener.wait_idle() and fake.recorded == [("mail", "ok")]
    opener.close()


@pytest.mark.parametrize(
    ("value", "expected"),
    [("", frozenset()), ("browser", {"browser"}), (" Browser , mail ", {"browser", "mail"})],
)
def test_the_setting_names_sources(value: str, expected: set[str]) -> None:
    assert parse_sources(value) == frozenset(expected)


def test_an_unknown_source_is_an_error_not_silence() -> None:
    with pytest.raises(ValueError, match="browser and mail"):
        parse_sources("browser,sms")
