"""The sentence composer (DA5 phase 3, item 3): four parts, a sentence per rule, no new fact."""

import re
from collections.abc import Callable, Iterable
from pathlib import Path

import rules.email as email_pack
import rules.page as page_pack
import rules.url as url_pack
from core.contracts import Confidence, ResponseAction, Signal, VerdictState
from core.detection.engine import analyze_url
from core.explain.composer import Explanation, compose, phrases, reword, unsupported
from rules.email.data import scoring as email_scoring
from rules.intel.data import scoring as intel_scoring
from rules.page import page_brands
from rules.page import scoring as page_scoring
from rules.url.data import scoring as url_scoring

ROOT = Path(__file__).parents[2]
S, M = VerdictState.SUSPICIOUS, VerdictState.MALICIOUS
LOW, MEDIUM, HIGH = Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH
WARN, BLOCK = ResponseAction.WARN, ResponseAction.BLOCK
CAVEAT = "This is not evidence of safety: there are no reputation, age or page-content checks."


def sig(rule_id: str, weight: float = 0.7, description: str = "") -> Signal:
    return Signal(
        rule_id=rule_id,
        category=rule_id.split(".")[0],
        weight=weight,
        description=description or f"evidence for {rule_id}",
    )


def all_rule_ids() -> set[str]:
    """Every id a signal can carry: the three registries, every scoring file (this covers the
    learned model, the brain's findings and the intelligence providers), the ids that name exact
    identification, and the file engine's own signals (found by reading its source)."""
    ids = {r.id for reg in (url_pack.RULES, email_pack.RULES, page_pack.RULES) for r in reg}
    for cfg in (url_scoring(), email_scoring(), page_scoring(), intel_scoring()):
        ids |= set(cfg["weights"])
    ids |= set(email_scoring()["certain"]["rules"])
    source = (ROOT / "core" / "files" / "engine.py").read_text(encoding="utf-8")
    return ids | set(re.findall(r'"(file\.[a-z_]+)"', source))


def facts_of(
    signals: Iterable[Signal], state: VerdictState, score: int | None, conf: Confidence,
    response: ResponseAction, caveat: str = "",
) -> str:  # fmt: skip
    """Everything the composer was told: its whole input, as one text."""
    parts = [state.value, str(score), conf.value, response.value, caveat]
    for s in signals:
        parts += [s.rule_id, s.category, s.description]
    return " ".join(parts)


def brands_in(text: str) -> set[str]:
    low = text.lower()
    names = {n.lower() for b in page_brands() for n in (b.name, *b.terms) if len(n) >= 4}
    return {n for n in names if re.search(rf"(?<!\w){re.escape(n)}(?!\w)", low)}


def test_every_rule_has_a_sentence() -> None:
    ids = all_rule_ids()
    assert len(ids) > 130  # the packs really were enumerated
    sentences = phrases()["rules"]
    assert sorted(i for i in ids if not sentences.get(i)) == []
    # short enough that a verdict's explanation stays well under the extension's 600 characters
    assert all(len(sentences[i]) <= 75 and not re.search(r"\d", sentences[i]) for i in ids)
    # an id nobody wrote a sentence for never crashes and never goes silent
    odd = compose(S, 50, LOW, WARN, [sig("zzz.new_rule"), sig("{x}.{y}", 0.1)])
    assert "zzz.new_rule" in odd.why and odd.text


def test_a_sentence_states_what_why_how_sure_and_what_next() -> None:
    signals = [
        sig("url.brand_in_domain", 0.3),
        sig("url.typosquat", 0.7),
        sig("url.login_path", 0.4),
    ]
    e = compose(M, 88, HIGH, BLOCK, signals)
    assert isinstance(e, Explanation)
    assert "risk score 88" in e.what and "phishing" in e.what
    # why: the strongest signs first, in words, and only the strongest two
    assert e.why == f"{phrases()['rules']['url.typosquat']} {phrases()['rules']['url.login_path']}"
    # how sure: the tier the scorer computed, named, with no invented probability
    assert "Confidence is high" in e.how_sure
    assert not re.search(r"%|probab|\bchance\b", e.text, re.I)
    assert "blocking" in e.next
    assert e.text == " ".join([e.what, e.why, e.how_sure, e.next]) and len(e.text) <= 400
    # the tier changes the wording and never the facts it states
    for tier in (LOW, MEDIUM, HIGH):
        assert f"Confidence is {tier.value.lower()}" in compose(S, 50, tier, WARN, signals).how_sure
    assert "sure of its source" in compose(S, 50, LOW, WARN, signals).next
    assert "quarantine" in compose(M, 90, HIGH, ResponseAction.QUARANTINE, signals).next
    # states with nothing to flag still say all four parts
    unknown = compose(
        VerdictState.UNKNOWN,
        None,
        LOW,
        ResponseAction.NONE,
        [sig("url.shortener", 0.2)],
        caveat=CAVEAT,
    )
    assert "could not tell" in unknown.what or "weak signs" in unknown.what
    assert unknown.why and "no confidence level" in unknown.how_sure and CAVEAT in unknown.next
    official = compose(VerdictState.BENIGN, 0, HIGH, ResponseAction.NONE, [], allowlisted=True)
    assert all(vars(official).values()) and "official domain" in official.what
    for state in VerdictState:  # nothing is left empty, whatever the state
        one = compose(state, None, LOW, ResponseAction.NONE, [sig("url.login_path", 0.4)])
        assert all(vars(one).values()), state
    # the engine's verdict carries the composer's text, and the old facts survive
    v = analyze_url("https://paypal.com@secure-check.test/login.php").verdict
    assert v.state in (S, M) and v.explanation.startswith("Lynceus found")
    assert phrases()["rules"]["url.userinfo_deception"] in v.explanation
    assert f"risk score {v.risk_score}" in v.explanation
    quiet = analyze_url("https://example.test/page").verdict
    assert "not evidence of safety" in quiet.explanation and "could not tell" in quiet.explanation
    assert "official domain" in analyze_url("https://www.paypal.com/signin").verdict.explanation
    # the two longest sentences together still fit the budget
    longest = sorted(phrases()["rules"], key=lambda r: -len(phrases()["rules"][r]))[:2]
    worst = compose(M, 100, HIGH, BLOCK, [sig(longest[0], 0.9), sig(longest[1], 0.8)])
    assert len(worst.text) <= 400


def test_no_fact_beyond_the_input_appears() -> None:
    cases: list[tuple[list[Signal], VerdictState, int | None, Confidence, ResponseAction]] = [
        ([sig(i)], S, 61, MEDIUM, WARN) for i in sorted(all_rule_ids())
    ]
    cases += [
        ([sig("url.typosquat"), sig("intel.phishtank.url", 0.85)], M, 93, HIGH, BLOCK),
        ([sig("url.shortener", 0.2)], VerdictState.UNKNOWN, None, LOW, ResponseAction.NONE),
        ([], VerdictState.BENIGN, 0, HIGH, ResponseAction.NONE),
        ([], VerdictState.ERROR, None, LOW, ResponseAction.NONE),
    ]
    for signals, state, score, conf, response in cases:
        e = compose(state, score, conf, response, signals, caveat=CAVEAT)
        facts = facts_of(signals, state, score, conf, response, CAVEAT)
        ids = [s.rule_id for s in signals]
        # numbers, dotted tokens (domains, rule ids) and brand names: each must come from the input
        for number in re.findall(r"\d+", e.text):
            assert re.search(rf"(?<!\d){number}(?!\d)", facts), (ids, number, e.text)
        for dotted in re.findall(r"[\w-]+(?:\.[\w-]+)*\.[\w-]{2,}", e.text.lower()):
            assert dotted in facts.lower(), (ids, dotted, e.text)
        assert brands_in(e.text) <= brands_in(facts), (ids, brands_in(e.text), e.text)
        assert unsupported(e.text, facts) == set(), (ids, e.text)
    # when the input names a brand and a domain the text may repeat them, and only them
    named = [sig("url.homograph_brand", 0.8, "PayPal lookalike (paypa1.com)")]
    e = compose(M, 82, HIGH, BLOCK, named)
    assert unsupported(e.text, facts_of(named, M, 82, HIGH, BLOCK)) == set()
    assert unsupported(
        e.text + " Seen on evil.example in 2024.", facts_of(named, M, 82, HIGH, BLOCK)
    )
    assert compose(M, 82, HIGH, BLOCK, named) == e  # the same input gives the same words


def test_a_fake_model_cannot_add_a_fact() -> None:
    plain = phrases()["rules"]["url.typosquat"]
    assert "misspelling" in plain

    def says(text: str) -> Callable[[str], str]:
        return lambda _: text

    for injected in (
        plain + " It was registered on evil-login.example.com.",  # a new domain
        plain.replace("a well-known brand's", "PayPal's"),  # a new brand
        plain.replace("a well-known brand's", "DHL's"),  # a short brand name, in capitals
        plain + " It is 97 sure.",  # a new number
        plain + " (url.homograph_brand)",  # a new rule name
        plain
        + " "
        + plain.replace("domain", "domain name") * 3,  # far longer than what it was given
    ):
        assert reword(plain, says(injected)) == plain, injected

    # a model that fails, or says nothing, leaves the deterministic text
    def boom(_: str) -> str:
        raise RuntimeError("model down")

    assert reword(plain, boom) == plain
    assert reword(plain, says("")) == plain and reword(plain, says("   \n ")) == plain
    assert reword(plain, lambda _: None) == plain  # type: ignore[arg-type,return-value]
    # a plain rewording is accepted, so the check is not simply refusing everything
    softer = plain.replace("misspelling", "misspelt version")
    assert reword(plain, says(softer)) == softer
    # facts that were supplied may be repeated; changing them is a new fact
    given = "Lynceus found strong signs of phishing (risk score 80). It imitates paypal.com."
    assert reword(given, says(given.replace("Lynceus found", "We found"))).startswith("We found")
    assert reword(given, says(given.replace("80", "90"))) == given
    assert reword(given, says(given.replace("paypal.com", "paypa1.com"))) == given
    assert reword(given, says(given + " Contact it at evil.example.")) == given
