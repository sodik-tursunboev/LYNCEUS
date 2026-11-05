"""Every message rule proves itself on a positive and a negative message, and the pack stays
consistent with its config. Messages are built here, parsed by the real guest parser, and judged by
the real engine; only the sandbox is replaced (tests/sandbox/test_email_sandbox.py covers that).
"""

import pytest
from mailhelp import PHISH_LINK, analyze, eml, fired, multipart

from core.contracts import VerdictState
from rules.email import RULES
from rules.email.data import scoring
from rules.url import RULES as URL_RULES

CYR_A = chr(0x430)
MIXED = (CYR_A + "llegro.test").encode("idna").decode("ascii")  # a lookalike 'a' inside Latin text
EXE = b"MZ\x90\x00" + b"\x00" * 60
PDF = b"%PDF-1.7\n%%EOF\n"
ZIP = b"PK\x03\x04" + b"\x00" * 30
BINARY = "application/octet-stream"
ATTACK_IDS = {
    "T1566.001",
    "T1566.002",
    "T1598.003",
    "T1204.002",
    "T1027.006",
    "T1036.007",
    "T1036.002",
}


def html(body: str) -> bytes:
    return eml(html=body)


def from_domain(domain: str) -> bytes:
    return eml(sender=f"Someone <x@{domain}>")


def links(n: int) -> bytes:
    return html("".join(f'<a href="https://site{i}.test/p">link {i}</a>' for i in range(n)))


# rule id -> (a message that must fire it, a similar message that must not)
CASES: dict[str, tuple[bytes, bytes]] = {
    "email.multiple_from": (eml(extra_headers=[("From", "other@elsewhere.test")]), eml()),
    "email.display_name_brand": (
        eml(sender='"PayPal Support" <help@mailer-x.test>'),
        eml(sender='"PayPal" <service@paypal.com>'),
    ),
    "email.reply_to_mismatch": (
        eml(extra_headers=[("Reply-To", "help@other-domain.test")]),
        eml(extra_headers=[("Reply-To", "noreply@mail.sender.test")]),
    ),
    "email.auth_failure": (
        eml(extra_headers=[("Authentication-Results", "mx.example.test; dmarc=fail; spf=pass")]),
        eml(extra_headers=[("Authentication-Results", "mx.example.test; dmarc=pass; spf=pass")]),
    ),
    "email.sender.homograph_brand": (from_domain("xn--pple-43d.test"), from_domain("sender.test")),
    "email.sender.mixed_script": (from_domain(MIXED), from_domain("sender.test")),
    "email.sender.typosquat": (from_domain("paypa1.test"), from_domain("sender.test")),
    "email.sender.combosquat": (from_domain("paypal-login.test"), from_domain("sender.test")),
    "email.sender.brand_in_subdomain": (
        from_domain("paypal.com.evil.test"),
        from_domain("login.example.test"),
    ),
    "email.sender.brand_in_domain": (from_domain("mbank-opinie.test"), from_domain("sender.test")),
    "email.link_text_brand_mismatch": (
        html(PHISH_LINK),
        html('<a href="https://www.paypal.com/login">https://www.paypal.com/login</a>'),
    ),
    "email.link_text_mismatch": (
        html('<a href="https://evil-site.test/x">https://www.example.com/offer</a>'),
        html('<a href="https://evil-site.test/x">Click here</a>'),
    ),
    "email.hidden_link": (
        html('<a href="https://track.test/x" style="display:none">x</a>'),
        html('<a href="https://track.test/x">x</a>'),
    ),
    "email.image_only_link": (
        html('<a href="https://promo.test/"><img src="https://img.promo.test/a.png"></a>'),
        html('<a href="https://promo.test/">see the offer</a>'),
    ),
    "email.password_form": (
        html('<form action="https://collect.test/p"><input type="password" name="p"></form>'),
        html('<form action="https://collect.test/p"><input type="text" name="q"></form>'),
    ),
    "email.script_content": (html("<script>var a = 1;</script><p>hi</p>"), html("<p>hi</p>")),
    "email.meta_refresh": (
        html('<meta http-equiv="refresh" content="0; url=https://redir.test/go">'),
        html('<meta http-equiv="content-type" content="text/html">'),
    ),
    "email.link_flood": (links(45), links(5)),
    "email.dangerous_attachment": (
        eml(attachments=[("update.exe", EXE, BINARY)]),
        eml(attachments=[("notes.txt", b"hello", "text/plain")]),
    ),
    "email.double_extension": (
        eml(attachments=[("invoice.pdf.exe", EXE, BINARY)]),
        eml(attachments=[("report.final.pdf", PDF, "application/pdf")]),
    ),
    "email.rtl_filename": (
        eml(attachments=[(f"invoice{chr(0x202E)}fdp.exe", b"x", BINARY)]),
        eml(attachments=[("invoice.pdf", PDF, "application/pdf")]),
    ),
    "email.attachment_type_mismatch": (
        eml(attachments=[("invoice.pdf", EXE, "application/pdf")]),
        eml(attachments=[("invoice.pdf", PDF, "application/pdf")]),
    ),
    "email.macro_attachment": (
        eml(attachments=[("budget.xlsm", ZIP, "application/vnd.ms-excel.sheet.macroEnabled.12")]),
        eml(attachments=[("budget.xlsx", ZIP, "application/vnd.openxmlformats")]),
    ),
    "email.html_attachment": (
        eml(attachments=[("form.html", b"<html><body>x</body></html>", "text/html")]),
        eml(attachments=[("note.txt", b"x", "text/plain")]),
    ),
    "email.archive_attachment": (
        eml(attachments=[("files.zip", ZIP, "application/zip")]),
        eml(attachments=[("photo.png", b"\x89PNG\r\n\x1a\n", "image/png")]),
    ),
    "email.malformed_mime": (
        b'From: a@x.test\r\nContent-Type: multipart/mixed; boundary="zz"\r\n\r\n'
        b"--zz\r\nContent-Type: text/plain\r\n\r\nhello\r\n",
        eml(),
    ),
    "email.parser_limits": (multipart(600), eml()),
    "email.social_engineering": (
        eml(
            subject="Urgent: your account will be suspended",
            text="Your account is suspended. Please verify your account and enter your password.",
        ),
        eml(subject="Lunch", text="Lunch on Friday? Same place as last time."),
    ),
}


def test_every_rule_has_a_case() -> None:
    assert set(CASES) == {r.id for r in RULES}
    assert len(RULES) == len({r.id for r in RULES})


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires_on_its_positive_message(rule_id: str) -> None:
    assert rule_id in fired(CASES[rule_id][0])


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_stays_quiet_on_its_negative_message(rule_id: str) -> None:
    assert rule_id not in fired(CASES[rule_id][1])


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_no_rule_can_make_a_message_malicious_alone(rule_id: str) -> None:
    v = analyze(CASES[rule_id][0]).report.verdict
    assert v.state is not VerdictState.MALICIOUS, (rule_id, [s.rule_id for s in v.signals])


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_every_signal_carries_evidence_and_a_valid_tag(rule_id: str) -> None:
    v = analyze(CASES[rule_id][0]).report.verdict
    mine = [s for s in v.signals if s.rule_id == rule_id]
    assert mine and all(s.evidence_ids and s.description for s in mine)
    assert all(s.attack is None or s.attack in ATTACK_IDS for s in v.signals)


# ---- consistency with the config -----------------------------------------------------------------


def test_every_rule_has_a_weight_and_every_weight_a_rule() -> None:
    weights = scoring()["weights"]
    assert set(weights) == {r.id for r in RULES}
    assert all(0 < w <= 1 for w in weights.values())


def test_every_category_has_a_cap_including_the_link_categories() -> None:
    caps = scoring()["category_caps"]
    assert {r.category for r in RULES} <= set(caps)
    assert {f"link.{r.category}" for r in URL_RULES} <= set(caps)
    assert all(0 < c <= 1 for c in caps.values())


def test_more_than_one_category_is_needed_for_malicious() -> None:
    assert scoring()["thresholds"]["min_categories"] >= 2


def test_attack_ids_used_by_rules_are_the_verified_ones() -> None:
    assert {r.attack for r in RULES if r.attack} <= ATTACK_IDS


# ---- what the rules say must not leak the message ------------------------------------------------


def test_rule_summaries_name_facts_not_message_text() -> None:
    raw = eml(
        sender='"SubjectMarkDisplay PayPal" <x@mailer-x.test>',
        subject="SUBJMARK urgent verify your account",
        text="BODYMARK your password immediately",
        html='<a href="https://evil-site.test/PATHMARK?q=QUERYMARK">https://www.paypal.com/ANCHORMARK</a>',
        attachments=[("FILEMARK.pdf.exe", EXE, BINARY)],
    )
    report = analyze(raw).report
    assert report.verdict.signals
    said = " ".join(
        [report.verdict.explanation]
        + [s.description for s in report.verdict.signals]
        + [e.summary for e in report.evidence]
    )
    for marker in (
        "SUBJMARK",
        "BODYMARK",
        "SubjectMarkDisplay",
        "PATHMARK",
        "QUERYMARK",
        "ANCHORMARK",
        "FILEMARK",
    ):
        assert marker not in said, marker
