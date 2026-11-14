"""Checked findings become ordinary signals in the `brain` category, with evidence that names the
finding and never the model's words."""

from collections.abc import Mapping

from core.contracts import Evidence, Signal

ATTACK = {
    "brain.page_impersonation": "T1566.002",  # Phishing: Spearphishing Link (the page it leads to)
    "brain.page_pressure": "T1566.002",
    "brain.page_script_exfiltration": "T1566.002",
    "brain.page_visual_brand": "T1566.002",
    "brain.mail_intent": "T1566",
    "brain.mail_impersonation": "T1566",
}


def to_signals(
    findings: list[tuple[str, str]], weights: Mapping[str, float], sha256: str, kind: str
) -> tuple[list[Signal], list[Evidence]]:
    signals: list[Signal] = []
    evidence: list[Evidence] = []
    for rule_id, description in findings:
        if rule_id not in weights:
            continue  # a finding without a weight is not scored (and a test catches it)
        ev = Evidence(kind=kind, summary=description[:500], sha256=sha256)
        evidence.append(ev)
        signals.append(
            Signal(
                rule_id=rule_id,
                category="brain",
                weight=weights[rule_id],
                description=description[:500],
                evidence_ids=[ev.id],
                attack=ATTACK.get(rule_id),
            )  # fmt: skip
        )
    return signals, evidence
