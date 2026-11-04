"""M0 stub engine: no detection logic. Always abstains, so it can never look "safe" by accident."""

from core.contracts import Artifact, Confidence, ResponseAction, Verdict, VerdictState

ENGINE_VERSION = "stub-0"


def analyze(artifact: Artifact) -> Verdict:
    return Verdict(
        artifact_id=artifact.id,
        state=VerdictState.UNKNOWN,
        risk_score=None,
        confidence=Confidence.LOW,
        signals=[],
        evidence_ids=[],
        provider_results=[],
        recommended_response=ResponseAction.NONE,
        applied_response=ResponseAction.NONE,
        explanation="Stub engine (M0): no detection rules are implemented.",
        engine_version=ENGINE_VERSION,
        ruleset_version="none",
    )
