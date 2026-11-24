"""Why a score is what it is, and what would change it (DA5 1a). Offline and pure.

`attribute` splits the engine's own scoring (core/risk/scoring.py) into numbers that rebuild it:
per signal, per category, then the category combination. `rebuild` recomputes the state and score
from those listed numbers alone. `counterfactuals` tries stated changes on the engine's signal list
and calls the engine's real scorer on each; nothing is estimated.
"""

import itertools
import math
from collections.abc import Callable, Mapping, Sequence
from typing import Any, NamedTuple

from core.contracts import Signal, VerdictState
from core.investigate import words
from core.risk.scoring import Scored, score

CERTAIN_FLOOR = 95  # core/risk/scoring.py: an exact identification scores at least this
SEARCH_BUDGET = 20_000  # scorer calls for the fewest-signals search; past it, sizes are not tried
_FLOOR = 1e-12  # keeps -ln(1 - weight) finite for a weight of exactly 1


def _noisy_or(weights: Sequence[float]) -> float:
    return 1 - math.prod(1 - w for w in sorted(weights))


def _hazard(p: float) -> float:
    return -math.log(max(1 - p, _FLOOR)) + 0.0  # + 0.0: no negative zero


def _thresholds(cfg: Mapping[str, Any]) -> dict[str, Any]:
    t = cfg["thresholds"]
    return {k: t[k] for k in ("suspicious", "malicious", "high_weight", "min_categories")}


def not_scored(cfg: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The attribution of an input that was not analysed: same keys, nothing listed."""
    return {
        "status": words.NOT_APPLICABLE, "note": words.NOT_SCORED, "formula": words.FORMULA,
        "thresholds": _thresholds(cfg) if cfg else None, "allowlisted": False,
        "certain_rules": [], "categories": [], "signals": [], "combined": None,
        "risk_points": None, "independent_categories": None, "rebuilt_state": None,
        "rebuilt_score": None, "matches_verdict": None,
    }  # fmt: skip


def attribute(
    signals: Sequence[Signal], allowlisted: bool, cfg: Mapping[str, Any]
) -> dict[str, Any]:
    t, caps = _thresholds(cfg), cfg["category_caps"]
    certain = sorted({s.rule_id for s in signals} & set(cfg.get("certain", {}).get("rules", ())))
    by_cat: dict[str, list[Signal]] = {}
    for s in signals:
        by_cat.setdefault(s.category, []).append(s)
    cats = []
    for name in sorted(by_cat):
        weights = [s.weight for s in by_cat[name]]
        within = _noisy_or(weights)
        cap = caps.get(name, 1.0)
        capped = min(within, cap)
        cats.append({
            "category": name, "signals": [s.rule_id for s in by_cat[name]], "noisy_or": within,
            "cap": cap, "capped": capped, "capped_by_cap": within > cap,
            "strong": max(weights) >= t["high_weight"], "points": 0.0,
        })  # fmt: skip
    combined = _noisy_or([c["capped"] for c in cats]) if cats else 0.0
    risk_points = 100 * combined
    total = sum(_hazard(c["capped"]) for c in cats)
    rows = []
    for c in cats:
        c["points"] = risk_points * _hazard(c["capped"]) / total if total else 0.0
        inside = sum(_hazard(s.weight) for s in by_cat[c["category"]])
        for s in by_cat[c["category"]]:
            share = _hazard(s.weight) / inside if inside else 0.0
            rows.append({
                "rule_id": s.rule_id, "category": s.category, "weight": s.weight,
                "description": s.description, "attack": s.attack,
                "points": c["points"] * share,
            })  # fmt: skip
    out: dict[str, Any] = {
        "status": words.OK, "note": "", "formula": words.FORMULA, "thresholds": t,
        "allowlisted": allowlisted, "certain_rules": certain, "categories": cats, "signals": rows,
        "combined": combined, "risk_points": risk_points,
        "independent_categories": sum(c["strong"] for c in cats),
    }  # fmt: skip
    state, shown = rebuild(out)
    return {**out, "rebuilt_state": state, "rebuilt_score": shown, "matches_verdict": None}


def rebuild(attribution: Mapping[str, Any]) -> tuple[str, int | None]:
    """State and shown score from the listed numbers alone (signal weights, category caps,
    thresholds, the allowlist flag): the same arithmetic as the engine, written out again."""
    t = attribution["thresholds"]
    weights: dict[str, list[float]] = {}
    for s in attribution["signals"]:
        weights.setdefault(s["category"], []).append(s["weight"])
    caps = {c["category"]: c["cap"] for c in attribution["categories"]}
    if not weights:
        if attribution["allowlisted"]:
            return VerdictState.BENIGN.value, 0
        return VerdictState.UNKNOWN.value, None
    capped = [min(_noisy_or(ws), caps[c]) for c, ws in sorted(weights.items())]
    risk = round(100 * _noisy_or(capped))
    strong = sum(max(ws) >= t["high_weight"] for ws in weights.values())
    if attribution["certain_rules"]:
        return VerdictState.MALICIOUS.value, max(risk, CERTAIN_FLOOR)
    if risk >= t["malicious"] and strong >= t["min_categories"]:
        return VerdictState.MALICIOUS.value, risk
    if risk >= t["suspicious"]:
        return VerdictState.SUSPICIOUS.value, risk
    if attribution["allowlisted"]:
        return VerdictState.BENIGN.value, risk
    return VerdictState.UNKNOWN.value, None


def _item(
    kind: str,
    statement: str,
    after: Scored | None,
    *,
    removed: Sequence[str] = (),
    added: Sequence[float] = (),
    points: int | None = None,
    alternatives: int | None = None,
    searched_up_to: int | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind, "statement": statement, "found": after is not None,
        "removed": list(removed), "added": list(added),
        "state": after.state.value if after else None,
        "score": after.risk_score if after else None, "points": points,
        "alternatives": alternatives, "searched_up_to": searched_up_to,
        "confirmed": after is not None,
    }  # fmt: skip


def _without(signals: Sequence[Signal], drop: Sequence[int]) -> list[Signal]:
    return [s for i, s in enumerate(signals) if i not in drop]


class _Fewest(NamedTuple):
    removed: tuple[int, ...]
    after: Scored | None
    others: int
    tried: int  # the largest set size fully tried


def _fewest(
    signals: Sequence[Signal],
    allowlisted: bool,
    cfg: Mapping[str, Any],
    done: Callable[[Scored], bool],
) -> _Fewest:
    """The smallest sets of signals whose removal satisfies `done`, by trying every set of each size
    in turn (the first such set in list order, and how many others of that size there are)."""
    n, spent = len(signals), 0
    for size in range(1, n + 1):
        spent += math.comb(n, size)
        if spent > SEARCH_BUDGET:
            return _Fewest((), None, 0, size - 1)
        hits = [
            (c, after)
            for c in itertools.combinations(range(n), size)
            if done(after := score(_without(signals, c), allowlisted, cfg))
        ]
        if hits:
            return _Fewest(hits[0][0], hits[0][1], len(hits) - 1, size)
    return _Fewest((), None, 0, n)


def _reach(
    signals: Sequence[Signal], allowlisted: bool, cfg: Mapping[str, Any], k: int, goal: VerdictState
) -> Scored | None:
    extra = Signal(
        rule_id="counterfactual.added", category="counterfactual", weight=k / 1000,
        description="a signal that is not in the engine's list",
    )  # fmt: skip
    after = score([*signals, extra], allowlisted, cfg)
    ok = after.state is goal or (
        goal is VerdictState.SUSPICIOUS and after.state is VerdictState.MALICIOUS
    )
    return after if ok else None


def _add(
    signals: Sequence[Signal],
    allowlisted: bool,
    cfg: Mapping[str, Any],
    attribution: Mapping[str, Any],
    goal: VerdictState,
) -> dict[str, Any]:
    """The smallest weight (steps of 0.001) of one extra signal, from a category not already there,
    that makes the engine's scorer reach `goal`; the scorer also confirms one step less does not."""
    malicious = goal is VerdictState.MALICIOUS
    kind = words.ADD_FOR_MALICIOUS if malicious else words.ADD_FOR_SUSPICIOUS
    statement = words.CF_ADD_FOR_MALICIOUS if malicious else words.CF_ADD_FOR_SUSPICIOUS
    if _reach(signals, allowlisted, cfg, 1000, goal) is None:
        return _item(kind, statement, None)
    lo, hi = 1, 1000
    while lo < hi:
        mid = (lo + hi) // 2
        if _reach(signals, allowlisted, cfg, mid, goal):
            hi = mid
        else:
            lo = mid + 1
    after = _reach(signals, allowlisted, cfg, lo, goal)
    confirmed = lo == 1 or _reach(signals, allowlisted, cfg, lo - 1, goal) is None
    line = cfg["thresholds"]["malicious" if malicious else "suspicious"]
    points = max(line - round(attribution["risk_points"]), 0)
    return _item(kind, statement, after if confirmed else None, added=[lo / 1000], points=points)


def counterfactuals(
    signals: Sequence[Signal],
    allowlisted: bool,
    cfg: Mapping[str, Any],
    attribution: Mapping[str, Any],
) -> dict[str, Any]:
    base = score(signals, allowlisted, cfg)
    items = [
        _item(
            words.REMOVE_ONE, words.CF_REMOVE_ONE,
            score(_without(signals, (i,)), allowlisted, cfg), removed=[s.rule_id],
        )
        for i, s in enumerate(signals)
    ]  # fmt: skip
    flagged = (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)
    steps = []
    if base.state is VerdictState.MALICIOUS:
        steps.append((words.BELOW_MALICIOUS, words.CF_BELOW_MALICIOUS,
                      lambda a: a.state is not VerdictState.MALICIOUS))  # fmt: skip
    if base.state in flagged:
        steps.append((words.BELOW_SUSPICIOUS, words.CF_BELOW_SUSPICIOUS,
                      lambda a: a.state not in flagged))  # fmt: skip
    for kind, statement, done in steps:
        f = _fewest(signals, allowlisted, cfg, done)
        names = [signals[i].rule_id for i in f.removed]
        items.append(_item(kind, statement, f.after, removed=names,
                           alternatives=f.others if f.after else None,
                           searched_up_to=f.tried))  # fmt: skip
    if base.state is VerdictState.SUSPICIOUS:
        items.append(_add(signals, allowlisted, cfg, attribution, VerdictState.MALICIOUS))
    elif base.state in (VerdictState.UNKNOWN, VerdictState.BENIGN):
        items.append(_add(signals, allowlisted, cfg, attribution, VerdictState.SUSPICIOUS))
    return {
        "status": words.OK, "note": words.CF_NOTE,
        "baseline": {"state": base.state.value, "score": base.risk_score}, "items": items,
    }  # fmt: skip


def not_tried() -> dict[str, Any]:
    return {"status": words.NOT_APPLICABLE, "note": words.CF_NOT_SCORED, "baseline": None,
            "items": []}  # fmt: skip
