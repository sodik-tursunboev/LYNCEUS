"""The learned domain model at run time (AI1 P1): a weights file, a sum and a sigmoid, under 1 ms.

`rules/learned/url_host.json` (bias, threshold, scale, the SHA-256 of the weights) and
`url_host.bin` (one signed 16-bit weight per hashed feature, little-endian; 16-bit changed none of
93,939 test decisions, 8-bit changed 112) are written by `python -m eval.learn_url` and copied here
only when the measurement passed the adoption rule (docs/milestones/AI1.md). Without them, or if
the weights do not match their recorded hash, nothing scores.
"""

import hashlib
import json
import math
import sys
import threading
from array import array
from dataclasses import dataclass
from pathlib import Path

from core.learn.hostfeatures import BUCKETS, features
from core.urls.parse import ParsedUrl

DEFAULT = Path(__file__).parents[2] / "rules" / "learned" / "url_host.json"


@dataclass(frozen=True)
class HostModel:
    version: str
    bias: float
    weights: "array[int]"  # signed 16-bit, BUCKETS long
    scale: float
    threshold: float  # the adopted operating point (probability)

    def probability(self, u: ParsedUrl) -> tuple[float, list[str]]:
        """P(phishing) from the registered domain, and the tokens that pushed it up most."""
        feats = features(u)
        z = self.bias + self.scale * sum(self.weights[i] for i in feats)
        p = 1.0 / (1.0 + math.exp(-max(-40.0, min(40.0, z))))
        pushes = sorted(((self.weights[i], t) for i, t in feats.items()), reverse=True)
        return p, [t for w, t in pushes[:3] if w > 0]


def pack(weights: list[float]) -> tuple[bytes, float]:
    """Weights -> (16-bit little-endian bytes, scale)."""
    peak = max((abs(w) for w in weights), default=1.0) or 1.0
    scale = peak / 32767
    packed = array("h", (round(w / scale) for w in weights))
    if sys.byteorder != "little":
        packed.byteswap()
    return packed.tobytes(), scale


def load(header: Path) -> HostModel:
    meta = json.loads(header.read_text(encoding="utf-8"))
    raw = header.with_suffix(".bin").read_bytes()
    if hashlib.sha256(raw).hexdigest() != meta["sha256"] or len(raw) != 2 * BUCKETS:
        raise ValueError("the weights do not match their header")
    weights = array("h")
    weights.frombytes(raw)
    if sys.byteorder != "little":
        weights.byteswap()
    return HostModel(
        version=str(meta["version"]), bias=float(meta["bias"]), weights=weights,
        scale=float(meta["scale"]), threshold=float(meta["threshold"]),
    )  # fmt: skip


_lock = threading.Lock()
_loaded: dict[str, HostModel | None] = {}


def current(path: Path = DEFAULT) -> HostModel | None:
    with _lock:
        key = str(path)
        if key not in _loaded:
            try:
                _loaded[key] = load(path)
            except (OSError, ValueError, KeyError):
                _loaded[key] = None
        return _loaded[key]
