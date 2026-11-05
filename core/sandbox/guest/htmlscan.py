"""HTML link and form scanner. Standard library only; runs inside the sandbox.

Only inline `style` and attributes are evaluated: there is no CSS cascade, so a class that hides an
element in a <style> block is not seen. Relative links are returned as written; the host resolves
them with the WHATWG parser, because that is what a browser would do.
"""

import re
from html.parser import HTMLParser
from typing import Any

from limits import (
    MAX_EXCERPT,
    MAX_HTML_DEPTH,
    MAX_LINK_BYTES,
    MAX_LINK_TEXT,
    MAX_LINK_URL,
    MAX_LINKS,
    MAX_TAGS,
)

_VOID = frozenset(
    [
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    ]
)
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad]")
_NUMBER = re.compile(r"^\s*(-?\d+(?:\.\d+)?)\s*([a-z%]*)\s*$")
_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.I)


def _num(value: str) -> float | None:
    m = _NUMBER.match(value)
    return float(m.group(1)) if m else None


def style_hides(style: str) -> bool:
    """True when inline CSS makes an element invisible or unreadable to a person."""
    if not style:
        return False
    props: dict[str, str] = {}
    for decl in style.lower().split(";"):
        name, _, setting = decl.partition(":")
        props[name.strip()] = setting.strip().replace("!important", "").strip()
    if props.get("display") == "none" or props.get("visibility") in ("hidden", "collapse"):
        return True
    opacity = _num(props.get("opacity", ""))
    if opacity is not None and opacity <= 0.05:
        return True
    size = _num(props.get("font-size", ""))
    if size is not None and size <= 1:
        return True
    for key in ("width", "height", "max-width", "max-height"):
        value = _num(props.get(key, ""))
        if value is not None and value == 0:
            return True
    for key in ("left", "top", "right", "bottom", "text-indent"):
        value = _num(props.get(key, ""))
        if (
            value is not None
            and value <= -500
            and (key == "text-indent" or props.get("position") in ("absolute", "fixed"))
        ):
            return True
    clip = props.get("clip", "") + props.get("clip-path", "")
    return "rect(0" in clip.replace(" ", "") or "inset(100%" in clip.replace(" ", "")


class Budget:
    """Shared across all HTML parts of one message."""

    def __init__(self) -> None:
        self.links: list[dict[str, Any]] = []
        self.link_bytes = 0
        self.hit: set[str] = set()
        self.base: str | None = None
        self.stats = {
            "forms": 0, "password_inputs": 0, "scripts": 0, "external_images": 0,
            "tracking_pixels": 0, "iframes": 0, "html_parts": 0,
        }  # fmt: skip
        self.excerpt: list[str] = []
        self.excerpt_len = 0

    def add_link(self, part: str, kind: str, url: str, flags: list[str]) -> dict[str, Any] | None:
        url = url.strip()
        if not url:
            return None
        if len(self.links) >= MAX_LINKS or self.link_bytes + len(url) > MAX_LINK_BYTES:
            self.hit.add("links")
            return None
        url = url[:MAX_LINK_URL]
        self.link_bytes += len(url)
        rec: dict[str, Any] = {"part": part, "kind": kind, "url": url, "text": "", "flags": flags}
        self.links.append(rec)
        return rec

    def add_text(self, text: str) -> None:
        if self.excerpt_len < MAX_EXCERPT:
            self.excerpt.append(text)
            self.excerpt_len += len(text) + 1


class Scanner(HTMLParser):
    def __init__(self, part: str, budget: Budget) -> None:
        super().__init__(convert_charrefs=True)
        self.part, self.b = part, budget
        self.stack: list[tuple[str, bool, dict[str, Any] | None]] = []
        self.anchors: list[dict[str, Any]] = []
        self.tags = 0
        self.skip = 0
        self.stopped = False

    @property
    def hidden(self) -> bool:
        return bool(self.stack and self.stack[-1][1])

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.stopped:
            return
        self.tags += 1
        if self.tags > MAX_TAGS:
            self.b.hit.add("html_tags")
            self.stopped = True
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        hidden = self.hidden or "hidden" in a or style_hides(a.get("style", ""))
        anchor: dict[str, Any] | None = None
        href = a.get("href") or a.get("xlink:href", "")
        if tag in ("a", "area") and href:
            flags = ["hidden"] if hidden else []
            if href.strip().lower().startswith("javascript:"):
                flags.append("javascript")
            rec = self.b.add_link(self.part, "a" if tag == "a" else "area", href, flags)
            if rec is not None:
                anchor = {"rec": rec, "text": [], "has_image": False}
                self.anchors.append(anchor)
        elif tag == "form":
            self.b.stats["forms"] += 1
            if a.get("action"):
                self.b.add_link(self.part, "form", a["action"], ["hidden"] if hidden else [])
        elif tag in ("iframe", "frame"):
            self.b.stats["iframes"] += 1
            if a.get("src"):
                self.b.add_link(self.part, "iframe", a["src"], ["hidden"] if hidden else [])
        elif tag == "script":
            self.b.stats["scripts"] += 1
            if a.get("src"):
                self.b.add_link(self.part, "script", a["src"], [])
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = _REFRESH_URL.search(a.get("content", ""))
            if m:
                self.b.add_link(self.part, "meta_refresh", m.group(1), [])
        elif tag == "base" and a.get("href") and self.b.base is None:
            self.b.base = a["href"].strip()[:MAX_LINK_URL]
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.b.stats["password_inputs"] += 1
        elif tag == "img":
            for open_anchor in self.anchors:
                open_anchor["has_image"] = True
            src = a.get("src", "").strip().lower()
            if src.startswith(("http://", "https://", "//")):
                self.b.stats["external_images"] += 1
            tiny = all(_num(a.get(k, "")) in (0.0, 1.0) for k in ("width", "height") if a.get(k))
            if tiny and (a.get("width") or a.get("height")):
                self.b.stats["tracking_pixels"] += 1
        if tag in ("script", "style"):
            self.skip += 1
        if tag not in _VOID:
            if len(self.stack) < MAX_HTML_DEPTH:
                self.stack.append((tag, hidden, anchor))
            else:
                self.b.hit.add("html_depth")

    def handle_endtag(self, tag: str) -> None:
        if self.stopped or tag in _VOID:
            return
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                for _t, _h, anchor in self.stack[i:]:
                    if anchor is not None:
                        self._finish(anchor)
                del self.stack[i:]
                break
        if tag in ("script", "style") and self.skip:
            self.skip -= 1

    def handle_data(self, data: str) -> None:
        if self.stopped or self.skip or not data.strip():
            return
        for anchor in self.anchors:
            if sum(len(t) for t in anchor["text"]) < MAX_LINK_TEXT * 2:
                anchor["text"].append(data)
        if not self.hidden:
            self.b.add_text(" ".join(data.split()))

    def _finish(self, anchor: dict[str, Any]) -> None:
        if anchor not in self.anchors:
            return
        self.anchors.remove(anchor)
        raw = "".join(anchor["text"])
        text = " ".join(_INVISIBLE.sub("", raw).split())[:MAX_LINK_TEXT]
        flags: list[str] = anchor["rec"]["flags"]
        if _INVISIBLE.search(raw):
            flags.append("invisible_text")
        if not text:
            flags.append("image_link" if anchor["has_image"] else "empty_text")
        anchor["rec"]["text"] = text

    def finish(self) -> None:
        for anchor in list(self.anchors):
            self._finish(anchor)


def scan_html(html: str, part: str, budget: Budget) -> None:
    budget.stats["html_parts"] += 1
    scanner = Scanner(part, budget)
    try:
        scanner.feed(html)
        scanner.close()
    except Exception:  # noqa: BLE001  (a hostile document must not abort the whole message)
        budget.hit.add("html_error")
    scanner.finish()
