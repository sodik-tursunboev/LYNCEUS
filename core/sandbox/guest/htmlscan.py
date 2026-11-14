"""HTML link and form scanner. Standard library only; runs inside the sandbox.

Hiding is read from inline `style`, the `hidden` attribute and (H1 C1) top-level rules in <style>
blocks with simple selectors (`tag`, `.class`, `#id`, `tag.class`, `tag#id`), cascaded by
specificity, with the element's inline style winning. Rules inside `@media` and other at-rules are
ignored, and so is any selector an at-rule mentions: a responsive mail hides its desktop or mobile
half on one screen size only, which is not hiding from the reader. A <style> block applies to the
elements after it (one pass). Relative links are returned as written; the host resolves them with
the WHATWG parser, because that is what a browser would do.
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
    MAX_SCRIPT_CHARS,
    MAX_TAGS,
)

# HTML smuggling: a page that builds a file in the reader's browser from encoded data and saves it.
# Only counts are reported; no one indicator is a verdict (rules decide).
_BLOB = re.compile(
    r"new\s+blob\s*\(|createobjecturl|mssaveorOpenblob|mssaveblob|new\s+file\s*\(", re.I
)
_BASE64 = re.compile(r"[A-Za-z0-9+/]{2000,}={0,2}")
_DECODER = re.compile(
    r"\batob\s*\(|fromcharcode|\bunescape\s*\(|\beval\s*\(|new\s+function\s*\(", re.I
)
_SAVE = re.compile(r"\.download\s*=|setattribute\(\s*['\"]download|\.click\s*\(\s*\)", re.I)
_COUNT_CAP = 10_000

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


_SIMPLE = re.compile(r"^([a-z][a-z0-9-]*)?(?:([.#])(-?[a-z_][a-z0-9_-]*))?$")
_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_HIDING_PROPS = frozenset(
    {
        "display", "visibility", "opacity", "font-size", "width", "height", "max-width",
        "max-height", "left", "top", "right", "bottom", "text-indent", "position", "clip",
        "clip-path",
    }
)  # fmt: skip
MAX_CSS = 200_000  # characters of <style> read per HTML part
MAX_RULES = 2_000


def _blocks(css: str) -> tuple[list[tuple[str, str]], set[str]]:
    """Top-level (selector list, declarations) pairs, and every selector named inside an at-rule."""
    top: list[tuple[str, str]] = []
    in_at: set[str] = set()
    depth, head_start, body_start, at, head = 0, 0, 0, False, ""
    for i, ch in enumerate(css):
        if ch == "{":
            if depth == 0:
                head = css[head_start:i].rsplit(";", 1)[-1].strip()  # after any `@import ...;`
                at, body_start = head.startswith("@"), i + 1
            elif at:  # a rule nested in @media: remember its selectors, never apply it
                inner = css[head_start:i].rsplit(";", 1)[-1].rsplit("{", 1)[-1]
                in_at.update(s.strip() for s in inner.split(","))
            depth += 1
            head_start = i + 1
        elif ch == "}":
            if depth == 0:
                head_start = i + 1
                continue
            depth -= 1
            if depth == 0 and not at:
                top.append((head, css[body_start:i]))
            head_start = i + 1
    return top, in_at


class StyleSheet:
    """Simple-selector rules from <style> blocks. Rules with the same selector are merged into one
    property map in source order (same specificity, so the later one wins, as in CSS), and only the
    properties that can hide an element are kept: each element costs a few lookups however many
    rules a hostile sheet repeats."""

    def __init__(self) -> None:
        # selector key -> tag qualifier (None: any tag) -> [specificity, first seen, properties]
        self.by_key: dict[str, dict[str | None, list[Any]]] = {}
        self.count = 0
        self.css_len = 0

    def add(self, css: str) -> None:
        css = _COMMENT.sub("", css[: max(0, MAX_CSS - self.css_len)].lower())
        self.css_len += len(css)
        top, in_at = _blocks(css)
        for head, body in top:
            props = {
                name.strip(): value.strip()
                for name, _, value in (d.partition(":") for d in body.split(";"))
                if name.strip() in _HIDING_PROPS
            }
            if not props:
                continue  # only rules that can hide or show an element matter here
            for selector in (s.strip() for s in head.split(",")[:50]):
                m = _SIMPLE.match(selector)
                if not selector or not m or selector in in_at:
                    continue
                tag, kind, name = m.groups()
                key = f"{kind}{name}" if kind else f"<{tag}"
                entries = self.by_key.setdefault(key, {})
                qualifier = tag if kind else None
                if qualifier not in entries:
                    if self.count >= MAX_RULES:
                        continue
                    spec = (100 if kind == "#" else 10 if kind == "." else 0) + (1 if tag else 0)
                    entries[qualifier] = [spec, self.count, {}]
                    self.count += 1
                entries[qualifier][2].update(props)

    def declarations(self, tag: str, attrs: dict[str, str]) -> list[str]:
        if not self.by_key:
            return []
        keys = [f"<{tag}", *(f".{c}" for c in attrs.get("class", "").lower().split()[:50])]
        if attrs.get("id"):
            keys.append(f"#{attrs['id'].lower()}")
        found = [
            (spec, order, props)
            for k in keys
            for qualifier, (spec, order, props) in self.by_key.get(k, {}).items()
            if qualifier in (None, tag)
        ]
        found.sort(key=lambda r: (r[0], r[1]))
        return [";".join(f"{k}:{v}" for k, v in props.items()) for *_, props in found]


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
            "blob_apis": 0, "base64_blobs": 0, "decoders": 0, "auto_saves": 0, "data_downloads": 0,
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
    def __init__(
        self, part: str, budget: Budget, depth: int = 0, sheet: StyleSheet | None = None
    ) -> None:
        super().__init__(convert_charrefs=True)
        self.part, self.b, self.depth = (
            part,
            budget,
            depth,
        )  # depth > 0: inside a conditional comment
        self.sheet = sheet if sheet is not None else StyleSheet()  # one per HTML part
        self.stack: list[tuple[str, bool, dict[str, Any] | None]] = []
        self.anchors: list[dict[str, Any]] = []
        self.tags = 0
        self.skip = 0
        self.in_script = 0
        self.in_style = 0
        self.css: list[str] = []
        self.script: list[str] = []
        self.script_len = 0
        self.stopped = False

    def _add(self, kind: str, url: str, flags: list[str]) -> dict[str, Any] | None:
        """Links only some clients see (Outlook for Windows reads `<!--[if mso]>`) are marked."""
        return self.b.add_link(
            self.part, kind, url, [*flags, "conditional"] if self.depth else flags
        )

    def handle_comment(self, data: str) -> None:
        """A downlevel-hidden conditional comment is a comment to this parser but real HTML to
        Outlook for Windows: its links are read too (one level deep), so they cannot hide a
        destination."""
        if self.stopped or self.depth >= 1:
            return
        body = data.lstrip()
        if body[:3].lower() != "[if":
            return
        end = body.find("]>")
        if end < 0:
            return
        inner = re.sub(r"<!\[endif\]\s*$", "", body[end + 2 :], flags=re.I)
        nested = Scanner(self.part, self.b, self.depth + 1, self.sheet)
        try:
            nested.feed(inner)
            nested.close()
        except Exception:  # noqa: BLE001  (a hostile comment must not abort the message)
            self.b.hit.add("html_error")
        nested.finish()

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
        a: dict[str, str] = {}
        for (
            k,
            v,
        ) in attrs:  # the first of a repeated attribute wins, as in browsers and mail clients
            a.setdefault(k.lower(), v or "")
        cascade = [
            *self.sheet.declarations(tag, a),
            a.get("style", ""),
        ]  # inline style last: it wins
        hidden = self.hidden or "hidden" in a or style_hides(";".join(cascade))
        anchor: dict[str, Any] | None = None
        href = a.get("href") or a.get("xlink:href", "")
        if tag in ("button", "input") and a.get("formaction"):
            self._add("form", a["formaction"], ["hidden"] if hidden else [])  # a click posts there
        if (tag in ("a", "area") or tag.startswith("v:")) and href:  # v:* is Outlook
            flags = ["hidden"] if hidden else []
            if href.strip().lower().startswith("javascript:"):
                flags.append("javascript")
            if "download" in a and href.strip().lower().startswith(("data:", "blob:")):
                self.b.stats["data_downloads"] += 1
            rec = self._add("area" if tag == "area" else "a", href, flags)
            if rec is not None:
                anchor = {"rec": rec, "text": [], "has_image": False}
                self.anchors.append(anchor)
        elif tag == "form":
            self.b.stats["forms"] += 1
            if a.get("action"):
                self._add("form", a["action"], ["hidden"] if hidden else [])
        elif tag in ("iframe", "frame"):
            self.b.stats["iframes"] += 1
            if a.get("src"):
                self._add("iframe", a["src"], ["hidden"] if hidden else [])
        elif tag == "embed" and a.get("src"):
            self._add("iframe", a["src"], ["hidden"] if hidden else [])  # embedded document
        elif tag == "object" and a.get("data"):
            self._add("iframe", a["data"], ["hidden"] if hidden else [])
        elif tag == "script":
            self.b.stats["scripts"] += 1
            if a.get("src"):
                self._add("script", a["src"], [])
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = _REFRESH_URL.search(a.get("content", ""))
            if m:
                self._add("meta_refresh", m.group(1), [])
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
        if tag == "script":
            self.in_script += 1
        if tag == "style":
            self.in_style += 1
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
        if tag == "script" and self.in_script:
            self.in_script -= 1
        if tag == "style" and self.in_style:
            self.in_style -= 1
            if not self.in_style and self.css:
                self.sheet.add("".join(self.css))
                self.css = []

    def handle_data(self, data: str) -> None:
        if (
            self.in_style
            and not self.in_script
            and not self.stopped
            and sum(map(len, self.css)) < MAX_CSS
        ):
            self.css.append(data)
        if self.in_script and not self.stopped and self.script_len < MAX_SCRIPT_CHARS:
            room = data[: MAX_SCRIPT_CHARS - self.script_len]
            self.script.append(room)
            self.script_len += len(room)
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
        if self.script:
            text = "".join(self.script)
            stats = self.b.stats
            for key, pattern in (
                ("blob_apis", _BLOB), ("base64_blobs", _BASE64),
                ("decoders", _DECODER), ("auto_saves", _SAVE),
            ):  # fmt: skip
                stats[key] = min(stats[key] + len(pattern.findall(text)), _COUNT_CAP)


_SVG_ACTIVE = (
    ("script", re.compile(r"<script\b", re.I)),
    ("event_handler", re.compile(r"<[^>]*\son[a-z]{3,30}\s*=", re.I)),
    ("foreign_object", re.compile(r"<foreignobject\b", re.I)),
    ("embedded_form", re.compile(r"<(?:form|input|iframe|embed|object|textarea)\b", re.I)),
    ("javascript_link", re.compile(r"(?:href|src|action)\s*=\s*['\"]?\s*javascript:", re.I)),
    ("data_html_link", re.compile(
        r"(?:href|src)\s*=\s*['\"]?\s*data:\s*(?:text/html|application/xhtml|image/svg)", re.I)),
)  # fmt: skip


def svg_active(text: str) -> list[str]:
    """What an SVG image can DO when opened in a browser (H1 C2): run script, react to events, hold
    an HTML form, or link to script or to an HTML page carried inside it. A picture needs none of
    these. Entities are decoded first, so `&#106;avascript:` is still seen."""
    import html as entities

    text = entities.unescape(text[: MAX_SCRIPT_CHARS * 2])
    return [name for name, pattern in _SVG_ACTIVE if pattern.search(text)]


def scan_html(html: str, part: str, budget: Budget) -> None:
    budget.stats["html_parts"] += 1
    scanner = Scanner(part, budget)
    try:
        scanner.feed(html)
        scanner.close()
    except Exception:  # noqa: BLE001  (a hostile document must not abort the whole message)
        budget.hit.add("html_error")
    scanner.finish()
