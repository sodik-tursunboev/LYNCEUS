"""PDF triage with qpdf (through pikepdf). Runs inside the sandbox on hostile input.

It reports which active-content and link features exist, never what they would do when opened:
nothing is rendered, executed, saved or fetched, and stream data is never decoded. A document the
library cannot read is reported as such (`parse`), not guessed about.
"""

import io
import itertools
import re
from collections.abc import Iterator
from typing import Any

from limits import MAX_PDF_OBJECTS, MAX_PDF_URIS, MAX_URI_CHARS

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_RICH = {"/RichMedia", "/Flash", "/3D", "/Movie", "/Sound", "/Screen"}


def _text(value: Any) -> str:
    return _CONTROL.sub("", str(value)).strip()[:MAX_URI_CHARS]


_MAX_NODES = 200  # direct dictionaries and arrays examined inside one object
_MAX_NEST = 8


def _nodes(root: Any, pikepdf: Any) -> Iterator[Any]:
    """The object plus the direct dictionaries and arrays nested in it (references are not
    followed: every indirect object is visited on its own)."""
    stack = [(root, 0)]
    seen = 0
    while stack and seen < _MAX_NODES:
        node, depth = stack.pop()
        seen += 1
        yield node
        if depth >= _MAX_NEST:
            continue
        if isinstance(node, (pikepdf.Dictionary, pikepdf.Stream)):
            children = [node[key] for key in node]
        elif isinstance(node, pikepdf.Array):
            children = list(node)
        else:
            continue
        stack += [
            (c, depth + 1)
            for c in children
            if isinstance(c, (pikepdf.Dictionary, pikepdf.Array)) and not c.is_indirect
        ]


def _object(obj: Any, out: dict[str, Any], uris: dict[str, None], pikepdf: Any) -> None:
    if not isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
        return
    keys = set(obj.keys())
    action = _text(obj["/S"]) if "/S" in keys else ""
    kind = _text(obj["/Type"]) if "/Type" in keys else ""
    if action == "/JavaScript" or "/JS" in keys:
        out["javascript"] += 1
    if action == "/Launch":
        out["launch"] += 1
    if action == "/SubmitForm":
        out["submit_form"] += 1
    if action == "/URI" and "/URI" in keys:
        uri = _text(obj["/URI"])
        if uri and (uri in uris or len(uris) < MAX_PDF_URIS):
            uris[uri] = None
        elif uri:
            out["limits"].add("uris")
    if kind == "/EmbeddedFile":
        out["embedded_files"] += 1
    if kind == "/Catalog":
        out["open_action"] = out["open_action"] or "/OpenAction" in keys
        out["additional_actions"] = out["additional_actions"] or "/AA" in keys
        if "/AcroForm" in keys:
            out["forms"] = True
            form = obj["/AcroForm"]
            if isinstance(form, pikepdf.Dictionary) and "/XFA" in form:
                out["xfa"] = True
    if "/Subtype" in keys and _text(obj["/Subtype"]) in _RICH:
        out["rich_media"] += 1


def scan_pdf(data: bytes) -> dict[str, Any]:
    import pikepdf

    out: dict[str, Any] = {
        "kind": "pdf", "parse": "ok", "encrypted": False, "pages": 0, "objects": 0,
        "javascript": 0, "launch": 0, "submit_form": 0, "embedded_files": 0, "rich_media": 0,
        "open_action": False, "additional_actions": False, "forms": False, "xfa": False,
        "uris": [], "limits": set(),
    }  # fmt: skip
    try:
        pdf = pikepdf.open(io.BytesIO(data), suppress_warnings=True)
    except pikepdf.PasswordError:
        out.update(parse="encrypted", encrypted=True, limits=[])
        return out
    except (MemoryError, RecursionError):
        raise
    except Exception:  # noqa: BLE001  (qpdf could not make sense of it)
        out.update(parse="failed", limits=[])
        return out
    uris: dict[str, None] = {}
    with pdf:
        out["encrypted"] = bool(pdf.is_encrypted)
        total = len(pdf.objects)
        out["objects"] = min(total, 10_000_000)
        if total > MAX_PDF_OBJECTS:
            out["limits"].add("objects")
        for obj in itertools.islice(pdf.objects, MAX_PDF_OBJECTS):
            try:
                for node in _nodes(obj, pikepdf):
                    _object(node, out, uris, pikepdf)
            except (MemoryError, RecursionError):
                raise
            except Exception:  # noqa: BLE001  (one broken object does not end the scan)
                out["limits"].add("broken_objects")
        try:
            out["pages"] = min(len(pdf.pages), 10_000_000)
        except Exception:  # noqa: BLE001
            out["limits"].add("page_tree")
    out["uris"] = list(uris)
    out["limits"] = sorted(out["limits"])
    return out
