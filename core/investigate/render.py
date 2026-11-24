"""A dossier as JSON, as text for a terminal, or as one self-contained HTML file (DA5 1a).

The text in a dossier can be hostile (an address, a page title). Control and invisible characters
(terminal escapes, bidi overrides) are shown as <U+XXXX>, and the HTML escapes every string: it has
no script, loads nothing, and says so to the browser in a content security policy.
"""

import html
import json
import unicodedata
from collections.abc import Iterator
from typing import Any


def visible(text: str) -> str:
    return "".join(
        f"<U+{ord(c):04X}>" if unicodedata.category(c) in ("Cc", "Cf", "Cs") else c for c in text
    )


def render_json(d: dict[str, Any]) -> str:
    return json.dumps(d, indent=2, ensure_ascii=True)


# ---- text ---------------------------------------------------------------------------------
def _scalar(x: Any) -> str:
    return "-" if x is None else visible(str(x))


def _lines(v: Any, pad: str) -> Iterator[str]:
    if isinstance(v, dict):
        for k, x in v.items():
            if isinstance(x, dict | list) and x:
                yield f"{pad}{k}:"
                yield from _lines(x, pad + "  ")
            else:
                yield f"{pad}{k}: {_scalar(x) if x != [] else '-'}"
    elif isinstance(v, list):
        for x in v:
            if isinstance(x, dict | list):
                yield f"{pad}-"
                yield from _lines(x, pad + "  ")
            else:
                yield f"{pad}- {_scalar(x)}"


def render_text(d: dict[str, Any]) -> str:
    v, t, a = d["verdict"], d["target"], d["attribution"]
    score = "n/a" if v["score"] is None else v["score"]
    out = [
        f"{v['state']}  score {score}  confidence {v['confidence']}",
        f"Target:   {t['kind']} {_scalar(t['value'])}  ({t['size']} bytes, sha256 {t['sha256']})",
        f"Why:      {_scalar(v['explanation'])}",
        f"Engine:   {d['engine']['name']}, version {d['engine']['version']}, "
        f"ruleset {d['engine']['ruleset_version']}",
    ]
    for name, s in d["sections"].items():
        out += ["", f"== {name}: {s['status']}"]
        out += [f"   {s['note']}"] if s["note"] else []
        out += _lines(s["facts"], "   ")
    out += ["", f"== attribution: {a['status']}", f"   {a['note'] or a['formula']}"]
    for c in a["categories"]:
        cap = " (capped)" if c["capped_by_cap"] else ""
        rows = f"{c['noisy_or']:.4f} -> {c['capped']:.4f}{cap}, {c['points']:.1f} points"
        out.append(f"   {c['category']}: {rows}")
    for s in a["signals"]:
        out.append(f"     {s['rule_id']} weight {s['weight']}: {s['points']:.1f} points")
    if a["status"] == "ok":
        out.append(
            f"   risk {a['risk_points']:.2f} points; rebuilt {a['rebuilt_state']} "
            f"{_scalar(a['rebuilt_score'])}; matches the verdict: {a['matches_verdict']}"
        )
    c = d["counterfactuals"]
    out += ["", f"== counterfactuals: {c['status']}", f"   {c['note']}"]
    for i in c["items"]:
        res = f"{i['state']} {_scalar(i['score'])}" if i["found"] else "not found"
        change = ", ".join(i["removed"]) or ", ".join(str(w) for w in i["added"])
        out.append(f"   {i['kind']} {change}: {res}")
    out += ["", "== limits"] + [f"   {x}" for x in d["limits"]]
    return "\n".join(visible(line) for line in out)


# ---- html ---------------------------------------------------------------------------------
_CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#5b6570;--line:#d5dae0;--card:#f5f7fa;--bad:#a4262c;--warn:#8a5a00}
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--fg:#e6e9ed;--muted:#9aa5b1;--line:#2d343b;
--card:#1c2025;--bad:#ff8a8f;--warn:#e3b341}}
*{box-sizing:border-box}body{margin:0;padding:16px;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin-inline:auto}
h1{font-size:1.4rem;margin:.2rem 0}h2{font-size:1.05rem;margin:1.4rem 0 .4rem}
section{border-top:1px solid var(--line)}.chip{border:1px solid var(--line);border-radius:1rem;
padding:0 .6rem;font-size:.8rem;color:var(--muted)}.note{color:var(--muted)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.15rem .8rem;margin:.3rem 0}
dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere;unicode-bidi:isolate}
table{border-collapse:collapse;width:100%;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:.2rem .5rem;text-align:left;unicode-bidi:isolate}
th{background:var(--card)}ul{margin:.2rem 0;padding-left:1.2rem}
.MALICIOUS{color:var(--bad)}.SUSPICIOUS{color:var(--warn)}
"""


def _e(x: Any) -> str:
    return html.escape(visible(str(x)))


def _node(v: Any) -> str:
    if v is None:
        return "<span class=note>-</span>"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, dict):
        return (
            "<dl>" + "".join(f"<dt>{_e(k)}</dt><dd>{_node(x)}</dd>" for k, x in v.items()) + "</dl>"
        )
    if isinstance(v, list):
        if not v:
            return "<span class=note>none</span>"
        if all(isinstance(x, dict) for x in v) and len({tuple(x) for x in v}) == 1:
            head = "".join(f"<th>{_e(k)}</th>" for k in v[0])
            rows = "".join(
                "<tr>" + "".join(f"<td>{_node(x)}</td>" for x in r.values()) + "</tr>" for r in v
            )
            return f"<table><tr>{head}</tr>{rows}</table>"
        return "<ul>" + "".join(f"<li>{_node(x)}</li>" for x in v) + "</ul>"
    return _e(v)


def render_html(d: dict[str, Any]) -> str:
    v, t = d["verdict"], d["target"]
    score = "n/a" if v["score"] is None else v["score"]
    parts = [
        f"<h1><span class={_e(v['state'])}>{_e(v['state'])}</span> {_e(score)}</h1>",
        f"<p>{_e(t['kind'])} {_e(t['value'])}</p><p class=note>{_e(v['explanation'])}</p>",
        "<section><h2>engine</h2>" + _node(d["engine"]) + "</section>",
        "<section><h2>verdict</h2>" + _node(v) + "</section>",
    ]
    for name, s in d["sections"].items():
        note = f"<p class=note>{_e(s['note'])}</p>" if s["note"] else ""
        parts.append(
            f"<section><h2>{_e(name)} <span class=chip>{_e(s['status'])}</span></h2>"
            f"{note}{_node(s['facts'])}</section>"
        )
    for name in ("attribution", "counterfactuals"):
        parts.append(f"<section><h2>{name}</h2>{_node(d[name])}</section>")
    parts.append("<section><h2>limits</h2>" + _node(d["limits"]) + "</section>")
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<meta http-equiv=Content-Security-Policy "
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>Lynceus dossier</title><style>{_CSS}</style></head><body>"
        + "".join(parts)
        + "</body></html>"
    )
