"""Open one URL in a locked-down Chromium and describe the page (D1).

Runs inside the detonator container as `pwuser`, with Chromium's own sandbox ON and every request
going through the egress proxy. Reads {"url", "proxy"} as JSON on stdin and writes one JSON result
on stdout. It never types, clicks, submits, grants a permission or keeps a download, and it stops
itself after WATCHDOG_SECONDS (the host kills the container a little later in any case).

What comes back is data for the host to check, never instructions: the host validates every field
against a closed schema with size limits and re-encodes the screenshot in its own sandbox.
"""

import base64
import json
import os
import re
import sys
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Response, sync_playwright

NAV_TIMEOUT_MS = 15_000
SETTLE_MS = 4_000
WATCHDOG_SECONDS = 26
MAX_CHAIN = 20
MAX_HOSTS = 100
MAX_REFS = 100
MAX_SCRIPTS = 25
MAX_SCRIPT_BYTES = 300_000
MAX_SCREENSHOT = 300_000
VIEWPORT = {"width": 1280, "height": 800}

# Read from the page; every value is cut to a fixed size in the browser before it comes back.
COLLECT = r"""() => {
  const cap = (s, n) => String(s || "").slice(0, n);
  const abs = (u) => { try { return new URL(u, document.baseURI).href; } catch (e) { return ""; } };
  const field = (e) => ({
    type: cap((e.type || e.tagName || "").toLowerCase(), 20),
    hint: cap([e.name, e.id, e.placeholder, e.autocomplete, e.getAttribute && e.getAttribute("aria-label")]
      .filter(Boolean).join(" ").toLowerCase(), 120),
  });
  const forms = [...document.forms].slice(0, 20).map((f) => ({
    action: cap(abs(f.getAttribute("action") || document.URL), 2048),
    method: cap((f.getAttribute("method") || "get").toLowerCase(), 10),
    fields: [...f.elements].slice(0, 50).filter((e) => e.tagName === "INPUT" || e.tagName === "SELECT"
      || e.tagName === "TEXTAREA").map(field),
  }));
  const loose = [...document.querySelectorAll("input")].filter((i) => !i.form).slice(0, 50).map(field);
  const logos = [...document.querySelectorAll("img, [role=img], svg")].slice(0, 80).map((i) => cap([
    i.getAttribute("alt"), i.getAttribute("aria-label"), i.getAttribute("title"),
    i.tagName === "IMG" ? (i.getAttribute("src") || "").split(/[?#]/)[0].split("/").pop() : "",
    i.tagName.toLowerCase() === "svg" && i.querySelector("title") ? i.querySelector("title").textContent : "",
  ].filter(Boolean).join(" "), 200)).filter(Boolean);
  const icon = document.querySelector('link[rel~="icon"]');
  return {
    title: cap(document.title, 300),
    headings: [...document.querySelectorAll("h1, h2")].slice(0, 10).map((h) => cap(h.innerText, 200)),
    logos,
    text: cap(document.body ? document.body.innerText : "", 20000),
    forms,
    loose,
    frames: [...document.querySelectorAll("iframe, frame")].slice(0, 30).map((f) => cap(abs(f.src), 2048)),
    inline: [...document.scripts].filter((s) => !s.src).map((s) => s.textContent || "").join("\n").slice(0, 400000),
    html_events: cap([...document.querySelectorAll("[oncontextmenu],[onkeydown],[onselectstart],[ondragstart]")]
      .slice(0, 20).map((e) => [e.getAttribute("oncontextmenu"), e.getAttribute("onkeydown"),
      e.getAttribute("onselectstart")].join(" ")).join(" "), 4000),
    favicon: icon ? cap(abs(icon.href), 2048) : "",
  };
}"""

# Signs of a page hiding from analysts. Each is a kind; the host decides what a number of kinds means.
MARKERS = {
    # a debugger trap or a window-size check; the bare word "devtools" is in every React build
    "devtools_trap": re.compile(
        r"outerWidth\s*-\s*(?:window\.)?innerWidth\s*>|setInterval\([^)]{0,300}\bdebugger\b"
        r"|\bdebugger\b[^;]{0,40};?\s*\}\s*,\s*\d{2,4}\s*\)",
        re.I,
    ),
    "key_block": re.compile(
        r"keyCode\s*={2,3}\s*123\b|key\s*={2,3}\s*['\"]F12['\"]"
        r"|ctrlKey\s*&&\s*\w+\.shiftKey\s*&&\s*\w+\.keyCode\s*={2,3}\s*7[3-4]",
        re.I,
    ),
    "context_block": re.compile(
        r"contextmenu['\"]?\s*,\s*(?:function\s*\(\s*\w*\s*\)|\(?\w*\)?\s*=>)\s*\{?[^}]{0,80}preventDefault"
        r"|oncontextmenu\s*=\s*['\"]?\s*return\s+false|return\s+false",
        re.I,
    ),
    "webdriver_check": re.compile(r"navigator\s*\.\s*webdriver", re.I),
    "decoded_writer": re.compile(
        r"document\s*\.\s*write\s*\(\s*(?:unescape|atob|decodeURIComponent|window\.atob)\s*\(", re.I
    ),
}
_DECODERS = re.compile(r"\batob\s*\(|\bunescape\s*\(|fromCharCode\s*\(|\\x[0-9a-f]{2}", re.I)
_LONG_BLOB = re.compile(r"[A-Za-z0-9+/=]{20000,}")
_REF = re.compile(r"https?://([a-z0-9.-]{1,253})((?:/[a-z0-9._~-]{1,40}){0,2})", re.I)


def _watchdog() -> None:
    sys.stdout.write(json.dumps({"status": "error", "error": "watchdog"}))
    sys.stdout.flush()
    os._exit(3)


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "")[:253]
    except ValueError:
        return ""


def markers(inline: str, own_scripts: list[str], html_events: str) -> list[str]:
    """Anti-analysis marker kinds, from the page's own code only (third-party libraries such as
    bot-protection services check `navigator.webdriver` for their own reasons)."""
    code = "\n".join([inline, *own_scripts])
    found = [name for name, rx in MARKERS.items() if name != "context_block" and rx.search(code)]
    if MARKERS["context_block"].search(html_events) or re.search(
        r"contextmenu[\s\S]{0,120}preventDefault", code, re.I
    ):
        found.append("context_block")
    if len(_DECODERS.findall(inline)) >= 25 or _LONG_BLOB.search(inline):
        found.append("heavy_decoding")
    return sorted(found)


def refs(texts: list[str]) -> list[str]:
    """host/first/two segments of every absolute URL written in the page's scripts."""
    out: list[str] = []
    for text in texts:
        for m in _REF.finditer(text):
            ref = (m.group(1) + m.group(2)).lower()[:120]
            if ref not in out:
                out.append(ref)
                if len(out) >= MAX_REFS:
                    return out
    return out


def _error_code(e: Exception) -> str:
    m = re.search(r"net::(ERR_[A-Z_]+)", str(e))
    if m:
        return m.group(1).lower()
    return "timeout" if "Timeout" in type(e).__name__ or "Timeout" in str(e)[:200] else "navigation"


DESKTOP: dict[str, Any] = {"viewport": VIEWPORT}
PHONE: dict[str, Any] = {
    "viewport": {"width": 390, "height": 844}, "is_mobile": True, "has_touch": True,
    "device_scale_factor": 3,
    "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 "
                  "(KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
}  # fmt: skip
PHONE_NAV_MS = 8_000
PHONE_SETTLE_MS = 3_000
RETRY_BEFORE_S = 9  # a phone visit only if the first ended this early: both fit the watchdog
_GATE_TITLES = ("just a moment", "attention required", "verify you are human", "checking your browser")

# Forms inside frames (H1 C5), read in each frame's own document, the same way as the page's.
FRAME_FORMS = r"""() => {
  const cap = (s, n) => String(s || "").slice(0, n);
  const abs = (u) => { try { return new URL(u, document.baseURI).href; } catch (e) { return ""; } };
  const field = (e) => ({
    type: cap((e.type || e.tagName || "").toLowerCase(), 20),
    hint: cap([e.name, e.id, e.placeholder, e.autocomplete, e.getAttribute && e.getAttribute("aria-label")]
      .filter(Boolean).join(" ").toLowerCase(), 120),
  });
  return [...document.forms].slice(0, 5).map((f) => ({
    action: cap(abs(f.getAttribute("action") || document.URL), 2048),
    method: cap((f.getAttribute("method") || "get").toLowerCase(), 10),
    fields: [...f.elements].slice(0, 50).filter((e) => e.tagName === "INPUT" || e.tagName === "SELECT"
      || e.tagName === "TEXTAREA").map(field),
  }));
}"""


def showed_nothing(r: dict[str, Any]) -> bool:
    """The desktop visit got a refusal, a blank page or a bot check: nothing to judge."""
    if r["status"] in ("dead", "error") or (r.get("http_status") or 0) in (401, 403, 429, 503):
        return True
    if str(r.get("title", "")).strip().lower().startswith(_GATE_TITLES):
        return True
    return not str(r.get("text", "")).strip() and not r.get("forms")


def shows_something(r: dict[str, Any]) -> bool:
    return (
        r["status"] in ("ok", "partial") and (r.get("http_status") or 0) < 400
        and bool(str(r.get("text", "")).strip() or r.get("forms"))
        and not str(r.get("title", "")).strip().lower().startswith(_GATE_TITLES)
    )  # fmt: skip


def _status_of(r: dict[str, Any]) -> str:
    return f"http_{r['http_status']}" if r.get("http_status") else str(r["status"])


def run(url: str, proxy: str | None) -> dict[str, Any]:
    """`proxy` is the egress proxy; None only in the offline tests, whose container has no network.
    One desktop visit; if it showed nothing and there is time, one more as a phone (H1 C5): some
    kits show scanners and desktops a refusal and phones the page."""
    started = time.monotonic()
    with sync_playwright() as p:
        args = [
            "--disable-quic",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--disable-background-networking",
        ]
        if proxy:
            args.append("--proxy-bypass-list=<-loopback>")  # even loopback goes to the proxy
        browser = p.chromium.launch(
            chromium_sandbox=True,  # Playwright's default is off; untrusted pages need it on
            proxy={"server": proxy} if proxy else None,
            args=args,
        )
        result = _visit(browser, url, DESKTOP, NAV_TIMEOUT_MS, SETTLE_MS)
        if showed_nothing(result) and time.monotonic() - started < RETRY_BEFORE_S:
            phone = _visit(browser, url, PHONE, PHONE_NAV_MS, PHONE_SETTLE_MS)
            if shows_something(phone):
                phone.update(phone_view=True, desktop_status=_status_of(result))
                result = phone
        result["browser"] = browser.version[:40]
        browser.close()
    result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return result


def _visit(browser: Any, url: str, profile: dict[str, Any], nav_ms: int, settle_ms: int) -> dict[str, Any]:
    """One visit in a fresh context: what the page showed, read without typing or clicking."""
    result: dict[str, Any] = {"status": "ok", "error": None, "chain": [], "hosts": [],
                              "downloads": [], "popups": 0, "dialogs": 0}  # fmt: skip
    responses: list[Response] = []
    last_main: list[Response] = []
    major = browser.version.split(".")[0]
    options: dict[str, Any] = {
        # the headless marker in the default user agent makes phishing kits show a blank page
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36",
        "locale": "en-US", "accept_downloads": False, "service_workers": "block",
        "permissions": [], "java_script_enabled": True,
    }  # fmt: skip
    context = browser.new_context(**{**options, **profile})  # a phone replaces viewport and agent
    page = context.new_page()
    hosts: list[str] = result["hosts"]

    def on_request(req: Any) -> None:
        h = _host(req.url)
        if h and h not in hosts and len(hosts) < MAX_HOSTS:
            hosts.append(h)

    def on_response(r: Response) -> None:
        if r.request.resource_type == "script" and len(responses) < MAX_SCRIPTS:
            responses.append(r)
        if r.request.is_navigation_request() and r.frame == page.main_frame:
            last_main[:] = [r]

    def on_nav(frame: Any) -> None:
        if frame == page.main_frame and len(result["chain"]) < MAX_CHAIN:
            result["chain"].append(frame.url[:2048])

    def on_download(d: Any) -> None:
        name = (d.suggested_filename or "")[-100:]
        ext = name.rsplit(".", 1)[-1].lower()[:10] if "." in name else ""
        scheme = (urlsplit(d.url).scheme or "")[:10]
        if len(result["downloads"]) < 10:
            result["downloads"].append({"ext": ext, "scheme": scheme})
        try:
            d.cancel()
        except PlaywrightError:
            pass

    def on_popup(other: Any) -> None:
        result["popups"] += 1
        try:
            other.close()
        except PlaywrightError:
            pass

    def on_dialog(dialog: Any) -> None:
        result["dialogs"] += 1
        try:
            dialog.dismiss()
        except PlaywrightError:
            pass

    context.on("request", on_request)
    page.on("response", on_response)
    page.on("framenavigated", on_nav)
    page.on("download", on_download)
    page.on("popup", on_popup)
    page.on("dialog", on_dialog)

    first = None
    try:
        first = page.goto(url, wait_until="load", timeout=nav_ms)
    except PlaywrightError as e:
        result["error"] = _error_code(e)
        result["status"] = "partial" if result["error"] == "timeout" else "dead"
    if result["status"] != "dead":
        try:
            page.wait_for_load_state("networkidle", timeout=settle_ms)
        except PlaywrightError:
            pass  # busy pages never go idle; what has loaded is enough
    main = last_main[0] if last_main else first
    result["http_status"] = main.status if main is not None else None
    result["final_url"] = page.url[:2048]
    if result["status"] != "dead" or page.url.startswith(("http://", "https://")):
        try:
            seen = page.evaluate(COLLECT)
        except PlaywrightError:
            seen = None
        if seen:
            inline = seen.pop("inline", "")
            html_events = seen.pop("html_events", "")
            for frame in page.frames[1:11]:  # forms inside frames, from any site (H1 C5)
                if len(seen["forms"]) >= 20:
                    break
                try:
                    framed = frame.evaluate(FRAME_FORMS)
                except PlaywrightError:
                    continue  # a frame that went away or never loaded
                for f in framed[: 20 - len(seen["forms"])]:
                    seen["forms"].append({**f, "frame": True})
            own_host = _host(page.url)
            own, other = [], []
            for r in responses:
                try:
                    body = r.body()[:MAX_SCRIPT_BYTES].decode("utf-8", "replace")
                except PlaywrightError:
                    continue
                (own if _host(r.url) == own_host else other).append(body)
            result.update(seen)
            result["markers"] = markers(inline, own, html_events)
            result["script_refs"] = refs([inline, *own, *other])
            result["script_hosts"] = sorted({_host(r.url) for r in responses} - {""})[:50]
        try:
            details = main.security_details() if main is not None else None
        except PlaywrightError:
            details = None
        if details:
            result["tls"] = {
                "valid_from": int(details.get("validFrom") or 0),
                "valid_to": int(details.get("validTo") or 0),
                "issuer": str(details.get("issuer") or "")[:200],
            }
        try:
            shot = page.screenshot(type="jpeg", quality=55, timeout=5000)
            if len(shot) > MAX_SCREENSHOT:
                shot = page.screenshot(type="jpeg", quality=30, timeout=5000)
            if len(shot) <= MAX_SCREENSHOT:
                result["screenshot"] = base64.b64encode(shot).decode("ascii")
        except PlaywrightError:
            pass
    context.close()
    return result

def main() -> int:
    timer = threading.Timer(WATCHDOG_SECONDS, _watchdog)
    timer.daemon = True
    timer.start()
    try:
        request = json.loads(sys.stdin.read(10_000))
        url = str(request["url"])[:8192]
        proxy = str(request["proxy"])[:200] if request.get("proxy") else None
        if not url.lower().startswith(("http://", "https://")):
            answer: dict[str, Any] = {"status": "error", "error": "scheme"}
        else:
            answer = run(url, proxy)
    except Exception as e:  # noqa: BLE001  (one line of JSON whatever happens)
        answer = {"status": "error", "error": type(e).__name__[:60]}
    sys.stdout.write(json.dumps(answer))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
