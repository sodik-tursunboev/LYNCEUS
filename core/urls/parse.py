"""URL parsing and normalisation (ADR-012).

The reference is the WHATWG URL Standard, implemented by ada-url: what we analyse is what a
browser would navigate to. `urllib` is deliberately not used for this: it disagrees with
browsers, e.g. `http://evil.example\\@good.example/` is `evil.example` to a browser.

Offline and deterministic. Parsed values are sensitive (private URLs): never log them.
Failures carry a fixed reason and never echo the input.
"""

import hashlib
import ipaddress
import re
import unicodedata
from enum import StrEnum
from typing import Annotated

import ada_url
from ada_url import URL, HostType
from pydantic import BaseModel, ConfigDict, Field

from core.urls import psl

MAX_URL_LEN = 8192  # characters; longer input is UNKNOWN(url_too_long), not an error

_NEEDS_HOST = frozenset({"http", "https", "ftp", "ws", "wss"})
_KNOWN_NO_SLASHES = frozenset(  # schemes that are valid without "//"
    {
        "javascript",
        "data",
        "mailto",
        "tel",
        "sms",
        "vbscript",
        "blob",
        "about",
        "file",
        "view-source",
    }
)
_DANGEROUS = frozenset({"javascript", "data", "vbscript", "file", "blob"})
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")
_PORT_NEXT = re.compile(r"\d{1,5}(?:[/\\?#]|$)")
_DOUBLE_ENCODED = re.compile(r"%25[0-9A-Fa-f]{2}")
_REFANG_SCHEME = re.compile(r"(?i)^hxxp(s?)(?=[\[:])")
_REFANG_TOKEN = re.compile(r"(?i)\[(?:\.|dot|:|://|/|@|at)\]|\((?:\.|dot)\)|\{(?:\.|dot)\}")
_REFANG_MAP = {".": ".", "dot": ".", ":": ":", "://": "://", "/": "/", "@": "@", "at": "@"}
_C0_AND_SPACE = "".join(chr(i) for i in range(0x21))


class HostKind(StrEnum):
    DOMAIN = "DOMAIN"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    NONE = "NONE"  # no host, e.g. javascript: or data:
    OPAQUE = "OPAQUE"  # host of a non-web scheme (foo://x): not lowercased, no PSL analysis


class UrlFlag(StrEnum):
    """Facts about how the input differed from its normalised form. Not verdicts."""

    SCHEME_ASSUMED = "SCHEME_ASSUMED"  # input had no scheme; https was assumed
    REFANGED = "REFANGED"  # defanged input (hxxp, [.]) was restored
    WHITESPACE_TRIMMED = "WHITESPACE_TRIMMED"
    INTERIOR_WHITESPACE_REMOVED = "INTERIOR_WHITESPACE_REMOVED"  # tab/newline inside the URL
    CONTROL_CHARS = "CONTROL_CHARS"
    INVISIBLE_CHARS = "INVISIBLE_CHARS"  # zero-width, bidi and other format characters
    BACKSLASH = "BACKSLASH"
    TRAILING_DOT = "TRAILING_DOT"
    DEFAULT_PORT_ELIDED = "DEFAULT_PORT_ELIDED"  # explicit :80 / :443 was written
    DOUBLE_ENCODED = "DOUBLE_ENCODED"  # %25xx
    HOST_PERCENT_ENCODED = "HOST_PERCENT_ENCODED"
    USERINFO = "USERINFO"  # user[:password]@ before the host
    IDN = "IDN"  # non-ASCII host as written
    PUNYCODE = "PUNYCODE"  # xn-- label in the normalised host
    IP_OBFUSCATED = "IP_OBFUSCATED"  # IPv4 written as decimal/hex/octal/short/encoded form
    IPV4_MAPPED = "IPV4_MAPPED"  # ::ffff:a.b.c.d
    NON_HTTP_SCHEME = "NON_HTTP_SCHEME"
    DANGEROUS_SCHEME = "DANGEROUS_SCHEME"  # javascript:, data:, vbscript:, file:, blob:


class FailReason(StrEnum):
    EMPTY = "EMPTY"
    TOO_LONG = "TOO_LONG"
    UNPARSEABLE = "UNPARSEABLE"  # not a URL under the WHATWG URL Standard
    NO_HOST = "NO_HOST"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ParseFailure(_Frozen):
    reason: FailReason
    detail: str  # fixed text; never contains the input


class ParsedUrl(_Frozen):
    input_sha256: str  # of the raw input, before refanging and scheme assumption
    url_sha256: str  # of `normalized`
    normalized: str
    scheme: str
    username: str | None
    has_password: bool
    # DOMAIN hosts: lowercase ASCII (punycode), no trailing dot. IPv6 in brackets.
    host: str | None
    host_unicode: str | None
    host_kind: HostKind
    ip_address: str | None  # canonical, for IPv4/IPv6 hosts (IPv6 without brackets)
    mapped_ipv4: str | None  # the IPv4 inside ::ffff:a.b.c.d
    port: Annotated[int, Field(ge=0, le=65535)] | None  # None when absent or the scheme default
    path: str
    query: str  # without the leading "?"
    fragment: str  # without the leading "#"
    public_suffix: str | None
    registered_domain: str | None
    subdomain: str
    private_suffix: bool  # registered under a multi-tenant host such as github.io
    flags: tuple[UrlFlag, ...]  # sorted

    def has(self, flag: UrlFlag) -> bool:
        return flag in self.flags


def _fail(reason: FailReason, detail: str) -> ParseFailure:
    return ParseFailure(reason=reason, detail=detail)


def refang(text: str) -> str:
    """Restore defanged URLs: hxxp -> http, [.] (.) {.} [dot] -> '.', [:] -> ':', [@] -> '@'."""
    text = _REFANG_SCHEME.sub(lambda m: "http" + m.group(1).lower(), text)
    return _REFANG_TOKEN.sub(lambda m: _REFANG_MAP[m.group(0)[1:-1].lower()], text)


def _scheme_of(text: str) -> str | None:
    """The explicit scheme, or None for scheme-less input like `evil.example:8080/x`."""
    m = _SCHEME.match(text)
    if not m:
        return None
    scheme = m.group(1).lower()
    if scheme in _NEEDS_HOST or scheme in _KNOWN_NO_SLASHES:
        return scheme
    return None if _PORT_NEXT.match(text, m.end()) else scheme  # name:8080 is host:port


def _authority_tokens(candidate: str) -> tuple[str, str]:
    """(host token, port token) as written, to compare with the normalised form.

    Mirrors the WHATWG authority rules: slashes and backslashes after the scheme are skipped, the
    authority ends at the first / \\ ? #, and the last @ ends the credentials.
    """
    rest = candidate[candidate.index(":") + 1 :].lstrip("/\\")
    end = next((i for i, ch in enumerate(rest) if ch in "/\\?#"), len(rest))
    hostport = rest[:end].rpartition("@")[2]
    if hostport.startswith("["):
        close = hostport.find("]")
        if close == -1:
            return hostport, ""
        tail = hostport[close + 1 :]
        return hostport[: close + 1], tail[1:] if tail.startswith(":") else ""
    host, _, port = hostport.partition(":")
    return host, port


def parse_url(raw: str) -> ParsedUrl | ParseFailure:
    if len(raw) > MAX_URL_LEN:
        return _fail(FailReason.TOO_LONG, f"input exceeds {MAX_URL_LEN} characters")
    flags: set[UrlFlag] = set()

    if any((ord(c) < 0x20 and c not in "\t\n\r") or 0x7F <= ord(c) <= 0x9F for c in raw):
        flags.add(UrlFlag.CONTROL_CHARS)
    text = raw.strip(_C0_AND_SPACE)
    if text != raw:
        flags.add(UrlFlag.WHITESPACE_TRIMMED)
    if any(c in text for c in "\t\n\r"):
        flags.add(UrlFlag.INTERIOR_WHITESPACE_REMOVED)
        text = text.replace("\t", "").replace("\n", "").replace("\r", "")
    if not text:
        return ParseFailure(reason=FailReason.EMPTY, detail="no URL in input")

    fanged = refang(text)
    if fanged != text:
        flags.add(UrlFlag.REFANGED)
    text = fanged

    scheme = _scheme_of(text)
    if scheme is None:
        flags.add(UrlFlag.SCHEME_ASSUMED)
        body = text.lstrip("/\\")
        if not body:
            return ParseFailure(reason=FailReason.UNPARSEABLE, detail="no host after the slashes")
        text, scheme = "https://" + body, "https"
    if any(unicodedata.category(c) == "Cf" for c in text):
        flags.add(UrlFlag.INVISIBLE_CHARS)

    try:
        u = URL(text)
    except ValueError:  # includes UnicodeEncodeError for lone surrogates
        return _fail(FailReason.UNPARSEABLE, "not a valid URL (WHATWG URL Standard)")
    scheme = str(u.protocol).rstrip(":").lower()

    host_token = port_token = ""
    if scheme in _NEEDS_HOST:
        host_token, port_token = _authority_tokens(text)
        if "\\" in text.split("?", 1)[0].split("#", 1)[0]:
            flags.add(UrlFlag.BACKSLASH)
    elif "\\" in text:
        flags.add(UrlFlag.BACKSLASH)

    host: str | None = str(u.hostname) or None
    kind = HostKind.NONE
    if host is not None and scheme not in _NEEDS_HOST:
        kind = HostKind.OPAQUE  # foo://Host/x: kept as the standard leaves it, not analysed
    elif host is not None:
        kind = {HostType.IPV4: HostKind.IPV4, HostType.IPV6: HostKind.IPV6}.get(
            u.host_type, HostKind.DOMAIN
        )
        if kind is HostKind.DOMAIN and host.endswith("."):
            flags.add(UrlFlag.TRAILING_DOT)
            stripped = host.rstrip(".")
            if not stripped:
                return _fail(FailReason.NO_HOST, "URL has no host")
            try:
                u.hostname = stripped
            except ValueError:  # e.g. "x.127.." -> "x.127" re-parses as a bad IPv4: do not guess
                return _fail(FailReason.UNPARSEABLE, "host could not be normalised")
            host = str(u.hostname)
            if host != stripped:
                return _fail(FailReason.UNPARSEABLE, "host could not be normalised")
    if scheme in _NEEDS_HOST and host is None:
        return ParseFailure(reason=FailReason.NO_HOST, detail="URL has no host")

    ip_address = mapped = None
    if kind is HostKind.IPV4 and host is not None:
        ip_address = host
        if host_token.lower().rstrip(".") != host:
            flags.add(UrlFlag.IP_OBFUSCATED)
    elif kind is HostKind.IPV6 and host is not None:
        ip_address = host.strip("[]")
        v4 = ipaddress.IPv6Address(ip_address).ipv4_mapped
        if v4 is not None:
            mapped = str(v4)
            flags.add(UrlFlag.IPV4_MAPPED)

    if "%" in host_token:
        flags.add(UrlFlag.HOST_PERCENT_ENCODED)
    if not host_token.isascii():
        flags.add(UrlFlag.IDN)
    if port_token and not str(u.port):
        flags.add(UrlFlag.DEFAULT_PORT_ELIDED)
    if u.username or u.password:
        flags.add(UrlFlag.USERINFO)
    if scheme not in ("http", "https"):
        flags.add(UrlFlag.NON_HTTP_SCHEME)
    if scheme in _DANGEROUS:
        flags.add(UrlFlag.DANGEROUS_SCHEME)

    normalized = str(u.href)
    if _DOUBLE_ENCODED.search(normalized):
        flags.add(UrlFlag.DOUBLE_ENCODED)

    host_unicode = public_suffix = registered = None
    subdomain, private = "", False
    if kind is HostKind.DOMAIN and host is not None:
        if any(label.startswith("xn--") for label in host.split(".")):
            flags.add(UrlFlag.PUNYCODE)
        host_unicode = str(ada_url.idna.decode(host))
        m = psl.lookup(host)
        public_suffix, registered, private = m.public_suffix, m.registered_domain, m.private
        if registered is not None:
            subdomain = host[: len(host) - len(registered)].rstrip(".")

    return ParsedUrl(
        input_sha256=hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest(),
        url_sha256=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        normalized=normalized,
        scheme=scheme,
        username=str(u.username) or None,
        has_password=bool(u.password),
        host=host,
        host_unicode=host_unicode or (host if kind is not HostKind.NONE else None),
        host_kind=kind,
        ip_address=ip_address,
        mapped_ipv4=mapped,
        port=int(u.port) if str(u.port) else None,
        path=str(u.pathname),
        query=str(u.search).removeprefix("?"),
        fragment=str(u.hash).removeprefix("#"),
        public_suffix=public_suffix,
        registered_domain=registered,
        subdomain=subdomain,
        private_suffix=private,
        flags=tuple(sorted(flags)),
    )
