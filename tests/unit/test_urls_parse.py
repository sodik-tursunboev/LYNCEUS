import hashlib
import random
import time

import pytest

from core.urls.parse import (
    MAX_URL_LEN,
    FailReason,
    HostKind,
    ParsedUrl,
    ParseFailure,
    UrlFlag,
    parse_url,
    refang,
)

F = UrlFlag


def ok(raw: str) -> ParsedUrl:
    r = parse_url(raw)
    assert isinstance(r, ParsedUrl), r
    return r


def fail(raw: str) -> ParseFailure:
    r = parse_url(raw)
    assert isinstance(r, ParseFailure), r
    return r


# Expected values follow the WHATWG URL Standard (what a browser navigates to), not urllib.
WHATWG = [
    # Backslash ends the host for special schemes: the browser goes to evil.example.
    ("http://evil.example\\@good.example/", "http://evil.example/@good.example/"),
    ("http:\\\\evil.example\\login", "http://evil.example/login"),
    ("http://good.example@evil.example/", "http://good.example@evil.example/"),
    ("http://evil.example#@good.example/", "http://evil.example/#@good.example/"),
    # Numeric hosts all mean 127.0.0.1.
    ("http://2130706433/", "http://127.0.0.1/"),
    ("http://0x7f000001/", "http://127.0.0.1/"),
    ("http://017700000001/", "http://127.0.0.1/"),
    ("http://127.1/", "http://127.0.0.1/"),
    ("http://0x7f.1/", "http://127.0.0.1/"),
    ("http://0177.0.0.1/", "http://127.0.0.1/"),
    ("http://[::ffff:127.0.0.1]/", "http://[::ffff:7f00:1]/"),
    ("http://[0:0:0:0:0:0:0:1]/", "http://[::1]/"),
    # Case, dot segments, default ports, trailing dots (ours: stripped).
    ("HTTP://EXAMPLE.test/A/../b", "http://example.test/b"),
    ("http://EXAMPLE.test./A/../b", "http://example.test/b"),
    ("http://example.test../x", "http://example.test/x"),
    ("http://example.test:80/", "http://example.test/"),
    ("https://example.test:443/", "https://example.test/"),
    ("http://example.test:8080/", "http://example.test:8080/"),
    ("http://example.test:0080/", "http://example.test/"),
    # Percent-encoding in the host is decoded; in the path it is kept or normalised.
    ("http://exa%6Dple.test/", "http://example.test/"),
    ("http://example.test/a b?c d#e f", "http://example.test/a%20b?c%20d#e%20f"),
    ("http://example.test/%2e%2e/x", "http://example.test/x"),
    ("http://example.test/?q=%2525", "http://example.test/?q=%2525"),
    # IDN -> punycode.
    ("http://m\u00fcnchen.test/", "http://xn--mnchen-3ya.test/"),
    ("http://\u0430pple.test/", "http://xn--pple-43d.test/"),  # Cyrillic a
    ("http://a.\u200bb.test/", "http://a.b.test/"),  # zero-width space is ignored by UTS46
    # Tabs and newlines vanish; leading/trailing control and space are trimmed.
    ("http://exa\tmp\nle.test/", "http://example.test/"),
    ("  \thttp://example.test/ \n ", "http://example.test/"),
    # Non-web schemes are parsed, not rejected.
    ("javascript:alert(1)", "javascript:alert(1)"),
    ("data:text/html,<b>x</b>", "data:text/html,<b>x</b>"),
    ("mailto:a@example.test", "mailto:a@example.test"),
    # No scheme: https is assumed (flagged below).
    ("evil.example/login", "https://evil.example/login"),
    ("//evil.example/login", "https://evil.example/login"),
    ("\\\\evil.example\\login", "https://evil.example/login"),
    ("evil.example:8080/x", "https://evil.example:8080/x"),
    ("user@evil.example/x", "https://user@evil.example/x"),
    ("[::1]:8080/x", "https://[::1]:8080/x"),
    # Defanged.
    ("hxxps://evil[.]example/login", "https://evil.example/login"),
    ("hxxp://evil(.)example[:]8080/x", "http://evil.example:8080/x"),
]


@pytest.mark.parametrize(("raw", "want"), WHATWG)
def test_normalised_form_matches_the_whatwg_standard(raw: str, want: str) -> None:
    assert ok(raw).normalized == want


def test_browser_target_is_the_host_not_the_decoy() -> None:
    u = ok("http://evil.example\\@good.example/")
    assert u.host == "evil.example" and u.registered_domain == "evil.example"
    assert u.username is None  # the "@" is in the path, not in credentials


# ---- flags -------------------------------------------------------------------------------------

FLAGS = [
    ("http://example.test/", set()),
    ("example.test", {F.SCHEME_ASSUMED}),
    ("  http://example.test/ ", {F.WHITESPACE_TRIMMED}),
    ("http://exa\tmple.test/", {F.INTERIOR_WHITESPACE_REMOVED}),
    ("\x00http://example.test/", {F.CONTROL_CHARS, F.WHITESPACE_TRIMMED}),
    ("http://example.test\\path", {F.BACKSLASH}),
    ("http://example.test./", {F.TRAILING_DOT}),
    ("http://example.test:80/", {F.DEFAULT_PORT_ELIDED}),
    ("https://example.test:443/", {F.DEFAULT_PORT_ELIDED}),
    ("http://example.test:8080/", set()),
    ("http://example.test/?q=%2525", {F.DOUBLE_ENCODED}),
    ("http://example.test/?q=%25", set()),
    ("http://exa%6Dple.test/", {F.HOST_PERCENT_ENCODED}),
    ("http://m\u00fcnchen.test/", {F.IDN, F.PUNYCODE}),
    ("http://xn--mnchen-3ya.test/", {F.PUNYCODE}),
    ("http://a.\u200bb.test/", {F.IDN, F.INVISIBLE_CHARS}),
    ("http://user@example.test/", {F.USERINFO}),
    ("http://127.0.0.1/", set()),  # canonical IPv4 is not obfuscated
    ("http://0x7f.0.0.1/", {F.IP_OBFUSCATED}),
    ("http://2130706433/", {F.IP_OBFUSCATED}),
    ("http://127.1/", {F.IP_OBFUSCATED}),
    ("http://0177.0.0.1/", {F.IP_OBFUSCATED}),
    ("http://%31%32%37.0.0.1/", {F.IP_OBFUSCATED, F.HOST_PERCENT_ENCODED}),
    ("http://[::ffff:127.0.0.1]/", {F.IPV4_MAPPED}),
    ("http://[2001:db8::1]/", set()),
    ("ftp://example.test/", {F.NON_HTTP_SCHEME}),
    ("javascript:alert(1)", {F.NON_HTTP_SCHEME, F.DANGEROUS_SCHEME}),
    ("data:text/plain,x", {F.NON_HTTP_SCHEME, F.DANGEROUS_SCHEME}),
    ("file:///etc/hosts", {F.NON_HTTP_SCHEME, F.DANGEROUS_SCHEME}),
    ("hxxps://evil[.]example/x", {F.REFANGED}),
]


@pytest.mark.parametrize(("raw", "want"), FLAGS)
def test_flags(raw: str, want: set[UrlFlag]) -> None:
    assert set(ok(raw).flags) == want


def test_flags_are_sorted_and_unique() -> None:
    flags = ok("  hxxp://user@m\u00fcnchen[.]test:80\\x ").flags
    assert list(flags) == sorted(set(flags))


# ---- fields ------------------------------------------------------------------------------------


def test_userinfo_deception() -> None:
    u = ok("https://brand.com@evil.example/login")
    assert (u.host, u.username, u.has_password) == ("evil.example", "brand.com", False)
    assert u.registered_domain == "evil.example"
    userinfo = "alice:" + "pw"  # built here so no "user:pass@" literal sits in the source
    with_pw = ok(f"https://{userinfo}@evil.example/")
    assert with_pw.username == "alice" and with_pw.has_password


def test_ip_hosts() -> None:
    v4 = ok("http://0x7f.1/")
    assert (v4.host_kind, v4.host, v4.ip_address) == (HostKind.IPV4, "127.0.0.1", "127.0.0.1")
    assert v4.registered_domain is None and v4.host_unicode == "127.0.0.1"
    v6 = ok("http://[::ffff:10.0.0.1]:8443/")
    assert (v6.host_kind, v6.ip_address, v6.mapped_ipv4, v6.port) == (
        HostKind.IPV6, "::ffff:a00:1", "10.0.0.1", 8443,
    )  # fmt: skip
    assert ok("http://[2001:db8::1]/").mapped_ipv4 is None


def test_registered_domain_and_subdomain() -> None:
    u = ok("https://brand.com.evil.example/login")
    assert (u.registered_domain, u.subdomain, u.public_suffix) == (
        "evil.example",
        "brand.com",
        "example",
    )
    u = ok("https://login.secure.paypa1.test/x")
    assert (u.registered_domain, u.subdomain) == ("paypa1.test", "login.secure")


def test_shared_hosting_is_its_own_registered_domain() -> None:
    u = ok("https://a.evil.github.io/x")
    assert (u.public_suffix, u.registered_domain, u.subdomain, u.private_suffix) == (
        "github.io", "evil.github.io", "a", True,
    )  # fmt: skip
    assert not ok("https://www.example.co.uk/").private_suffix


def test_non_web_scheme_hosts_are_opaque_and_not_analysed() -> None:
    u = ok("foo://Some.Host/x")
    assert (u.host_kind, u.host, u.registered_domain, u.public_suffix) == (
        HostKind.OPAQUE, "Some.Host", None, None,
    )  # fmt: skip
    assert F.NON_HTTP_SCHEME in u.flags
    # "http." is a legal scheme name, so this is an opaque host, not a web host.
    assert ok("http.://Com\u00fcx/").host_kind is HostKind.OPAQUE


def test_idn_display_form() -> None:
    u = ok("http://xn--mnchen-3ya.test/")
    assert (u.host, u.host_unicode) == ("xn--mnchen-3ya.test", "m\u00fcnchen.test")


def test_components() -> None:
    u = ok("https://example.test:8443/a/b?x=1&y=2#frag")
    assert (u.scheme, u.port, u.path, u.query, u.fragment) == (
        "https",
        8443,
        "/a/b",
        "x=1&y=2",
        "frag",
    )
    js = ok("javascript:alert(1)")
    assert (js.host, js.host_kind, js.path, js.registered_domain) == (
        None,
        HostKind.NONE,
        "alert(1)",
        None,
    )


def test_hashes() -> None:
    raw = "hxxps://evil[.]example/x"
    u = ok(raw)
    assert u.input_sha256 == hashlib.sha256(raw.encode()).hexdigest()  # of the input as given
    assert u.url_sha256 == hashlib.sha256(u.normalized.encode()).hexdigest()


def test_deterministic() -> None:
    raw = "  hxxp://user@m\u00fcnchen[.]test:80\\x?q=%2525 "
    assert parse_url(raw) == parse_url(raw)


# ---- failures: UNKNOWN material, never a guess -------------------------------------------------


@pytest.mark.parametrize("raw", ["", "   ", "\t\n\r", "\x00\x01 "])
def test_empty(raw: str) -> None:
    assert fail(raw).reason is FailReason.EMPTY


@pytest.mark.parametrize(
    "raw",
    [
        "http://ex ample.test/",
        "http://256.256.256.256/",
        "http://1.2.3.4.5/",
        "http://[::1/",
        "http://%00.test/",
        "http://\ud800.test/",  # lone surrogate
        "http://",
        "http:///",
        "//",
        "/\\",
    ],
)
def test_unparseable(raw: str) -> None:
    assert fail(raw).reason is FailReason.UNPARSEABLE


@pytest.mark.parametrize("raw", ["http://./x", "http://../", "https://...:8080/"])
def test_no_host_after_trailing_dot_removal(raw: str) -> None:
    assert fail(raw).reason is FailReason.NO_HOST


def test_trailing_dot_removal_that_breaks_the_host_is_unparseable_not_an_exception() -> None:
    # Found by fuzzing: ".127.." parses, but stripping its dots leaves ".127", a bad IPv4.
    assert fail("https://.127../@").reason is FailReason.UNPARSEABLE


def test_length_cap_boundary() -> None:
    base = "http://example.test/"
    assert isinstance(parse_url(base + "a" * (MAX_URL_LEN - len(base))), ParsedUrl)
    assert fail(base + "a" * (MAX_URL_LEN - len(base) + 1)).reason is FailReason.TOO_LONG


def test_failures_never_echo_the_input() -> None:
    for raw in ["http://SECRETMARKER ex.test/", "SECRETMARKER" * 1000, "http://[SECRETMARKER/"]:
        r = fail(raw)
        assert "SECRETMARKER" not in repr(r)


# ---- refang ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("hxxp://a[.]test", "http://a.test"),
        ("hxxps[:]//a(.)test", "https://a.test"),
        ("HXXPS://A.TEST", "https://A.TEST"),
        ("a{.}test", "a.test"),
        ("a[dot]test", "a.test"),
        ("user[@]a.test", "user@a.test"),
        ("hxxp[://]a.test", "http://a.test"),
        # Untouched:
        ("http://a.test/?x=[1]", "http://a.test/?x=[1]"),
        ("http://[::1]/", "http://[::1]/"),
        ("HTTP://A.TEST", "HTTP://A.TEST"),
    ],
)
def test_refang(raw: str, want: str) -> None:
    assert refang(raw) == want


# ---- robustness --------------------------------------------------------------------------------

ATOMS = [
    "http",
    "https",
    "://",
    ":",
    "/",
    "//",
    "\\",
    "@",
    "?",
    "#",
    "&",
    "=",
    ".",
    "..",
    "-",
    "_",
    "[",
    "]",
    "::1",
    "%",
    "25",
    "2e",
    "00",
    "xn--",
    "\u00fc",
    "\u0430",
    "\u200b",
    " ",
    "\t",
    "\n",
    "0x7f",
    "127",
    "1",
    "evil",
    "example",
    "test",
    "com",
    "co.uk",
    "hxxp",
    "[.]",
    "www",
    "javascript",
    "data",
    ":80",
    ":8080",
    "~",
    "\x00",
    "\ud800",
    "\U0001f600",
]


def test_fuzz_never_raises_and_normalisation_is_idempotent() -> None:
    rng = random.Random(20261104)
    parsed = 0
    for _ in range(4000):
        raw = "".join(rng.choice(ATOMS) for _ in range(rng.randint(1, 12)))
        r = parse_url(raw)
        if isinstance(r, ParseFailure):
            continue
        parsed += 1
        again = parse_url(r.normalized)
        assert isinstance(again, ParsedUrl), (raw, r.normalized)
        assert again.normalized == r.normalized, (raw, r.normalized, again.normalized)
        if r.host_kind is HostKind.DOMAIN:
            assert r.host and not r.host.endswith(".") and r.host == r.host.lower(), (raw, r.host)
        if r.host_kind is HostKind.NONE:
            assert r.host is None
    assert parsed > 500  # the generator reaches real URLs, not only failures


@pytest.mark.parametrize(
    "raw",
    [
        "http://" + "a." * 4000,
        "[.]" * 2700,
        "\\" * 8000,
        "%25" * 2700,
        "@" * 8000,
        ":" * 8000,
        "http://" * 1100,
        "[" * 8000,
        "http://" + "\u0430" * 4000,
    ],
)
def test_pathological_inputs_are_fast(raw: str) -> None:
    t0 = time.perf_counter()
    parse_url(raw)
    assert time.perf_counter() - t0 < 1.0
