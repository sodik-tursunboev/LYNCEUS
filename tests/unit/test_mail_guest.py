"""The sandbox-side parsers, run in this process: structure, links, hidden text, hostile shapes.

Isolation is tested in tests/sandbox. Here the question is what the parser reports, and that no
hostile shape makes it raise, hang or return something the host would not accept.
"""

import hashlib
import random

import htmlscan
import limits
import mailparse
import pytest
from mailhelp import eml, multipart, nested, parsed

from core.email.models import MessageScan

BIDI = chr(0x202E)


def html_scan(html: str) -> htmlscan.Budget:
    budget = htmlscan.Budget()
    htmlscan.scan_html(html, "1", budget)
    return budget


def link_of(html: str) -> dict[str, object]:
    links = html_scan(html).links
    assert len(links) == 1, links
    return links[0]


# ---- links a mail client would follow: what we analyse must be what it opens --------------------


def test_a_repeated_attribute_uses_the_first_value_like_a_mail_client() -> None:
    link = link_of('<a href="https://evil.test/x" href="https://www.paypal.com/y">paypal</a>')
    assert link["url"] == "https://evil.test/x"


def test_links_in_an_outlook_conditional_comment_are_read_and_marked() -> None:
    html = '<p>hi</p><!--[if mso]><a href="https://evil.test/o">Verify</a><![endif]-->'
    links = html_scan(html).links
    assert [(x["url"], x["flags"]) for x in links] == [("https://evil.test/o", ["conditional"])]


def test_outlooks_vml_button_link_is_read() -> None:
    html = '<!--[if mso]><v:roundrect href="https://evil.test/v"><center>Go</center></v:roundrect><![endif]-->'
    assert [x["url"] for x in html_scan(html).links] == ["https://evil.test/v"]


def test_an_ordinary_comment_is_not_read_and_a_broken_conditional_does_not_crash() -> None:
    assert html_scan('<!-- <a href="https://evil.test/c">x</a> -->').links == []
    assert html_scan('<!--[if mso <a href="https://evil.test/c">x</a> -->').links == []
    assert html_scan("<!--[if mso]>" + "<a href='https://e.test/a'>" * 3 + "<![endif]-->").links


def test_conditional_content_cannot_nest_deeper_or_exhaust_the_link_budget() -> None:
    inner = '<!--[if mso]><a href="https://deep.test/">x</a><![endif]-->'
    # a conditional inside a conditional is not followed: one level only
    outer = html_scan(f"<!--[if mso]>{inner}<![endif]-->")
    assert all("deep.test" not in str(x["url"]) for x in outer.links)
    many = html_scan(
        "<!--[if mso]>"
        + '<a href="https://e.test/x">y</a>' * (limits.MAX_LINKS + 50)
        + "<![endif]-->"
    )
    assert len(many.links) <= limits.MAX_LINKS and "links" in many.hit


def test_a_button_that_posts_elsewhere_and_embedded_documents_are_links() -> None:
    posted = html_scan('<form><button formaction="https://evil.test/post">Go</button></form>')
    assert [(x["kind"], x["url"]) for x in posted.links] == [("form", "https://evil.test/post")]
    asinput = html_scan('<input type="image" formaction="https://evil.test/i">')
    assert [x["kind"] for x in asinput.links] == ["form"]
    embedded = html_scan(
        '<embed src="https://evil.test/e"><object data="https://evil.test/o"></object>'
    )
    assert [(x["kind"], x["url"]) for x in embedded.links] == [
        ("iframe", "https://evil.test/e"), ("iframe", "https://evil.test/o"),
    ]  # fmt: skip


# ---- headers and structure ---------------------------------------------------------------------


def test_a_plain_message_is_described() -> None:
    raw = eml(subject="Lunch", text="See https://plain.test/menu today")
    scan = parsed(raw)
    h = scan.headers
    assert (h.from_[0].name, h.from_[0].addr, h.from_[0].domain) == (
        "Alice", "alice@sender.test", "sender.test",
    )  # fmt: skip
    assert (h.subject, h.from_count, h.recipient_count, h.date_present) == ("Lunch", 1, 1, True)
    assert scan.sha256 == hashlib.sha256(raw).hexdigest() and scan.size == len(raw)
    assert [(p.ctype, p.attachment) for p in scan.parts] == [("text/plain", False)]
    assert [(link.kind, link.url) for link in scan.links] == [("text", "https://plain.test/menu")]


def test_multiple_from_headers_are_counted() -> None:
    scan = parsed(eml(extra_headers=[("From", "other@elsewhere.test")]))
    assert scan.headers.from_count == 2


def test_authentication_results_are_read() -> None:
    header = "mx.example.test; spf=fail smtp.mailfrom=x.test; dkim=pass header.d=x.test; dmarc=fail"
    auth = parsed(eml(extra_headers=[("Authentication-Results", header)])).headers.auth
    assert (auth.spf, auth.dkim, auth.dmarc, auth.authserv) == (
        "fail", "pass", "fail", "mx.example.test",
    )  # fmt: skip


def test_a_missing_authentication_result_is_not_a_pass() -> None:
    auth = parsed(eml()).headers.auth
    assert (auth.spf, auth.dkim, auth.dmarc, auth.count) == (None, None, None, 0)


def test_long_subject_and_text_are_cut() -> None:
    scan = parsed(eml(subject="s" * 5000, text="word " * 40000))
    assert len(scan.headers.subject) <= limits.MAX_SUBJECT
    assert len(scan.excerpt) <= limits.MAX_EXCERPT


def test_html_alternative_gives_both_parts_and_links() -> None:
    raw = eml(html='<p><a href="https://shop.test/a">Shop</a></p>')
    scan = parsed(raw)
    assert [p.ctype for p in scan.parts] == ["text/plain", "text/html"]
    assert [(link.kind, link.url, link.text) for link in scan.links if link.kind == "a"] == [
        ("a", "https://shop.test/a", "Shop")
    ]
    assert scan.html.html_parts == 1


# ---- attachments -------------------------------------------------------------------------------


def test_attachment_type_comes_from_content_not_name() -> None:
    exe = b"MZ\x90\x00" + b"\x00" * 60
    scan = parsed(eml(attachments=[("invoice.pdf", exe, "application/pdf")]))
    (att,) = [p for p in scan.parts if p.attachment]
    assert (att.filename, att.ctype, att.magic) == ("invoice.pdf", "application/pdf", "exe")
    assert att.sha256 == hashlib.sha256(exe).hexdigest() and att.size == len(exe)


def test_a_right_to_left_override_is_flagged_and_removed_from_the_name() -> None:
    name = f"invoice{BIDI}fdp.exe"
    scan = parsed(eml(attachments=[(name, b"data", "application/octet-stream")]))
    (att,) = [p for p in scan.parts if p.attachment]
    assert "bidi_filename" in att.flags
    assert att.filename is not None and BIDI not in att.filename


def test_a_path_in_a_filename_is_flagged_and_stripped() -> None:
    scan = parsed(eml(attachments=[("..\\..\\evil.exe", b"x", "application/octet-stream")]))
    (att,) = [p for p in scan.parts if p.attachment]
    assert "path_in_filename" in att.flags and att.filename == "evil.exe"


def test_a_very_long_filename_is_cut() -> None:
    name = "a" * 600 + ".txt"
    scan = parsed(eml(attachments=[(name, b"x", "text/plain")]))
    (att,) = [p for p in scan.parts if p.attachment]
    assert "long_filename" in att.flags and att.filename is not None
    assert len(att.filename) <= limits.MAX_FILENAME


def test_an_html_attachment_is_scanned_for_links() -> None:
    page = b'<html><body><a href="https://landing.test/x">open</a></body></html>'
    scan = parsed(eml(attachments=[("statement.html", page, "text/html")]))
    assert any(link.url == "https://landing.test/x" for link in scan.links)


@pytest.mark.parametrize(
    ("data", "magic"),
    [
        (b"%PDF-1.7\n", "pdf"), (b"PK\x03\x04rest", "zip"), (b"MZ\x90\x00", "exe"),
        (b"\x7fELFxxxx", "elf"), (b"\xd0\xcf\x11\xe0xxxx", "ole"), (b"{\\rtf1\\ansi", "rtf"),
        (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff\xe0", "jpeg"), (b"GIF89a", "gif"),
        (b"Rar!\x1a\x07\x00", "rar"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"\x1f\x8b\x08", "gz"),
        (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "webp"),
        (b"<!DOCTYPE html><html>", "html"), (b"  \n<html><body>", "html"),
        (b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>', "svg"),
        (b"just some words", None), (b"", None),
    ],
)  # fmt: skip
def test_magic_table(data: bytes, magic: str | None) -> None:
    assert mailparse.detect_magic(data) == magic


def test_iso_magic_is_found_at_its_offset() -> None:
    data = b"\x00" * 0x8001 + b"CD001" + b"\x00" * 10
    assert mailparse.detect_magic(data) == "iso"


# ---- hostile shapes ----------------------------------------------------------------------------


def test_ten_thousand_parts_stop_at_the_part_limit() -> None:
    out = mailparse.scan(multipart(10_000))
    assert "parts" in out["limits_hit"]
    assert len(out["parts"]) < limits.MAX_PARTS
    MessageScan.model_validate(out)  # still a reply the host accepts


def test_deep_nesting_is_stopped_not_followed() -> None:
    out = mailparse.scan(nested(2000))
    assert out.get("error") == "mime_too_deep" or "depth" in out["limits_hit"]


def test_a_missing_closing_boundary_is_a_defect() -> None:
    raw = (
        b'From: a@x.test\r\nContent-Type: multipart/mixed; boundary="zz"\r\n\r\n'
        b"--zz\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
    )
    assert "CloseBoundaryNotFoundDefect" in parsed(raw).defects


def test_too_many_headers_are_noticed() -> None:
    raw = ("".join(f"X-H{i}: v\r\n" for i in range(limits.MAX_HEADERS + 50)) + "\r\nbody").encode()
    assert "headers" in mailparse.scan(raw)["limits_hit"]


def test_garbage_base64_does_not_raise() -> None:
    raw = (
        b'From: a@x.test\r\nContent-Type: application/octet-stream; name="a.bin"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n@@@@ not base64 !!!!\r\n"
    )
    parsed(raw)


def test_an_unknown_charset_does_not_raise_and_text_survives() -> None:
    raw = (
        b"From: a@x.test\r\nContent-Type: text/plain; charset=x-no-such-charset\r\n\r\n"
        b"please verify \xff\xfe your account\r\n"
    )
    assert "please verify" in parsed(raw).excerpt


def test_one_enormous_line_is_bounded() -> None:
    raw = b"From: a@x.test\r\n\r\n" + b"A" * 3_000_000
    scan = parsed(raw)
    assert len(scan.excerpt) <= limits.MAX_EXCERPT


@pytest.mark.parametrize("seed", range(8))
def test_random_bytes_never_break_the_contract(seed: int) -> None:
    rng = random.Random(seed)
    raw = bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 50, 5000, 70000])))
    out = mailparse.scan(raw)
    assert "error" in out or MessageScan.model_validate(out)


def test_header_shaped_garbage_never_breaks_the_contract() -> None:
    rng = random.Random(7)
    words = [
        "From:", "To:", "Content-Type:", "multipart/mixed;", 'boundary="x"', "\r\n", "\r\n\r\n",
        "--x", "--x--", "=?utf-8?b?", "?=", "base64", "<", ">", "@", "\x00", chr(0x202E),
    ]  # fmt: skip
    for _ in range(200):
        raw = "".join(rng.choice(words) for _ in range(rng.randrange(1, 40))).encode()
        out = mailparse.scan(raw)
        assert "error" in out or MessageScan.model_validate(out)


# ---- HTML: what a reader sees versus what is there ---------------------------------------------


def test_link_text_and_target_are_kept_apart() -> None:
    link = link_of('<a href="https://evil.test/x">https://www.paypal.com/login</a>')
    assert (link["url"], link["text"], link["flags"]) == (
        "https://evil.test/x", "https://www.paypal.com/login", [],
    )  # fmt: skip


@pytest.mark.parametrize(
    "style",
    [
        "display:none",
        "visibility:hidden",
        "opacity:0",
        "font-size:0",
        "font-size:1px",
        "width:0",
        "height:0px",
        "position:absolute;left:-9999px",
        "text-indent:-5000px",
        "clip:rect(0,0,0,0)",
        "DISPLAY : NONE !important",
    ],
)
def test_css_that_hides_an_element_is_noticed(style: str) -> None:
    link = link_of(f'<a href="https://x.test/" style="{style}">go</a>')
    assert "hidden" in link["flags"]  # type: ignore[operator]


@pytest.mark.parametrize(
    "style", ["color:red", "display:block", "font-size:14px", "opacity:1", "left:-10px", ""]
)
def test_ordinary_css_is_not_hiding(style: str) -> None:
    assert htmlscan.style_hides(style) is False


def test_the_hidden_attribute_and_hidden_ancestors_count() -> None:
    assert "hidden" in link_of('<a href="https://x.test/" hidden>go</a>')["flags"]  # type: ignore[operator]
    nested = '<div style="display:none"><p><a href="https://x.test/">go</a></p></div>'
    assert "hidden" in link_of(nested)["flags"]  # type: ignore[operator]


def test_a_javascript_link_is_flagged() -> None:
    assert "javascript" in link_of('<a href=" JavaScript:alert(1)">x</a>')["flags"]  # type: ignore[operator]


def test_an_image_only_link_and_an_empty_link_are_told_apart() -> None:
    image = link_of('<a href="https://x.test/"><img src="https://img.x.test/a.png"></a>')
    empty = link_of('<a href="https://x.test/"></a>')
    assert "image_link" in image["flags"] and "empty_text" in empty["flags"]  # type: ignore[operator]


def test_zero_width_text_in_a_link_is_flagged() -> None:
    link = link_of('<a href="https://x.test/">pay\u200bpal.com</a>')
    assert "invisible_text" in link["flags"]  # type: ignore[operator]
    assert link["text"] == "paypal.com"


def test_forms_scripts_frames_and_refresh_are_collected() -> None:
    b = html_scan(
        '<meta http-equiv="refresh" content="0; url=https://redir.test/go">'
        '<form action="https://collect.test/p"><input type="password"></form>'
        '<iframe src="https://frame.test/"></iframe><script src="https://js.test/a.js"></script>'
        '<base href="https://base.test/">'
    )
    assert {link["kind"] for link in b.links} == {"meta_refresh", "form", "iframe", "script"}
    assert b.base == "https://base.test/"
    assert (b.stats["forms"], b.stats["password_inputs"], b.stats["scripts"]) == (1, 1, 1)
    assert b.stats["iframes"] == 1


def test_tracking_pixels_and_external_images_are_counted() -> None:
    b = html_scan('<img src="https://t.test/p.gif" width="1" height="1"><img src="/local.png">')
    assert (b.stats["external_images"], b.stats["tracking_pixels"]) == (1, 1)


def test_script_and_style_text_is_not_visible_text() -> None:
    b = html_scan("<style>.a{color:red}</style><script>var secret=1</script><p>Hello there</p>")
    assert b.excerpt == ["Hello there"]


def test_text_in_a_hidden_element_is_not_in_the_excerpt() -> None:
    b = html_scan('<p>shown</p><div style="display:none">stuffing</div>')
    assert b.excerpt == ["shown"]


def test_link_count_is_capped() -> None:
    b = html_scan(
        "".join(f'<a href="https://s{i}.test/">x</a>' for i in range(limits.MAX_LINKS + 50))
    )
    assert len(b.links) == limits.MAX_LINKS and "links" in b.hit


def test_tag_count_is_capped() -> None:
    b = html_scan("<b>" * (limits.MAX_TAGS + 100))
    assert "html_tags" in b.hit


def test_html_depth_is_capped() -> None:
    b = html_scan("<div>" * (limits.MAX_HTML_DEPTH + 100))
    assert "html_depth" in b.hit


def test_unclosed_and_broken_markup_does_not_raise() -> None:
    html_scan('<a href="https://x.test/><b><<<>>> &#xZZ; <p <p <a href=')
    html_scan("<a href='https://x.test/'>no end tag")
