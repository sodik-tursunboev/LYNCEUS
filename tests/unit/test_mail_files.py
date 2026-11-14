"""The attachment scanners, run in this process: what they report about archives, PDFs and images,
and that bombs are reported from their headers and never expanded. Isolation and limits under the
real sandbox are tested in tests/sandbox/test_email_sandbox.py."""

import io
import random
import time
import tracemalloc

import archives
import filehelp as fh
import filescan
import htmlscan
import imagescan
import limits
import pdfscan
import pytest

from core.email.models import ArchiveScan, FileReply, ImageScan, PdfScan


def archive(data: bytes) -> ArchiveScan:
    out = archives.scan_archive(data)
    return ArchiveScan.model_validate(out)


def pdf(data: bytes) -> PdfScan:
    return PdfScan.model_validate(pdfscan.scan_pdf(data))


def image(data: bytes) -> ImageScan:
    return ImageScan.model_validate(imagescan.scan_image(data))


# ---- dispatch ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "kind"),
    [
        (fh.make_zip({"a.txt": b"x"}), "archive"),
        (fh.make_tar({"a.txt": b"x"}), "archive"),
        (fh.PDF_PLAIN, "pdf"),
        (fh.blank_png(), "image"),
        (b"MZ\x90\x00 an executable", "content"),  # looked inside (deep analysis, ADR-020)
        (b"plain words", "content"),
        (b"", "none"),
    ],
)
def test_the_scanner_is_chosen_by_content_not_by_name(data: bytes, kind: str) -> None:
    assert filescan.inspect_data(data)["kind"] == kind


def test_every_scan_is_a_reply_the_host_accepts() -> None:
    for data in (fh.make_zip({"a.txt": b"x"}), fh.PDF_JS, fh.qr_png("https://x.test/"), b"zzz"):
        FileReply.model_validate({"ok": True, "file": filescan.inspect_data(data)})


# ---- archives ------------------------------------------------------------------------------------


def test_a_zip_is_listed_by_extension_and_by_real_type() -> None:
    s = archive(fh.make_zip({"a.txt": b"hello", "run.scr": b"MZ\x90\x00", "p.pdf": b"%PDF-1.7"}))
    assert (s.format, s.entries, s.encrypted, s.traversal, s.nested) == ("zip", 3, 0, 0, 0)
    assert s.exts == {"pdf": 1, "scr": 1, "txt": 1}
    assert s.magics == {"exe": 1, "pdf": 1}


def test_a_type_that_disagrees_with_the_name_shows_in_magics() -> None:
    s = archive(fh.make_zip({"holiday.jpg": b"MZ\x90\x00"}))
    assert s.exts == {"jpg": 1} and s.magics == {"exe": 1}


def test_encrypted_entries_are_counted_and_not_read() -> None:
    s = archive(fh.mark_encrypted(fh.make_zip({"a.txt": b"hello", "b.txt": b"world"})))
    assert s.encrypted == 2 and s.magics == {}


@pytest.mark.parametrize("name", ["../x.txt", "a/../../x.txt", "/etc/passwd", "C:\\x.txt", "..\\x"])
def test_names_that_escape_their_folder_are_counted(name: str) -> None:
    assert archive(fh.make_zip({name: b"x"})).traversal == 1


@pytest.mark.parametrize("name", ["docs/readme.txt", "a..b/c.txt", "x...y.txt"])
def test_ordinary_names_are_not_traversal(name: str) -> None:
    assert archive(fh.make_zip({name: b"x"})).traversal == 0


def test_double_extension_pairs_are_reported_as_facts() -> None:
    s = archive(fh.make_zip({"invoice.pdf.exe": b"x", "archive.tar.gz": b"x", "a.b": b"x"}))
    assert ("pdf", "exe") in s.double_pairs and ("tar", "gz") in s.double_pairs
    assert all(len(pair) == 2 for pair in s.double_pairs)


def test_odd_extensions_are_bucketed_not_echoed() -> None:
    s = archive(fh.make_zip({"x.<script>": b"x", "y.\u202etxt": b"x"}))
    assert set(s.exts) <= {"(odd)", "txt"} and "(odd)" in s.exts


def test_a_tar_and_its_compressed_forms_are_listed() -> None:
    data = fh.make_tar({"a.txt": b"hello", "run.js": b"x"})
    for form in (data, __import__("gzip").compress(data), fh.bz2_of(data)):
        s = archive(form)
        assert s.entries == 2 and s.exts == {"js": 1, "txt": 1}


def test_a_symlink_that_points_outside_is_traversal() -> None:
    s = archive(fh.make_tar({"a.txt": b"x"}, symlinks={"link": "../../etc/passwd"}))
    assert s.traversal == 1


def test_nested_archives_are_followed_to_a_depth_then_stopped() -> None:
    shallow = archive(fh.nested_zip(2))
    assert (shallow.nested, shallow.depth, shallow.limits) == (2, 2, [])
    deep = archive(fh.nested_zip(8))
    assert deep.depth == limits.MAX_ARCHIVE_DEPTH and "depth" in deep.limits


def test_a_zip_bomb_is_reported_from_its_headers_and_not_expanded() -> None:
    bomb = fh.zip_bomb(300)
    assert len(bomb) < 1_000_000
    tracemalloc.start()
    start = time.perf_counter()
    s = archive(bomb)
    elapsed = time.perf_counter() - start
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert s.total_size >= 300 * fh.MiB and s.ratio > 500
    assert elapsed < 2 and peak < 32 * fh.MiB


def test_a_gzip_bomb_stops_at_the_byte_budget() -> None:
    s = archive(fh.gzip_bomb(100))
    assert "decompressed_bytes" in s.limits
    assert s.total_size <= limits.MAX_ARCHIVE_BUDGET + limits.MAX_SNIFF


def test_too_many_entries_stop_at_the_entry_limit() -> None:
    s = archive(fh.many_entries_zip(limits.MAX_ENTRIES + 500))
    assert s.entries == limits.MAX_ENTRIES and "entries" in s.limits


def test_a_bomb_hidden_in_a_nested_archive_is_still_budgeted() -> None:
    inner = fh.gzip_bomb(100)
    s = archive(fh.make_zip({"x.gz": inner}))
    assert "decompressed_bytes" in s.limits or "nested_size" in s.limits


@pytest.mark.parametrize(
    "data",
    [
        b"PK\x03\x04" + b"\x00" * 100,  # a header and nothing else
        fh.make_zip({"a.txt": b"x" * 1000})[:-30],  # cut off
        b"\x1f\x8b\x08" + b"\xff" * 50,  # bad gzip
        b"BZh9" + b"\x00" * 50,  # bad bzip2
        b"ustar" * 200,  # looks like tar at the wrong offset
    ],
)
def test_broken_archives_are_reported_not_raised(data: bytes) -> None:
    out = archives.scan_archive(data)
    ArchiveScan.model_validate(out)


@pytest.mark.parametrize("seed", range(6))
def test_random_bytes_behind_an_archive_header_never_raise(seed: int) -> None:
    rng = random.Random(seed)
    head = rng.choice([b"PK\x03\x04", b"\x1f\x8b\x08\x00", b"BZh9", b"\xfd7zXZ\x00"])
    data = head + bytes(rng.randrange(256) for _ in range(rng.choice([10, 500, 20000])))
    ArchiveScan.model_validate(archives.scan_archive(data))


# ---- PDF -----------------------------------------------------------------------------------------


def test_a_plain_pdf_reports_no_active_content() -> None:
    s = pdf(fh.PDF_PLAIN)
    assert (s.parse, s.pages, s.javascript, s.launch, s.embedded_files, s.uris) == (
        "ok",
        1,
        0,
        0,
        0,
        [],
    )


def test_javascript_launch_and_embedded_files_are_found() -> None:
    assert pdf(fh.PDF_JS).javascript == 1 and pdf(fh.PDF_JS).open_action is True
    assert pdf(fh.PDF_LAUNCH).launch == 1
    assert pdf(fh.PDF_EMBEDDED).embedded_files == 1


def test_a_name_written_with_hex_escapes_is_still_found() -> None:
    assert pdf(fh.PDF_JS_OBFUSCATED).javascript == 1  # /J#61vaScr#69pt is /JavaScript


def test_uris_inside_link_annotations_are_extracted_once_each() -> None:
    s = pdf(fh.pdf_with_uris("https://a-b.test/x", "https://c-d.test/y", "https://a-b.test/x"))
    assert s.uris == ["https://a-b.test/x", "https://c-d.test/y"]


def test_uris_are_capped_and_stripped_of_control_characters() -> None:
    many = fh.pdf_with_uris(*[f"https://s{i}.test/p" for i in range(limits.MAX_PDF_URIS + 20)])
    s = pdf(many)
    assert len(s.uris) == limits.MAX_PDF_URIS and "uris" in s.limits
    assert all("\x00" not in u for u in pdf(fh.pdf_with_uris("https://a-b.test/\x01x")).uris)


def test_an_encrypted_pdf_is_reported_not_guessed_about() -> None:
    s = pdf(fh.encrypted_pdf())
    assert (s.parse, s.encrypted, s.javascript) == ("encrypted", True, 0)


def test_a_huge_object_count_stops_at_the_object_limit() -> None:
    start = time.perf_counter()
    s = pdf(fh.pdf_with_objects(limits.MAX_PDF_OBJECTS + 5000))
    assert "objects" in s.limits and time.perf_counter() - start < 20


@pytest.mark.parametrize(
    "data", [b"%PDF-", b"%PDF-1.7 and then garbage", b"%PDF-1.4\n" + b"\x00" * 500]
)
def test_a_pdf_that_cannot_be_read_is_reported(data: bytes) -> None:
    assert pdf(data).parse == "failed"


@pytest.mark.parametrize("seed", range(6))
def test_random_bytes_behind_a_pdf_header_never_raise(seed: int) -> None:
    rng = random.Random(seed)
    data = b"%PDF-1.7\n" + bytes(rng.randrange(256) for _ in range(rng.choice([10, 1000, 30000])))
    PdfScan.model_validate(pdfscan.scan_pdf(data))


# ---- images --------------------------------------------------------------------------------------


def test_a_qr_code_is_decoded() -> None:
    s = image(fh.qr_png("https://phish-site.test/login?e=a%40b.test"))
    assert s.qr == ["https://phish-site.test/login?e=a%40b.test"]
    assert (s.format, s.parse, s.bomb) == ("png", "ok", False)


def test_an_image_without_a_qr_code_reports_none() -> None:
    assert image(fh.blank_png()).qr == []


def test_a_light_on_dark_qr_code_is_decoded() -> None:
    import cv2
    import numpy as np

    dark = 255 - cv2.imdecode(np.frombuffer(fh.qr_png("https://x-y.test/"), np.uint8), 0)
    ok, png = cv2.imencode(".png", dark)
    assert ok and image(png.tobytes()).qr == ["https://x-y.test/"]


def test_a_decompression_bomb_header_is_refused_before_decoding() -> None:
    start = time.perf_counter()
    tracemalloc.start()
    s = image(fh.png_declaring(60000, 60000))
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert s.bomb is True and s.parse == "bomb" and s.qr == []
    assert time.perf_counter() - start < 2 and peak < 32 * fh.MiB


def test_an_image_just_over_the_pixel_cap_is_refused() -> None:
    side = int(limits.MAX_PIXELS**0.5) + 50
    assert image(fh.png_declaring(side, side)).bomb is True


def test_a_format_outside_the_allowed_list_is_not_opened() -> None:
    from PIL import Image

    buf = io.BytesIO()
    Image.new("L", (8, 8)).save(
        buf, "PPM"
    )  # a format Pillow can read but this scanner does not allow
    assert filescan.inspect_data(buf.getvalue())["kind"] != "image"  # never decoded as a picture


@pytest.mark.parametrize("seed", range(6))
def test_random_bytes_behind_an_image_header_never_raise(seed: int) -> None:
    rng = random.Random(seed)
    head = rng.choice([b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff\xe0", b"GIF89a", b"BM", b"II*\x00"])
    data = head + bytes(rng.randrange(256) for _ in range(rng.choice([10, 1000, 30000])))
    ImageScan.model_validate(imagescan.scan_image(data))


def test_a_truncated_png_is_reported_as_failed() -> None:
    assert image(fh.qr_png("https://x-y.test/")[:60]).parse == "failed"


# ---- HTML smuggling indicators -------------------------------------------------------------------


def stats(html: str) -> dict[str, int]:
    budget = htmlscan.Budget()
    htmlscan.scan_html(html, "1", budget)
    return budget.stats


def test_blob_building_script_is_counted() -> None:
    s = stats(
        '<script>var f = new Blob([atob("QUJD")]); var u = URL.createObjectURL(f);'
        'a.download = "x.zip"; a.click();</script>'
    )
    assert s["blob_apis"] == 2 and s["decoders"] >= 1 and s["auto_saves"] == 2


def test_a_large_encoded_block_is_counted() -> None:
    assert stats("<script>var d = '" + "QUJD" * 600 + "';</script>")["base64_blobs"] == 1


def test_a_data_download_link_is_counted() -> None:
    s = stats('<a href="data:application/zip;base64,UEsDBA==" download="invoice.zip">open</a>')
    assert s["data_downloads"] == 1


def test_ordinary_script_and_links_are_not_counted() -> None:
    s = stats('<script>console.log("hi");</script><a href="https://x.test/f.zip" download>get</a>')
    assert (s["blob_apis"], s["base64_blobs"], s["decoders"], s["data_downloads"]) == (0, 0, 0, 0)


def test_script_text_examined_is_capped() -> None:
    s = stats("<script>" + "new Blob(x);" * 100_000 + "</script>")
    assert s["blob_apis"] <= limits.MAX_SCRIPT_CHARS // len("new Blob(x);")


# ---- H1 C4: links written in the page text -----------------------------------------------------


def text_pdf(*lines: bytes, pages: int = 1) -> bytes:
    import pikepdf

    doc = pikepdf.new()
    font = doc.make_indirect(pikepdf.Dictionary(Type=pikepdf.Name.Font, Subtype=pikepdf.Name.Type1,
                                                BaseFont=pikepdf.Name.Helvetica))  # fmt: skip
    for _ in range(pages):
        ops = b"BT /F1 12 Tf 72 712 Td " + b" ".join(lines) + b" ET"
        page = doc.add_blank_page()
        page.obj.Resources = pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=font))
        page.obj.Contents = doc.make_stream(ops)
    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()


def test_a_link_written_in_the_page_text_is_found() -> None:
    data = text_pdf(b"(Your invoice is ready: https://pay-portal.test/inv/42 please sign in) Tj")
    assert "https://pay-portal.test/inv/42" in pdf(data).uris


def test_a_link_split_across_kerned_pieces_is_joined() -> None:
    data = text_pdf(b"[(https://sec) -20 (ure-docs.test/view)] TJ")
    assert "https://secure-docs.test/view" in pdf(data).uris


def test_text_without_links_adds_nothing_and_annotations_still_count() -> None:
    assert pdf(text_pdf(b"(Minutes of the meeting on Tuesday) Tj")).uris == []
    annotated = fh.make_pdf("", ["<< /S /URI /URI (https://annot.test/a) >>"])
    assert pdf(annotated).uris == ["https://annot.test/a"]


def test_page_text_links_are_capped_and_never_raise() -> None:
    many = b" ".join(b"(https://site%d.test/x) Tj" % i for i in range(400))
    scan = pdf(text_pdf(many, pages=2))
    assert len(scan.uris) <= limits.MAX_PDF_URIS and "uris" in scan.limits
