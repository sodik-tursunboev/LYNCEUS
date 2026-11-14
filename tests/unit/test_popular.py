"""H1 B1: the popular-domain list. A popular registered domain is not judged a look-alike of a
brand by name, and nothing else changes: subdomain tricks, homographs, paths and lists still
apply."""

import asyncio
import io
import zipfile
from pathlib import Path

import httpx
import pytest

from core.detection.engine import analyze_url
from core.intel import popular as popular_sync
from core.intel.http import FetchError, make_client
from core.urls import popular


def rules(url: str) -> set[str]:
    return {s.rule_id for s in analyze_url(url).report().verdict.signals}


@pytest.mark.parametrize(
    ("url", "rule"),
    [
        ("https://google.no/", "url.typosquat"),  # Google's own country site
        ("https://amazon.ca/login", "url.typosquat"),
        ("https://discordapp.com/login", "url.brand_in_domain"),  # owned by the brand
    ],
)
def test_a_popular_domain_is_not_called_a_lookalike(url: str, rule: str) -> None:
    assert rule in rules(url)  # without the list: today's false alarm
    popular.use(frozenset({"google.no", "amazon.ca", "discordapp.com"}))
    assert rule not in rules(url)


def test_the_same_names_off_the_list_are_still_caught() -> None:
    popular.use(frozenset({"google.no"}))
    assert "url.typosquat" in rules("https://google.ru.com/")
    assert "url.typosquat" in rules("https://paypa1.com/signin")
    assert "url.combosquat" in rules("https://paypal-login-secure.com/")


def test_subdomain_tricks_on_a_popular_domain_are_still_caught() -> None:
    popular.use(frozenset({"blogspot.com", "weebly.com"}))
    assert "url.brand_in_subdomain" in rules("https://paypal.com.account.weebly.com/")


def test_the_list_file_is_read_and_comments_skipped(tmp_path: Path) -> None:
    (tmp_path / popular.FILE).write_text("# header\nGoogle.no\n\namazon.ca\n", encoding="ascii")
    assert popular._load(tmp_path / popular.FILE) == {"google.no", "amazon.ca"}  # noqa: SLF001
    assert popular._load(tmp_path / "missing.txt") == frozenset()  # noqa: SLF001


def test_top_from_csv_keeps_rank_order_and_drops_junk() -> None:
    text = "1,google.com\n2,<script>\n3,EXAMPLE.org\n4,localhost\n5,a.b.c\n"
    assert popular.top_from_csv(text, 3) == ["google.com", "example.org", "a.b.c"]


def zipped(csv: str, name: str = "top-1m.csv") -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr(name, csv)
    return out.getvalue()


BIG = "".join(f"{i},site{i}.com\n" for i in range(1, popular.TOP + 50))


def run_sync(tmp_path: Path, respond: object) -> tuple[int, str]:
    client = make_client(httpx.MockTransport(respond))  # type: ignore[arg-type]
    return asyncio.run(popular_sync.sync(tmp_path, client))


def test_sync_keeps_the_top_and_writes_its_source(tmp_path: Path) -> None:
    seen: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, content=zipped(BIG))

    kept, _ = run_sync(tmp_path, respond)
    text = (tmp_path / popular.FILE).read_text(encoding="ascii").splitlines()
    assert kept == popular.TOP and len(text) == popular.TOP + 1 and text[0].startswith("# Tranco")
    assert seen == [popular_sync.SOURCE]  # one GET of the public list, nothing else


def test_sync_follows_the_relative_redirect_to_the_daily_file(tmp_path: Path) -> None:
    seen: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.path == "/top-1m.csv.zip":
            return httpx.Response(307, headers={"location": "/download/daily/top-1m.csv.zip"})
        return httpx.Response(200, content=zipped(BIG))

    kept, _ = run_sync(tmp_path, respond)
    assert kept == popular.TOP
    assert seen == [popular_sync.SOURCE, "https://tranco-list.eu/download/daily/top-1m.csv.zip"]


def test_sync_follows_one_redirect_only_within_tranco(tmp_path: Path) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("top-1m.csv.zip"):
            return httpx.Response(302, headers={"location": "https://evil.example/list.zip"})
        return httpx.Response(200, content=zipped(BIG))

    with pytest.raises(FetchError, match="redirect"):
        run_sync(tmp_path, respond)
    assert not (tmp_path / popular.FILE).exists()


@pytest.mark.parametrize("body", [b"not a zip", zipped("1,google.com\n"), zipped(BIG, "notes.txt")])
def test_a_bad_download_leaves_the_old_list_in_place(tmp_path: Path, body: bytes) -> None:
    (tmp_path / popular.FILE).write_text("old.example\n", encoding="ascii")
    with pytest.raises(FetchError):
        run_sync(tmp_path, lambda r: httpx.Response(200, content=body))
    assert (tmp_path / popular.FILE).read_text(encoding="ascii") == "old.example\n"
