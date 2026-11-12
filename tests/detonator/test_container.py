"""The real detonator container (D1). Skipped without Docker or the image (`python tasks.py
detonator`). The offline cases use --network none and fixture pages served inside the container;
the egress cases start the real proxy and network layout and try to get out to private places.
Only one case reaches the internet, and only example.com."""

import subprocess
import time

import pytest

from core.detonate.runner import BROWSER, IMAGE, INNER, detonate, ensure_ready
from rules.page import evaluate
from tests.detonator.helpers import needs_docker, offline

pytestmark = needs_docker


def _rules(report_url: str, page: str) -> set[str]:
    r, _ = offline(page)
    public = r.model_copy(update={"final_url": report_url})
    return {rule.id for rule, _ in evaluate(public)}


def test_chromium_runs_with_its_sandbox_on_and_reads_a_kit_page() -> None:
    r, err = offline("kit_login.html")
    assert r.status == "ok", err[-800:]  # chromium_sandbox=True: a launch without it would fail
    assert r.title == "Sign in to your Microsoft account"
    assert {"devtools_trap", "key_block", "context_block"} <= set(r.markers)
    assert "api.telegram.org/bot000000" in r.script_refs
    assert r.screenshot and len(r.screenshot) < 400_000


def test_the_kit_page_fires_its_rules() -> None:
    assert _rules("https://secure-check.example/", "kit_login.html") >= {
        "page.brand_credential", "page.collection_endpoint", "page.evasion", "page.form_offsite",
    }  # fmt: skip


def test_a_file_built_inside_the_page_is_seen_and_not_kept() -> None:
    r, _ = offline("smuggle.html")
    assert [d.model_dump() for d in r.downloads] == [{"ext": "iso", "scheme": "blob"}]


def test_a_hostile_page_is_bounded() -> None:
    started = time.monotonic()
    r, _ = offline("hostile.html")
    assert time.monotonic() - started < 45
    assert r.status in ("ok", "partial")
    assert r.dialogs == 3 and r.popups == 5


def test_the_browser_network_has_no_route_out() -> None:
    probe = (
        "import socket\n"
        "for host in ('1.1.1.1', '8.8.8.8'):\n"
        "    try:\n"
        "        socket.create_connection((host, 443), 3); print('OPEN')\n"
        "    except OSError:\n"
        "        print('closed')\n"
    )
    ensure_ready()
    done = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            INNER,
            *BROWSER,
            "--entrypoint",
            "/usr/bin/python3",
            IMAGE,
            "-I",
            "-c",
            probe,
        ],  # fmt: skip
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.stdout.split() == ["closed", "closed"], done.stderr[-500:]


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://host.docker.internal:8765/health",
        "http://127.0.0.1:8765/health",
        "https://lynceus-egress/",
    ],
)
def test_the_page_cannot_reach_private_places(url: str) -> None:
    """https fails at the tunnel; plain http gets the proxy's own 403 page. Either way nothing from
    the private address comes back, and the page does not count as alive."""
    r = detonate(url)
    assert not r.alive, (r.status, r.http_status)
    assert r.title == "" and not r.forms
    if r.status == "ok":
        assert r.http_status == 403 and r.text.startswith("refused:"), r.text[:80]


def test_a_public_page_opens_through_the_proxy() -> None:
    r = detonate("https://example.com/")
    assert r.status == "ok", r.error
    assert "Example Domain" in r.title
    assert r.tls is not None and r.tls.valid_to > r.tls.valid_from
