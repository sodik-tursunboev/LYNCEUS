"""What the detonator may say (D1). A closed schema with a size on every field: the reply comes from
a browser that just ran a hostile page, so it is data to check, never something to trust."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Url = Annotated[str, StringConstraints(max_length=2048)]
Host = Annotated[str, StringConstraints(max_length=253)]
Short = Annotated[str, StringConstraints(max_length=300)]


class _Closed(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PageField(_Closed):
    type: Annotated[str, StringConstraints(max_length=20)]
    hint: Annotated[str, StringConstraints(max_length=120)] = ""


class PageForm(_Closed):
    action: Url
    method: Annotated[str, StringConstraints(max_length=10)]
    fields: list[PageField] = Field(default_factory=list, max_length=50)
    frame: bool = False  # inside a frame of the page, possibly from another site (H1 C5)


class Download(_Closed):
    ext: Annotated[str, StringConstraints(max_length=10)]
    scheme: Annotated[str, StringConstraints(max_length=10)]


class Tls(_Closed):
    valid_from: int
    valid_to: int
    issuer: Annotated[str, StringConstraints(max_length=200)]


Marker = Literal[
    "devtools_trap", "key_block", "context_block", "webdriver_check", "decoded_writer",
    "heavy_decoding",
    "devtools_check",  # the broad first version (pages captured on 2026-11-11); no longer emitted
]  # fmt: skip


class PageReport(_Closed):
    status: Literal["ok", "partial", "dead", "error"]
    error: Annotated[str, StringConstraints(max_length=60)] | None = None
    final_url: Url = ""
    chain: list[Url] = Field(default_factory=list, max_length=20)
    http_status: int | None = None
    title: Short = ""
    headings: list[Annotated[str, StringConstraints(max_length=200)]] = Field(
        default_factory=list, max_length=10
    )
    logos: list[Annotated[str, StringConstraints(max_length=200)]] = Field(
        default_factory=list, max_length=80
    )
    text: Annotated[str, StringConstraints(max_length=20000)] = ""
    forms: list[PageForm] = Field(default_factory=list, max_length=20)
    loose: list[PageField] = Field(default_factory=list, max_length=50)
    frames: list[Url] = Field(default_factory=list, max_length=30)
    favicon: Url = ""
    hosts: list[Host] = Field(default_factory=list, max_length=100)
    script_hosts: list[Host] = Field(default_factory=list, max_length=50)
    script_refs: list[Annotated[str, StringConstraints(max_length=120)]] = Field(
        default_factory=list, max_length=100
    )
    markers: list[Marker] = Field(default_factory=list, max_length=7)
    # the page's own code (inline and same-site scripts), for the script brain (AI1 P4); it is
    # attacker text
    code: Annotated[str, StringConstraints(max_length=12_000)] = ""
    downloads: list[Download] = Field(default_factory=list, max_length=10)
    popups: int = Field(default=0, ge=0, le=10_000)
    dialogs: int = Field(default=0, ge=0, le=10_000)
    tls: Tls | None = None
    screenshot: Annotated[str, StringConstraints(max_length=400_000)] | None = None  # base64 JPEG
    browser: Annotated[str, StringConstraints(max_length=40)] = ""
    elapsed_ms: int = Field(default=0, ge=0)
    # H1 C5: the desktop visit showed nothing (refused, blank or a bot check), so the page was
    # opened once more as a phone, and this report is what the phone was shown
    phone_view: bool = False
    desktop_status: Annotated[str, StringConstraints(max_length=20)] | None = None
    # DA1: when the page was opened (seconds since 1970, UTC). Set by the core when the report
    # comes back from the container (runner.py), never taken from the page; None on reports kept
    # before DA1
    visited_at: int | None = Field(default=None, ge=0)
    # DA1: the first reading showed almost nothing, and what is reported is a second, later look
    second_look: bool = False

    @property
    def alive(self) -> bool:
        """A page was there to judge: it loaded (fully or in part) and did not answer an error."""
        return self.status in ("ok", "partial") and (
            self.http_status is None or self.http_status < 400
        )

    def fields(self) -> list[PageField]:
        return [f for form in self.forms for f in form.fields] + list(self.loose)
