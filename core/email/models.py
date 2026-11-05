"""What the sandbox worker may tell the host about a message, and nothing more.

The worker parses hostile input, so its reply is hostile too. Every field is typed and bounded,
unknown fields and unknown enum values are rejected, and a reply that fails validation becomes an
ERROR verdict, never a guess. Strings the worker returns are attacker-controlled text.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Text = Annotated[str, Field(max_length=300)]
Count = Annotated[int, Field(ge=0, le=10_000_000)]
AuthResult = Literal[
    "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy", "unknown"
]
Magic = Literal[
    "pdf", "zip", "rar", "7z", "gz", "bz2", "exe", "elf", "ole", "rtf", "png", "jpeg", "gif", "bmp",
    "tiff", "webp", "lnk", "iso", "html", "svg",
]  # fmt: skip
PartFlag = Literal[
    "decode_error",
    "bidi_filename",
    "control_chars_in_filename",
    "path_in_filename",
    "long_filename",
]
LinkKind = Literal["a", "area", "form", "iframe", "script", "meta_refresh", "text"]
LinkFlag = Literal["hidden", "javascript", "invisible_text", "image_link", "empty_text"]
LimitHit = Literal[
    "parts", "depth", "headers", "part_bytes", "decoded_bytes", "links", "text_urls", "html_tags",
    "html_depth", "html_error",
]  # fmt: skip
WorkerError = Literal["mime_too_deep", "memory", "unknown_op"]


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


class Addr(_Strict):
    name: Annotated[str, Field(max_length=200)]
    addr: Annotated[str, Field(max_length=320)]
    domain: Annotated[str, Field(max_length=255)]


class Auth(_Strict):
    spf: AuthResult | None
    dkim: AuthResult | None
    dmarc: AuthResult | None
    authserv: Annotated[str, Field(max_length=255)] | None
    count: Annotated[int, Field(ge=0, le=1000)]


class Headers(_Strict):
    from_: Annotated[list[Addr], Field(alias="from", max_length=20)]
    from_count: Annotated[int, Field(ge=0, le=1000)]
    reply_to: Annotated[list[Addr], Field(max_length=20)]
    return_path: Annotated[list[Addr], Field(max_length=20)]
    sender: Annotated[list[Addr], Field(max_length=20)]
    recipient_count: Annotated[int, Field(ge=0, le=1000)]
    subject: Annotated[str, Field(max_length=256)]
    received_count: Annotated[int, Field(ge=0, le=1000)]
    auth: Auth
    list_unsubscribe: bool
    date_present: bool


class Part(_Strict):
    path: Annotated[str, Field(max_length=100)]
    ctype: Annotated[str, Field(max_length=100)]
    charset: Annotated[str, Field(max_length=60)] | None
    disposition: Literal["inline", "attachment"] | None
    filename: Annotated[str, Field(max_length=255)] | None
    size: Annotated[int, Field(ge=0, le=64 * 1024 * 1024)]
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    magic: Magic | None
    attachment: bool
    flags: Annotated[list[PartFlag], Field(max_length=10)]


class Link(_Strict):
    part: Annotated[str, Field(max_length=100)]
    kind: LinkKind
    url: Annotated[str, Field(min_length=1, max_length=8193)]
    text: Text
    flags: Annotated[list[LinkFlag], Field(max_length=10)]


class HtmlStats(_Strict):
    forms: Count
    password_inputs: Count
    scripts: Count
    external_images: Count
    tracking_pixels: Count
    iframes: Count
    html_parts: Count


class MessageScan(_Strict):
    v: Literal[1]
    size: Annotated[int, Field(ge=0, le=64 * 1024 * 1024)]
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    limits_hit: Annotated[list[LimitHit], Field(max_length=20)]
    defects: Annotated[list[Annotated[str, Field(max_length=100)]], Field(max_length=20)]
    headers: Headers
    parts: Annotated[list[Part], Field(max_length=500)]
    links: Annotated[list[Link], Field(max_length=500)]
    base: Annotated[str, Field(max_length=8193)] | None
    html: HtmlStats
    excerpt: Annotated[str, Field(max_length=20_000)]


class WorkerReply(_Strict):
    ok: Literal[True] | None = None
    scan: MessageScan | None = None
    error: WorkerError | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> "WorkerReply":
        if (self.scan is not None) == (self.error is not None) or (self.scan is not None) != bool(
            self.ok
        ):
            raise ValueError("a reply is either a scan or an error")
        return self
