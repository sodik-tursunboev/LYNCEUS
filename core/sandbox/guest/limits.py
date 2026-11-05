"""Hard caps for the message scanner. Every one is tested; hitting one is reported, never fatal."""

MAX_PARTS = 500  # MIME parts walked, containers included
MAX_DEPTH = 20  # MIME nesting
MAX_HEADERS = 1000
MAX_HEADER_CHARS = 8192  # a header value is cut here before any parsing
MAX_ADDRS = 20
MAX_LINKS = 500
MAX_LINK_URL = 8193  # one over the host's URL cap, so the host reports it as too long
MAX_LINK_TEXT = 300
MAX_LINK_BYTES = 1024 * 1024  # all link URLs together
MAX_PART_BYTES = 20 * 1024 * 1024  # one decoded part
MAX_DECODED_TOTAL = 64 * 1024 * 1024  # all decoded parts together
MAX_HTML_CHARS = 2 * 1024 * 1024
MAX_TAGS = 50_000
MAX_HTML_DEPTH = 200
MAX_EXCERPT = 20_000  # visible text handed to the host for keyword checks
MAX_FILENAME = 255
MAX_SUBJECT = 256
MAX_DEFECTS = 20
