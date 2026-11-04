"""SSRF probe inputs for the M1 fetch/redirect guard (CLAUDE.md rule 6).

Data only in M0: nothing fetches these. M1 tests must run them against a fake resolver and a fake
HTTP layer, never the network. Kept out of corpus/ so they cannot distort P/R/F1.
"""

SSRF_INPUTS: tuple[tuple[str, str], ...] = (
    ("http://127.0.0.1/", "loopback v4"),
    ("http://localhost/", "loopback name"),
    ("http://[::1]/", "loopback v6"),
    ("http://127.1/", "short-form loopback"),
    ("http://2130706433/", "decimal-encoded loopback"),
    ("http://0x7f000001/", "hex-encoded loopback"),
    ("http://017700000001/", "octal-encoded loopback"),
    ("http://[::ffff:127.0.0.1]/", "IPv4-mapped IPv6 loopback"),
    ("http://0.0.0.0/", "unspecified address"),
    ("http://10.0.0.5/", "RFC 1918 10/8"),
    ("http://172.16.0.1/", "RFC 1918 172.16/12"),
    ("http://192.168.1.1/", "RFC 1918 192.168/16"),
    ("http://100.64.0.1/", "CGNAT shared space"),
    ("http://169.254.169.254/latest/meta-data/", "cloud metadata, link-local"),
    ("http://[fd00:ec2::254]/", "cloud metadata, IPv6"),
    ("http://metadata.google.internal/", "cloud metadata by name"),
    ("http://example.com@127.0.0.1/", "userinfo makes the host look public"),
    ("http://rebind.test/", "name a fake resolver maps to a private IP (DNS rebinding)"),
    ("http://redirector.test/to-internal", "public name whose 302 targets a private address"),
)
