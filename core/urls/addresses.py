"""Is an IP address one that only the public internet can reach? (CLAUDE.md rule 6)

Pure address arithmetic, no network: shared by the redirect resolver (safe_fetch, unwired, ADR-011)
and by the RDAP provider (H1 A3), which must never be steered to this machine or its network.
"""

import ipaddress

_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")  # deprecated, and holds :: and ::1
_DENY = (ipaddress.ip_network("168.63.129.16/32"),)  # Azure platform endpoint, publicly numbered


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.sixtofour is not None:
        return ip.sixtofour
    return ip.teredo[1] if ip.teredo else None


def is_public(address: str) -> bool:
    """True only for a globally routable unicast address, after unwrapping any IPv4 inside IPv6.

    `is_global` alone is not enough: it passes 64:ff9b::7f00:1, ::127.0.0.1 and multicast.
    """
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in _NAT64_LOCAL or ip in _IPV4_COMPATIBLE or ip.is_site_local:
            return False
        inner = _embedded_ipv4(ip)
        if inner is not None:
            return is_public(str(inner))
    if any(ip in net for net in _DENY):
        return False
    return ip.is_global and not ip.is_multicast and not ip.is_reserved
