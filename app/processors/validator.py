"""IOC format validation, type classification, and special IP scope inspection."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from app.schemas import IOCType

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
_ALPHA_TLD_RE = re.compile(r"^[a-zA-Z]{2,63}$")
_PUNYCODE_TLD_RE = re.compile(r"^xn--[a-zA-Z0-9-]{2,59}$", re.IGNORECASE)

_ALLOWED_URL_SCHEMES: frozenset[str] = frozenset({"http", "https", "ftp"})

# RFC 5737 IPv4 documentation networks & RFC 3849 IPv6 documentation network
_DOC_NETWORKS_V4: tuple[tuple[ipaddress.IPv4Network, str], ...] = (
    (
        ipaddress.ip_network("192.0.2.0/24"),
        "RFC 5737 TEST-NET-1 documentation IP (non-routable)",
    ),
    (
        ipaddress.ip_network("198.51.100.0/24"),
        "RFC 5737 TEST-NET-2 documentation IP (non-routable)",
    ),
    (
        ipaddress.ip_network("203.0.113.0/24"),
        "RFC 5737 TEST-NET-3 documentation IP (non-routable)",
    ),
)
_DOC_NETWORK_V6 = ipaddress.ip_network("2001:db8::/32")


class IOCValidationError(ValueError):
    """Raised when an input string cannot be validated as a supported IOC."""

    def __init__(self, raw_input: str, reason: str) -> None:
        self.raw_input = raw_input
        self.reason = reason
        super().__init__(f"Invalid IOC '{raw_input}': {reason}")


def inspect_ip_scope(
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[bool, str | None]:
    """Identify whether an IP belongs to documentation, private, loopback, or reserved space."""
    if isinstance(ip_obj, ipaddress.IPv4Address):
        for net, label in _DOC_NETWORKS_V4:
            if ip_obj in net:
                return True, label
    elif ip_obj in _DOC_NETWORK_V6:
        return True, "RFC 3849 IPv6 documentation address (non-routable)"

    if ip_obj.is_loopback:
        return True, "Loopback IP address (local host only)"
    if ip_obj.is_link_local:
        return True, "Link-local IP address (non-routable)"
    if ip_obj.is_unspecified:
        return True, "Unspecified IP address"
    if ip_obj.is_multicast:
        return True, "Multicast IP address"
    if ip_obj.is_private:
        return True, "Private/internal network IP address (non-routable)"
    if ip_obj.is_reserved or not ip_obj.is_global:
        return True, "Reserved / non-global IP address"
    return False, None


def is_valid_domain(candidate: str) -> bool:
    """Validate a candidate FQDN domain name (strictly rejecting malformed IPs and URLs)."""
    if not candidate or any(ch in candidate for ch in ("/", "\\", ":", "@", "?", "#", " ")):
        return False

    cleaned = candidate[:-1] if candidate.endswith(".") else candidate
    if not cleaned or len(cleaned) > 253 or ".." in cleaned:
        return False

    # Reject anything that parses as an IP address
    try:
        ipaddress.ip_address(cleaned)
        return False
    except ValueError:
        pass

    labels = cleaned.split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not _DOMAIN_LABEL_RE.match(label):
            return False

    tld = labels[-1]
    if not (_ALPHA_TLD_RE.match(tld) or _PUNYCODE_TLD_RE.match(tld)):
        return False

    return True


def _validate_url(candidate: str, raw_input: str) -> None:
    parsed = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_URL_SCHEMES:
        raise IOCValidationError(raw_input, f"Unsupported URL scheme '{parsed.scheme}'")

    hostname = parsed.hostname
    if not hostname:
        raise IOCValidationError(raw_input, "URL is missing a valid hostname")

    # Validate port range explicitly (urlsplit raises ValueError on invalid port)
    try:
        port = parsed.port
    except ValueError as exc:
        raise IOCValidationError(raw_input, "URL contains an invalid port") from exc
    if port is not None and not (1 <= port <= 65535):
        raise IOCValidationError(raw_input, f"URL port out of range: {port}")

    # Hostname must be either a valid IP address or a valid FQDN domain
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if not is_ip and not is_valid_domain(hostname):
        raise IOCValidationError(raw_input, f"URL hostname '{hostname}' is not a valid IP or FQDN")


def classify_and_validate(candidate: str, raw_input: str | None = None) -> IOCType:
    """Detect and strictly validate the IOC type for a refanged candidate string.

    Args:
        candidate: Cleaned/refanged IOC candidate string.
        raw_input: Original raw input for clear error reporting.

    Returns:
        Validated IOCType enum member.

    Raises:
        IOCValidationError: If the string is empty, malformed, or unsupported.
    """
    original = raw_input if raw_input is not None else candidate

    if not candidate or not candidate.strip():
        raise IOCValidationError(original, "IOC value is empty")

    if any(ch.isspace() for ch in candidate):
        raise IOCValidationError(original, "IOC value must not contain whitespace")

    # 1. URL (explicit scheme required)
    lower = candidate.lower()
    if "://" in candidate:
        _validate_url(candidate, original)
        return IOCType.URL

    # 2. Cryptographic file hashes (exact hex length)
    if _HEX_RE.match(candidate):
        length = len(candidate)
        if length == 32:
            return IOCType.MD5
        if length == 40:
            return IOCType.SHA1
        if length == 64:
            return IOCType.SHA256
        raise IOCValidationError(
            original,
            f"Hex string of length {length} is not a valid MD5 (32), SHA1 (40), or SHA256 (64)",
        )

    # 3. IPv4 / IPv6
    try:
        ip_obj = ipaddress.ip_address(candidate)
        return IOCType.IPV4 if isinstance(ip_obj, ipaddress.IPv4Address) else IOCType.IPV6
    except ValueError:
        pass

    # Helpful error for URLs missing scheme or IP:port inputs
    if "/" in candidate:
        raise IOCValidationError(
            original,
            "Contains path '/' without scheme; include http:// or https:// for URLs",
        )
    if "@" in candidate:
        raise IOCValidationError(original, "Email addresses are not a supported IOC type")
    if ":" in candidate and not lower.startswith("["):
        raise IOCValidationError(
            original,
            "Unexpected ':' (not a valid IPv6 address or URL with scheme)",
        )

    # 4. Domain name (FQDN)
    if is_valid_domain(candidate):
        return IOCType.DOMAIN

    raise IOCValidationError(
        original,
        "Does not match valid IPv4, IPv6, Domain, URL, MD5, SHA1, or SHA256 format",
    )
