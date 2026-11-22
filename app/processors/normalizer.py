"""IOC refanging, defanging, and canonical normalization."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from app.processors.validator import classify_and_validate, inspect_ip_scope
from app.schemas import IOCType, NormalizedIOC

_SCHEME_REFANG_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^hxxps(?=\s*(?:\[:\]|:)//|\[://\])", re.IGNORECASE), "https"),
    (re.compile(r"^hxxp(?=\s*(?:\[:\]|:)//|\[://\])", re.IGNORECASE), "http"),
    (re.compile(r"^h__ps(?=\s*(?:\[:\]|:)//|\[://\])", re.IGNORECASE), "https"),
    (re.compile(r"^h__p(?=\s*(?:\[:\]|:)//|\[://\])", re.IGNORECASE), "http"),
    (re.compile(r"^fxp(?=\s*(?:\[:\]|:)//|\[://\])", re.IGNORECASE), "ftp"),
)

_TOKEN_REFANG_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\[://\]|\(://\)|\{://\}"), "://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]|\(:\)|\{:\}"), ":"),
    (re.compile(r"\[/\]|\(/\)"), "/"),
    (re.compile(r"\[@\]|\(@\)"), "@"),
)

_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443, "ftp": 21}


def refang_ioc(raw_value: str) -> tuple[str, bool]:
    """Convert defanged SOC indicator text back to canonical form.

    Returns:
        (refanged_string, was_defanged)
    """
    cleaned = raw_value.strip().strip("\"'<>")
    result = cleaned

    for pattern, replacement in _SCHEME_REFANG_PATTERNS:
        result = pattern.sub(replacement, result)

    for pattern, replacement in _TOKEN_REFANG_PATTERNS:
        result = pattern.sub(replacement, result)

    was_defanged = result != cleaned
    return result, was_defanged


def defang_ioc(value: str, ioc_type: IOCType | None = None) -> str:
    """Render an IOC safely for analyst reports and exports to prevent accidental clicks."""
    if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
        return value

    if ioc_type == IOCType.URL or "://" in value:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme == "https":
            safe_scheme = "hxxps"
        elif scheme == "http":
            safe_scheme = "hxxp"
        elif scheme == "ftp":
            safe_scheme = "fxp"
        else:
            safe_scheme = scheme
        safe_netloc = parsed.netloc.replace(".", "[.]")
        return urlunsplit((safe_scheme, safe_netloc, parsed.path, parsed.query, parsed.fragment))

    if ioc_type == IOCType.IPV6:
        return value.replace(":", "[:]")

    return value.replace(".", "[.]")


def _normalize_url(candidate: str) -> str:
    parsed = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()

    # Canonicalize IP hostname if applicable, otherwise strip trailing dot from domain
    try:
        ip_obj = ipaddress.ip_address(hostname)
        norm_host = f"[{ip_obj}]" if isinstance(ip_obj, ipaddress.IPv6Address) else str(ip_obj)
    except ValueError:
        norm_host = hostname.rstrip(".")

    # Rebuild netloc while omitting redundant default ports
    userinfo = ""
    if parsed.username is not None:
        userinfo = parsed.username
        if parsed.password is not None:
            userinfo = f"{userinfo}:{parsed.password}"
        userinfo = f"{userinfo}@"

    port = parsed.port
    port_suffix = ""
    if port is not None and _DEFAULT_PORTS.get(scheme) != port:
        port_suffix = f":{port}"

    netloc = f"{userinfo}{norm_host}{port_suffix}"
    # Preserve case-sensitive path & query; drop empty/root trailing slash consistency & fragment
    path = parsed.path if parsed.path not in ("", "/") else ""
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def normalize_value(refanged_value: str, ioc_type: IOCType) -> str:
    """Return the canonical normalized string representation for a validated IOC."""
    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        return str(ipaddress.ip_address(refanged_value))
    if ioc_type == IOCType.DOMAIN:
        return refanged_value.rstrip(".").lower()
    if ioc_type == IOCType.URL:
        return _normalize_url(refanged_value)
    if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
        return refanged_value.lower()
    return refanged_value


def normalize_ioc(raw_input: str, source_hint: str | None = None) -> NormalizedIOC:
    """Refang, validate, classify, and normalize a single raw IOC string."""
    refanged, was_defanged = refang_ioc(raw_input)
    ioc_type = classify_and_validate(refanged, raw_input=raw_input)
    normalized = normalize_value(refanged, ioc_type)

    is_reserved_ip = False
    ip_scope_note: str | None = None
    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        ip_obj = ipaddress.ip_address(normalized)
        is_reserved_ip, ip_scope_note = inspect_ip_scope(ip_obj)

    return NormalizedIOC(
        value=normalized,
        normalized_value=normalized,
        ioc_type=ioc_type,
        raw_input=raw_input.strip(),
        was_defanged=was_defanged,
        is_reserved_ip=is_reserved_ip,
        ip_scope_note=ip_scope_note,
        source_hint=source_hint,
    )

