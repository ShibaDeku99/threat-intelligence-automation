"""Unit tests for IOC format validation, classification, and IP scope detection."""

from __future__ import annotations

import ipaddress

import pytest

from app.processors.validator import (
    IOCValidationError,
    classify_and_validate,
    inspect_ip_scope,
    is_valid_domain,
)
from app.schemas import IOCType


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        ("8.8.8.8", IOCType.IPV4),
        ("198.51.100.23", IOCType.IPV4),
        ("2001:db8::1", IOCType.IPV6),
        ("2001:4860:4860::8888", IOCType.IPV6),
        ("example.com", IOCType.DOMAIN),
        ("sub.domain-1.example.co.uk.", IOCType.DOMAIN),
        ("xn--bcher-kva.example", IOCType.DOMAIN),
        ("http://example.com/malware.bin", IOCType.URL),
        ("https://198.51.100.23:8443/stage?a=1", IOCType.URL),
        ("ftp://files.example.org/payload.zip", IOCType.URL),
        ("44d88612fea8a8f36de82e1278abb02f", IOCType.MD5),
        ("3395856ce81f2b7382dee72602f798b642f14140", IOCType.SHA1),
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", IOCType.SHA256),
    ],
)
def test_classify_and_validate_valid_iocs(candidate: str, expected: IOCType) -> None:
    assert classify_and_validate(candidate) == expected


@pytest.mark.parametrize(
    "invalid_value",
    [
        "",
        "   ",
        "not a valid ioc",
        "999.999.999.999",  # Must NOT fall through to domain!
        "192.168.1",
        "localhost",
        "-badlabel.example.com",
        "badlabel-.example.com",
        "double..dot.example.com",
        "example.123",
        "user@example.com",
        "example.com/path/without/scheme",
        "198.51.100.23:8080",
        "http://",
        "http://localhost/admin",
        "http://example.com:99999/badport",
        "javascript://alert(1)",
        "deadbeef",  # Wrong hex length
        "g" * 32,  # Non-hex 32-char string
    ],
)
def test_classify_and_validate_rejects_invalid_iocs(invalid_value: str) -> None:
    with pytest.raises(IOCValidationError):
        classify_and_validate(invalid_value)


def test_is_valid_domain_edge_cases() -> None:
    assert is_valid_domain("sub.example.com") is True
    assert is_valid_domain("sub.example.com.") is True
    assert is_valid_domain("198.51.100.23") is False
    assert is_valid_domain("999.999.999.999") is False
    assert is_valid_domain("singlelabel") is False


@pytest.mark.parametrize(
    ("ip_str", "expected_reserved", "expected_snippet"),
    [
        ("198.51.100.23", True, "TEST-NET-2"),
        ("192.0.2.10", True, "TEST-NET-1"),
        ("203.0.113.5", True, "TEST-NET-3"),
        ("2001:db8::1", True, "RFC 3849"),
        ("10.0.0.1", True, "Private"),
        ("127.0.0.1", True, "Loopback"),
        ("169.254.1.1", True, "Link-local"),
        ("8.8.8.8", False, None),
    ],
)
def test_inspect_ip_scope(
    ip_str: str, expected_reserved: bool, expected_snippet: str | None
) -> None:
    ip_obj = ipaddress.ip_address(ip_str)
    is_reserved, note = inspect_ip_scope(ip_obj)
    assert is_reserved is expected_reserved
    if expected_snippet is None:
        assert note is None
    else:
        assert note is not None and expected_snippet in note

