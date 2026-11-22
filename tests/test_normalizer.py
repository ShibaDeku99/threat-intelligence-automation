"""Unit tests for IOC refanging, defanging, and canonical normalization."""

from __future__ import annotations

import pytest

from app.processors.normalizer import defang_ioc, normalize_ioc, refang_ioc
from app.schemas import IOCType


@pytest.mark.parametrize(
    ("raw", "expected_refanged", "expected_defanged_flag"),
    [
        ("198[.]51[.]100[.]23", "198.51.100.23", True),
        ("198(.)51(.)100(.)23", "198.51.100.23", True),
        ("hxxps://cdn[.]evil[.]example[.]org/Path", "https://cdn.evil.example.org/Path", True),
        ("hXXp[:]//evil[dot]example[dot]com[/]drop.exe", "http://evil.example.com/drop.exe", True),
        ("  'example.com'  ", "example.com", False),
        ("8.8.8.8", "8.8.8.8", False),
    ],
)
def test_refang_ioc(raw: str, expected_refanged: str, expected_defanged_flag: bool) -> None:
    refanged, was_defanged = refang_ioc(raw)
    assert refanged == expected_refanged
    assert was_defanged is expected_defanged_flag


def test_normalize_ipv4_defanged_testnet() -> None:
    ioc = normalize_ioc("198[.]51[.]100[.]23", source_hint="SIEM")
    assert ioc.ioc_type == IOCType.IPV4
    assert ioc.normalized_value == "198.51.100.23"
    assert ioc.raw_input == "198[.]51[.]100[.]23"
    assert ioc.was_defanged is True
    assert ioc.is_reserved_ip is True
    assert ioc.ip_scope_note is not None and "TEST-NET-2" in ioc.ip_scope_note


def test_normalize_ipv6_compression() -> None:
    ioc = normalize_ioc("2001:0db8:0000:0000::0001")
    assert ioc.ioc_type == IOCType.IPV6
    assert ioc.normalized_value == "2001:db8::1"
    assert ioc.is_reserved_ip is True


def test_normalize_domain_case_and_trailing_dot() -> None:
    ioc = normalize_ioc("  MALICIOUS-DEMO[.]EXAMPLE[.]COM.  ")
    assert ioc.ioc_type == IOCType.DOMAIN
    assert ioc.normalized_value == "malicious-demo.example.com"
    assert ioc.was_defanged is True


def test_normalize_url_preserves_path_case_and_strips_default_port() -> None:
    ioc = normalize_ioc("HXXPS://CDN[.]Example[.]ORG:443/Login/Verify?Token=AbC#frag")
    assert ioc.ioc_type == IOCType.URL
    assert ioc.normalized_value == "https://cdn.example.org/Login/Verify?Token=AbC"

    ioc_custom_port = normalize_ioc("http://Example.COM:8080/Payload")
    assert ioc_custom_port.normalized_value == "http://example.com:8080/Payload"


def test_normalize_hashes_lowercase() -> None:
    md5 = normalize_ioc("44D88612FEA8A8F36DE82E1278ABB02F")
    assert md5.ioc_type == IOCType.MD5
    assert md5.normalized_value == "44d88612fea8a8f36de82e1278abb02f"

    sha256 = normalize_ioc("275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F")
    assert sha256.ioc_type == IOCType.SHA256
    assert sha256.normalized_value == sha256.raw_input.lower()


def test_defang_ioc_safe_rendering() -> None:
    assert defang_ioc("198.51.100.23", IOCType.IPV4) == "198[.]51[.]100[.]23"
    assert defang_ioc("evil.example.com", IOCType.DOMAIN) == "evil[.]example[.]com"
    assert (
        defang_ioc("https://evil.example.com/a.exe", IOCType.URL)
        == "hxxps://evil[.]example[.]com/a.exe"
    )
    # Hashes must stay unchanged
    md5 = "44d88612fea8a8f36de82e1278abb02f"
    assert defang_ioc(md5, IOCType.MD5) == md5
