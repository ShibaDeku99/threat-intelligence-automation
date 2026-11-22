"""Mocked HTTP tests for AlienVault OTX and URLhaus collectors (using respx)."""

from __future__ import annotations

import httpx
import respx

from app.collectors.otx import OTXCollector
from app.collectors.urlhaus import URLhausCollector
from app.config import Settings
from app.processors.normalizer import normalize_ioc
from app.schemas import EnrichmentStatus


def _no_sleep(_: float) -> None:
    return None


def _settings_with_keys() -> Settings:
    return Settings(
        _env_file=None,
        otx_api_key="test-otx-secret-key",
        urlhaus_auth_key="test-urlhaus-secret-key",
        http_max_retries=2,
        http_backoff_seconds=0.0,
    )


def _settings_without_keys() -> Settings:
    return Settings(
        _env_file=None,
        otx_api_key=None,
        urlhaus_auth_key=None,
        http_max_retries=1,
        http_backoff_seconds=0.0,
    )


# ------------------------------------------------------------------
# AlienVault OTX tests
# ------------------------------------------------------------------
def test_otx_skips_cleanly_when_api_key_missing() -> None:
    ioc = normalize_ioc("198.51.100.23")
    with OTXCollector(_settings_without_keys(), sleep_fn=_no_sleep) as collector:
        evidence = collector.lookup(ioc)

    assert evidence.status == EnrichmentStatus.SKIPPED_NO_KEY
    assert evidence.is_malicious_signal is False
    assert evidence.error_message and "OTX_API_KEY" in evidence.error_message


@respx.mock
def test_otx_ipv4_malicious_pulses_parsed_correctly() -> None:
    settings = _settings_with_keys()
    ioc = normalize_ioc("198.51.100.23")
    route = respx.get(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/198.51.100.23/general"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "reputation": -5,
                "country_code": "US",
                "asn": "AS64512",
                "validation": [],
                "pulse_info": {
                    "count": 2,
                    "pulses": [
                        {
                            "id": "pulse-1",
                            "name": "Emotet C2 Infrastructure",
                            "created": "2026-11-10T08:00:00Z",
                            "modified": "2026-11-22T12:00:00Z",
                            "tags": ["c2", "emotet"],
                            "malware_families": [{"display_name": "Emotet"}],
                            "attack_ids": [{"id": "T1071"}, "T1566.001"],
                            "references": ["https://example.org/advisory/1"],
                            "adversary": "TA542",
                        },
                        {
                            "id": "pulse-2",
                            "name": "Botnet Tracker",
                            "created": "2026-11-01T00:00:00Z",
                            "modified": "2026-11-15T00:00:00Z",
                            "tags": ["botnet"],
                            "malware_families": ["Emotet"],
                            "attack_ids": ["t1071"],
                            "references": [],
                        },
                    ],
                },
            },
        )
    )

    with OTXCollector(settings, sleep_fn=_no_sleep) as collector:
        ev = collector.lookup(ioc)

    assert route.called
    assert route.calls[0].request.headers["X-OTX-API-KEY"] == "test-otx-secret-key"
    assert ev.status == EnrichmentStatus.OK
    assert ev.is_malicious_signal is True
    assert ev.pulse_count == 2
    assert "Emotet" in ev.malware_families
    assert ev.attack_ids == ["T1071", "T1566.001"]
    assert "c2" in ev.threat_types
    assert "malware" in ev.threat_types
    assert ev.source_first_seen is not None and ev.source_first_seen.day == 1
    assert ev.source_last_seen is not None and ev.source_last_seen.day == 22


@respx.mock
def test_otx_zero_pulses_returns_not_found() -> None:
    ioc = normalize_ioc("example.com")
    respx.get(
        "https://otx.alienvault.com/api/v1/indicators/domain/example.com/general"
    ).mock(return_value=httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}}))

    with OTXCollector(_settings_with_keys(), sleep_fn=_no_sleep) as collector:
        ev = collector.lookup(ioc)

    assert ev.status == EnrichmentStatus.NOT_FOUND
    assert ev.is_malicious_signal is False


@respx.mock
def test_otx_retries_on_429_and_handles_timeout_and_auth_error() -> None:
    settings = _settings_with_keys()
    ioc = normalize_ioc("198.51.100.23")
    endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv4/198.51.100.23/general"

    # 429 followed by 200 succeeds on retry
    route = respx.get(endpoint).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}}),
        ]
    )
    with OTXCollector(settings, sleep_fn=_no_sleep) as collector:
        ev = collector.lookup(ioc)
    assert route.call_count == 2
    assert ev.status == EnrichmentStatus.NOT_FOUND

    # Timeout exhausted -> TIMEOUT
    respx.get(endpoint).mock(side_effect=httpx.ReadTimeout("timed out"))
    with OTXCollector(settings, sleep_fn=_no_sleep) as collector:
        ev_timeout = collector.lookup(ioc)
    assert ev_timeout.status == EnrichmentStatus.TIMEOUT

    # 401 -> ERROR without leaking API key
    respx.get(endpoint).mock(return_value=httpx.Response(401))
    with OTXCollector(settings, sleep_fn=_no_sleep) as collector:
        ev_auth = collector.lookup(ioc)
    assert ev_auth.status == EnrichmentStatus.ERROR
    assert ev_auth.error_message is not None
    assert "test-otx-secret-key" not in ev_auth.error_message


@respx.mock
def test_otx_fetch_subscribed_pulses() -> None:
    respx.get("https://otx.alienvault.com/api/v1/pulses/subscribed").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "tags": ["phishing"],
                        "indicators": [
                            {"indicator": "198.51.100.23"},
                            {"indicator": "evil.example.com"},
                        ],
                    }
                ]
            },
        )
    )
    with OTXCollector(_settings_with_keys(), sleep_fn=_no_sleep) as collector:
        items = collector.fetch_subscribed_pulses(limit=5)
    assert [i.raw_value for i in items] == ["198.51.100.23", "evil.example.com"]


# ------------------------------------------------------------------
# URLhaus tests
# ------------------------------------------------------------------
def test_urlhaus_missing_key_and_unsupported_sha1() -> None:
    sha1_ioc = normalize_ioc("3395856ce81f2b7382dee72602f798b642f14140")
    url_ioc = normalize_ioc("https://evil.example.com/drop.exe")

    with URLhausCollector(_settings_without_keys(), sleep_fn=_no_sleep) as collector:
        assert collector.lookup(sha1_ioc).status == EnrichmentStatus.UNSUPPORTED_TYPE
        ev = collector.lookup(url_ioc)
        assert ev.status == EnrichmentStatus.SKIPPED_NO_KEY


@respx.mock
def test_urlhaus_url_online_host_offline_and_payload_hash() -> None:
    settings = _settings_with_keys()

    # 1. URL lookup (online)
    url_route = respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
                "date_added": "2026-11-20 10:00:00 UTC",
                "last_online": "2026-11-23 02:00:00 UTC",
                "tags": ["emotet", "exe"],
                "urlhaus_reference": "https://urlhaus.abuse.ch/url/12345/",
                "payloads": [{"signature": "Emotet"}],
            },
        )
    )

    # 2. Host lookup (offline)
    respx.post("https://urlhaus-api.abuse.ch/v1/host/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "host": "198.51.100.23",
                "firstseen": "2026-09-01 00:00:00 UTC",
                "url_count": 2,
                "urlhaus_reference": "https://urlhaus.abuse.ch/host/198.51.100.23/",
                "urls": [
                    {
                        "url_status": "offline",
                        "threat": "malware_download",
                        "date_added": "2026-10-05 12:00:00 UTC",
                        "tags": ["mirai"],
                    }
                ],
            },
        )
    )

    # 3. Payload SHA256 lookup
    respx.post("https://urlhaus-api.abuse.ch/v1/payload/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "signature": "AgentTesla",
                "firstseen": "2026-11-18 05:00:00 UTC",
                "lastseen": "2026-11-21 09:00:00 UTC",
                "url_count": 3,
                "urls": [{"url_status": "online"}],
            },
        )
    )

    with URLhausCollector(settings, sleep_fn=_no_sleep) as collector:
        url_ev = collector.lookup(normalize_ioc("https://evil.example.com/drop.exe"))
        host_ev = collector.lookup(normalize_ioc("198.51.100.23"))
        sha_ev = collector.lookup(
            normalize_ioc("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        )

    assert url_route.calls[0].request.headers["Auth-Key"] == "test-urlhaus-secret-key"
    assert url_ev.status == EnrichmentStatus.OK
    assert url_ev.is_active is True
    assert "Emotet" in url_ev.malware_families

    assert host_ev.status == EnrichmentStatus.OK
    assert host_ev.is_active is False
    assert host_ev.pulse_count == 2

    assert sha_ev.status == EnrichmentStatus.OK
    assert sha_ev.is_active is True
    assert sha_ev.malware_families == ["AgentTesla"]


@respx.mock
def test_urlhaus_no_results_retry_503_and_recent_feed() -> None:
    settings = _settings_with_keys()
    host_route = respx.post("https://urlhaus-api.abuse.ch/v1/host/").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(200, json={"query_status": "no_results"}),
        ]
    )
    respx.get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/5/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "urls": [{"url": "http://bad.example.com/a.exe", "tags": ["trojan"]}],
            },
        )
    )

    with URLhausCollector(settings, sleep_fn=_no_sleep) as collector:
        ev = collector.lookup(normalize_ioc("example.com"))
        recent = collector.fetch_recent_urls(limit=5)

    assert host_route.call_count == 2
    assert ev.status == EnrichmentStatus.NOT_FOUND
    assert ev.is_malicious_signal is False
    assert len(recent) == 1
    assert recent[0].raw_value == "http://bad.example.com/a.exe"

