"""Tests for EnrichmentEngine multi-source correlation, caching, and graceful degradation."""

from __future__ import annotations

import httpx
import respx

from app.collectors.otx import OTXCollector
from app.collectors.urlhaus import URLhausCollector
from app.config import Settings
from app.database.repository import ThreatIntelRepository
from app.enrichment.enrichment_engine import EnrichmentEngine
from app.processors.normalizer import normalize_ioc
from app.schemas import EnrichmentStatus


def _no_sleep(_: float) -> None:
    return None


@respx.mock
def test_enrichment_engine_correlates_sources_and_uses_ttl_cache() -> None:
    settings = Settings(
        _env_file=None,
        otx_api_key="otx-key",
        urlhaus_auth_key="uh-key",
        cache_ttl_hours=24,
        http_max_retries=1,
        http_backoff_seconds=0.0,
    )
    repo = ThreatIntelRepository(":memory:")
    ioc = normalize_ioc("198.51.100.23")

    otx_route = respx.get(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/198.51.100.23/general"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "pulse_info": {
                    "count": 3,
                    "pulses": [
                        {
                            "id": "p1",
                            "name": "C2 Tracker",
                            "created": "2026-11-10T00:00:00Z",
                            "modified": "2026-11-22T00:00:00Z",
                            "tags": ["c2", "emotet"],
                            "malware_families": ["Emotet"],
                            "attack_ids": ["T1071"],
                        }
                    ],
                }
            },
        )
    )
    uh_route = respx.post("https://urlhaus-api.abuse.ch/v1/host/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "host": "198.51.100.23",
                "firstseen": "2026-11-05 00:00:00 UTC",
                "url_count": 1,
                "urls": [
                    {
                        "url_status": "online",
                        "threat": "malware_download",
                        "date_added": "2026-11-21 10:00:00 UTC",
                        "tags": ["emotet", "loader"],
                    }
                ],
            },
        )
    )

    collectors = [
        OTXCollector(settings, sleep_fn=_no_sleep),
        URLhausCollector(settings, sleep_fn=_no_sleep),
    ]
    with EnrichmentEngine(repo, settings, collectors=collectors) as engine:
        first = engine.enrich_indicator(ioc)
        second = engine.enrich_indicator(ioc)
        forced = engine.enrich_indicator(ioc, force_refresh=True)

    # First run calls both APIs; second run hits cache; forced refresh calls APIs again
    assert otx_route.call_count == 2
    assert uh_route.call_count == 2

    assert first.sources_checked == 2
    assert first.sources_with_evidence == 2
    assert first.cache_hits == 0
    assert first.any_active is True
    assert first.attack_ids == ["T1071"]
    assert "emotet" in [t.lower() for t in first.tags]
    assert first.earliest_first_seen is not None and first.earliest_first_seen.day == 5
    assert first.latest_last_seen is not None and first.latest_last_seen.day == 22

    assert second.cache_hits == 2
    assert all(ev.from_cache for ev in second.evidence)
    assert forced.cache_hits == 0
    repo.close()


@respx.mock
def test_enrichment_engine_graceful_degradation_on_partial_failure() -> None:
    settings = Settings(
        _env_file=None,
        otx_api_key="otx-key",
        urlhaus_auth_key="uh-key",
        cache_ttl_hours=24,
        http_max_retries=0,
        http_backoff_seconds=0.0,
    )
    repo = ThreatIntelRepository(":memory:")
    ioc = normalize_ioc("198.51.100.23")

    respx.get(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/198.51.100.23/general"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "pulse_info": {
                    "count": 1,
                    "pulses": [
                        {
                            "id": "p1",
                            "created": "2026-11-20T00:00:00Z",
                            "modified": "2026-11-21T00:00:00Z",
                            "tags": ["phishing"],
                        }
                    ],
                }
            },
        )
    )
    uh_route = respx.post("https://urlhaus-api.abuse.ch/v1/host/").mock(
        side_effect=httpx.ReadTimeout("timeout")
    )

    collectors = [
        OTXCollector(settings, sleep_fn=_no_sleep),
        URLhausCollector(settings, sleep_fn=_no_sleep),
    ]
    with EnrichmentEngine(repo, settings, collectors=collectors) as engine:
        result = engine.enrich_indicator(ioc)
        # Re-running should reuse cached OTX but RETRY timed-out URLhaus
        second = engine.enrich_indicator(ioc)

    assert result.sources_checked == 2
    assert result.sources_with_evidence == 1
    statuses = {ev.source_name: ev.status for ev in result.evidence}
    assert statuses["AlienVault OTX"] == EnrichmentStatus.OK
    assert statuses["URLhaus"] == EnrichmentStatus.TIMEOUT

    assert second.cache_hits == 1
    assert uh_route.call_count == 2  # Timeout was NOT cached

    metrics = repo.get_system_metrics()
    assert metrics.total_indicators == 1
    assert metrics.api_failure_rate > 0
    repo.close()


def test_enrichment_engine_without_api_keys_degrades_gracefully() -> None:
    settings = Settings(_env_file=None, otx_api_key=None, urlhaus_auth_key=None)
    repo = ThreatIntelRepository(":memory:")
    ioc = normalize_ioc("198.51.100.23")

    with EnrichmentEngine(repo, settings) as engine:
        result = engine.enrich_indicator(ioc)

    assert result.sources_checked == 0
    assert result.sources_with_evidence == 0
    assert all(ev.status == EnrichmentStatus.SKIPPED_NO_KEY for ev in result.evidence)
    repo.close()

