"""Tests for SQLite schema initialization, deduplication, caching, and telemetry."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.database.repository import ThreatIntelRepository
from app.schemas import (
    AttackTechnique,
    Classification,
    EnrichmentEvidence,
    EnrichmentStatus,
    IOCType,
    LogMatch,
    NormalizedIOC,
    RiskLevel,
    ScoreBreakdown,
    TechniqueMapping,
    ThreatReport,
)


def _sample_ip_ioc() -> NormalizedIOC:
    return NormalizedIOC(
        value="198.51.100.23",
        normalized_value="198.51.100.23",
        ioc_type=IOCType.IPV4,
        raw_input="198[.]51[.]100[.]23",
        was_defanged=True,
        is_reserved_ip=True,
        ip_scope_note="RFC 5737 TEST-NET-2 documentation IP",
    )


def test_default_sources_seeded_idempotently(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    repo = ThreatIntelRepository(db_file)
    repo.initialize()  # Idempotent re-init

    sources = repo.list_sources()
    names = {src.name for src in sources}
    assert {"AlienVault OTX", "URLhaus", "MITRE ATT&CK", "CSV Dataset"}.issubset(names)
    assert len(sources) == 4


def test_indicator_deduplication_and_source_timestamps() -> None:
    repo = ThreatIntelRepository(":memory:")
    ioc = _sample_ip_ioc()
    t1 = datetime(2026, 11, 20, 10, 0, tzinfo=UTC)
    t2 = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
    t0 = datetime(2026, 11, 18, 8, 0, tzinfo=UTC)

    rec1, is_new1 = repo.upsert_indicator(ioc, first_seen=t1, last_seen=t1)
    rec2, is_new2 = repo.upsert_indicator(ioc, first_seen=t0, last_seen=t2)

    assert is_new1 is True
    assert is_new2 is False
    assert rec1.id == rec2.id
    # Must keep earliest first_seen and latest last_seen
    assert rec2.first_seen == t0
    assert rec2.last_seen == t2
    assert len(repo.list_indicators()) == 1
    repo.close()


def test_enrichment_preserves_source_vs_retrieved_timestamps_and_cache_ttl() -> None:
    repo = ThreatIntelRepository(":memory:")
    indicator, _ = repo.upsert_indicator(_sample_ip_ioc())

    source_first = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)
    source_last = datetime(2026, 11, 15, 0, 0, tzinfo=UTC)
    retrieved_now = datetime.now(UTC)

    ok_evidence = EnrichmentEvidence(
        source_name="AlienVault OTX",
        source_url="https://otx.alienvault.com/api/v1",
        status=EnrichmentStatus.OK,
        is_malicious_signal=True,
        is_active=True,
        pulse_count=4,
        threat_types=["c2"],
        attack_ids=["T1071"],
        source_first_seen=source_first,
        source_last_seen=source_last,
        latency_ms=240,
        retrieved_at=retrieved_now,
    )
    repo.save_enrichment_result(indicator.id, ok_evidence)

    # Indicator first_seen/last_seen updated from TI source timestamps, NOT retrieved_at
    refreshed_indicator = repo.get_indicator_by_id(indicator.id)
    assert refreshed_indicator is not None
    assert refreshed_indicator.first_seen == source_first
    assert refreshed_indicator.last_seen == source_last
    assert refreshed_indicator.last_seen != retrieved_now

    # Fresh cache hit
    cached = repo.get_fresh_enrichment(indicator.id, "AlienVault OTX", ttl_hours=24)
    assert cached is not None
    assert cached.from_cache is True
    assert cached.pulse_count == 4

    # Errors/timeouts must NOT be served from cache
    timeout_ev = EnrichmentEvidence(
        source_name="URLhaus",
        source_url="https://urlhaus-api.abuse.ch/v1",
        status=EnrichmentStatus.TIMEOUT,
        latency_ms=5000,
        error_message="Read timeout",
        retrieved_at=retrieved_now,
    )
    repo.save_enrichment_result(indicator.id, timeout_ev)
    assert repo.get_fresh_enrichment(indicator.id, "URLhaus", ttl_hours=24) is None

    # Stale result outside TTL must not hit cache
    old_ev = EnrichmentEvidence(
        source_name="URLhaus",
        source_url="https://urlhaus-api.abuse.ch/v1",
        status=EnrichmentStatus.NOT_FOUND,
        latency_ms=120,
        retrieved_at=retrieved_now - timedelta(hours=48),
    )
    repo.save_enrichment_result(indicator.id, old_ev)
    assert repo.get_fresh_enrichment(indicator.id, "URLhaus", ttl_hours=24) is None
    repo.close()


def test_reports_mitre_links_log_matches_and_metrics() -> None:
    repo = ThreatIntelRepository(":memory:")
    indicator, _ = repo.upsert_indicator(_sample_ip_ioc())

    repo.save_enrichment_result(
        indicator.id,
        EnrichmentEvidence(
            source_name="AlienVault OTX",
            status=EnrichmentStatus.OK,
            is_malicious_signal=True,
            latency_ms=200,
        ),
    )
    repo.save_enrichment_result(
        indicator.id,
        EnrichmentEvidence(
            source_name="URLhaus",
            status=EnrichmentStatus.ERROR,
            latency_ms=400,
            error_message="HTTP 500",
        ),
    )
    repo.save_enrichment_result(
        indicator.id,
        EnrichmentEvidence(
            source_name="CSV Dataset",
            status=EnrichmentStatus.SKIPPED_NO_KEY,
            latency_ms=0,
        ),
    )

    mapping = TechniqueMapping(
        technique=AttackTechnique(
            technique_id="T1071",
            name="Application Layer Protocol",
            tactic="command-and-control",
            url="https://attack.mitre.org/techniques/T1071/",
        ),
        source_name="AlienVault OTX",
        evidence="Matched attack_id T1071 from OTX pulse",
        confidence="high",
    )
    repo.link_indicator_technique(indicator.id, mapping)
    # Re-linking same technique from same source updates cleanly without duplicates
    repo.link_indicator_technique(indicator.id, mapping)

    report = ThreatReport(
        indicator=indicator,
        risk_score=67,
        confidence_score=60,
        risk_level=RiskLevel.HIGH,
        classification=Classification.SUSPICIOUS,
        score_breakdown=ScoreBreakdown(
            source_reliability=30,
            independent_sources=12,
            recency=15,
            activity_status=10,
        ),
        threat_types=["c2"],
        sources_checked=2,
        sources_with_evidence=1,
        summary="Suspicious IPv4 observed in 1 source.",
        recommended_actions=["Review firewall logs for outbound traffic."],
    )
    report_id = repo.save_threat_report(report)
    assert report_id > 0

    loaded = repo.get_latest_threat_report(indicator.id)
    assert loaded is not None
    assert loaded.risk_score == 67
    assert loaded.risk_level == RiskLevel.HIGH
    assert len(loaded.attack_techniques) == 1
    assert loaded.attack_techniques[0].technique.technique_id == "T1071"
    assert len(loaded.evidence) == 3

    listed = repo.list_latest_reports(risk_level=RiskLevel.HIGH, ioc_type=IOCType.IPV4)
    assert len(listed) == 1

    match_id = repo.save_log_match(
        LogMatch(
            indicator_id=indicator.id,
            indicator_value=indicator.normalized_value,
            indicator_type=indicator.ioc_type,
            log_source="firewall.csv",
            log_timestamp="2026-11-23T01:00:00Z",
            matched_field="dst_ip",
            raw_log_line="2026-11-23T01:00:00Z,10.0.0.5,198.51.100.23,443,ALLOW",
        )
    )
    assert match_id > 0
    matches = repo.list_log_matches()
    assert len(matches) == 1
    assert matches[0].risk_level == RiskLevel.HIGH

    metrics = repo.get_system_metrics()
    assert metrics.total_indicators == 1
    assert metrics.total_reports == 1
    assert metrics.total_enrichments == 3
    # 1 ok + 1 error attempted (skipped_no_key excluded from attempted ratio)
    assert metrics.enrichment_success_rate == 50.0
    assert metrics.api_failure_rate == 50.0
    assert metrics.avg_latency_ms == 300.0
    assert metrics.risk_distribution == {"High": 1}
    assert metrics.type_distribution == {"ipv4": 1}
    repo.close()

