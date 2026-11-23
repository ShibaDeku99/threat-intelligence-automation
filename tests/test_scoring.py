"""Unit tests for Heuristic Risk Score, Confidence Score, and Analyst Summaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.analysis.risk_scoring import ThreatAnalyzer, classify_risk_level
from app.enrichment.enrichment_engine import EnrichmentCorrelation
from app.enrichment.mitre_mapper import MitreAttackMapper
from app.processors.normalizer import normalize_ioc
from app.schemas import (
    Classification,
    EnrichmentEvidence,
    EnrichmentStatus,
    IndicatorRecord,
    RiskLevel,
)

FIXED_NOW = datetime(2026, 11, 23, 6, 0, tzinfo=UTC)


def _make_indicator(raw: str = "8.8.4.4") -> IndicatorRecord:
    ioc = normalize_ioc(raw)
    return IndicatorRecord(
        id=1,
        value=ioc.value,
        normalized_value=ioc.normalized_value,
        ioc_type=ioc.ioc_type,
        raw_input=ioc.raw_input,
        is_reserved_ip=ioc.is_reserved_ip,
        ip_scope_note=ioc.ip_scope_note,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
    )


def test_risk_level_threshold_boundaries() -> None:
    assert classify_risk_level(0) == RiskLevel.LOW
    assert classify_risk_level(29) == RiskLevel.LOW
    assert classify_risk_level(30) == RiskLevel.MEDIUM
    assert classify_risk_level(59) == RiskLevel.MEDIUM
    assert classify_risk_level(60) == RiskLevel.HIGH
    assert classify_risk_level(79) == RiskLevel.HIGH
    assert classify_risk_level(80) == RiskLevel.CRITICAL
    assert classify_risk_level(100) == RiskLevel.CRITICAL


def test_critical_multi_source_active_recent_ioc() -> None:
    ind = _make_indicator("198.51.100.23")
    ev_otx = EnrichmentEvidence(
        source_name="AlienVault OTX",
        status=EnrichmentStatus.OK,
        is_malicious_signal=True,
        is_active=True,
        pulse_count=6,
        malware_families=["Emotet"],
        attack_ids=["T1071"],
        references=["https://otx.alienvault.com/pulse/p1"],
        source_first_seen=FIXED_NOW - timedelta(days=10),
        source_last_seen=FIXED_NOW - timedelta(days=2),
    )
    ev_uh = EnrichmentEvidence(
        source_name="URLhaus",
        status=EnrichmentStatus.OK,
        is_malicious_signal=True,
        is_active=True,
        pulse_count=4,
        malware_families=["Emotet"],
        threat_types=["malware_download"],
        references=["https://urlhaus.abuse.ch/host/198.51.100.23/"],
        source_first_seen=FIXED_NOW - timedelta(days=5),
        source_last_seen=FIXED_NOW - timedelta(days=1),
    )
    corr = EnrichmentCorrelation(
        indicator=ind,
        evidence=[ev_otx, ev_uh],
        sources_checked=2,
        sources_with_evidence=2,
        threat_types=["malware_download", "malware"],
        malware_families=["Emotet"],
        attack_ids=["T1071"],
        references=ev_otx.references + ev_uh.references,
        earliest_first_seen=FIXED_NOW - timedelta(days=10),
        latest_last_seen=FIXED_NOW - timedelta(days=1),
        any_active=True,
    )

    techniques = MitreAttackMapper().map_correlation(corr)
    analyzer = ThreatAnalyzer()
    report = analyzer.analyze(corr, techniques=techniques, now=FIXED_NOW)

    # 40 (URLhaus active) + 25 (2 sources) + 20 (<=7 days) + 15 (active) = 100
    assert report.risk_score == 100
    assert report.risk_level == RiskLevel.CRITICAL
    assert report.classification == Classification.MALICIOUS
    assert report.confidence_score == 100
    # Reserved TEST-NET notice must appear in summary & recommended actions
    assert "TEST-NET-2" in report.summary
    assert any("không định tuyến" in action for action in report.recommended_actions)

    # Reproducibility check
    report_repeat = analyzer.analyze(corr, techniques=techniques, now=FIXED_NOW)
    assert report_repeat.risk_score == report.risk_score
    assert report_repeat.confidence_score == report.confidence_score
    assert report_repeat.score_breakdown == report.score_breakdown


def test_historical_old_offline_ioc_scores_medium() -> None:
    ind = _make_indicator("evil.example.com")
    ev_otx = EnrichmentEvidence(
        source_name="AlienVault OTX",
        status=EnrichmentStatus.OK,
        is_malicious_signal=True,
        is_active=False,
        pulse_count=1,
        source_first_seen=FIXED_NOW - timedelta(days=600),
        source_last_seen=FIXED_NOW - timedelta(days=500),
    )
    ev_uh = EnrichmentEvidence(
        source_name="URLhaus",
        status=EnrichmentStatus.NOT_FOUND,
        is_malicious_signal=False,
    )
    corr = EnrichmentCorrelation(
        indicator=ind,
        evidence=[ev_otx, ev_uh],
        sources_checked=2,
        sources_with_evidence=1,
        earliest_first_seen=FIXED_NOW - timedelta(days=600),
        latest_last_seen=FIXED_NOW - timedelta(days=500),
        any_active=False,
    )

    report = ThreatAnalyzer().analyze(corr, now=FIXED_NOW)
    # 22 (single OTX pulse) + 12 (1 source) + 2 (>365 days) + 5 (offline) = 41 -> Medium
    assert report.risk_score == 41
    assert report.risk_level == RiskLevel.MEDIUM
    assert report.classification == Classification.SUSPICIOUS


def test_clean_ioc_returns_low_risk_and_non_zero_confidence() -> None:
    ind = _make_indicator("8.8.8.8")
    corr = EnrichmentCorrelation(
        indicator=ind,
        evidence=[
            EnrichmentEvidence(source_name="AlienVault OTX", status=EnrichmentStatus.NOT_FOUND),
            EnrichmentEvidence(source_name="URLhaus", status=EnrichmentStatus.NOT_FOUND),
        ],
        sources_checked=2,
        sources_with_evidence=0,
    )
    report = ThreatAnalyzer().analyze(corr, now=FIXED_NOW)
    assert report.risk_score == 0
    assert report.risk_level == RiskLevel.LOW
    assert report.classification == Classification.BENIGN_UNKNOWN
    assert report.confidence_score >= 70


def test_missing_api_keys_yields_zero_risk_and_zero_confidence() -> None:
    ind = _make_indicator("198.51.100.23")
    corr = EnrichmentCorrelation(
        indicator=ind,
        evidence=[
            EnrichmentEvidence(
                source_name="AlienVault OTX", status=EnrichmentStatus.SKIPPED_NO_KEY
            ),
            EnrichmentEvidence(source_name="URLhaus", status=EnrichmentStatus.SKIPPED_NO_KEY),
        ],
        sources_checked=0,
        sources_with_evidence=0,
    )
    report = ThreatAnalyzer().analyze(corr, now=FIXED_NOW)
    assert report.risk_score == 0
    assert report.confidence_score == 0
    assert "Không được coi IOC này là đã xác minh an toàn" in report.summary
    assert any("OTX_API_KEY" in a for a in report.recommended_actions)


def test_partial_failure_decouples_high_risk_from_lower_confidence() -> None:
    ind = _make_indicator("https://evil.example.com/drop.exe")
    corr = EnrichmentCorrelation(
        indicator=ind,
        evidence=[
            EnrichmentEvidence(
                source_name="URLhaus",
                status=EnrichmentStatus.OK,
                is_malicious_signal=True,
                is_active=True,
                threat_types=["malware_download"],
                source_last_seen=FIXED_NOW - timedelta(days=1),
            ),
            EnrichmentEvidence(
                source_name="AlienVault OTX",
                status=EnrichmentStatus.TIMEOUT,
                error_message="Read timeout",
            ),
        ],
        sources_checked=2,
        sources_with_evidence=1,
        threat_types=["malware_download"],
        latest_last_seen=FIXED_NOW - timedelta(days=1),
        any_active=True,
    )
    report = ThreatAnalyzer().analyze(corr, now=FIXED_NOW)
    # High risk (40 + 12 + 20 + 15 = 87 -> Critical), but confidence reduced because OTX timed out
    assert report.risk_score == 87
    assert report.risk_level == RiskLevel.CRITICAL
    assert report.confidence_score <= 60
    assert "Độ phủ bị suy giảm" in report.summary

