"""Unit tests for SOC Log IOC Matcher against Firewall, DNS, Proxy, and EDR logs."""

from __future__ import annotations

from pathlib import Path

from app.collectors.csv_loader import load_iocs_from_csv
from app.database.repository import ThreatIntelRepository
from app.matching.log_matcher import SOCLogMatcher
from app.processors.deduplicator import ingest_batch_to_repository
from app.schemas import (
    Classification,
    RiskLevel,
    ScoreBreakdown,
    ThreatReport,
)


def test_log_matcher_correlates_sample_logs_and_persists() -> None:
    repo = ThreatIntelRepository(":memory:")
    inputs = load_iocs_from_csv(Path("data/sample_iocs.csv"))
    ingest = ingest_batch_to_repository(inputs, repo)
    assert ingest.inserted_new == 7

    matcher = SOCLogMatcher(repo)
    summary = matcher.match_file(Path("data/sample_logs.csv"), persist=True)

    assert summary.total_records_scanned == 7
    # Matches:
    # 1. Firewall dst_ip 198.51.100.23
    # 2. DNS domain malicious-demo.example.com
    # 3. Proxy url https://cdn.phish-demo.example.org/login/Verify?id=42
    # 4. Proxy url http://malicious-demo.example.com/stage2.bin -> domain cross-match!
    # 5. EDR file_hash EICAR SHA256
    assert summary.total_matches == 5
    assert summary.unique_iocs_matched == 4
    matched_values = {m.indicator_value for m in summary.matches}
    assert "198.51.100.23" in matched_values
    assert "malicious-demo.example.com" in matched_values
    assert "https://cdn.phish-demo.example.org/login/Verify?id=42" in matched_values
    assert (
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        in matched_values
    )

    saved = repo.list_log_matches()
    assert len(saved) == 5
    repo.close()


def test_log_matcher_respects_min_risk_level_and_jsonl() -> None:
    repo = ThreatIntelRepository(":memory:")
    ingest = ingest_batch_to_repository(["198.51.100.23", "evil.example.com"], repo)
    ip_ind = next(i for i in ingest.indicators if i.normalized_value == "198.51.100.23")
    dom_ind = next(i for i in ingest.indicators if i.normalized_value == "evil.example.com")

    # Mark IP as High risk and Domain as Low risk
    repo.save_threat_report(
        ThreatReport(
            indicator=ip_ind,
            risk_score=75,
            confidence_score=80,
            risk_level=RiskLevel.HIGH,
            classification=Classification.MALICIOUS,
            score_breakdown=ScoreBreakdown(
                source_reliability=35, independent_sources=25, recency=15, activity_status=0
            ),
            summary="High risk IP",
        )
    )
    repo.save_threat_report(
        ThreatReport(
            indicator=dom_ind,
            risk_score=10,
            confidence_score=70,
            risk_level=RiskLevel.LOW,
            classification=Classification.BENIGN_UNKNOWN,
            score_breakdown=ScoreBreakdown(),
            summary="Low risk domain",
        )
    )

    jsonl = (
        '{"timestamp":"2026-11-23T02:00:00Z","source":"Firewall","dst_ip":"198.51.100.23"}\n'
        '{"timestamp":"2026-11-23T02:01:00Z","source":"DNS","query":"evil.example.com"}\n'
    )
    matcher = SOCLogMatcher(repo)
    high_only = matcher.match_lines(jsonl, min_risk_level=RiskLevel.HIGH, persist=False)

    assert high_only.total_records_scanned == 2
    assert high_only.total_matches == 1
    assert high_only.matches[0].indicator_value == "198.51.100.23"
    assert high_only.matches[0].risk_level == RiskLevel.HIGH
    repo.close()

