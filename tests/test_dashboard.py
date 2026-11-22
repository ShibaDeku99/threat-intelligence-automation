"""Tests for Plotly chart builders and headless Streamlit Dashboard rendering."""

from __future__ import annotations

from pathlib import Path

from streamlit.testing.v1 import AppTest

from app.dashboard.dashboard import (
    build_breakdown_figure,
    build_risk_distribution_figure,
    build_risk_gauge_figure,
    build_source_health_figure,
    build_type_distribution_figure,
    collect_top_mitre_techniques,
)
from app.processors.normalizer import normalize_ioc
from app.schemas import (
    AttackTechnique,
    Classification,
    IndicatorRecord,
    RiskLevel,
    ScoreBreakdown,
    SourceMetrics,
    SystemMetrics,
    TechniqueMapping,
    ThreatReport,
    utc_now,
)


def _sample_report() -> ThreatReport:
    now = utc_now()
    ioc = normalize_ioc("198.51.100.23")
    ind = IndicatorRecord(
        id=1,
        value=ioc.value,
        normalized_value=ioc.normalized_value,
        ioc_type=ioc.ioc_type,
        raw_input=ioc.raw_input,
        is_reserved_ip=True,
        ip_scope_note=ioc.ip_scope_note,
        created_at=now,
        updated_at=now,
    )
    return ThreatReport(
        id=1,
        indicator=ind,
        risk_score=75,
        confidence_score=80,
        risk_level=RiskLevel.HIGH,
        classification=Classification.MALICIOUS,
        score_breakdown=ScoreBreakdown(
            source_reliability=35,
            independent_sources=25,
            recency=15,
            activity_status=0,
        ),
        attack_techniques=[
            TechniqueMapping(
                technique=AttackTechnique(
                    technique_id="T1071",
                    name="Application Layer Protocol",
                    tactic="command-and-control",
                ),
                source_name="AlienVault OTX",
                evidence="Direct pulse ID",
                confidence="high",
            )
        ],
        summary="High risk test report.",
    )


def test_plotly_chart_builders_and_mitre_aggregation() -> None:
    report = _sample_report()
    assert len(build_risk_gauge_figure(75, "High").data) == 1
    assert len(build_breakdown_figure(report).data) == 1
    assert len(build_risk_distribution_figure({"High": 2, "Low": 1}).data) >= 1
    assert len(build_type_distribution_figure({"ipv4": 3, "domain": 2}).data) == 1

    metrics = SystemMetrics(
        total_indicators=3,
        by_source=[
            SourceMetrics(
                source_name="AlienVault OTX",
                total_queries=3,
                ok_count=2,
                timeout_count=1,
                avg_latency_ms=210.0,
                api_failure_rate=33.33,
            )
        ],
    )
    assert len(build_source_health_figure(metrics).data) >= 1

    mitre_df = collect_top_mitre_techniques([report])
    assert len(mitre_df) == 1
    assert "T1071" in mitre_df.iloc[0]["Technique"]


def test_streamlit_dashboard_renders_and_handles_sample_workflow(
    tmp_path: Path, monkeypatch: object
) -> None:
    # Isolate DB path so AppTest never pollutes repo data/ directory
    import pytest

    assert isinstance(monkeypatch, pytest.MonkeyPatch)
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "ui_test.db"))
    monkeypatch.setenv("OTX_API_KEY", "")
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "")

    dashboard_script = Path(__file__).resolve().parents[1] / "app" / "dashboard" / "dashboard.py"
    at = AppTest.from_file(str(dashboard_script), default_timeout=20)
    at.run()
    assert not at.exception
    assert len(at.tabs) == 4

    # Exercise sidebar "Load Sample IOCs (CSV)" button end-to-end
    sample_btn = next(b for b in at.sidebar.button if "Load Sample IOCs" in b.label)
    sample_btn.click().run()
    assert not at.exception
    assert any("Loaded 7 unique IOCs" in msg.value for msg in at.sidebar.success)
