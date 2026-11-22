"""Unit tests for JSON, CSV, and XSS-safe HTML report exporters."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from app.processors.normalizer import normalize_ioc
from app.reporting.exporter import (
    export_csv,
    export_html,
    export_json,
    render_html_string,
    render_json_string,
)
from app.schemas import (
    AttackTechnique,
    Classification,
    EnrichmentEvidence,
    EnrichmentStatus,
    IndicatorRecord,
    RiskLevel,
    ScoreBreakdown,
    TechniqueMapping,
    ThreatReport,
)


def _sample_report(malicious_tag: str = "emotet") -> ThreatReport:
    now = datetime(2026, 11, 23, 6, 0, tzinfo=UTC)
    src_first = datetime(2026, 11, 10, 0, 0, tzinfo=UTC)
    src_last = datetime(2026, 11, 22, 0, 0, tzinfo=UTC)
    ioc = normalize_ioc("https://evil.example.com/drop.exe")
    ind = IndicatorRecord(
        id=42,
        value=ioc.value,
        normalized_value=ioc.normalized_value,
        ioc_type=ioc.ioc_type,
        raw_input=ioc.raw_input,
        first_seen=src_first,
        last_seen=src_last,
        created_at=now,
        updated_at=now,
    )
    ev = EnrichmentEvidence(
        source_name="URLhaus",
        status=EnrichmentStatus.OK,
        is_malicious_signal=True,
        is_active=True,
        pulse_count=1,
        threat_types=["malware_download"],
        malware_families=["Emotet"],
        tags=[malicious_tag],
        source_first_seen=src_first,
        source_last_seen=src_last,
        latency_ms=185,
        retrieved_at=now,
    )
    tech = TechniqueMapping(
        technique=AttackTechnique(
            technique_id="T1105",
            name="Ingress Tool Transfer",
            tactic="command-and-control",
            url="https://attack.mitre.org/techniques/T1105/",
        ),
        source_name="URLhaus",
        evidence=f"Observed tag {malicious_tag}",
        confidence="medium",
    )
    return ThreatReport(
        id=1,
        indicator=ind,
        risk_score=87,
        confidence_score=82,
        risk_level=RiskLevel.CRITICAL,
        classification=Classification.MALICIOUS,
        score_breakdown=ScoreBreakdown(
            source_reliability=40,
            independent_sources=12,
            recency=20,
            activity_status=15,
        ),
        threat_types=["malware_download"],
        sources_checked=1,
        sources_with_evidence=1,
        evidence=[ev],
        attack_techniques=[tech],
        summary="Critical malware download URL confirmed by URLhaus.",
        recommended_actions=["Block URL after verifying business impact."],
        generated_at=now,
    )


def test_export_json_csv_html_files(tmp_path: Path) -> None:
    report = _sample_report()

    json_path = export_json(report, tmp_path / "out.json", defang=True)
    csv_path = export_csv([report], tmp_path / "out.csv", defang=True)
    html_path = export_html([report], tmp_path / "out.html", defang=True)

    json_data = json.loads(json_path.read_text(encoding="utf-8"))
    assert json_data["report_count"] == 1
    assert json_data["defanged"] is True
    assert json_data["reports"][0]["display_ioc"] == "hxxps://evil[.]example[.]com/drop.exe"

    csv_text = csv_path.read_text(encoding="utf-8-sig")
    assert "hxxps://evil[.]example[.]com/drop.exe" in csv_text
    assert "T1105 (Ingress Tool Transfer)" in csv_text

    html_text = html_path.read_text(encoding="utf-8")
    assert "hxxps://evil[.]example[.]com/drop.exe" in html_text
    assert "Heuristic Risk Score" in html_text
    assert "T1105" in html_text


def test_json_raw_mode_disables_defang() -> None:
    report = _sample_report()
    data = json.loads(render_json_string(report, defang=False))
    assert data["reports"][0]["display_ioc"] == "https://evil.example.com/drop.exe"


def test_html_report_escapes_xss_payloads() -> None:
    xss = '<script>alert("xss")</script>'
    report = _sample_report(malicious_tag=xss)
    html = render_html_string(report, defang=True)
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html

