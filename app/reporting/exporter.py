"""JSON, CSV, and auto-escaped HTML report exporters for Threat Intelligence reports."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.processors.normalizer import defang_ioc
from app.schemas import ThreatReport, utc_now

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _fmt_dt(value: datetime | None) -> str:
    if value is None:
        return "N/A"
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def _normalize_report_list(reports: ThreatReport | Sequence[ThreatReport]) -> list[ThreatReport]:
    if isinstance(reports, ThreatReport):
        return [reports]
    return list(reports)


def _display_ioc(report: ThreatReport, defang: bool) -> str:
    raw = report.indicator.normalized_value
    return defang_ioc(raw, report.indicator.ioc_type) if defang else raw


def _serialize_report_for_json(report: ThreatReport, defang: bool) -> dict[str, Any]:
    data = report.model_dump(mode="json")
    data["display_ioc"] = _display_ioc(report, defang)
    if defang:
        data["indicator"]["value"] = data["display_ioc"]
        data["indicator"]["normalized_value"] = data["display_ioc"]
    return data


def render_json_string(
    reports: ThreatReport | Sequence[ThreatReport],
    defang: bool = True,
) -> str:
    """Render one or more ThreatReports to a formatted JSON string."""
    report_list = _normalize_report_list(reports)
    payload = {
        "generated_at": utc_now().isoformat(),
        "report_count": len(report_list),
        "defanged": defang,
        "disclaimer": (
            "Heuristic Risk Score is a decision-support indicator, not an international "
            "standard. Verify findings before applying blocking rules."
        ),
        "reports": [_serialize_report_for_json(r, defang=defang) for r in report_list],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def export_json(
    reports: ThreatReport | Sequence[ThreatReport],
    output_path: Path | str,
    defang: bool = True,
) -> Path:
    """Write JSON Threat Intelligence report to disk."""
    dest = Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(render_json_string(reports, defang=defang), encoding="utf-8")
    return dest


def reports_to_dataframe(
    reports: ThreatReport | Sequence[ThreatReport],
    defang: bool = True,
) -> pd.DataFrame:
    """Flatten ThreatReports into a SOC-ready pandas DataFrame."""
    report_list = _normalize_report_list(reports)
    rows: list[dict[str, Any]] = []
    for r in report_list:
        rows.append(
            {
                "ioc": _display_ioc(r, defang),
                "type": r.indicator.ioc_type.value,
                "classification": r.classification.value,
                "risk_score": r.risk_score,
                "risk_level": r.risk_level.value,
                "confidence_score": r.confidence_score,
                "score_source_reliability": r.score_breakdown.source_reliability,
                "score_independent_sources": r.score_breakdown.independent_sources,
                "score_recency": r.score_breakdown.recency,
                "score_activity": r.score_breakdown.activity_status,
                "sources_checked": r.sources_checked,
                "sources_with_evidence": r.sources_with_evidence,
                "threat_types": "; ".join(r.threat_types),
                "attack_techniques": "; ".join(
                    f"{t.technique.technique_id} ({t.technique.name})"
                    for t in r.attack_techniques
                ),
                "source_first_seen": _fmt_dt(r.indicator.first_seen),
                "source_last_seen": _fmt_dt(r.indicator.last_seen),
                "generated_at": _fmt_dt(r.generated_at),
                "is_reserved_ip": r.indicator.is_reserved_ip,
                "summary": r.summary,
            }
        )
    return pd.DataFrame(rows)


def render_csv_string(
    reports: ThreatReport | Sequence[ThreatReport],
    defang: bool = True,
) -> str:
    """Render one or more ThreatReports to a CSV string."""
    df = reports_to_dataframe(reports, defang=defang)
    return df.to_csv(index=False)


def export_csv(
    reports: ThreatReport | Sequence[ThreatReport],
    output_path: Path | str,
    defang: bool = True,
) -> Path:
    """Write CSV Threat Intelligence report to disk (UTF-8 with BOM for Excel compatibility)."""
    dest = Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(render_csv_string(reports, defang=defang), encoding="utf-8-sig")
    return dest


def render_html_string(
    reports: ThreatReport | Sequence[ThreatReport],
    defang: bool = True,
    title: str = "Threat Intelligence & IOC Investigation Report",
) -> str:
    """Render an auto-escaped, XSS-safe HTML investigation report using Jinja2."""
    report_list = _normalize_report_list(reports)
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
    )
    template = env.get_template("report.html.j2")

    view_models: list[dict[str, Any]] = []
    for r in report_list:
        ev_rows: list[dict[str, Any]] = []
        for ev in r.evidence:
            context_pieces: list[str] = []
            if ev.pulse_count:
                context_pieces.append(f"Pulses/URLs: {ev.pulse_count}")
            if ev.malware_families:
                context_pieces.append(f"Malware: {', '.join(ev.malware_families[:5])}")
            if ev.threat_types:
                context_pieces.append(f"Threats: {', '.join(ev.threat_types[:5])}")
            if ev.tags:
                context_pieces.append(f"Tags: {', '.join(ev.tags[:6])}")
            ev_rows.append(
                {
                    "source_name": ev.source_name,
                    "status": ev.status.value,
                    "from_cache": ev.from_cache,
                    "is_malicious_signal": ev.is_malicious_signal,
                    "error_message": ev.error_message,
                    "context_text": " | ".join(context_pieces) if context_pieces else "No record",
                    "source_last_seen": _fmt_dt(ev.source_last_seen),
                    "retrieved_at": _fmt_dt(ev.retrieved_at),
                    "latency_ms": ev.latency_ms,
                }
            )

        tech_rows = [
            {
                "technique_id": m.technique.technique_id,
                "name": m.technique.name,
                "tactic": m.technique.tactic,
                "confidence": m.confidence,
                "evidence": m.evidence,
            }
            for m in r.attack_techniques
        ]

        view_models.append(
            {
                "display_ioc": _display_ioc(r, defang),
                "ioc_type": r.indicator.ioc_type.value.upper(),
                "risk_score": r.risk_score,
                "risk_level": r.risk_level.value,
                "confidence_score": r.confidence_score,
                "classification": r.classification.value,
                "is_reserved_ip": r.indicator.is_reserved_ip,
                "source_first_seen": _fmt_dt(r.indicator.first_seen),
                "source_last_seen": _fmt_dt(r.indicator.last_seen),
                "generated_at": _fmt_dt(r.generated_at),
                "summary": r.summary,
                "breakdown": r.score_breakdown,
                "sources_checked": r.sources_checked,
                "sources_with_evidence": r.sources_with_evidence,
                "evidence": ev_rows,
                "techniques": tech_rows,
                "recommended_actions": r.recommended_actions,
            }
        )

    return template.render(
        title=title,
        generated_at=_fmt_dt(utc_now()),
        defanged=defang,
        reports=view_models,
    )


def export_html(
    reports: ThreatReport | Sequence[ThreatReport],
    output_path: Path | str,
    defang: bool = True,
    title: str = "Threat Intelligence & IOC Investigation Report",
) -> Path:
    """Write an auto-escaped HTML Threat Intelligence report to disk."""
    dest = Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        render_html_string(reports, defang=defang, title=title),
        encoding="utf-8",
    )
    return dest

