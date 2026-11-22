"""Command-line interface for the Automated Threat Intelligence & IOC Enrichment Platform."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from app.config import Settings, get_settings
from app.enrichment.mitre_mapper import sync_mitre_attack_bundle
from app.matching.log_matcher import SOCLogMatcher
from app.pipeline import ThreatIntelPipeline
from app.processors.normalizer import defang_ioc
from app.processors.validator import IOCValidationError
from app.reporting.exporter import export_csv, export_html, export_json
from app.schemas import IOCType, RiskLevel, ThreatReport


def _export_reports(
    reports: list[ThreatReport],
    fmt: str,
    output_path: Path | None,
    reports_dir: Path,
    defang: bool,
    stem: str,
) -> Path:
    ext = fmt.lower()
    target = output_path or (reports_dir / f"{stem}.{ext}")
    if ext == "json":
        return export_json(reports, target, defang=defang)
    if ext == "csv":
        return export_csv(reports, target, defang=defang)
    if ext == "html":
        return export_html(reports, target, defang=defang)
    raise ValueError(f"Unsupported export format: {fmt}")


def _print_report_summary(report: ThreatReport, defang: bool) -> None:
    ind = report.indicator
    display_val = defang_ioc(ind.normalized_value, ind.ioc_type) if defang else ind.normalized_value
    print("=" * 72)
    print(f"IOC:            {display_val} ({ind.ioc_type.value.upper()})")
    if ind.is_reserved_ip and ind.ip_scope_note:
        print(f"Scope Warning:  {ind.ip_scope_note}")
    print(f"Classification: {report.classification.value}")
    print(f"Risk Score:     {report.risk_score}/100 ({report.risk_level.value}) [Heuristic]")
    print(f"Confidence:     {report.confidence_score}/100")
    print(
        f"Sources:        {report.sources_with_evidence} confirming / "
        f"{report.sources_checked} checked"
    )
    print(
        "Breakdown:      "
        f"Reliability={report.score_breakdown.source_reliability}/40, "
        f"Sources={report.score_breakdown.independent_sources}/25, "
        f"Recency={report.score_breakdown.recency}/20, "
        f"Activity={report.score_breakdown.activity_status}/15"
    )
    if report.attack_techniques:
        tech_str = ", ".join(
            f"{m.technique.technique_id} ({m.technique.name})" for m in report.attack_techniques[:5]
        )
        print(f"MITRE ATT&CK:   {tech_str}")
    print(f"Summary:        {report.summary}")
    if report.recommended_actions:
        print("Next Actions:")
        for action in report.recommended_actions:
            print(f"  - {action}")
    print("=" * 72)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat-intel",
        description="Automated Threat Intelligence & IOC Enrichment Platform CLI",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help="Override SQLite database path (default from .env / settings)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # lookup
    p_lookup = sub.add_parser("lookup", help="Investigate a single IOC")
    p_lookup.add_argument("ioc", help="IP, Domain, URL, or MD5/SHA1/SHA256 (defanged supported)")
    p_lookup.add_argument("--source-hint", default="CLI Lookup", help="Optional input source label")
    p_lookup.add_argument("--force-refresh", action="store_true", help="Bypass TTL cache")
    p_lookup.add_argument("--export", choices=["json", "csv", "html"], default=None)
    p_lookup.add_argument("--output", type=Path, default=None, help="Output file path for export")
    p_lookup.add_argument("--no-defang", action="store_true", help="Display/export raw IOC values")

    # batch
    p_batch = sub.add_parser("batch", help="Investigate a CSV batch of IOCs")
    p_batch.add_argument("csv_path", type=Path, help="Path to CSV dataset")
    p_batch.add_argument("--column", default=None, help="Explicit IOC column name")
    p_batch.add_argument("--force-refresh", action="store_true", help="Bypass TTL cache")
    p_batch.add_argument("--export", choices=["json", "csv", "html"], default=None)
    p_batch.add_argument("--output", type=Path, default=None, help="Output file path for export")
    p_batch.add_argument("--no-defang", action="store_true", help="Display/export raw IOC values")

    # match-logs
    p_match = sub.add_parser("match-logs", help="Match stored IOCs against SOC log file")
    p_match.add_argument("log_path", type=Path, help="Path to CSV, JSONL, or plain-text SOC log")
    p_match.add_argument(
        "--min-risk",
        choices=[lvl.value for lvl in RiskLevel],
        default=None,
        help="Minimum IOC Risk Level to alert on",
    )
    p_match.add_argument("--no-save", action="store_true", help="Do not persist matches to DB")

    # list-reports
    p_list = sub.add_parser("list-reports", help="List latest stored Threat Reports")
    p_list.add_argument("--risk", choices=[lvl.value for lvl in RiskLevel], default=None)
    p_list.add_argument("--type", choices=[t.value for t in IOCType], default=None)
    p_list.add_argument("--search", default=None)
    p_list.add_argument("--limit", type=int, default=20)

    # metrics
    sub.add_parser("metrics", help="Display measured system & API evaluation metrics")

    # sync-mitre
    sub.add_parser(
        "sync-mitre",
        help="Download and cache the full official MITRE Enterprise ATT&CK STIX 2.1 bundle",
    )

    return parser


def main(argv: Sequence[str] | None = None, settings: Settings | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    cfg = settings or get_settings()
    if args.db is not None:
        cfg = cfg.model_copy(update={"database_path": args.db})

    if args.command == "sync-mitre":
        dest = cfg.mitre_data_dir / "enterprise-attack.json"
        try:
            saved = sync_mitre_attack_bundle(destination=dest)
            print(f"MITRE ATT&CK STIX 2.1 bundle synced to {saved}")
            return 0
        except Exception as exc:
            print(f"Failed to sync MITRE ATT&CK bundle: {exc}", file=sys.stderr)
            return 1

    with ThreatIntelPipeline(settings=cfg) as pipeline:
        if args.command == "lookup":
            defang = not args.no_defang
            try:
                report = pipeline.investigate_single(
                    args.ioc,
                    source_hint=args.source_hint,
                    force_refresh=args.force_refresh,
                )
            except IOCValidationError as exc:
                print(f"Validation error: {exc}", file=sys.stderr)
                return 1

            _print_report_summary(report, defang=defang)
            if args.export:
                out = _export_reports(
                    [report],
                    fmt=args.export,
                    output_path=args.output,
                    reports_dir=cfg.reports_dir,
                    defang=defang,
                    stem=f"ioc_report_{report.indicator.id}",
                )
                print(f"Exported {args.export.upper()} report to: {out}")
            return 0

        if args.command == "batch":
            defang = not args.no_defang
            try:
                result = pipeline.investigate_csv(
                    args.csv_path,
                    ioc_column=args.column,
                    force_refresh=args.force_refresh,
                )
            except Exception as exc:
                print(f"Batch error: {exc}", file=sys.stderr)
                return 1

            print(
                f"Batch processed: received={result.batch.total_received}, "
                f"unique={len(result.batch.unique_iocs)}, "
                f"duplicates_removed={result.batch.duplicate_count}, "
                f"invalid={result.batch.invalid_count}, "
                f"cache_hits={result.total_cache_hits}"
            )
            for report in result.reports:
                _print_report_summary(report, defang=defang)

            if args.export and result.reports:
                out = _export_reports(
                    result.reports,
                    fmt=args.export,
                    output_path=args.output,
                    reports_dir=cfg.reports_dir,
                    defang=defang,
                    stem="batch_report",
                )
                print(f"Exported {args.export.upper()} batch report to: {out}")
            return 0

        if args.command == "match-logs":
            matcher = SOCLogMatcher(pipeline.repo)
            min_risk = RiskLevel(args.min_risk) if args.min_risk else None
            try:
                summary = matcher.match_file(
                    args.log_path,
                    min_risk_level=min_risk,
                    persist=not args.no_save,
                )
            except Exception as exc:
                print(f"Log matching error: {exc}", file=sys.stderr)
                return 1

            print(
                f"Scanned {summary.total_records_scanned} log record(s): "
                f"{summary.total_matches} match(es) across "
                f"{summary.unique_iocs_matched} unique IOC(s)."
            )
            for m in summary.matches:
                risk_txt = m.risk_level.value if m.risk_level else "Unscored"
                print(
                    f"  [{risk_txt}] {m.indicator_value} ({m.indicator_type.value}) "
                    f"in {m.log_source}:{m.matched_field} @ {m.log_timestamp or 'N/A'}"
                )
            return 0

        if args.command == "list-reports":
            risk_filter = RiskLevel(args.risk) if args.risk else None
            type_filter = IOCType(args.type) if args.type else None
            reports = pipeline.repo.list_latest_reports(
                risk_level=risk_filter,
                ioc_type=type_filter,
                search=args.search,
                limit=args.limit,
            )
            if not reports:
                print("No threat reports found matching criteria.")
                return 0
            for r in reports:
                print(
                    f"#{r.indicator.id:03d} | {r.risk_level.value:<8} | "
                    f"Risk={r.risk_score:3d} | Conf={r.confidence_score:3d} | "
                    f"{r.indicator.ioc_type.value:<6} | {r.indicator.normalized_value}"
                )
            return 0

        if args.command == "metrics":
            m = pipeline.repo.get_system_metrics()
            print("Measured Platform Telemetry:")
            print(f"  Total Indicators:        {m.total_indicators}")
            print(f"  Total Threat Reports:    {m.total_reports}")
            print(f"  Total Enrichment Calls:  {m.total_enrichments}")
            print(f"  Enrichment Success Rate: {m.enrichment_success_rate:.2f}%")
            print(f"  API Failure Rate:        {m.api_failure_rate:.2f}%")
            print(f"  Average API Latency:     {m.avg_latency_ms:.2f} ms")
            print(f"  Risk Distribution:       {m.risk_distribution}")
            print(f"  IOC Type Distribution:   {m.type_distribution}")
            for src in m.by_source:
                print(
                    f"  - {src.source_name}: total={src.total_queries}, ok={src.ok_count}, "
                    f"not_found={src.not_found_count}, err={src.error_count}, "
                    f"timeout={src.timeout_count}, skipped={src.skipped_count}, "
                    f"avg_ms={src.avg_latency_ms:.1f}"
                )
            return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

