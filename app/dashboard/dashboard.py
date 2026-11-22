"""Streamlit + Plotly Threat Intelligence & IOC Enrichment Dashboard."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

# Ensure repository root is importable when launched via `streamlit run app/dashboard/dashboard.py`
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import pandas as pd  # noqa: E402
import plotly.express as px  # noqa: E402
import plotly.graph_objects as go  # noqa: E402
import streamlit as st  # noqa: E402

from app.collectors.csv_loader import CSVLoaderError, load_iocs_from_text  # noqa: E402
from app.config import Settings, get_settings  # noqa: E402
from app.matching.log_matcher import SOCLogMatcher  # noqa: E402
from app.pipeline import ThreatIntelPipeline  # noqa: E402
from app.processors.normalizer import defang_ioc  # noqa: E402
from app.processors.validator import IOCValidationError  # noqa: E402
from app.reporting.exporter import (  # noqa: E402
    render_csv_string,
    render_html_string,
    render_json_string,
)
from app.schemas import IOCType, RiskLevel, SystemMetrics, ThreatReport  # noqa: E402

RISK_COLORS: dict[str, str] = {
    RiskLevel.CRITICAL.value: "#dc2626",
    RiskLevel.HIGH.value: "#ea580c",
    RiskLevel.MEDIUM.value: "#ca8a04",
    RiskLevel.LOW.value: "#16a34a",
}

SAMPLE_IOCS_PATH = _PROJECT_ROOT / "data" / "sample_iocs.csv"
SAMPLE_LOGS_PATH = _PROJECT_ROOT / "data" / "sample_logs.csv"


def _display_ioc(value: str, ioc_type: IOCType, defang: bool) -> str:
    return defang_ioc(value, ioc_type) if defang else value


def build_risk_gauge_figure(risk_score: int, risk_level: str) -> go.Figure:
    """Create a Plotly gauge visual for Heuristic Risk Score (0-100)."""
    color = RISK_COLORS.get(risk_level, "#2563eb")
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=risk_score,
            number={"suffix": " / 100"},
            title={"text": f"Heuristic Risk ({risk_level})", "font": {"size": 15}},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": color},
                "steps": [
                    {"range": [0, 29], "color": "#dcfce7"},
                    {"range": [30, 59], "color": "#fef9c3"},
                    {"range": [60, 79], "color": "#ffedd5"},
                    {"range": [80, 100], "color": "#fee2e2"},
                ],
            },
        )
    )
    fig.update_layout(height=230, margin={"t": 40, "b": 10, "l": 20, "r": 20})
    return fig


def build_breakdown_figure(report: ThreatReport) -> go.Figure:
    """Create a horizontal bar chart showing each Heuristic Risk Score component."""
    b = report.score_breakdown
    df = pd.DataFrame(
        [
            {
                "Criterion": "Source Reliability (max 40)",
                "Score": b.source_reliability,
                "Max": 40,
            },
            {
                "Criterion": "Independent Sources (max 25)",
                "Score": b.independent_sources,
                "Max": 25,
            },
            {"Criterion": "Data Recency (max 20)", "Score": b.recency, "Max": 20},
            {"Criterion": "Activity Status (max 15)", "Score": b.activity_status, "Max": 15},
        ]
    )
    fig = px.bar(
        df,
        x="Score",
        y="Criterion",
        orientation="h",
        text="Score",
        range_x=[0, 42],
        title="Heuristic Risk Score Breakdown",
    )
    fig.update_traces(marker_color="#2563eb", textposition="outside")
    fig.update_layout(
        height=230,
        margin={"t": 40, "b": 10, "l": 10, "r": 20},
        yaxis={"autorange": "reversed"},
    )
    return fig


def build_risk_distribution_figure(risk_distribution: dict[str, int]) -> go.Figure:
    """Create a Plotly bar chart of IOC count by Risk Level."""
    ordered_levels = [
        RiskLevel.CRITICAL.value,
        RiskLevel.HIGH.value,
        RiskLevel.MEDIUM.value,
        RiskLevel.LOW.value,
    ]
    rows = [
        {"Risk Level": lvl, "Indicators": risk_distribution.get(lvl, 0)}
        for lvl in ordered_levels
    ]
    df = pd.DataFrame(rows)
    fig = px.bar(
        df,
        x="Risk Level",
        y="Indicators",
        color="Risk Level",
        color_discrete_map=RISK_COLORS,
        text="Indicators",
        title="Indicators by Heuristic Risk Level",
    )
    fig.update_layout(height=300, showlegend=False, margin={"t": 45, "b": 20})
    return fig


def build_type_distribution_figure(type_distribution: dict[str, int]) -> go.Figure:
    """Create a Plotly pie/donut chart of IOC count by IOC Type."""
    if not type_distribution:
        return go.Figure()
    df = pd.DataFrame(
        [{"IOC Type": k.upper(), "Count": v} for k, v in sorted(type_distribution.items())]
    )
    fig = px.pie(
        df,
        names="IOC Type",
        values="Count",
        hole=0.45,
        title="Indicators by IOC Type",
    )
    fig.update_layout(height=300, margin={"t": 45, "b": 20})
    return fig


def build_source_health_figure(metrics: SystemMetrics) -> go.Figure:
    """Create a stacked bar chart of TI source query outcomes."""
    if not metrics.by_source:
        return go.Figure()
    rows: list[dict[str, object]] = []
    for src in metrics.by_source:
        for label, val in (
            ("OK (Evidence)", src.ok_count),
            ("Not Found", src.not_found_count),
            ("Timeout", src.timeout_count),
            ("API Error", src.error_count),
            ("Skipped (No Key)", src.skipped_count),
            ("Unsupported Type", src.unsupported_count),
        ):
            if val > 0:
                rows.append({"Source": src.source_name, "Status": label, "Queries": val})
    if not rows:
        return go.Figure()
    df = pd.DataFrame(rows)
    fig = px.bar(
        df,
        x="Source",
        y="Queries",
        color="Status",
        barmode="stack",
        title="Threat Intelligence API Query Outcomes by Source",
    )
    fig.update_layout(height=320, margin={"t": 45, "b": 20})
    return fig


def collect_top_mitre_techniques(reports: list[ThreatReport]) -> pd.DataFrame:
    """Aggregate the most frequently mapped MITRE ATT&CK techniques across latest reports."""
    counter: Counter[tuple[str, str, str]] = Counter()
    for report in reports:
        for mapping in report.attack_techniques:
            t = mapping.technique
            counter[(t.technique_id, t.name, t.tactic)] += 1
    if not counter:
        return pd.DataFrame(columns=["Technique", "Tactic", "Indicators"])
    rows = [
        {"Technique": f"{tid} - {name}", "Tactic": tactic, "Indicators": count}
        for (tid, name, tactic), count in counter.most_common(10)
    ]
    return pd.DataFrame(rows)


def _render_download_buttons(
    reports: list[ThreatReport],
    defang: bool,
    key_prefix: str,
) -> None:
    if not reports:
        return
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button(
            label="Export JSON",
            data=render_json_string(reports, defang=defang),
            file_name=f"{key_prefix}_report.json",
            mime="application/json",
            key=f"dl_json_{key_prefix}",
            use_container_width=True,
        )
    with c2:
        st.download_button(
            label="Export CSV",
            data=render_csv_string(reports, defang=defang).encode("utf-8-sig"),
            file_name=f"{key_prefix}_report.csv",
            mime="text/csv",
            key=f"dl_csv_{key_prefix}",
            use_container_width=True,
        )
    with c3:
        st.download_button(
            label="Export HTML",
            data=render_html_string(reports, defang=defang),
            file_name=f"{key_prefix}_report.html",
            mime="text/html",
            key=f"dl_html_{key_prefix}",
            use_container_width=True,
        )


def _render_report_card(report: ThreatReport, defang: bool, key_prefix: str) -> None:
    ind = report.indicator
    shown_ioc = _display_ioc(ind.normalized_value, ind.ioc_type, defang)

    st.subheader(f"`{shown_ioc}` ({ind.ioc_type.value.upper()})")
    if ind.is_reserved_ip and ind.ip_scope_note:
        st.warning(f"Non-routable / Special IP Notice: {ind.ip_scope_note}")

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Heuristic Risk Score", f"{report.risk_score} / 100", report.risk_level.value)
    k2.metric("Confidence Score", f"{report.confidence_score} / 100")
    k3.metric("Classification", report.classification.value)
    k4.metric(
        "Sources Confirmed",
        f"{report.sources_with_evidence} / {report.sources_checked} checked",
    )

    chart_left, chart_right = st.columns(2)
    with chart_left:
        st.plotly_chart(
            build_risk_gauge_figure(report.risk_score, report.risk_level.value),
            use_container_width=True,
            key=f"gauge_{key_prefix}",
        )
    with chart_right:
        st.plotly_chart(
            build_breakdown_figure(report),
            use_container_width=True,
            key=f"breakdown_{key_prefix}",
        )

    st.info(report.summary)
    st.caption(report.disclaimer)

    # Timestamps clarity: Source first/last seen vs Report generated
    t1, t2, t3 = st.columns(3)
    t1.caption(
        "Source First Seen: "
        + (ind.first_seen.strftime("%Y-%m-%d %H:%M UTC") if ind.first_seen else "N/A")
    )
    t2.caption(
        "Source Last Seen: "
        + (ind.last_seen.strftime("%Y-%m-%d %H:%M UTC") if ind.last_seen else "N/A")
    )
    t3.caption("Last Checked: " + report.generated_at.strftime("%Y-%m-%d %H:%M UTC"))

    st.markdown("#### Threat Intelligence Evidence")
    if report.evidence:
        ev_rows = []
        for ev in report.evidence:
            details = ev.error_message or (
                ", ".join(filter(None, [
                    f"Pulses/URLs: {ev.pulse_count}" if ev.pulse_count else "",
                    f"Malware: {', '.join(ev.malware_families)}" if ev.malware_families else "",
                    f"Threats: {', '.join(ev.threat_types)}" if ev.threat_types else "",
                    f"Tags: {', '.join(ev.tags[:6])}" if ev.tags else "",
                ]))
                or "No malicious record"
            )
            ev_rows.append(
                {
                    "Source": ev.source_name,
                    "Status": ev.status.value + (" (cached)" if ev.from_cache else ""),
                    "Malicious Signal": "Yes" if ev.is_malicious_signal else "No",
                    "Active": (
                        "Active" if ev.is_active is True
                        else ("Offline" if ev.is_active is False else "Unknown")
                    ),
                    "Source Last Seen": (
                        ev.source_last_seen.strftime("%Y-%m-%d %H:%M UTC")
                        if ev.source_last_seen
                        else "N/A"
                    ),
                    "Retrieved At (UTC)": ev.retrieved_at.strftime("%Y-%m-%d %H:%M UTC"),
                    "Latency (ms)": ev.latency_ms,
                    "Evidence / Note": details,
                }
            )
        st.dataframe(pd.DataFrame(ev_rows), use_container_width=True, hide_index=True)
    else:
        st.caption("No enrichment records stored yet.")

    st.markdown("#### MITRE ATT&CK Mapping (STIX 2.1)")
    if report.attack_techniques:
        tech_rows = [
            {
                "Technique ID": m.technique.technique_id,
                "Name": m.technique.name,
                "Tactic": m.technique.tactic,
                "Confidence": m.confidence.upper(),
                "Source": m.source_name,
                "Evidence": m.evidence,
                "URL": m.technique.url,
            }
            for m in report.attack_techniques
        ]
        st.dataframe(pd.DataFrame(tech_rows), use_container_width=True, hide_index=True)
    else:
        st.caption("No evidence-backed MITRE ATT&CK techniques mapped for this indicator.")

    if report.recommended_actions:
        st.markdown("#### Recommended SOC Investigation Actions")
        for action in report.recommended_actions:
            st.markdown(f"- {action}")

    st.markdown("#### Export Report")
    _render_download_buttons([report], defang=defang, key_prefix=key_prefix)


def _get_pipeline(settings: Settings) -> ThreatIntelPipeline:
    return ThreatIntelPipeline(settings=settings)


def render_dashboard(settings: Settings | None = None) -> None:
    """Main Streamlit application entry point."""
    cfg = settings or get_settings()
    st.set_page_config(
        page_title="Threat Intelligence & IOC Enrichment Platform",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("🛡️ Automated Threat Intelligence & IOC Enrichment Platform")
    st.caption(
        "SOC workbench for automated IOC normalization, multi-source TI enrichment "
        "(AlienVault OTX, URLhaus), STIX 2.1 MITRE ATT&CK mapping, Heuristic Risk scoring, "
        "and SOC log correlation."
    )

    # Sidebar: Credentials, Safe Display Mode & Quick Demo Actions
    with st.sidebar:
        st.header("Platform Status")
        if cfg.has_otx_key:
            st.success("AlienVault OTX: API Key Configured")
        else:
            st.warning("AlienVault OTX: No API Key (add OTX_API_KEY in .env)")

        if cfg.has_urlhaus_key:
            st.success("URLhaus: Auth-Key Configured")
        else:
            st.warning("URLhaus: No Auth-Key (add URLHAUS_AUTH_KEY in .env)")

        with _get_pipeline(cfg) as probe_pipeline:
            st.info(
                f"MITRE ATT&CK STIX 2.1: {probe_pipeline.mitre_mapper.technique_count} "
                f"techniques ({probe_pipeline.mitre_mapper.bundle_path.name})"
            )

        st.divider()
        defang_mode = st.toggle(
            "Defang IOCs in UI & Exports (Safe Mode)",
            value=cfg.default_defang_exports,
            help="Renders URLs/domains/IPs as hxxps:// and [.] to prevent accidental clicks.",
        )
        st.caption(f"SQLite DB: `{cfg.database_path}`")
        st.caption(f"Cache TTL: `{cfg.cache_ttl_hours}h`")

        st.divider()
        st.subheader("Quick Demo Setup")
        if st.button("Load Sample IOCs (CSV)", use_container_width=True):
            if SAMPLE_IOCS_PATH.exists():
                with st.spinner("Ingesting and analyzing data/sample_iocs.csv..."):
                    with _get_pipeline(cfg) as pipeline:
                        res = pipeline.investigate_csv(SAMPLE_IOCS_PATH)
                st.success(
                    f"Loaded {len(res.reports)} unique IOCs "
                    f"({res.batch.duplicate_count} duplicates removed)."
                )
            else:
                st.error(f"Sample dataset not found at {SAMPLE_IOCS_PATH}")

    tab_lookup, tab_explorer, tab_analytics, tab_logs = st.tabs(
        [
            "🔍 IOC Investigation",
            "📊 Threat Explorer & Reports",
            "📈 Analytics & System Health",
            "🚨 SOC Log Matching",
        ]
    )

    # ------------------------------------------------------------------
    # TAB 1: IOC Investigation (Single & Batch)
    # ------------------------------------------------------------------
    with tab_lookup:
        mode = st.radio(
            "Investigation Mode",
            ["Single IOC Lookup", "Batch CSV / Bulk Paste"],
            horizontal=True,
        )

        if mode == "Single IOC Lookup":
            with st.form("single_ioc_form"):
                raw_ioc = st.text_input(
                    "Enter IOC (IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256 — defanged supported)",
                    placeholder="198.51.100.23 or hxxps://cdn[.]example[.]org/payload",
                )
                c_opt1, c_opt2 = st.columns([2, 1])
                with c_opt1:
                    source_hint = st.text_input("Source / Ticket Reference", value="SOC Dashboard")
                with c_opt2:
                    force_refresh = st.checkbox("Force Refresh (bypass cache)", value=False)
                submitted = st.form_submit_button(
                    "Investigate IOC", type="primary", use_container_width=True
                )

            if submitted:
                if not raw_ioc.strip():
                    st.error("Please enter an IOC before submitting.")
                else:
                    with st.spinner("Normalizing, querying TI sources, and scoring IOC..."):
                        try:
                            with _get_pipeline(cfg) as pipeline:
                                report = pipeline.investigate_single(
                                    raw_ioc,
                                    source_hint=source_hint or "SOC Dashboard",
                                    force_refresh=force_refresh,
                                )
                            st.session_state["last_single_report"] = report
                        except IOCValidationError as exc:
                            st.error(f"Invalid IOC format: {exc.reason}")
                        except Exception as exc:
                            st.error(f"Investigation failed unexpectedly: {exc}")

            last_report: ThreatReport | None = st.session_state.get("last_single_report")
            if last_report is not None:
                st.divider()
                _render_report_card(last_report, defang=defang_mode, key_prefix="single")
            else:
                st.info(
                    "Tip: Try investigating `198.51.100.23` (RFC 5737 TEST-NET demo IP) or "
                    "a defanged indicator like `198[.]51[.]100[.]23`."
                )

        else:
            uploaded_csv = st.file_uploader("Upload IOC CSV file", type=["csv"])
            bulk_text = st.text_area(
                "Or paste IOCs (one per line; lines starting with # are ignored)",
                height=140,
                placeholder="198.51.100.23\nmalicious-demo.example.com\n44d88612fea8a8f36de82e1278abb02f",
            )
            b_col1, b_col2 = st.columns([1, 2])
            with b_col1:
                batch_force = st.checkbox("Force Refresh Batch", value=False)
            with b_col2:
                run_batch = st.button("Run Batch Investigation", type="primary")

            if run_batch:
                with st.spinner("Processing, deduplicating, and enriching batch..."):
                    try:
                        with _get_pipeline(cfg) as pipeline:
                            if uploaded_csv is not None:
                                batch_res = pipeline.investigate_csv_bytes(
                                    uploaded_csv.getvalue(), force_refresh=batch_force
                                )
                            elif bulk_text.strip():
                                inputs = load_iocs_from_text(bulk_text, source_hint="Bulk Paste")
                                batch_res = pipeline.investigate_batch(
                                    inputs, force_refresh=batch_force
                                )
                            else:
                                st.error("Upload a CSV file or paste at least one IOC.")
                                batch_res = None
                        if batch_res is not None:
                            st.session_state["last_batch_result"] = batch_res
                    except CSVLoaderError as exc:
                        st.error(f"CSV Error: {exc}")
                    except Exception as exc:
                        st.error(f"Batch processing failed: {exc}")

            last_batch = st.session_state.get("last_batch_result")
            if last_batch is not None:
                b_stats = last_batch.batch
                m1, m2, m3, m4, m5 = st.columns(5)
                m1.metric("Received", b_stats.total_received)
                m2.metric("Unique Valid", len(b_stats.unique_iocs))
                m3.metric("Duplicates Removed", b_stats.duplicate_count)
                m4.metric("Invalid Rows", b_stats.invalid_count)
                m5.metric("Cache Hits", last_batch.total_cache_hits)

                if b_stats.invalid_records:
                    with st.expander(f"View {b_stats.invalid_count} invalid input(s)"):
                        st.dataframe(
                            pd.DataFrame([r.model_dump() for r in b_stats.invalid_records]),
                            use_container_width=True,
                            hide_index=True,
                        )

                if last_batch.reports:
                    summary_rows = [
                        {
                            "IOC": _display_ioc(
                                r.indicator.normalized_value, r.indicator.ioc_type, defang_mode
                            ),
                            "Type": r.indicator.ioc_type.value.upper(),
                            "Classification": r.classification.value,
                            "Risk Score": r.risk_score,
                            "Risk Level": r.risk_level.value,
                            "Confidence": r.confidence_score,
                            "Confirming Sources": r.sources_with_evidence,
                            "MITRE Techniques": len(r.attack_techniques),
                        }
                        for r in last_batch.reports
                    ]
                    st.dataframe(
                        pd.DataFrame(summary_rows), use_container_width=True, hide_index=True
                    )
                    _render_download_buttons(
                        last_batch.reports, defang=defang_mode, key_prefix="batch"
                    )

    # ------------------------------------------------------------------
    # TAB 2: Threat Explorer & Reports
    # ------------------------------------------------------------------
    with tab_explorer:
        f1, f2, f3 = st.columns([2, 1, 1])
        with f1:
            search_query = st.text_input("Search IOC or Summary", placeholder="e.g. 198.51.100")
        with f2:
            risk_choice = st.selectbox(
                "Risk Level",
                ["All", *[lvl.value for lvl in RiskLevel]],
            )
        with f3:
            type_choice = st.selectbox(
                "IOC Type",
                ["All", *[t.value for t in IOCType]],
            )

        with _get_pipeline(cfg) as pipeline:
            filtered_reports = pipeline.repo.list_latest_reports(
                risk_level=None if risk_choice == "All" else RiskLevel(risk_choice),
                ioc_type=None if type_choice == "All" else IOCType(type_choice),
                search=search_query or None,
                limit=200,
            )

        if not filtered_reports:
            st.info(
                "No stored threat reports match the current filters. Investigate an IOC in Tab 1 "
                "or click 'Load Sample IOCs (CSV)' in the sidebar."
            )
        else:
            explorer_rows = [
                {
                    "ID": r.indicator.id,
                    "IOC": _display_ioc(
                        r.indicator.normalized_value, r.indicator.ioc_type, defang_mode
                    ),
                    "Type": r.indicator.ioc_type.value.upper(),
                    "Classification": r.classification.value,
                    "Risk Score": r.risk_score,
                    "Risk Level": r.risk_level.value,
                    "Confidence": r.confidence_score,
                    "Sources Confirmed": f"{r.sources_with_evidence}/{r.sources_checked}",
                    "MITRE Count": len(r.attack_techniques),
                    "Source Last Seen": (
                        r.indicator.last_seen.strftime("%Y-%m-%d")
                        if r.indicator.last_seen
                        else "N/A"
                    ),
                    "Last Checked (UTC)": r.generated_at.strftime("%Y-%m-%d %H:%M"),
                }
                for r in filtered_reports
            ]
            st.dataframe(pd.DataFrame(explorer_rows), use_container_width=True, hide_index=True)

            st.markdown("#### Export Filtered Reports")
            _render_download_buttons(
                filtered_reports, defang=defang_mode, key_prefix="explorer_filtered"
            )

            st.divider()
            labels = {
                f"#{r.indicator.id} — "
                f"{_display_ioc(r.indicator.normalized_value, r.indicator.ioc_type, defang_mode)} "
                f"[{r.risk_level.value} {r.risk_score}/100]": r
                for r in filtered_reports
            }
            selected_label = st.selectbox("Inspect Full Analyst Report", list(labels.keys()))
            if selected_label:
                _render_report_card(
                    labels[selected_label],
                    defang=defang_mode,
                    key_prefix=f"explorer_{labels[selected_label].indicator.id}",
                )

    # ------------------------------------------------------------------
    # TAB 3: Analytics & System Health
    # ------------------------------------------------------------------
    with tab_analytics:
        with _get_pipeline(cfg) as pipeline:
            metrics = pipeline.repo.get_system_metrics()
            all_reports = pipeline.repo.list_latest_reports(limit=500)

        a1, a2, a3, a4, a5 = st.columns(5)
        a1.metric("Unique Indicators", metrics.total_indicators)
        a2.metric("Threat Reports", metrics.total_reports)
        a3.metric("Enrichment Success Rate", f"{metrics.enrichment_success_rate:.1f}%")
        a4.metric("API Failure Rate", f"{metrics.api_failure_rate:.1f}%")
        a5.metric("Avg API Latency", f"{metrics.avg_latency_ms:.0f} ms")

        if metrics.total_indicators == 0:
            st.info("No operational telemetry recorded yet. Run an IOC lookup or load sample data.")
        else:
            col_left, col_right = st.columns(2)
            with col_left:
                st.plotly_chart(
                    build_risk_distribution_figure(metrics.risk_distribution),
                    use_container_width=True,
                )
            with col_right:
                st.plotly_chart(
                    build_type_distribution_figure(metrics.type_distribution),
                    use_container_width=True,
                )

            if metrics.by_source:
                st.plotly_chart(build_source_health_figure(metrics), use_container_width=True)
                st.markdown("#### Measured Per-Source Telemetry")
                src_df = pd.DataFrame([s.model_dump() for s in metrics.by_source])
                st.dataframe(src_df, use_container_width=True, hide_index=True)

            mitre_df = collect_top_mitre_techniques(all_reports)
            st.markdown("#### Top Mapped MITRE ATT&CK Techniques")
            if not mitre_df.empty:
                fig_mitre = px.bar(
                    mitre_df,
                    x="Indicators",
                    y="Technique",
                    color="Tactic",
                    orientation="h",
                    title="Most Observed MITRE ATT&CK Techniques",
                )
                fig_mitre.update_layout(height=320, yaxis={"autorange": "reversed"})
                st.plotly_chart(fig_mitre, use_container_width=True)
            else:
                st.caption(
                    "No MITRE ATT&CK techniques mapped yet (techniques appear once TI sources "
                    "confirm malicious evidence)."
                )

    # ------------------------------------------------------------------
    # TAB 4: SOC Log Matching
    # ------------------------------------------------------------------
    with tab_logs:
        st.markdown(
            "Correlate Firewall, DNS, Proxy, or EDR logs (`.csv`, `.jsonl`, `.log`, `.txt`) "
            "against collected Threat Intelligence IOCs in SQLite."
        )
        l_col1, l_col2 = st.columns([2, 1])
        with l_col1:
            uploaded_log = st.file_uploader(
                "Upload SOC Log File", type=["csv", "jsonl", "log", "txt"]
            )
        with l_col2:
            min_risk_choice = st.selectbox(
                "Minimum IOC Risk Level",
                ["All Stored IOCs", *[lvl.value for lvl in RiskLevel]],
            )

        min_risk_val = (
            None if min_risk_choice == "All Stored IOCs" else RiskLevel(min_risk_choice)
        )

        btn_col1, btn_col2 = st.columns(2)
        run_uploaded = btn_col1.button(
            "Scan Uploaded Log", type="primary", use_container_width=True
        )
        run_sample = btn_col2.button(
            "Run Sample SOC Logs (data/sample_logs.csv)", use_container_width=True
        )

        match_summary = None
        if run_uploaded:
            if uploaded_log is None:
                st.error("Please upload a log file first.")
            else:
                content = uploaded_log.getvalue().decode("utf-8-sig", errors="replace")
                with st.spinner("Correlating logs against stored IOCs..."):
                    with _get_pipeline(cfg) as pipeline:
                        matcher = SOCLogMatcher(pipeline.repo)
                        if uploaded_log.name.lower().endswith(".csv"):
                            match_summary = matcher.match_csv_text(
                                content,
                                default_log_source=uploaded_log.name,
                                min_risk_level=min_risk_val,
                                persist=True,
                            )
                        else:
                            match_summary = matcher.match_lines(
                                content,
                                log_source=uploaded_log.name,
                                min_risk_level=min_risk_val,
                                persist=True,
                            )

        if run_sample:
            if not SAMPLE_LOGS_PATH.exists():
                st.error(f"Sample log file not found: {SAMPLE_LOGS_PATH}")
            else:
                with st.spinner("Scanning sample Firewall/DNS/Proxy/EDR logs..."):
                    with _get_pipeline(cfg) as pipeline:
                        matcher = SOCLogMatcher(pipeline.repo)
                        match_summary = matcher.match_file(
                            SAMPLE_LOGS_PATH,
                            min_risk_level=min_risk_val,
                            persist=True,
                        )

        if match_summary is not None:
            st.session_state["last_log_match_summary"] = match_summary

        active_summary = st.session_state.get("last_log_match_summary")
        if active_summary is not None:
            s1, s2, s3 = st.columns(3)
            s1.metric("Log Records Scanned", active_summary.total_records_scanned)
            s2.metric("Total IOC Matches", active_summary.total_matches)
            s3.metric("Unique IOCs Matched", active_summary.unique_iocs_matched)

            if active_summary.matches:
                match_rows = [
                    {
                        "Risk Level": m.risk_level.value if m.risk_level else "Unscored",
                        "Matched IOC": _display_ioc(
                            m.indicator_value, m.indicator_type, defang_mode
                        ),
                        "Type": m.indicator_type.value.upper(),
                        "Log Source": m.log_source,
                        "Matched Field": m.matched_field,
                        "Log Timestamp": m.log_timestamp or "N/A",
                        "Raw Log Line": m.raw_log_line,
                    }
                    for m in active_summary.matches
                ]
                match_df = pd.DataFrame(match_rows)
                st.dataframe(match_df, use_container_width=True, hide_index=True)
                st.download_button(
                    "Export SOC Match Alerts (CSV)",
                    data=match_df.to_csv(index=False).encode("utf-8-sig"),
                    file_name="soc_log_matches.csv",
                    mime="text/csv",
                )
            else:
                st.info(
                    "No IOC matches found in the scanned log. Make sure indicators have been "
                    "loaded (e.g., via 'Load Sample IOCs' in the sidebar) or relax the risk filter."
                )

        with st.expander("Historical Persisted Log Matches"):
            with _get_pipeline(cfg) as pipeline:
                history = pipeline.repo.list_log_matches(limit=100)
            if history:
                hist_rows = [
                    {
                        "Matched At (UTC)": m.matched_at.strftime("%Y-%m-%d %H:%M"),
                        "Risk Level": m.risk_level.value if m.risk_level else "Unscored",
                        "IOC": _display_ioc(m.indicator_value, m.indicator_type, defang_mode),
                        "Log Source": m.log_source,
                        "Field": m.matched_field,
                        "Log Timestamp": m.log_timestamp or "N/A",
                    }
                    for m in history
                ]
                st.dataframe(pd.DataFrame(hist_rows), use_container_width=True, hide_index=True)
            else:
                st.caption("No persisted log matches recorded yet.")


if __name__ == "__main__":
    render_dashboard()
