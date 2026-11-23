"""Giao diện Streamlit + Plotly cho Nền tảng Tự động Tình báo Mối đe dọa & Làm giàu IOC."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

# Đảm bảo thư mục gốc dự án có trong sys.path khi chạy `streamlit run app/dashboard/dashboard.py`
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

RISK_LABELS_VI: dict[str, str] = {
    RiskLevel.CRITICAL.value: "Nghiêm trọng (Critical)",
    RiskLevel.HIGH.value: "Cao (High)",
    RiskLevel.MEDIUM.value: "Trung bình (Medium)",
    RiskLevel.LOW.value: "Thấp (Low)",
}

CLASSIFICATION_LABELS_VI: dict[str, str] = {
    "Benign/Unknown": "Sạch / Chưa rõ",
    "Suspicious": "Đáng ngờ",
    "Malicious": "Độc hại",
}

STATUS_LABELS_VI: dict[str, str] = {
    "ok": "Có dữ liệu",
    "not_found": "Không tìm thấy",
    "error": "Lỗi API",
    "timeout": "Quá thời gian",
    "skipped_no_key": "Bỏ qua (thiếu key)",
    "unsupported_type": "Không hỗ trợ",
}

CONFIDENCE_LABELS_VI: dict[str, str] = {
    "high": "Cao",
    "medium": "Trung bình",
    "low": "Thấp",
}

SAMPLE_IOCS_PATH = _PROJECT_ROOT / "data" / "sample_iocs.csv"
SAMPLE_LOGS_PATH = _PROJECT_ROOT / "data" / "sample_logs.csv"


def _display_ioc(value: str, ioc_type: IOCType, defang: bool) -> str:
    return defang_ioc(value, ioc_type) if defang else value


def _risk_vi(level: str | RiskLevel | None) -> str:
    if level is None:
        return "Chưa chấm điểm"
    key = level.value if isinstance(level, RiskLevel) else str(level)
    return RISK_LABELS_VI.get(key, key)


def _class_vi(classification: str) -> str:
    return CLASSIFICATION_LABELS_VI.get(classification, classification)


def _status_vi(status: str) -> str:
    return STATUS_LABELS_VI.get(status, status)


def build_risk_gauge_figure(risk_score: int, risk_level: str) -> go.Figure:
    """Tạo biểu đồ đồng hồ Plotly cho Heuristic Risk Score (0-100)."""
    color = RISK_COLORS.get(risk_level, "#2563eb")
    label = _risk_vi(risk_level)
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=risk_score,
            number={"suffix": " / 100"},
            title={"text": f"Điểm rủi ro Heuristic ({label})", "font": {"size": 14}},
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
    """Tạo biểu đồ cột ngang hiển thị 4 thành phần của Heuristic Risk Score."""
    b = report.score_breakdown
    df = pd.DataFrame(
        [
            {
                "Tiêu chí": "Độ tin cậy nguồn (tối đa 40)",
                "Điểm": b.source_reliability,
                "Tối đa": 40,
            },
            {
                "Tiêu chí": "Số nguồn độc lập (tối đa 25)",
                "Điểm": b.independent_sources,
                "Tối đa": 25,
            },
            {"Tiêu chí": "Mức độ gần đây (tối đa 20)", "Điểm": b.recency, "Tối đa": 20},
            {
                "Tiêu chí": "Trạng thái hoạt động (tối đa 15)",
                "Điểm": b.activity_status,
                "Tối đa": 15,
            },
        ]
    )
    fig = px.bar(
        df,
        x="Điểm",
        y="Tiêu chí",
        orientation="h",
        text="Điểm",
        range_x=[0, 42],
        title="Chi tiết thành phần Điểm rủi ro Heuristic",
    )
    fig.update_traces(marker_color="#2563eb", textposition="outside")
    fig.update_layout(
        height=230,
        margin={"t": 40, "b": 10, "l": 10, "r": 20},
        yaxis={"autorange": "reversed"},
    )
    return fig


def build_risk_distribution_figure(risk_distribution: dict[str, int]) -> go.Figure:
    """Tạo biểu đồ cột phân bố số lượng IOC theo Mức độ rủi ro."""
    ordered_levels = [
        RiskLevel.CRITICAL.value,
        RiskLevel.HIGH.value,
        RiskLevel.MEDIUM.value,
        RiskLevel.LOW.value,
    ]
    color_map_vi = {_risk_vi(k): v for k, v in RISK_COLORS.items()}
    rows = [
        {"Mức độ rủi ro": _risk_vi(lvl), "Số lượng IOC": risk_distribution.get(lvl, 0)}
        for lvl in ordered_levels
    ]
    df = pd.DataFrame(rows)
    fig = px.bar(
        df,
        x="Mức độ rủi ro",
        y="Số lượng IOC",
        color="Mức độ rủi ro",
        color_discrete_map=color_map_vi,
        text="Số lượng IOC",
        title="Phân bố IOC theo Mức độ rủi ro",
    )
    fig.update_layout(height=300, showlegend=False, margin={"t": 45, "b": 20})
    return fig


def build_type_distribution_figure(type_distribution: dict[str, int]) -> go.Figure:
    """Tạo biểu đồ tròn donut phân bố IOC theo loại."""
    if not type_distribution:
        return go.Figure()
    df = pd.DataFrame(
        [{"Loại IOC": k.upper(), "Số lượng": v} for k, v in sorted(type_distribution.items())]
    )
    fig = px.pie(
        df,
        names="Loại IOC",
        values="Số lượng",
        hole=0.45,
        title="Phân bố IOC theo Loại chỉ báo",
    )
    fig.update_layout(height=300, margin={"t": 45, "b": 20})
    return fig


def build_source_health_figure(metrics: SystemMetrics) -> go.Figure:
    """Tạo biểu đồ cột chồng thể hiện trạng thái truy vấn theo từng nguồn TI."""
    if not metrics.by_source:
        return go.Figure()
    rows: list[dict[str, object]] = []
    for src in metrics.by_source:
        for label, val in (
            ("Có dữ liệu (OK)", src.ok_count),
            ("Không tìm thấy", src.not_found_count),
            ("Quá thời gian (Timeout)", src.timeout_count),
            ("Lỗi API", src.error_count),
            ("Bỏ qua (thiếu key)", src.skipped_count),
            ("Loại không hỗ trợ", src.unsupported_count),
        ):
            if val > 0:
                rows.append(
                    {"Nguồn TI": src.source_name, "Trạng thái": label, "Lượt truy vấn": val}
                )
    if not rows:
        return go.Figure()
    df = pd.DataFrame(rows)
    fig = px.bar(
        df,
        x="Nguồn TI",
        y="Lượt truy vấn",
        color="Trạng thái",
        barmode="stack",
        title="Kết quả truy vấn API theo từng nguồn Threat Intelligence",
    )
    fig.update_layout(height=320, margin={"t": 45, "b": 20})
    return fig


def collect_top_mitre_techniques(reports: list[ThreatReport]) -> pd.DataFrame:
    """Tổng hợp các kỹ thuật MITRE ATT&CK xuất hiện nhiều nhất trên các báo cáo mới nhất."""
    counter: Counter[tuple[str, str, str]] = Counter()
    for report in reports:
        for mapping in report.attack_techniques:
            t = mapping.technique
            counter[(t.technique_id, t.name, t.tactic)] += 1
    if not counter:
        return pd.DataFrame(columns=["Kỹ thuật", "Chiến thuật", "Số IOC"])
    rows = [
        {"Kỹ thuật": f"{tid} - {name}", "Chiến thuật": tactic, "Số IOC": count}
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
            label="Xuất JSON",
            data=render_json_string(reports, defang=defang),
            file_name=f"{key_prefix}_report.json",
            mime="application/json",
            key=f"dl_json_{key_prefix}",
            use_container_width=True,
        )
    with c2:
        st.download_button(
            label="Xuất CSV",
            data=render_csv_string(reports, defang=defang).encode("utf-8-sig"),
            file_name=f"{key_prefix}_report.csv",
            mime="text/csv",
            key=f"dl_csv_{key_prefix}",
            use_container_width=True,
        )
    with c3:
        st.download_button(
            label="Xuất báo cáo HTML",
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
        st.warning(f"Cảnh báo dải IP đặc biệt: {ind.ip_scope_note}")

    k1, k2, k3, k4 = st.columns(4)
    k1.metric(
        "Điểm rủi ro (Heuristic)",
        f"{report.risk_score} / 100",
        _risk_vi(report.risk_level),
    )
    k2.metric("Độ tin cậy (Confidence)", f"{report.confidence_score} / 100")
    k3.metric("Phân loại", _class_vi(report.classification.value))
    k4.metric(
        "Nguồn xác nhận",
        f"{report.sources_with_evidence} / {report.sources_checked} nguồn đã hỏi",
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

    # Hiển thị tách biệt rõ thời điểm nguồn ghi nhận với thời điểm hệ thống truy vấn
    t1, t2, t3 = st.columns(3)
    t1.caption(
        "Nguồn thấy lần đầu: "
        + (ind.first_seen.strftime("%Y-%m-%d %H:%M UTC") if ind.first_seen else "Chưa có")
    )
    t2.caption(
        "Nguồn thấy gần nhất: "
        + (ind.last_seen.strftime("%Y-%m-%d %H:%M UTC") if ind.last_seen else "Chưa có")
    )
    t3.caption("Hệ thống kiểm tra lúc: " + report.generated_at.strftime("%Y-%m-%d %H:%M UTC"))

    st.markdown("#### Bằng chứng từ các nguồn Threat Intelligence")
    if report.evidence:
        ev_rows = []
        for ev in report.evidence:
            details = ev.error_message or (
                ", ".join(
                    filter(
                        None,
                        [
                            f"Pulses/URLs: {ev.pulse_count}" if ev.pulse_count else "",
                            (
                                f"Mã độc: {', '.join(ev.malware_families)}"
                                if ev.malware_families
                                else ""
                            ),
                            (
                                f"Mối đe dọa: {', '.join(ev.threat_types)}"
                                if ev.threat_types
                                else ""
                            ),
                            f"Nhãn: {', '.join(ev.tags[:6])}" if ev.tags else "",
                        ],
                    )
                )
                or "Không có bản ghi độc hại"
            )
            ev_rows.append(
                {
                    "Nguồn TI": ev.source_name,
                    "Trạng thái": _status_vi(ev.status.value)
                    + (" (từ cache)" if ev.from_cache else ""),
                    "Tín hiệu độc hại": "Có" if ev.is_malicious_signal else "Không",
                    "Hoạt động": (
                        "Đang hoạt động"
                        if ev.is_active is True
                        else ("Đã ngừng" if ev.is_active is False else "Không rõ")
                    ),
                    "Nguồn thấy gần nhất": (
                        ev.source_last_seen.strftime("%Y-%m-%d %H:%M UTC")
                        if ev.source_last_seen
                        else "Chưa có"
                    ),
                    "Truy vấn lúc (UTC)": ev.retrieved_at.strftime("%Y-%m-%d %H:%M UTC"),
                    "Độ trễ (ms)": ev.latency_ms,
                    "Bằng chứng / Ghi chú": details,
                }
            )
        st.dataframe(pd.DataFrame(ev_rows), use_container_width=True, hide_index=True)
    else:
        st.caption("Chưa có dữ liệu làm giàu nào được lưu.")

    st.markdown("#### Ánh xạ MITRE ATT&CK (STIX 2.1)")
    if report.attack_techniques:
        tech_rows = [
            {
                "Mã kỹ thuật": m.technique.technique_id,
                "Tên kỹ thuật": m.technique.name,
                "Chiến thuật (Tactic)": m.technique.tactic,
                "Mức tin cậy": CONFIDENCE_LABELS_VI.get(m.confidence, m.confidence),
                "Nguồn": m.source_name,
                "Bằng chứng": m.evidence,
                "Tham chiếu": m.technique.url,
            }
            for m in report.attack_techniques
        ]
        st.dataframe(pd.DataFrame(tech_rows), use_container_width=True, hide_index=True)
    else:
        st.caption("Chưa có kỹ thuật MITRE ATT&CK nào được ánh xạ có bằng chứng cho IOC này.")

    if report.recommended_actions:
        st.markdown("#### Khuyến nghị hành động điều tra cho SOC")
        for action in report.recommended_actions:
            st.markdown(f"- {action}")

    st.markdown("#### Xuất báo cáo")
    _render_download_buttons([report], defang=defang, key_prefix=key_prefix)


def _get_pipeline(settings: Settings) -> ThreatIntelPipeline:
    return ThreatIntelPipeline(settings=settings)


def render_dashboard(settings: Settings | None = None) -> None:
    """Điểm khởi chạy chính của ứng dụng web Streamlit."""
    cfg = settings or get_settings()
    st.set_page_config(
        page_title="Nền tảng Tự động Tình báo Mối đe dọa & Làm giàu IOC",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("🛡️ Nền tảng Tự động Tình báo Mối đe dọa & Làm giàu IOC")
    st.caption(
        "Công cụ hỗ trợ SOC Analyst chuẩn hóa IOC, làm giàu đa nguồn "
        "(AlienVault OTX, URLhaus), ánh xạ MITRE ATT&CK (STIX 2.1), chấm điểm rủi ro "
        "Heuristic và đối chiếu log bảo mật."
    )

    # Thanh bên: Trạng thái API Key, chế độ an toàn & nạp dữ liệu mẫu
    with st.sidebar:
        st.header("Trạng thái hệ thống")
        if cfg.has_otx_key:
            st.success("AlienVault OTX: Đã cấu hình API Key")
        else:
            st.warning("AlienVault OTX: Chưa có API Key (thêm OTX_API_KEY vào .env)")

        if cfg.has_urlhaus_key:
            st.success("URLhaus: Đã cấu hình Auth-Key")
        else:
            st.warning("URLhaus: Chưa có Auth-Key (thêm URLHAUS_AUTH_KEY vào .env)")

        with _get_pipeline(cfg) as probe_pipeline:
            st.info(
                f"MITRE ATT&CK STIX 2.1: {probe_pipeline.mitre_mapper.technique_count} "
                f"kỹ thuật ({probe_pipeline.mitre_mapper.bundle_path.name})"
            )

        st.divider()
        defang_mode = st.toggle(
            "Làm mờ (Defang) IOC khi hiển thị & xuất",
            value=cfg.default_defang_exports,
            help="Hiển thị URL/domain/IP dưới dạng hxxps:// và [.] để tránh bấm nhầm link độc hại.",
        )
        st.caption(f"Cơ sở dữ liệu SQLite: `{cfg.database_path}`")
        st.caption(f"Thời hạn Cache (TTL): `{cfg.cache_ttl_hours} giờ`")

        st.divider()
        st.subheader("Dữ liệu Demo nhanh")
        if st.button("Nạp bộ IOC mẫu (CSV)", use_container_width=True):
            if SAMPLE_IOCS_PATH.exists():
                with st.spinner("Đang nạp và phân tích data/sample_iocs.csv..."):
                    with _get_pipeline(cfg) as pipeline:
                        res = pipeline.investigate_csv(SAMPLE_IOCS_PATH)
                st.success(
                    f"Đã nạp thành công {len(res.reports)} IOC duy nhất "
                    f"(loại bỏ {res.batch.duplicate_count} bản trùng lặp)."
                )
            else:
                st.error(f"Không tìm thấy file dữ liệu mẫu tại {SAMPLE_IOCS_PATH}")

    tab_lookup, tab_explorer, tab_analytics, tab_logs = st.tabs(
        [
            "🔍 Điều tra IOC",
            "📊 Kho phân tích & Báo cáo",
            "📈 Thống kê & Sức khỏe hệ thống",
            "🚨 Đối chiếu Log SOC",
        ]
    )

    # ------------------------------------------------------------------
    # TAB 1: Điều tra IOC (Đơn lẻ & Hàng loạt)
    # ------------------------------------------------------------------
    with tab_lookup:
        mode = st.radio(
            "Chế độ điều tra",
            ["Tra cứu 1 IOC", "Tra cứu hàng loạt (CSV / Dán văn bản)"],
            horizontal=True,
        )

        if mode == "Tra cứu 1 IOC":
            with st.form("single_ioc_form"):
                raw_ioc = st.text_input(
                    "Nhập IOC (IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256 — hỗ trợ dạng defang)",
                    placeholder="198.51.100.23 hoặc hxxps://cdn[.]example[.]org/payload",
                )
                c_opt1, c_opt2 = st.columns([2, 1])
                with c_opt1:
                    source_hint = st.text_input("Nguồn cảnh báo / Mã ticket", value="SOC Dashboard")
                with c_opt2:
                    force_refresh = st.checkbox("Làm mới trực tiếp (bỏ qua cache)", value=False)
                submitted = st.form_submit_button(
                    "Phân tích IOC", type="primary", use_container_width=True
                )

            if submitted:
                if not raw_ioc.strip():
                    st.error("Vui lòng nhập một IOC trước khi phân tích.")
                else:
                    with st.spinner("Đang chuẩn hóa, truy vấn nguồn TI và chấm điểm IOC..."):
                        try:
                            with _get_pipeline(cfg) as pipeline:
                                report = pipeline.investigate_single(
                                    raw_ioc,
                                    source_hint=source_hint or "SOC Dashboard",
                                    force_refresh=force_refresh,
                                )
                            st.session_state["last_single_report"] = report
                        except IOCValidationError as exc:
                            st.error(f"Định dạng IOC không hợp lệ: {exc.reason}")
                        except Exception as exc:
                            st.error(f"Quá trình điều tra gặp lỗi ngoài dự kiến: {exc}")

            last_report: ThreatReport | None = st.session_state.get("last_single_report")
            if last_report is not None:
                st.divider()
                _render_report_card(last_report, defang=defang_mode, key_prefix="single")
            else:
                st.info(
                    "Gợi ý: Hãy thử tra cứu `198.51.100.23` (IP mẫu TEST-NET), mã hash EICAR "
                    "`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` "
                    "hoặc IOC đã làm mờ như `198[.]51[.]100[.]23`."
                )

        else:
            uploaded_csv = st.file_uploader("Tải lên tệp CSV chứa danh sách IOC", type=["csv"])
            bulk_text = st.text_area(
                "Hoặc dán nhiều IOC (mỗi dòng một IOC; dòng bắt đầu bằng # sẽ được bỏ qua)",
                height=140,
                placeholder=(
                    "198.51.100.23\n"
                    "malicious-demo.example.com\n"
                    "44d88612fea8a8f36de82e1278abb02f"
                ),
            )
            b_col1, b_col2 = st.columns([1, 2])
            with b_col1:
                batch_force = st.checkbox("Làm mới trực tiếp cả lô", value=False)
            with b_col2:
                run_batch = st.button("Chạy phân tích hàng loạt", type="primary")

            if run_batch:
                with st.spinner("Đang chuẩn hóa, khử trùng lặp và làm giàu lô IOC..."):
                    try:
                        with _get_pipeline(cfg) as pipeline:
                            if uploaded_csv is not None:
                                batch_res = pipeline.investigate_csv_bytes(
                                    uploaded_csv.getvalue(), force_refresh=batch_force
                                )
                            elif bulk_text.strip():
                                inputs = load_iocs_from_text(bulk_text, source_hint="Dán hàng loạt")
                                batch_res = pipeline.investigate_batch(
                                    inputs, force_refresh=batch_force
                                )
                            else:
                                st.error("Vui lòng tải lên tệp CSV hoặc dán ít nhất một IOC.")
                                batch_res = None
                        if batch_res is not None:
                            st.session_state["last_batch_result"] = batch_res
                    except CSVLoaderError as exc:
                        st.error(f"Lỗi đọc tệp CSV: {exc}")
                    except Exception as exc:
                        st.error(f"Xử lý hàng loạt thất bại: {exc}")

            last_batch = st.session_state.get("last_batch_result")
            if last_batch is not None:
                b_stats = last_batch.batch
                m1, m2, m3, m4, m5 = st.columns(5)
                m1.metric("Tổng đầu vào", b_stats.total_received)
                m2.metric("IOC hợp lệ duy nhất", len(b_stats.unique_iocs))
                m3.metric("Đã loại trùng lặp", b_stats.duplicate_count)
                m4.metric("Dòng sai định dạng", b_stats.invalid_count)
                m5.metric("Lượt dùng Cache", last_batch.total_cache_hits)

                if b_stats.invalid_records:
                    with st.expander(f"Xem {b_stats.invalid_count} dòng không hợp lệ"):
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
                            "Loại": r.indicator.ioc_type.value.upper(),
                            "Phân loại": _class_vi(r.classification.value),
                            "Điểm rủi ro": r.risk_score,
                            "Mức rủi ro": _risk_vi(r.risk_level),
                            "Độ tin cậy": r.confidence_score,
                            "Nguồn xác nhận": r.sources_with_evidence,
                            "Số kỹ thuật MITRE": len(r.attack_techniques),
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
    # TAB 2: Kho phân tích & Báo cáo
    # ------------------------------------------------------------------
    with tab_explorer:
        risk_options = {"Tất cả": None, **{_risk_vi(lvl): lvl for lvl in RiskLevel}}
        f1, f2, f3 = st.columns([2, 1, 1])
        with f1:
            search_query = st.text_input(
                "Tìm kiếm IOC hoặc nội dung tóm tắt", placeholder="VD: 198.51.100"
            )
        with f2:
            risk_choice_label = st.selectbox("Mức độ rủi ro", list(risk_options.keys()))
        with f3:
            type_choice = st.selectbox(
                "Loại IOC",
                ["Tất cả", *[t.value for t in IOCType]],
            )

        with _get_pipeline(cfg) as pipeline:
            filtered_reports = pipeline.repo.list_latest_reports(
                risk_level=risk_options[risk_choice_label],
                ioc_type=None if type_choice == "Tất cả" else IOCType(type_choice),
                search=search_query or None,
                limit=200,
            )

        if not filtered_reports:
            st.info(
                "Chưa có báo cáo nào khớp với bộ lọc hiện tại. Hãy điều tra IOC ở tab "
                "'Điều tra IOC' hoặc bấm 'Nạp bộ IOC mẫu (CSV)' ở thanh bên."
            )
        else:
            explorer_rows = [
                {
                    "ID": r.indicator.id,
                    "IOC": _display_ioc(
                        r.indicator.normalized_value, r.indicator.ioc_type, defang_mode
                    ),
                    "Loại": r.indicator.ioc_type.value.upper(),
                    "Phân loại": _class_vi(r.classification.value),
                    "Điểm rủi ro": r.risk_score,
                    "Mức rủi ro": _risk_vi(r.risk_level),
                    "Độ tin cậy": r.confidence_score,
                    "Nguồn xác nhận": f"{r.sources_with_evidence}/{r.sources_checked}",
                    "MITRE": len(r.attack_techniques),
                    "Nguồn thấy gần nhất": (
                        r.indicator.last_seen.strftime("%Y-%m-%d")
                        if r.indicator.last_seen
                        else "Chưa có"
                    ),
                    "Kiểm tra lúc (UTC)": r.generated_at.strftime("%Y-%m-%d %H:%M"),
                }
                for r in filtered_reports
            ]
            st.dataframe(pd.DataFrame(explorer_rows), use_container_width=True, hide_index=True)

            st.markdown("#### Xuất danh sách báo cáo đang lọc")
            _render_download_buttons(
                filtered_reports, defang=defang_mode, key_prefix="explorer_filtered"
            )

            st.divider()
            labels = {
                f"#{r.indicator.id} — "
                f"{_display_ioc(r.indicator.normalized_value, r.indicator.ioc_type, defang_mode)} "
                f"[{_risk_vi(r.risk_level)} · {r.risk_score}/100]": r
                for r in filtered_reports
            }
            selected_label = st.selectbox("Xem chi tiết báo cáo điều tra", list(labels.keys()))
            if selected_label:
                _render_report_card(
                    labels[selected_label],
                    defang=defang_mode,
                    key_prefix=f"explorer_{labels[selected_label].indicator.id}",
                )

    # ------------------------------------------------------------------
    # TAB 3: Thống kê & Sức khỏe hệ thống
    # ------------------------------------------------------------------
    with tab_analytics:
        with _get_pipeline(cfg) as pipeline:
            metrics = pipeline.repo.get_system_metrics()
            all_reports = pipeline.repo.list_latest_reports(limit=500)

        a1, a2, a3, a4, a5 = st.columns(5)
        a1.metric("Tổng IOC duy nhất", metrics.total_indicators)
        a2.metric("Tổng báo cáo", metrics.total_reports)
        a3.metric("Tỷ lệ làm giàu thành công", f"{metrics.enrichment_success_rate:.1f}%")
        a4.metric("Tỷ lệ lỗi API", f"{metrics.api_failure_rate:.1f}%")
        a5.metric("Độ trễ API trung bình", f"{metrics.avg_latency_ms:.0f} ms")

        if metrics.total_indicators == 0:
            st.info(
                "Chưa có dữ liệu vận hành. Hãy tra cứu một IOC hoặc nạp bộ dữ liệu mẫu ở thanh bên."
            )
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
                st.markdown("#### Chỉ số đo lường thực tế theo từng nguồn TI")
                src_rows = [
                    {
                        "Nguồn TI": s.source_name,
                        "Tổng truy vấn": s.total_queries,
                        "Có dữ liệu": s.ok_count,
                        "Không thấy": s.not_found_count,
                        "Lỗi API": s.error_count,
                        "Quá hạn (Timeout)": s.timeout_count,
                        "Bỏ qua (thiếu key)": s.skipped_count,
                        "Không hỗ trợ": s.unsupported_count,
                        "Độ trễ TB (ms)": s.avg_latency_ms,
                        "Tỷ lệ lỗi (%)": s.api_failure_rate,
                    }
                    for s in metrics.by_source
                ]
                st.dataframe(pd.DataFrame(src_rows), use_container_width=True, hide_index=True)

            mitre_df = collect_top_mitre_techniques(all_reports)
            st.markdown("#### Các kỹ thuật MITRE ATT&CK ghi nhận nhiều nhất")
            if not mitre_df.empty:
                fig_mitre = px.bar(
                    mitre_df,
                    x="Số IOC",
                    y="Kỹ thuật",
                    color="Chiến thuật",
                    orientation="h",
                    title="Top kỹ thuật MITRE ATT&CK được ánh xạ",
                )
                fig_mitre.update_layout(height=320, yaxis={"autorange": "reversed"})
                st.plotly_chart(fig_mitre, use_container_width=True)
            else:
                st.caption(
                    "Chưa có kỹ thuật MITRE ATT&CK nào được ánh xạ (sẽ tự động xuất hiện khi "
                    "nguồn TI xác nhận bằng chứng độc hại)."
                )

    # ------------------------------------------------------------------
    # TAB 4: Đối chiếu Log SOC
    # ------------------------------------------------------------------
    with tab_logs:
        st.markdown(
            "Đối chiếu log **Firewall, DNS, Proxy hoặc EDR** (`.csv`, `.jsonl`, `.log`, `.txt`) "
            "với toàn bộ kho IOC trong SQLite để phát hiện hệ thống nội bộ có giao tiếp với "
            "IOC độc hại hay không."
        )
        min_risk_options = {
            "Tất cả IOC đã lưu": None,
            **{_risk_vi(lvl): lvl for lvl in RiskLevel},
        }
        l_col1, l_col2 = st.columns([2, 1])
        with l_col1:
            uploaded_log = st.file_uploader(
                "Tải lên tệp Log SOC", type=["csv", "jsonl", "log", "txt"]
            )
        with l_col2:
            min_risk_label = st.selectbox(
                "Ngưỡng rủi ro IOC tối thiểu", list(min_risk_options.keys())
            )

        min_risk_val = min_risk_options[min_risk_label]

        btn_col1, btn_col2 = st.columns(2)
        run_uploaded = btn_col1.button(
            "Quét tệp Log đã tải lên", type="primary", use_container_width=True
        )
        run_sample = btn_col2.button(
            "Chạy quét Log SOC mẫu (data/sample_logs.csv)", use_container_width=True
        )

        match_summary = None
        if run_uploaded:
            if uploaded_log is None:
                st.error("Vui lòng tải lên một tệp log trước khi quét.")
            else:
                content = uploaded_log.getvalue().decode("utf-8-sig", errors="replace")
                with st.spinner("Đang đối chiếu log với kho IOC trong SQLite..."):
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
                st.error(f"Không tìm thấy tệp log mẫu tại: {SAMPLE_LOGS_PATH}")
            else:
                with st.spinner("Đang quét bộ log Firewall / DNS / Proxy / EDR mẫu..."):
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
            s1.metric("Số dòng log đã quét", active_summary.total_records_scanned)
            s2.metric("Tổng số lượt trùng khớp", active_summary.total_matches)
            s3.metric("Số IOC duy nhất phát hiện", active_summary.unique_iocs_matched)

            if active_summary.matches:
                match_rows = [
                    {
                        "Mức rủi ro": _risk_vi(m.risk_level),
                        "IOC trùng khớp": _display_ioc(
                            m.indicator_value, m.indicator_type, defang_mode
                        ),
                        "Loại": m.indicator_type.value.upper(),
                        "Nguồn log": m.log_source,
                        "Trường khớp": m.matched_field,
                        "Thời gian log": m.log_timestamp or "Chưa có",
                        "Nội dung log gốc": m.raw_log_line,
                    }
                    for m in active_summary.matches
                ]
                match_df = pd.DataFrame(match_rows)
                st.dataframe(match_df, use_container_width=True, hide_index=True)
                st.download_button(
                    "Xuất cảnh báo trùng khớp SOC (CSV)",
                    data=match_df.to_csv(index=False).encode("utf-8-sig"),
                    file_name="soc_log_matches.csv",
                    mime="text/csv",
                )
            else:
                st.info(
                    "Không tìm thấy IOC trùng khớp trong tệp log. Hãy đảm bảo bạn đã nạp IOC "
                    "(ví dụ bấm 'Nạp bộ IOC mẫu (CSV)' ở thanh bên) hoặc nới lỏng bộ lọc rủi ro."
                )

        with st.expander("Lịch sử cảnh báo đối chiếu đã lưu"):
            with _get_pipeline(cfg) as pipeline:
                history = pipeline.repo.list_log_matches(limit=100)
            if history:
                hist_rows = [
                    {
                        "Phát hiện lúc (UTC)": m.matched_at.strftime("%Y-%m-%d %H:%M"),
                        "Mức rủi ro": _risk_vi(m.risk_level),
                        "IOC": _display_ioc(m.indicator_value, m.indicator_type, defang_mode),
                        "Nguồn log": m.log_source,
                        "Trường khớp": m.matched_field,
                        "Thời gian log": m.log_timestamp or "Chưa có",
                    }
                    for m in history
                ]
                st.dataframe(pd.DataFrame(hist_rows), use_container_width=True, hide_index=True)
            else:
                st.caption("Chưa có lịch sử đối chiếu log nào được lưu.")


if __name__ == "__main__":
    render_dashboard()
