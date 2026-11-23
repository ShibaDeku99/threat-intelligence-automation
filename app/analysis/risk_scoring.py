"""Heuristic Risk Score, Confidence Score, and SOC Analyst Summary engine."""

from __future__ import annotations

from datetime import UTC, datetime

from app.enrichment.enrichment_engine import EnrichmentCorrelation
from app.schemas import (
    Classification,
    EnrichmentEvidence,
    EnrichmentStatus,
    RiskLevel,
    ScoreBreakdown,
    TechniqueMapping,
    ThreatReport,
    utc_now,
)

# Default source weights when not specified explicitly (max 40)
_DEFAULT_SOURCE_WEIGHTS: dict[str, int] = {
    "URLhaus": 40,
    "AlienVault OTX": 35,
    "CSV Dataset": 15,
}


def classify_risk_level(risk_score: int) -> RiskLevel:
    """Map Heuristic Risk Score (0-100) to Low / Medium / High / Critical."""
    if risk_score >= 80:
        return RiskLevel.CRITICAL
    if risk_score >= 60:
        return RiskLevel.HIGH
    if risk_score >= 30:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _score_source_reliability(evidence_list: list[EnrichmentEvidence]) -> int:
    """Criterion 1 (max 40): Highest reliability contribution among confirming sources."""
    scores: list[int] = []
    for ev in evidence_list:
        if ev.status != EnrichmentStatus.OK or not ev.is_malicious_signal:
            continue

        base = _DEFAULT_SOURCE_WEIGHTS.get(ev.source_name, 25)
        if ev.source_name == "AlienVault OTX":
            if ev.pulse_count >= 5:
                scores.append(min(35, base))
            elif ev.pulse_count >= 2:
                scores.append(30)
            else:
                scores.append(22)
        elif ev.source_name == "URLhaus":
            scores.append(40 if (ev.is_active is True or ev.malware_families) else 35)
        else:
            scores.append(min(40, base))

    return min(40, max(scores, default=0))


def _score_independent_sources(sources_with_evidence: int) -> int:
    """Criterion 2 (max 25): Corroboration across independent TI sources."""
    if sources_with_evidence >= 2:
        return 25
    if sources_with_evidence == 1:
        return 12
    return 0


def _score_recency(
    latest_last_seen: datetime | None,
    has_malicious_evidence: bool,
    now: datetime,
) -> int:
    """Criterion 3 (max 20): Freshness based strictly on TI source timestamps."""
    if not has_malicious_evidence:
        return 0
    if latest_last_seen is None:
        return 5

    ref_now = now.astimezone(UTC) if now.tzinfo else now.replace(tzinfo=UTC)
    ref_seen = (
        latest_last_seen.astimezone(UTC)
        if latest_last_seen.tzinfo
        else latest_last_seen.replace(tzinfo=UTC)
    )
    age_days = max(0.0, (ref_now - ref_seen).total_seconds() / 86400.0)

    if age_days <= 7:
        return 20
    if age_days <= 30:
        return 15
    if age_days <= 90:
        return 10
    if age_days <= 365:
        return 5
    return 2


def _score_activity_status(any_active: bool | None, has_malicious_evidence: bool) -> int:
    """Criterion 4 (max 15): Active / online status of the IOC."""
    if not has_malicious_evidence:
        return 0
    if any_active is True:
        return 15
    if any_active is False:
        return 5
    return 0


def calculate_confidence_score(
    correlation: EnrichmentCorrelation,
    techniques: list[TechniqueMapping],
) -> int:
    """Compute Confidence Score (0-100) reflecting evidence quality and API coverage.

    Deliberately decoupled from Heuristic Risk Score:
    - If all sources failed or lacked API keys -> confidence is 0.
    - Partial API failure lowers confidence even if risk score is elevated.
    """
    applicable = [
        ev for ev in correlation.evidence if ev.status != EnrichmentStatus.UNSUPPORTED_TYPE
    ]
    if not applicable:
        return 0

    clean_responses = [
        ev
        for ev in applicable
        if ev.status in (EnrichmentStatus.OK, EnrichmentStatus.NOT_FOUND)
    ]
    if not clean_responses:
        return 0

    # 1. Coverage score (max 40): fraction of applicable sources that responded cleanly
    coverage_score = round((len(clean_responses) / len(applicable)) * 40)

    # 2. Corroboration score (max 30)
    if correlation.sources_with_evidence >= 2:
        corroboration_score = 30
    elif correlation.sources_with_evidence == 1:
        confirming = [
            ev
            for ev in clean_responses
            if ev.status == EnrichmentStatus.OK and ev.is_malicious_signal
        ]
        strong_single = any(
            ev.source_name == "URLhaus" or ev.pulse_count >= 3 for ev in confirming
        )
        corroboration_score = 20 if strong_single else 12
    else:
        # Clean / not found across responding sources
        corroboration_score = 25 if len(clean_responses) >= 2 else 15

    # 3. Metadata completeness (max 20)
    if correlation.sources_with_evidence > 0:
        metadata_score = 0
        if correlation.earliest_first_seen or correlation.latest_last_seen:
            metadata_score += 8
        if correlation.malware_families or correlation.threat_types:
            metadata_score += 6
        if correlation.references:
            metadata_score += 6
    else:
        metadata_score = 12 if len(clean_responses) >= 2 else 8

    # 4. Technical / ATT&CK context (max 10)
    if any(t.confidence in ("high", "medium") for t in techniques):
        context_score = 10
    elif techniques:
        context_score = 5
    elif correlation.sources_with_evidence == 0 and len(clean_responses) >= 2:
        context_score = 5
    else:
        context_score = 0

    total = coverage_score + corroboration_score + metadata_score + context_score
    return max(0, min(100, total))


def determine_classification(
    risk_score: int, sources_with_evidence: int
) -> Classification:
    """Map score and evidence count to analyst-facing verdict label."""
    if sources_with_evidence == 0:
        return Classification.BENIGN_UNKNOWN
    if risk_score >= 70 or (sources_with_evidence >= 2 and risk_score >= 60):
        return Classification.MALICIOUS
    return Classification.SUSPICIOUS


_RISK_LABELS_VI: dict[RiskLevel, str] = {
    RiskLevel.LOW: "Thấp (Low)",
    RiskLevel.MEDIUM: "Trung bình (Medium)",
    RiskLevel.HIGH: "Cao (High)",
    RiskLevel.CRITICAL: "Nghiêm trọng (Critical)",
}

_CLASSIFICATION_LABELS_VI: dict[Classification, str] = {
    Classification.BENIGN_UNKNOWN: "Sạch / Chưa rõ",
    Classification.SUSPICIOUS: "Đáng ngờ",
    Classification.MALICIOUS: "Độc hại",
}


def build_summary_and_actions(
    correlation: EnrichmentCorrelation,
    risk_score: int,
    confidence_score: int,
    risk_level: RiskLevel,
    classification: Classification,
    techniques: list[TechniqueMapping],
) -> tuple[str, list[str]]:
    """Generate a clear, evidence-grounded Vietnamese SOC analyst summary and action checklist."""
    ind = correlation.indicator
    applicable = [
        ev for ev in correlation.evidence if ev.status != EnrichmentStatus.UNSUPPORTED_TYPE
    ]
    responded = [
        ev
        for ev in applicable
        if ev.status in (EnrichmentStatus.OK, EnrichmentStatus.NOT_FOUND)
    ]
    failed = [
        ev
        for ev in applicable
        if ev.status in (EnrichmentStatus.ERROR, EnrichmentStatus.TIMEOUT)
    ]
    skipped = [ev for ev in applicable if ev.status == EnrichmentStatus.SKIPPED_NO_KEY]

    risk_vi = _RISK_LABELS_VI[risk_level]
    class_vi = _CLASSIFICATION_LABELS_VI[classification]

    parts: list[str] = [
        f"IOC {ind.normalized_value} ({ind.ioc_type.value.upper()}) được phân loại "
        f"{class_vi} với Heuristic Risk Score {risk_score}/100 ({risk_vi}) "
        f"và Độ tin cậy (Confidence Score) {confidence_score}/100."
    ]

    if not responded:
        parts.append(
            "Chưa có nguồn Threat Intelligence nào phản hồi trực tiếp "
            f"(bỏ qua do thiếu key: {len(skipped)}, lỗi/quá thời gian: {len(failed)}). "
            "Không được coi IOC này là đã xác minh an toàn."
        )
    elif correlation.sources_with_evidence == 0:
        parts.append(
            f"Đã kiểm tra {len(responded)}/{len(applicable)} nguồn khả dụng và "
            "không ghi nhận bằng chứng độc hại."
        )
    else:
        confirming_names = [
            ev.source_name
            for ev in correlation.evidence
            if ev.status == EnrichmentStatus.OK and ev.is_malicious_signal
        ]
        parts.append(
            f"Được xác nhận bởi {correlation.sources_with_evidence} nguồn độc lập: "
            f"{', '.join(confirming_names)}."
        )
        if correlation.malware_families:
            parts.append(
                f"Họ mã độc liên quan: {', '.join(correlation.malware_families[:5])}."
            )
        if correlation.threat_types:
            parts.append(
                f"Ngữ cảnh mối đe dọa: {', '.join(correlation.threat_types[:5])}."
            )
        if correlation.any_active is True:
            parts.append("IOC hiện đang được ghi nhận hoạt động (active/online).")
        elif correlation.any_active is False:
            parts.append("IOC hiện đã ngừng hoạt động (offline / dữ liệu lịch sử).")

    if techniques:
        tids = ", ".join(m.technique.technique_id for m in techniques[:5])
        parts.append(f"Kỹ thuật MITRE ATT&CK ánh xạ được: {tids}.")

    if failed:
        failed_names = ", ".join(f"{ev.source_name} ({ev.status.value})" for ev in failed)
        parts.append(f"Độ phủ bị suy giảm do lỗi truy vấn nguồn: {failed_names}.")

    if ind.is_reserved_ip and ind.ip_scope_note:
        parts.append(f"Lưu ý phạm vi IP: {ind.ip_scope_note}.")

    # Build actionable Vietnamese SOC recommendations
    actions: list[str] = []
    if ind.is_reserved_ip:
        actions.append(
            "Kiểm tra lại ngữ cảnh cảnh báo SIEM/Firewall: IP này thuộc dải không định tuyến "
            "công cộng (dải tài liệu/nội bộ), có thể xuất phát từ lưu lượng thử nghiệm hoặc NAT."
        )

    if not responded:
        actions.append(
            "Cấu hình OTX_API_KEY và URLHAUS_AUTH_KEY trong file .env (hoặc thử lại khi mạng "
            "ổn định) để lấy dữ liệu Threat Intelligence thực tế trước khi đóng cảnh báo."
        )
    elif risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        actions.append(
            "Truy vết log SIEM, Firewall, DNS và Proxy trong 30 ngày gần nhất để tìm các máy "
            "nội bộ có giao tiếp với IOC này."
        )
        actions.append(
            "Xác minh nguy cơ cảnh báo giả (false positive) và chủ sở hữu dịch vụ trước khi "
            "tạo luật chặn trên Firewall, DNS sinkhole hoặc EDR."
        )
        if techniques:
            actions.append(
                "Rà soát các rule phát hiện trên EDR/SIEM tương ứng với kỹ thuật MITRE ATT&CK "
                f"({', '.join(m.technique.technique_id for m in techniques[:4])})."
            )
    elif risk_level == RiskLevel.MEDIUM:
        actions.append(
            "Đối chiếu IOC này với log Firewall/DNS/Proxy nội bộ và theo dõi thêm các kết nối "
            "lặp lại hoặc bất thường."
        )
        actions.append(
            "Thu thập thêm ngữ cảnh từ EDR nội bộ hoặc passive DNS trước khi nâng mức cô lập."
        )
    else:
        actions.append(
            "Chưa cần chặn ngay dựa trên bằng chứng hiện tại; giữ trong danh sách theo dõi nếu "
            "ngữ cảnh SIEM nội bộ vẫn đáng ngờ."
        )

    if failed or skipped:
        actions.append(
            "Chạy làm giàu lại với tùy chọn 'Làm mới trực tiếp (bỏ qua cache)' sau khi khắc phục "
            "nguồn lỗi hoặc bổ sung API key để tăng độ tin cậy."
        )

    return " ".join(parts), actions


class ThreatAnalyzer:
    """Computes Heuristic Risk Score, Confidence Score, and full ThreatReport."""

    def analyze(
        self,
        correlation: EnrichmentCorrelation,
        techniques: list[TechniqueMapping] | None = None,
        now: datetime | None = None,
    ) -> ThreatReport:
        """Analyze correlated TI evidence and return a complete ThreatReport."""
        eval_time = now or utc_now()
        mapped_techniques = techniques or []
        has_evidence = correlation.sources_with_evidence > 0

        breakdown = ScoreBreakdown(
            source_reliability=_score_source_reliability(correlation.evidence),
            independent_sources=_score_independent_sources(correlation.sources_with_evidence),
            recency=_score_recency(correlation.latest_last_seen, has_evidence, eval_time),
            activity_status=_score_activity_status(correlation.any_active, has_evidence),
        )
        risk_score = breakdown.total
        risk_level = classify_risk_level(risk_score)
        classification = determine_classification(risk_score, correlation.sources_with_evidence)
        confidence_score = calculate_confidence_score(correlation, mapped_techniques)

        summary, recommended_actions = build_summary_and_actions(
            correlation=correlation,
            risk_score=risk_score,
            confidence_score=confidence_score,
            risk_level=risk_level,
            classification=classification,
            techniques=mapped_techniques,
        )

        return ThreatReport(
            indicator=correlation.indicator,
            risk_score=risk_score,
            confidence_score=confidence_score,
            risk_level=risk_level,
            classification=classification,
            score_breakdown=breakdown,
            threat_types=correlation.threat_types,
            sources_checked=correlation.sources_checked,
            sources_with_evidence=correlation.sources_with_evidence,
            evidence=correlation.evidence,
            attack_techniques=mapped_techniques,
            summary=summary,
            recommended_actions=recommended_actions,
            generated_at=eval_time,
        )

