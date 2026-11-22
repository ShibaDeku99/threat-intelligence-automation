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


def build_summary_and_actions(
    correlation: EnrichmentCorrelation,
    risk_score: int,
    confidence_score: int,
    risk_level: RiskLevel,
    classification: Classification,
    techniques: list[TechniqueMapping],
) -> tuple[str, list[str]]:
    """Generate a clear, evidence-grounded SOC analyst summary and action checklist."""
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

    parts: list[str] = [
        f"IOC {ind.normalized_value} ({ind.ioc_type.value.upper()}) is classified as "
        f"{classification.value} with Heuristic Risk Score {risk_score}/100 ({risk_level.value}) "
        f"and Confidence Score {confidence_score}/100."
    ]

    if not responded:
        parts.append(
            "No Threat Intelligence source returned a live response "
            f"(skipped due to missing keys: {len(skipped)}, failed/timed out: {len(failed)}). "
            "Do not treat this indicator as verified benign."
        )
    elif correlation.sources_with_evidence == 0:
        parts.append(
            f"Checked {len(responded)}/{len(applicable)} applicable source(s) with no "
            "malicious evidence recorded."
        )
    else:
        confirming_names = [
            ev.source_name
            for ev in correlation.evidence
            if ev.status == EnrichmentStatus.OK and ev.is_malicious_signal
        ]
        parts.append(
            f"Confirmed by {correlation.sources_with_evidence} independent source(s): "
            f"{', '.join(confirming_names)}."
        )
        if correlation.malware_families:
            parts.append(
                f"Associated malware families: {', '.join(correlation.malware_families[:5])}."
            )
        if correlation.threat_types:
            parts.append(f"Observed threat context: {', '.join(correlation.threat_types[:5])}.")
        if correlation.any_active is True:
            parts.append("Indicator is currently reported as active/online.")
        elif correlation.any_active is False:
            parts.append("Indicator is currently reported as inactive/offline (historical).")

    if techniques:
        tids = ", ".join(m.technique.technique_id for m in techniques[:5])
        parts.append(f"Mapped MITRE ATT&CK techniques: {tids}.")

    if failed:
        failed_names = ", ".join(f"{ev.source_name} ({ev.status.value})" for ev in failed)
        parts.append(f"Degraded coverage due to source error(s): {failed_names}.")

    if ind.is_reserved_ip and ind.ip_scope_note:
        parts.append(f"Scope notice: {ind.ip_scope_note}.")

    # Build actionable SOC recommendations
    actions: list[str] = []
    if ind.is_reserved_ip:
        actions.append(
            "Verify SIEM/firewall alert context: this IP belongs to a non-routable or "
            "documentation range and may indicate test traffic, internal scanning, or NAT logs."
        )

    if not responded:
        actions.append(
            "Configure OTX_API_KEY and URLHAUS_AUTH_KEY in .env (or retry after network recovery) "
            "to obtain live Threat Intelligence evidence before closing the ticket."
        )
    elif risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        actions.append(
            "Hunt SIEM, firewall, DNS, and proxy logs over the past 30 days for internal "
            "hosts communicating with this IOC."
        )
        actions.append(
            "Validate false-positive risk and business ownership before applying firewall, "
            "DNS sinkhole, or EDR blocking rules."
        )
        if techniques:
            actions.append(
                "Review EDR/SIEM detections aligned with mapped MITRE ATT&CK techniques "
                f"({', '.join(m.technique.technique_id for m in techniques[:4])})."
            )
    elif risk_level == RiskLevel.MEDIUM:
        actions.append(
            "Correlate this IOC against internal firewall/DNS/proxy logs and monitor for "
            "repeated or anomalous activity."
        )
        actions.append(
            "Collect additional context from internal EDR telemetry or passive DNS before "
            "escalating to containment."
        )
    else:
        actions.append(
            "No immediate blocking action warranted based on current evidence; retain in "
            "watchlist if local SIEM context remains suspicious."
        )

    if failed or skipped:
        actions.append(
            "Re-run enrichment with Force Refresh once degraded or unconfigured TI sources "
            "are available to raise confidence."
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

