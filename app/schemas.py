"""Shared Pydantic schemas for IOC processing, enrichment, scoring, and reporting."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, computed_field


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class IOCType(StrEnum):
    """Supported Indicator of Compromise types."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class EnrichmentStatus(StrEnum):
    """Outcome status for an individual Threat Intelligence source query."""

    OK = "ok"
    NOT_FOUND = "not_found"
    ERROR = "error"
    TIMEOUT = "timeout"
    SKIPPED_NO_KEY = "skipped_no_key"
    UNSUPPORTED_TYPE = "unsupported_type"


class RiskLevel(StrEnum):
    """Heuristic Risk Level labels."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Classification(StrEnum):
    """Analyst-facing IOC verdict classification."""

    BENIGN_UNKNOWN = "Benign/Unknown"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"


class IOCInput(BaseModel):
    """Raw IOC input prior to normalization and validation."""

    raw_value: str
    source_hint: str | None = None
    tags: list[str] = Field(default_factory=list)


class NormalizedIOC(BaseModel):
    """Validated and normalized IOC ready for deduplication and enrichment."""

    value: str
    normalized_value: str
    ioc_type: IOCType
    raw_input: str
    was_defanged: bool = False
    is_reserved_ip: bool = False
    ip_scope_note: str | None = None
    source_hint: str | None = None


class IndicatorRecord(BaseModel):
    """Persisted indicator row from SQLite."""

    id: int
    value: str
    normalized_value: str
    ioc_type: IOCType
    raw_input: str
    is_reserved_ip: bool = False
    ip_scope_note: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime
    updated_at: datetime


class SourceRecord(BaseModel):
    """Threat intelligence source metadata stored in SQLite."""

    id: int
    name: str
    source_url: str
    reliability_weight: int = Field(default=20, ge=0, le=40)
    enabled: bool = True


class EnrichmentEvidence(BaseModel):
    """Normalized evidence gathered from a single Threat Intelligence source.

    Note: source_first_seen / source_last_seen reflect timestamps reported by the
    external TI source, whereas retrieved_at is when this platform queried it.
    """

    id: int | None = None
    indicator_id: int | None = None
    source_name: str
    source_url: str = ""
    status: EnrichmentStatus
    is_malicious_signal: bool = False
    is_active: bool | None = None
    pulse_count: int = Field(default=0, ge=0)
    threat_types: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    attack_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    source_first_seen: datetime | None = None
    source_last_seen: datetime | None = None
    raw_result: dict[str, Any] = Field(default_factory=dict)
    latency_ms: int = Field(default=0, ge=0)
    error_message: str | None = None
    retrieved_at: datetime = Field(default_factory=utc_now)
    from_cache: bool = False


class ScoreBreakdown(BaseModel):
    """Transparent component breakdown for the Heuristic Risk Score (0-100)."""

    source_reliability: int = Field(default=0, ge=0, le=40)
    independent_sources: int = Field(default=0, ge=0, le=25)
    recency: int = Field(default=0, ge=0, le=20)
    activity_status: int = Field(default=0, ge=0, le=15)

    @computed_field
    @property
    def total(self) -> int:
        return (
            self.source_reliability
            + self.independent_sources
            + self.recency
            + self.activity_status
        )


class AttackTechnique(BaseModel):
    """MITRE ATT&CK technique metadata extracted from STIX 2.1."""

    technique_id: str
    name: str
    tactic: str
    description: str = ""
    url: str = ""


class TechniqueMapping(BaseModel):
    """Evidence-backed mapping between an IOC and a MITRE ATT&CK technique."""

    technique: AttackTechnique
    source_name: str
    evidence: str
    confidence: str = "medium"
    matched_at: datetime = Field(default_factory=utc_now)


class ThreatReport(BaseModel):
    """Aggregated analyst report for a single IOC."""

    id: int | None = None
    indicator: IndicatorRecord
    risk_score: int = Field(ge=0, le=100)
    confidence_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    classification: Classification
    score_breakdown: ScoreBreakdown
    threat_types: list[str] = Field(default_factory=list)
    sources_checked: int = Field(default=0, ge=0)
    sources_with_evidence: int = Field(default=0, ge=0)
    evidence: list[EnrichmentEvidence] = Field(default_factory=list)
    attack_techniques: list[TechniqueMapping] = Field(default_factory=list)
    summary: str
    recommended_actions: list[str] = Field(default_factory=list)
    disclaimer: str = (
        "Heuristic Risk Score is a decision-support metric, not an international "
        "standard. Analysts must verify findings before applying blocking controls."
    )
    generated_at: datetime = Field(default_factory=utc_now)


class LogMatch(BaseModel):
    """Match found when correlating collected IOCs against SOC logs."""

    id: int | None = None
    indicator_id: int
    indicator_value: str
    indicator_type: IOCType
    risk_level: RiskLevel | None = None
    log_source: str
    log_timestamp: str | None = None
    matched_field: str
    raw_log_line: str
    matched_at: datetime = Field(default_factory=utc_now)


class SourceMetrics(BaseModel):
    """Measured runtime telemetry for a single Threat Intelligence source."""

    source_name: str
    total_queries: int = 0
    ok_count: int = 0
    not_found_count: int = 0
    error_count: int = 0
    timeout_count: int = 0
    skipped_count: int = 0
    unsupported_count: int = 0
    avg_latency_ms: float = 0.0
    api_failure_rate: float = 0.0


class SystemMetrics(BaseModel):
    """Aggregated operational and evaluation metrics measured from SQLite."""

    total_indicators: int = 0
    total_reports: int = 0
    total_enrichments: int = 0
    enrichment_success_rate: float = 0.0
    api_failure_rate: float = 0.0
    avg_latency_ms: float = 0.0
    risk_distribution: dict[str, int] = Field(default_factory=dict)
    type_distribution: dict[str, int] = Field(default_factory=dict)
    by_source: list[SourceMetrics] = Field(default_factory=list)

