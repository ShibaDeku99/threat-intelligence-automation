"""Multi-source Threat Intelligence enrichment and evidence correlation engine."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from pydantic import BaseModel, Field

from app.collectors.base import BaseTICollector, dedupe_preserve_order
from app.collectors.otx import OTXCollector
from app.collectors.urlhaus import URLhausCollector
from app.config import Settings
from app.database.repository import ThreatIntelRepository
from app.schemas import (
    EnrichmentEvidence,
    EnrichmentStatus,
    IndicatorRecord,
    NormalizedIOC,
    utc_now,
)

_ATTEMPTED_STATUSES: frozenset[EnrichmentStatus] = frozenset(
    {
        EnrichmentStatus.OK,
        EnrichmentStatus.NOT_FOUND,
        EnrichmentStatus.ERROR,
        EnrichmentStatus.TIMEOUT,
    }
)


class EnrichmentCorrelation(BaseModel):
    """Correlated multi-source enrichment evidence for a single persisted indicator."""

    indicator: IndicatorRecord
    evidence: list[EnrichmentEvidence] = Field(default_factory=list)
    sources_checked: int = 0
    sources_with_evidence: int = 0
    cache_hits: int = 0
    threat_types: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    attack_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    earliest_first_seen: datetime | None = None
    latest_last_seen: datetime | None = None
    any_active: bool | None = None


class EnrichmentEngine:
    """Orchestrates IOC enrichment across configured TI collectors with TTL caching."""

    def __init__(
        self,
        repo: ThreatIntelRepository,
        settings: Settings,
        collectors: list[BaseTICollector] | None = None,
    ) -> None:
        self.repo = repo
        self.settings = settings
        self.collectors: list[BaseTICollector] = (
            collectors
            if collectors is not None
            else [OTXCollector(settings), URLhausCollector(settings)]
        )

    def close(self) -> None:
        for collector in self.collectors:
            collector.close()

    def __enter__(self) -> EnrichmentEngine:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def enrich_indicator(
        self,
        ioc: NormalizedIOC,
        force_refresh: bool = False,
    ) -> EnrichmentCorrelation:
        """Persist IOC, query all collectors (or cache), store evidence, and correlate."""
        indicator, _ = self.repo.upsert_indicator(ioc)
        evidence_list: list[EnrichmentEvidence] = []
        cache_hits = 0

        for collector in self.collectors:
            self.repo.get_or_create_source(
                name=collector.name,
                source_url=collector.source_url,
                reliability_weight=collector.reliability_weight,
            )

            cached: EnrichmentEvidence | None = None
            if not force_refresh and self.settings.cache_ttl_hours > 0:
                cached = self.repo.get_fresh_enrichment(
                    indicator_id=indicator.id,
                    source_name=collector.name,
                    ttl_hours=self.settings.cache_ttl_hours,
                )

            if cached is not None:
                cache_hits += 1
                evidence_list.append(cached)
                continue

            try:
                ev = collector.lookup(ioc)
            except Exception as exc:
                ev = EnrichmentEvidence(
                    source_name=collector.name,
                    source_url=collector.source_url,
                    status=EnrichmentStatus.ERROR,
                    error_message=f"Unexpected collector error: {exc.__class__.__name__}",
                    retrieved_at=utc_now(),
                )

            ev.indicator_id = indicator.id
            ev_id = self.repo.save_enrichment_result(indicator.id, ev)
            ev.id = ev_id
            evidence_list.append(ev)

        refreshed = self.repo.get_indicator_by_id(indicator.id) or indicator
        return self._correlate(refreshed, evidence_list, cache_hits)

    def enrich_batch(
        self,
        iocs: Iterable[NormalizedIOC],
        force_refresh: bool = False,
    ) -> list[EnrichmentCorrelation]:
        """Enrich a sequence of normalized IOCs sequentially."""
        return [self.enrich_indicator(ioc, force_refresh=force_refresh) for ioc in iocs]

    @staticmethod
    def _correlate(
        indicator: IndicatorRecord,
        evidence_list: list[EnrichmentEvidence],
        cache_hits: int,
    ) -> EnrichmentCorrelation:
        threat_types: list[str] = []
        malware_families: list[str] = []
        tags: list[str] = []
        attack_ids: list[str] = []
        references: list[str] = []
        first_seen_dates: list[datetime] = []
        last_seen_dates: list[datetime] = []
        active_flags: list[bool] = []

        sources_checked = 0
        malicious_sources: set[str] = set()

        for ev in evidence_list:
            if ev.status in _ATTEMPTED_STATUSES:
                sources_checked += 1
            if ev.status == EnrichmentStatus.OK and ev.is_malicious_signal:
                malicious_sources.add(ev.source_name)
                threat_types.extend(ev.threat_types)
                malware_families.extend(ev.malware_families)
                tags.extend(ev.tags)
                attack_ids.extend(ev.attack_ids)
                references.extend(ev.references)
                if ev.source_first_seen is not None:
                    first_seen_dates.append(ev.source_first_seen)
                if ev.source_last_seen is not None:
                    last_seen_dates.append(ev.source_last_seen)
                if ev.is_active is not None:
                    active_flags.append(ev.is_active)

        any_active: bool | None
        if any(active_flags):
            any_active = True
        elif active_flags:
            any_active = False
        else:
            any_active = None

        return EnrichmentCorrelation(
            indicator=indicator,
            evidence=evidence_list,
            sources_checked=sources_checked,
            sources_with_evidence=len(malicious_sources),
            cache_hits=cache_hits,
            threat_types=dedupe_preserve_order(threat_types),
            malware_families=dedupe_preserve_order(malware_families),
            tags=dedupe_preserve_order(tags),
            attack_ids=dedupe_preserve_order([aid.upper() for aid in attack_ids]),
            references=dedupe_preserve_order(references),
            earliest_first_seen=min(first_seen_dates) if first_seen_dates else indicator.first_seen,
            latest_last_seen=max(last_seen_dates) if last_seen_dates else indicator.last_seen,
            any_active=any_active,
        )

