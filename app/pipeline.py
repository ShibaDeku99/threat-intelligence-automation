"""End-to-end Threat Intelligence investigation pipeline shared by CLI and Dashboard."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import BinaryIO, TextIO

from pydantic import BaseModel, Field

from app.analysis.risk_scoring import ThreatAnalyzer
from app.collectors.base import BaseTICollector
from app.collectors.csv_loader import load_iocs_from_csv, load_iocs_from_csv_bytes
from app.collectors.otx import OTXCollector
from app.collectors.urlhaus import URLhausCollector
from app.config import Settings, get_settings
from app.database.repository import ThreatIntelRepository
from app.enrichment.enrichment_engine import EnrichmentEngine
from app.enrichment.mitre_mapper import MitreAttackMapper
from app.processors.deduplicator import BatchProcessResult, process_raw_inputs
from app.processors.normalizer import normalize_ioc
from app.schemas import IOCInput, NormalizedIOC, ThreatReport


class PipelineBatchResult(BaseModel):
    """Combined outcome of batch IOC normalization, enrichment, mapping, and scoring."""

    batch: BatchProcessResult
    reports: list[ThreatReport] = Field(default_factory=list)
    total_cache_hits: int = 0


class ThreatIntelPipeline:
    """Single source of truth orchestrating all Threat Intelligence modules."""

    def __init__(
        self,
        settings: Settings | None = None,
        repo: ThreatIntelRepository | None = None,
        collectors: list[BaseTICollector] | None = None,
        mitre_mapper: MitreAttackMapper | None = None,
        analyzer: ThreatAnalyzer | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.settings.ensure_directories()
        self._owns_repo = repo is None
        self.repo = repo or ThreatIntelRepository(self.settings.database_path)
        self.enrichment_engine = EnrichmentEngine(
            repo=self.repo,
            settings=self.settings,
            collectors=collectors,
        )
        self.mitre_mapper = mitre_mapper or MitreAttackMapper()
        self.analyzer = analyzer or ThreatAnalyzer()

    def close(self) -> None:
        self.enrichment_engine.close()
        if self._owns_repo:
            self.repo.close()

    def __enter__(self) -> ThreatIntelPipeline:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _investigate_normalized(
        self, ioc: NormalizedIOC, force_refresh: bool = False
    ) -> tuple[ThreatReport, int]:
        correlation = self.enrichment_engine.enrich_indicator(
            ioc, force_refresh=force_refresh
        )
        techniques = self.mitre_mapper.map_and_save(correlation, self.repo)
        report = self.analyzer.analyze(correlation, techniques=techniques)
        report_id = self.repo.save_threat_report(report)
        report.id = report_id
        return report, correlation.cache_hits

    def investigate_single(
        self,
        raw_ioc: str,
        source_hint: str | None = None,
        force_refresh: bool = False,
    ) -> ThreatReport:
        """Normalize, enrich, map to ATT&CK, score, and persist a single IOC."""
        normalized = normalize_ioc(raw_ioc, source_hint=source_hint)
        report, _ = self._investigate_normalized(normalized, force_refresh=force_refresh)
        return report

    def investigate_batch(
        self,
        inputs: Iterable[IOCInput | str],
        force_refresh: bool = False,
    ) -> PipelineBatchResult:
        """Process, deduplicate, and investigate a batch of IOCs without failing on bad rows."""
        batch = process_raw_inputs(inputs)
        reports: list[ThreatReport] = []
        total_cache_hits = 0

        for ioc in batch.unique_iocs:
            report, cache_hits = self._investigate_normalized(
                ioc, force_refresh=force_refresh
            )
            reports.append(report)
            total_cache_hits += cache_hits

        return PipelineBatchResult(
            batch=batch,
            reports=reports,
            total_cache_hits=total_cache_hits,
        )

    def investigate_csv(
        self,
        source: Path | str | TextIO | BinaryIO,
        ioc_column: str | None = None,
        force_refresh: bool = False,
    ) -> PipelineBatchResult:
        """Load IOCs from a CSV file and run full enrichment and analysis."""
        inputs = load_iocs_from_csv(source, ioc_column=ioc_column)
        return self.investigate_batch(inputs, force_refresh=force_refresh)

    def investigate_csv_bytes(
        self,
        content: bytes,
        ioc_column: str | None = None,
        force_refresh: bool = False,
    ) -> PipelineBatchResult:
        """Load IOCs from uploaded CSV bytes and run full enrichment and analysis."""
        inputs = load_iocs_from_csv_bytes(content, ioc_column=ioc_column)
        return self.investigate_batch(inputs, force_refresh=force_refresh)

    def collect_and_investigate_feeds(
        self,
        otx_limit: int = 0,
        urlhaus_limit: int = 0,
        force_refresh: bool = False,
    ) -> PipelineBatchResult:
        """Pull fresh IOCs from configured OTX / URLhaus feeds and enrich them."""
        collected: list[IOCInput] = []
        for collector in self.enrichment_engine.collectors:
            if otx_limit > 0 and isinstance(collector, OTXCollector):
                collected.extend(collector.fetch_subscribed_pulses(limit=otx_limit))
            elif urlhaus_limit > 0 and isinstance(collector, URLhausCollector):
                collected.extend(collector.fetch_recent_urls(limit=urlhaus_limit))
        return self.investigate_batch(collected, force_refresh=force_refresh)

