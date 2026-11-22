"""Batch IOC normalization, deduplication, and SQLite ingestion helpers."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, Field

from app.database.repository import ThreatIntelRepository
from app.processors.normalizer import normalize_ioc
from app.processors.validator import IOCValidationError
from app.schemas import IndicatorRecord, IOCInput, IOCType, NormalizedIOC


class InvalidIOCRecord(BaseModel):
    """Captures an invalid IOC entry without interrupting batch processing."""

    raw_input: str
    reason: str
    row_number: int | None = None
    source_hint: str | None = None


class BatchProcessResult(BaseModel):
    """Summary of normalizing, validating, and deduplicating a batch of IOCs."""

    total_received: int = 0
    valid_count: int = 0
    unique_iocs: list[NormalizedIOC] = Field(default_factory=list)
    duplicate_count: int = 0
    duplicates_removed: list[str] = Field(default_factory=list)
    invalid_count: int = 0
    invalid_records: list[InvalidIOCRecord] = Field(default_factory=list)


class IngestResult(BaseModel):
    """Combined result of batch processing and deduplicated SQLite persistence."""

    batch: BatchProcessResult
    indicators: list[IndicatorRecord] = Field(default_factory=list)
    inserted_new: int = 0
    existing_in_db: int = 0


def deduplicate_iocs(
    iocs: Iterable[NormalizedIOC],
) -> tuple[list[NormalizedIOC], list[NormalizedIOC]]:
    """Deduplicate normalized IOCs by (normalized_value, ioc_type), preserving order.

    Returns:
        (unique_iocs, duplicate_iocs)
    """
    seen: set[tuple[str, IOCType]] = set()
    unique: list[NormalizedIOC] = []
    duplicates: list[NormalizedIOC] = []

    for ioc in iocs:
        key = (ioc.normalized_value, ioc.ioc_type)
        if key in seen:
            duplicates.append(ioc)
        else:
            seen.add(key)
            unique.append(ioc)

    return unique, duplicates


def process_raw_inputs(inputs: Iterable[IOCInput | str]) -> BatchProcessResult:
    """Normalize, validate, and deduplicate a sequence of raw IOC inputs."""
    total_received = 0
    valid_iocs: list[NormalizedIOC] = []
    invalid_records: list[InvalidIOCRecord] = []

    for idx, item in enumerate(inputs, start=1):
        total_received += 1
        if isinstance(item, IOCInput):
            raw_value = item.raw_value
            source_hint = item.source_hint
        else:
            raw_value = item
            source_hint = None

        try:
            normalized = normalize_ioc(raw_value, source_hint=source_hint)
            valid_iocs.append(normalized)
        except IOCValidationError as exc:
            invalid_records.append(
                InvalidIOCRecord(
                    raw_input=raw_value,
                    reason=exc.reason,
                    row_number=idx,
                    source_hint=source_hint,
                )
            )

    unique_iocs, duplicate_iocs = deduplicate_iocs(valid_iocs)
    return BatchProcessResult(
        total_received=total_received,
        valid_count=len(valid_iocs),
        unique_iocs=unique_iocs,
        duplicate_count=len(duplicate_iocs),
        duplicates_removed=[dup.raw_input for dup in duplicate_iocs],
        invalid_count=len(invalid_records),
        invalid_records=invalid_records,
    )


def ingest_batch_to_repository(
    inputs: Iterable[IOCInput | str],
    repo: ThreatIntelRepository,
) -> IngestResult:
    """Process a batch of IOCs and upsert unique indicators into SQLite."""
    batch = process_raw_inputs(inputs)
    indicators: list[IndicatorRecord] = []
    inserted_new = 0
    existing_in_db = 0

    for ioc in batch.unique_iocs:
        record, is_new = repo.upsert_indicator(ioc)
        indicators.append(record)
        if is_new:
            inserted_new += 1
        else:
            existing_in_db += 1

    return IngestResult(
        batch=batch,
        indicators=indicators,
        inserted_new=inserted_new,
        existing_in_db=existing_in_db,
    )
