"""IOC normalization, validation, and deduplication processors."""

from app.processors.deduplicator import (
    BatchProcessResult,
    IngestResult,
    InvalidIOCRecord,
    deduplicate_iocs,
    ingest_batch_to_repository,
    process_raw_inputs,
)
from app.processors.normalizer import defang_ioc, normalize_ioc, normalize_value, refang_ioc
from app.processors.validator import (
    IOCValidationError,
    classify_and_validate,
    inspect_ip_scope,
    is_valid_domain,
)

__all__ = [
    "BatchProcessResult",
    "IOCValidationError",
    "IngestResult",
    "InvalidIOCRecord",
    "classify_and_validate",
    "deduplicate_iocs",
    "defang_ioc",
    "ingest_batch_to_repository",
    "inspect_ip_scope",
    "is_valid_domain",
    "normalize_ioc",
    "normalize_value",
    "process_raw_inputs",
    "refang_ioc",
]
