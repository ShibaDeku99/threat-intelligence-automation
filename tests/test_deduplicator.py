"""Unit tests for deduplication, batch processing, and CSV/text collectors."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.collectors.csv_loader import (
    CSVLoaderError,
    load_iocs_from_csv,
    load_iocs_from_csv_bytes,
    load_iocs_from_text,
)
from app.database.repository import ThreatIntelRepository
from app.processors.deduplicator import ingest_batch_to_repository, process_raw_inputs
from app.schemas import IOCType


def test_process_raw_inputs_deduplicates_variants_and_isolates_invalid() -> None:
    raw_items = [
        "198.51.100.23",
        "198[.]51[.]100[.]23",  # Defanged duplicate
        "MALICIOUS.EXAMPLE.COM.",
        "malicious.example.com",  # Case + trailing dot duplicate
        "999.999.999.999",  # Invalid IP
        "44D88612FEA8A8F36DE82E1278ABB02F",
        "44d88612fea8a8f36de82e1278abb02f",  # Hash case duplicate
        "not a valid entry",  # Invalid string
    ]
    result = process_raw_inputs(raw_items)

    assert result.total_received == 8
    assert result.valid_count == 6
    assert len(result.unique_iocs) == 3
    assert result.duplicate_count == 3
    assert result.invalid_count == 2
    assert {ioc.ioc_type for ioc in result.unique_iocs} == {
        IOCType.IPV4,
        IOCType.DOMAIN,
        IOCType.MD5,
    }


def test_sample_csv_end_to_end_ingestion_is_idempotent() -> None:
    sample_csv = Path("data/sample_iocs.csv")
    inputs = load_iocs_from_csv(sample_csv)
    assert len(inputs) == 11

    repo = ThreatIntelRepository(":memory:")
    first_run = ingest_batch_to_repository(inputs, repo)
    assert first_run.batch.invalid_count == 0
    # 11 rows contain 4 intentional duplicates -> 7 unique indicators
    assert len(first_run.batch.unique_iocs) == 7
    assert first_run.batch.duplicate_count == 4
    assert first_run.inserted_new == 7
    assert first_run.existing_in_db == 0

    # Re-ingesting the same CSV must not create duplicate rows in SQLite
    second_run = ingest_batch_to_repository(inputs, repo)
    assert second_run.inserted_new == 0
    assert second_run.existing_in_db == 7
    assert len(repo.list_indicators()) == 7
    repo.close()


def test_csv_loader_bytes_single_column_and_errors() -> None:
    single_col_csv = b"\xef\xbb\xbfobservable\n8.8.8.8\nexample.com\n"
    items = load_iocs_from_csv_bytes(single_col_csv)
    assert [i.raw_value for i in items] == ["8.8.8.8", "example.com"]

    with pytest.raises(CSVLoaderError):
        load_iocs_from_csv("data/does_not_exist.csv")

    bad_headers = b"col_a,col_b\nfoo,bar\n"
    with pytest.raises(CSVLoaderError):
        load_iocs_from_csv_bytes(bad_headers)


def test_load_iocs_from_text_skips_comments_and_blanks() -> None:
    raw = """
    # IOCs from SIEM ticket INC-1042
    198.51.100.23

    hxxps://evil[.]example[.]com/drop
    # trailing comment
    """
    items = load_iocs_from_text(raw, source_hint="Ticket INC-1042")
    assert len(items) == 2
    assert items[0].source_hint == "Ticket INC-1042"
    assert items[1].raw_value == "hxxps://evil[.]example[.]com/drop"

