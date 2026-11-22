"""CSV and bulk-text IOC collectors for manual input and offline datasets."""

from __future__ import annotations

import io
from pathlib import Path
from typing import BinaryIO, TextIO

import pandas as pd

from app.schemas import IOCInput

_CANDIDATE_IOC_COLUMNS: tuple[str, ...] = (
    "ioc",
    "indicator",
    "value",
    "observable",
    "artifact",
)
_CANDIDATE_SOURCE_COLUMNS: tuple[str, ...] = ("source", "source_hint", "feed")
_CANDIDATE_TAG_COLUMNS: tuple[str, ...] = ("tags", "tag", "category")


class CSVLoaderError(ValueError):
    """Raised when an IOC CSV source cannot be read or lacks an IOC column."""


def _find_column(columns_lower: dict[str, str], candidates: tuple[str, ...]) -> str | None:
    for candidate in candidates:
        if candidate in columns_lower:
            return columns_lower[candidate]
    return None


def _parse_tags(raw_tags: object) -> list[str]:
    if raw_tags is None or pd.isna(raw_tags):
        return []
    text = str(raw_tags).strip()
    if not text:
        return []
    parts = [part.strip() for part in text.replace(";", ",").split(",")]
    return [part for part in parts if part]


def _dataframe_to_inputs(
    df: pd.DataFrame,
    ioc_column: str | None = None,
    default_source_hint: str = "CSV Dataset",
) -> list[IOCInput]:
    if df.empty:
        return []

    columns_lower = {str(col).strip().lower(): str(col) for col in df.columns}
    if ioc_column is not None:
        resolved_ioc_col = columns_lower.get(ioc_column.strip().lower())
        if resolved_ioc_col is None:
            raise CSVLoaderError(
                f"Specified IOC column '{ioc_column}' not found. "
                f"Available columns: {list(df.columns)}"
            )
    else:
        resolved_ioc_col = _find_column(columns_lower, _CANDIDATE_IOC_COLUMNS)
        if resolved_ioc_col is None:
            if len(df.columns) == 1:
                resolved_ioc_col = str(df.columns[0])
            else:
                raise CSVLoaderError(
                    "Could not detect IOC column. Expected one of "
                    f"{list(_CANDIDATE_IOC_COLUMNS)} but found {list(df.columns)}."
                )

    source_col = _find_column(columns_lower, _CANDIDATE_SOURCE_COLUMNS)
    tag_col = _find_column(columns_lower, _CANDIDATE_TAG_COLUMNS)

    inputs: list[IOCInput] = []
    for _, row in df.iterrows():
        raw_val = row[resolved_ioc_col]
        if raw_val is None or pd.isna(raw_val):
            continue
        val_str = str(raw_val).strip()
        if not val_str:
            continue

        source_hint = default_source_hint
        if source_col is not None and not pd.isna(row[source_col]):
            src_str = str(row[source_col]).strip()
            if src_str:
                source_hint = src_str

        tags = _parse_tags(row[tag_col]) if tag_col is not None else []
        inputs.append(IOCInput(raw_value=val_str, source_hint=source_hint, tags=tags))

    return inputs


def load_iocs_from_csv(
    source: Path | str | TextIO | BinaryIO,
    ioc_column: str | None = None,
    default_source_hint: str = "CSV Dataset",
) -> list[IOCInput]:
    """Load IOC inputs from a CSV file path or file-like object using pandas."""
    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.exists():
            raise CSVLoaderError(f"CSV file not found: {path}")
        if path.stat().st_size == 0:
            return []
        try:
            df = pd.read_csv(path, dtype=str, encoding="utf-8-sig", keep_default_na=True)
        except pd.errors.EmptyDataError:
            return []
        except Exception as exc:
            raise CSVLoaderError(f"Failed to parse CSV '{path}': {exc}") from exc
    else:
        try:
            df = pd.read_csv(source, dtype=str, encoding="utf-8-sig", keep_default_na=True)
        except pd.errors.EmptyDataError:
            return []
        except Exception as exc:
            raise CSVLoaderError(f"Failed to parse uploaded CSV: {exc}") from exc

    return _dataframe_to_inputs(
        df,
        ioc_column=ioc_column,
        default_source_hint=default_source_hint,
    )


def load_iocs_from_csv_bytes(
    content: bytes,
    ioc_column: str | None = None,
    default_source_hint: str = "CSV Upload",
) -> list[IOCInput]:
    """Load IOC inputs from raw CSV bytes (e.g., Streamlit file uploader)."""
    if not content or not content.strip():
        return []
    return load_iocs_from_csv(
        io.BytesIO(content),
        ioc_column=ioc_column,
        default_source_hint=default_source_hint,
    )


def load_iocs_from_text(
    raw_text: str,
    source_hint: str = "Manual Input",
) -> list[IOCInput]:
    """Parse newline-separated IOCs from analyst bulk paste, ignoring blanks and # comments."""
    inputs: list[IOCInput] = []
    for line in raw_text.splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        inputs.append(IOCInput(raw_value=cleaned, source_hint=source_hint))
    return inputs
