"""SOC Log IOC Matcher for correlating collected IOCs against Firewall/DNS/Proxy/EDR logs."""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from app.database.repository import ThreatIntelRepository
from app.processors.normalizer import normalize_ioc
from app.processors.validator import IOCValidationError
from app.schemas import IndicatorRecord, IOCType, LogMatch, RiskLevel, utc_now

_RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}

_URL_RE = re.compile(r"https?://[^\s\"',;<>]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32}(?:[0-9a-fA-F]{8})?(?:[0-9a-fA-F]{24})?\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)

_TIMESTAMP_FIELDS: tuple[str, ...] = ("timestamp", "time", "datetime", "event_time", "ts")
_SOURCE_FIELDS: tuple[str, ...] = ("log_source", "source", "device", "sensor", "log_type")


class LogMatchSummary(BaseModel):
    """Summary of matching collected IOCs against a SOC log dataset."""

    total_records_scanned: int = 0
    total_matches: int = 0
    unique_iocs_matched: int = 0
    matches: list[LogMatch] = Field(default_factory=list)


class SOCLogMatcher:
    """Correlates structured CSV/JSONL or raw text SOC logs against stored IOCs."""

    def __init__(self, repo: ThreatIntelRepository) -> None:
        self.repo = repo

    def _build_indicator_index(
        self, min_risk_level: RiskLevel | None = None
    ) -> tuple[dict[str, IndicatorRecord], dict[int, RiskLevel | None]]:
        """Build O(1) normalized_value -> IndicatorRecord index filtered by risk level."""
        reports = self.repo.list_latest_reports(limit=10000)
        risk_by_ind_id: dict[int, RiskLevel | None] = {
            r.indicator.id: r.risk_level for r in reports
        }

        indicators = self.repo.list_indicators(limit=10000)
        index: dict[str, IndicatorRecord] = {}
        min_rank = _RISK_ORDER[min_risk_level] if min_risk_level is not None else -1

        for ind in indicators:
            ind_risk = risk_by_ind_id.get(ind.id)
            if min_risk_level is not None:
                if ind_risk is None or _RISK_ORDER[ind_risk] < min_rank:
                    continue
            index[ind.normalized_value.lower()] = ind

        return index, risk_by_ind_id

    @staticmethod
    def _extract_candidates_from_value(raw_val: str) -> list[str]:
        """Extract normalized candidate keys (including host extracted from URLs)."""
        cleaned = raw_val.strip()
        if not cleaned:
            return []

        candidates: list[str] = []

        # Attempt direct normalization first for structured fields
        try:
            ioc = normalize_ioc(cleaned)
            candidates.append(ioc.normalized_value.lower())
            if ioc.ioc_type == IOCType.URL:
                host = (urlsplit(ioc.normalized_value).hostname or "").lower().rstrip(".")
                if host:
                    candidates.append(host)
            return list(dict.fromkeys(candidates))
        except IOCValidationError:
            pass

        # Fallback token extraction for free-form log lines / messages
        for url_match in _URL_RE.findall(cleaned):
            try:
                norm_url = normalize_ioc(url_match)
                candidates.append(norm_url.normalized_value.lower())
                host = (urlsplit(norm_url.normalized_value).hostname or "").lower().rstrip(".")
                if host:
                    candidates.append(host)
            except IOCValidationError:
                pass

        for token in (
            *_IPV4_RE.findall(cleaned),
            *_HASH_RE.findall(cleaned),
            *_DOMAIN_RE.findall(cleaned),
        ):
            candidates.append(token.lower().rstrip("."))

        return list(dict.fromkeys(candidates))

    def match_csv_text(
        self,
        csv_text: str,
        default_log_source: str = "soc_log.csv",
        min_risk_level: RiskLevel | None = None,
        persist: bool = True,
    ) -> LogMatchSummary:
        """Scan structured CSV logs against collected IOCs in SQLite."""
        index, risk_by_id = self._build_indicator_index(min_risk_level=min_risk_level)
        reader = csv.DictReader(io.StringIO(csv_text.lstrip("\ufeff")))
        matches: list[LogMatch] = []
        scanned = 0

        for row in reader:
            scanned += 1
            if not index:
                continue

            lower_map = {str(k).strip().lower(): k for k in row if k is not None}
            log_ts = next(
                (str(row[lower_map[f]]).strip() for f in _TIMESTAMP_FIELDS if f in lower_map),
                None,
            )
            log_src = (
                next(
                    (
                        str(row[lower_map[f]]).strip()
                        for f in _SOURCE_FIELDS
                        if f in lower_map and str(row[lower_map[f]]).strip()
                    ),
                    default_log_source,
                )
                or default_log_source
            )
            raw_line = ",".join(str(v or "") for v in row.values())

            matched_in_row: set[tuple[int, str]] = set()
            for field_name, field_val in row.items():
                if not field_name or not field_val:
                    continue
                for candidate in self._extract_candidates_from_value(str(field_val)):
                    indicator = index.get(candidate)
                    if indicator is None:
                        continue
                    dedupe_key = (indicator.id, field_name)
                    if dedupe_key in matched_in_row:
                        continue
                    matched_in_row.add(dedupe_key)

                    match = LogMatch(
                        indicator_id=indicator.id,
                        indicator_value=indicator.normalized_value,
                        indicator_type=indicator.ioc_type,
                        risk_level=risk_by_id.get(indicator.id),
                        log_source=log_src,
                        log_timestamp=log_ts or None,
                        matched_field=field_name,
                        raw_log_line=raw_line[:500],
                        matched_at=utc_now(),
                    )
                    if persist:
                        match.id = self.repo.save_log_match(match)
                    matches.append(match)

        unique_ids = {m.indicator_id for m in matches}
        return LogMatchSummary(
            total_records_scanned=scanned,
            total_matches=len(matches),
            unique_iocs_matched=len(unique_ids),
            matches=matches,
        )

    def match_lines(
        self,
        text: str,
        log_source: str = "raw_log",
        min_risk_level: RiskLevel | None = None,
        persist: bool = True,
    ) -> LogMatchSummary:
        """Scan JSONL or plain-text log lines against collected IOCs."""
        index, risk_by_id = self._build_indicator_index(min_risk_level=min_risk_level)
        matches: list[LogMatch] = []
        scanned = 0

        for line in text.splitlines():
            cleaned = line.strip()
            if not cleaned:
                continue
            scanned += 1
            if not index:
                continue

            # Check if line is a JSON object
            parsed_obj: dict[str, object] | None = None
            if cleaned.startswith("{") and cleaned.endswith("}"):
                try:
                    loaded = json.loads(cleaned)
                    if isinstance(loaded, dict):
                        parsed_obj = loaded
                except ValueError:
                    parsed_obj = None

            if parsed_obj is not None:
                log_ts = next(
                    (str(parsed_obj[f]) for f in _TIMESTAMP_FIELDS if f in parsed_obj),
                    None,
                )
                line_src = next(
                    (str(parsed_obj[f]) for f in _SOURCE_FIELDS if f in parsed_obj),
                    log_source,
                )
                seen_ids: set[int] = set()
                for key, val in parsed_obj.items():
                    if val is None:
                        continue
                    for candidate in self._extract_candidates_from_value(str(val)):
                        indicator = index.get(candidate)
                        if indicator is not None and indicator.id not in seen_ids:
                            seen_ids.add(indicator.id)
                            match = LogMatch(
                                indicator_id=indicator.id,
                                indicator_value=indicator.normalized_value,
                                indicator_type=indicator.ioc_type,
                                risk_level=risk_by_id.get(indicator.id),
                                log_source=line_src,
                                log_timestamp=log_ts,
                                matched_field=str(key),
                                raw_log_line=cleaned[:500],
                                matched_at=utc_now(),
                            )
                            if persist:
                                match.id = self.repo.save_log_match(match)
                            matches.append(match)
            else:
                seen_ids = set()
                for candidate in self._extract_candidates_from_value(cleaned):
                    indicator = index.get(candidate)
                    if indicator is not None and indicator.id not in seen_ids:
                        seen_ids.add(indicator.id)
                        match = LogMatch(
                            indicator_id=indicator.id,
                            indicator_value=indicator.normalized_value,
                            indicator_type=indicator.ioc_type,
                            risk_level=risk_by_id.get(indicator.id),
                            log_source=log_source,
                            log_timestamp=None,
                            matched_field="raw_line",
                            raw_log_line=cleaned[:500],
                            matched_at=utc_now(),
                        )
                        if persist:
                            match.id = self.repo.save_log_match(match)
                        matches.append(match)

        return LogMatchSummary(
            total_records_scanned=scanned,
            total_matches=len(matches),
            unique_iocs_matched=len({m.indicator_id for m in matches}),
            matches=matches,
        )

    def match_file(
        self,
        log_path: Path | str,
        min_risk_level: RiskLevel | None = None,
        persist: bool = True,
    ) -> LogMatchSummary:
        """Auto-detect CSV vs JSONL/plain-text log file and match against stored IOCs."""
        path = Path(log_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")
        content = path.read_text(encoding="utf-8-sig")
        if path.suffix.lower() == ".csv":
            return self.match_csv_text(
                content,
                default_log_source=path.name,
                min_risk_level=min_risk_level,
                persist=persist,
            )
        return self.match_lines(
            content,
            log_source=path.name,
            min_risk_level=min_risk_level,
            persist=persist,
        )

