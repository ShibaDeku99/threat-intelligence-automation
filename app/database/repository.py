"""SQLite repository for indicators, enrichment results, reports, ATT&CK, and telemetry."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.database.models import apply_schema
from app.schemas import (
    AttackTechnique,
    Classification,
    EnrichmentEvidence,
    EnrichmentStatus,
    IndicatorRecord,
    IOCType,
    LogMatch,
    NormalizedIOC,
    RiskLevel,
    ScoreBreakdown,
    SourceMetrics,
    SourceRecord,
    SystemMetrics,
    TechniqueMapping,
    ThreatReport,
    utc_now,
)

CACHEABLE_STATUSES: frozenset[str] = frozenset(
    {
        EnrichmentStatus.OK.value,
        EnrichmentStatus.NOT_FOUND.value,
        EnrichmentStatus.UNSUPPORTED_TYPE.value,
    }
)


def _dt_to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    else:
        value = value.astimezone(UTC)
    return value.isoformat()


def _iso_to_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _earlier_dt(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if a <= b else b


def _later_dt(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if a >= b else b


class ThreatIntelRepository:
    """Data-access layer backed by SQLite with deduplication and telemetry queries."""

    def __init__(self, db_path: Path | str = "data/threat_intel.db") -> None:
        self._db_path_str = str(db_path)
        self._is_memory = self._db_path_str == ":memory:"
        self._memory_conn: sqlite3.Connection | None = None
        self.initialize()

    def _create_connection(self) -> sqlite3.Connection:
        if not self._is_memory:
            Path(self._db_path_str).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path_str, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        if not self._is_memory:
            conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if self._is_memory:
            if self._memory_conn is None:
                self._memory_conn = self._create_connection()
            try:
                yield self._memory_conn
                self._memory_conn.commit()
            except Exception:
                self._memory_conn.rollback()
                raise
        else:
            conn = self._create_connection()
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def initialize(self) -> None:
        """Create database tables, indexes, and seed default sources."""
        with self._connection() as conn:
            apply_schema(conn)

    def close(self) -> None:
        """Close persistent in-memory connection if open."""
        if self._memory_conn is not None:
            self._memory_conn.close()
            self._memory_conn = None

    # ------------------------------------------------------------------
    # Sources
    # ------------------------------------------------------------------
    def get_or_create_source(
        self,
        name: str,
        source_url: str,
        reliability_weight: int = 20,
        enabled: bool = True,
    ) -> SourceRecord:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO sources (name, source_url, reliability_weight, enabled)
                VALUES (?, ?, ?, ?)
                """,
                (name, source_url, reliability_weight, int(enabled)),
            )
            row = conn.execute(
                """
                SELECT id, name, source_url, reliability_weight, enabled
                FROM sources
                WHERE name = ?
                """,
                (name,),
            ).fetchone()
            assert row is not None
            return self._row_to_source(row)

    def get_source_by_name(self, name: str) -> SourceRecord | None:
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT id, name, source_url, reliability_weight, enabled
                FROM sources
                WHERE name = ?
                """,
                (name,),
            ).fetchone()
            return self._row_to_source(row) if row else None

    def list_sources(self) -> list[SourceRecord]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, name, source_url, reliability_weight, enabled
                FROM sources
                ORDER BY id ASC
                """
            ).fetchall()
            return [self._row_to_source(row) for row in rows]

    # ------------------------------------------------------------------
    # Indicators (with DB-level deduplication)
    # ------------------------------------------------------------------
    def upsert_indicator(
        self,
        ioc: NormalizedIOC,
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
    ) -> tuple[IndicatorRecord, bool]:
        """Insert a new indicator or update an existing deduplicated indicator.

        Returns:
            (IndicatorRecord, is_new) where is_new is True if inserted, False if deduplicated.
        """
        now_iso = _dt_to_iso(utc_now())
        assert now_iso is not None
        with self._connection() as conn:
            existing = conn.execute(
                """
                SELECT * FROM indicators
                WHERE normalized_value = ? AND type = ?
                """,
                (ioc.normalized_value, ioc.ioc_type.value),
            ).fetchone()

            if existing is None:
                cursor = conn.execute(
                    """
                    INSERT INTO indicators (
                        value, normalized_value, type, raw_input,
                        is_reserved_ip, ip_scope_note,
                        first_seen, last_seen, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ioc.value,
                        ioc.normalized_value,
                        ioc.ioc_type.value,
                        ioc.raw_input,
                        int(ioc.is_reserved_ip),
                        ioc.ip_scope_note,
                        _dt_to_iso(first_seen),
                        _dt_to_iso(last_seen),
                        now_iso,
                        now_iso,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM indicators WHERE id = ?", (cursor.lastrowid,)
                ).fetchone()
                assert row is not None
                return self._row_to_indicator(row), True

            merged_first = _earlier_dt(_iso_to_dt(existing["first_seen"]), first_seen)
            merged_last = _later_dt(_iso_to_dt(existing["last_seen"]), last_seen)
            conn.execute(
                """
                UPDATE indicators
                SET first_seen = ?,
                    last_seen = ?,
                    is_reserved_ip = ?,
                    ip_scope_note = COALESCE(?, ip_scope_note),
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    _dt_to_iso(merged_first),
                    _dt_to_iso(merged_last),
                    int(bool(existing["is_reserved_ip"]) or ioc.is_reserved_ip),
                    ioc.ip_scope_note,
                    now_iso,
                    existing["id"],
                ),
            )
            row = conn.execute(
                "SELECT * FROM indicators WHERE id = ?", (existing["id"],)
            ).fetchone()
            assert row is not None
            return self._row_to_indicator(row), False

    def get_indicator_by_id(self, indicator_id: int) -> IndicatorRecord | None:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM indicators WHERE id = ?", (indicator_id,)
            ).fetchone()
            return self._row_to_indicator(row) if row else None

    def get_indicator(self, normalized_value: str, ioc_type: IOCType) -> IndicatorRecord | None:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM indicators WHERE normalized_value = ? AND type = ?",
                (normalized_value, ioc_type.value),
            ).fetchone()
            return self._row_to_indicator(row) if row else None

    def list_indicators(
        self,
        ioc_type: IOCType | None = None,
        search: str | None = None,
        limit: int = 100,
    ) -> list[IndicatorRecord]:
        clauses: list[str] = []
        params: list[object] = []
        if ioc_type is not None:
            clauses.append("type = ?")
            params.append(ioc_type.value)
        if search:
            clauses.append("(normalized_value LIKE ? OR value LIKE ?)")
            pattern = f"%{search.strip()}%"
            params.extend([pattern, pattern])
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM indicators {where_sql} ORDER BY updated_at DESC LIMIT ?",
                params,
            ).fetchall()
            return [self._row_to_indicator(row) for row in rows]

    # ------------------------------------------------------------------
    # Enrichment Results & TTL Cache
    # ------------------------------------------------------------------
    def save_enrichment_result(
        self, indicator_id: int, evidence: EnrichmentEvidence
    ) -> int:
        """Persist a source enrichment record and update indicator source timestamps."""
        source = self.get_or_create_source(
            name=evidence.source_name,
            source_url=evidence.source_url or "unknown://source",
        )
        payload = {
            "pulse_count": evidence.pulse_count,
            "threat_types": evidence.threat_types,
            "malware_families": evidence.malware_families,
            "tags": evidence.tags,
            "attack_ids": evidence.attack_ids,
            "references": evidence.references,
            "raw_result": evidence.raw_result,
        }
        is_active_int = None if evidence.is_active is None else int(evidence.is_active)
        retrieved_iso = _dt_to_iso(evidence.retrieved_at)
        assert retrieved_iso is not None

        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO enrichment_results (
                    indicator_id, source_id, status, is_malicious_signal,
                    is_active, result_json, source_first_seen, source_last_seen,
                    latency_ms, error_message, retrieved_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    indicator_id,
                    source.id,
                    evidence.status.value,
                    int(evidence.is_malicious_signal),
                    is_active_int,
                    json.dumps(payload, ensure_ascii=False),
                    _dt_to_iso(evidence.source_first_seen),
                    _dt_to_iso(evidence.source_last_seen),
                    evidence.latency_ms,
                    evidence.error_message,
                    retrieved_iso,
                ),
            )

            # Update indicator first_seen/last_seen ONLY from TI source timestamps,
            # never from retrieved_at.
            if evidence.source_first_seen is not None or evidence.source_last_seen is not None:
                ind = conn.execute(
                    "SELECT first_seen, last_seen FROM indicators WHERE id = ?",
                    (indicator_id,),
                ).fetchone()
                if ind is not None:
                    merged_first = _earlier_dt(
                        _iso_to_dt(ind["first_seen"]), evidence.source_first_seen
                    )
                    merged_last = _later_dt(
                        _iso_to_dt(ind["last_seen"]), evidence.source_last_seen
                    )
                    conn.execute(
                        """
                        UPDATE indicators
                        SET first_seen = ?, last_seen = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            _dt_to_iso(merged_first),
                            _dt_to_iso(merged_last),
                            _dt_to_iso(utc_now()),
                            indicator_id,
                        ),
                    )
            assert cursor.lastrowid is not None
            return int(cursor.lastrowid)

    def get_fresh_enrichment(
        self,
        indicator_id: int,
        source_name: str,
        ttl_hours: int,
    ) -> EnrichmentEvidence | None:
        """Return a cached enrichment result if within TTL and cacheable."""
        if ttl_hours <= 0:
            return None
        cutoff = utc_now() - timedelta(hours=ttl_hours)
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT er.*, s.name AS source_name, s.source_url AS source_url
                FROM enrichment_results er
                JOIN sources s ON s.id = er.source_id
                WHERE er.indicator_id = ? AND s.name = ?
                ORDER BY er.retrieved_at DESC, er.id DESC
                LIMIT 1
                """,
                (indicator_id, source_name),
            ).fetchone()
            if row is None:
                return None
            if row["status"] not in CACHEABLE_STATUSES:
                return None
            retrieved_dt = _iso_to_dt(row["retrieved_at"])
            if retrieved_dt is None or retrieved_dt < cutoff:
                return None
            evidence = self._row_to_enrichment(row)
            evidence.from_cache = True
            return evidence

    def get_enrichment_results(
        self, indicator_id: int, latest_per_source: bool = True
    ) -> list[EnrichmentEvidence]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT er.*, s.name AS source_name, s.source_url AS source_url
                FROM enrichment_results er
                JOIN sources s ON s.id = er.source_id
                WHERE er.indicator_id = ?
                ORDER BY er.retrieved_at DESC, er.id DESC
                """,
                (indicator_id,),
            ).fetchall()

        results = [self._row_to_enrichment(row) for row in rows]
        if not latest_per_source:
            return results

        seen_sources: set[str] = set()
        latest: list[EnrichmentEvidence] = []
        for item in results:
            if item.source_name not in seen_sources:
                seen_sources.add(item.source_name)
                latest.append(item)
        return latest

    # ------------------------------------------------------------------
    # MITRE ATT&CK Techniques
    # ------------------------------------------------------------------
    def upsert_attack_technique(self, technique: AttackTechnique) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO attack_techniques (technique_id, name, tactic, description, url)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(technique_id) DO UPDATE SET
                    name = excluded.name,
                    tactic = excluded.tactic,
                    description = excluded.description,
                    url = excluded.url
                """,
                (
                    technique.technique_id,
                    technique.name,
                    technique.tactic,
                    technique.description,
                    technique.url,
                ),
            )

    def link_indicator_technique(
        self, indicator_id: int, mapping: TechniqueMapping
    ) -> None:
        self.upsert_attack_technique(mapping.technique)
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO indicator_attack_techniques (
                    indicator_id, technique_id, source_name, evidence, confidence, matched_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(indicator_id, technique_id, source_name) DO UPDATE SET
                    evidence = excluded.evidence,
                    confidence = excluded.confidence,
                    matched_at = excluded.matched_at
                """,
                (
                    indicator_id,
                    mapping.technique.technique_id,
                    mapping.source_name,
                    mapping.evidence,
                    mapping.confidence,
                    _dt_to_iso(mapping.matched_at),
                ),
            )

    def get_indicator_techniques(self, indicator_id: int) -> list[TechniqueMapping]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT
                    iat.source_name, iat.evidence, iat.confidence, iat.matched_at,
                    at.technique_id, at.name, at.tactic, at.description, at.url
                FROM indicator_attack_techniques iat
                JOIN attack_techniques at ON at.technique_id = iat.technique_id
                WHERE iat.indicator_id = ?
                ORDER BY at.technique_id ASC
                """,
                (indicator_id,),
            ).fetchall()
        return [
            TechniqueMapping(
                technique=AttackTechnique(
                    technique_id=row["technique_id"],
                    name=row["name"],
                    tactic=row["tactic"],
                    description=row["description"],
                    url=row["url"],
                ),
                source_name=row["source_name"],
                evidence=row["evidence"],
                confidence=row["confidence"],
                matched_at=_iso_to_dt(row["matched_at"]) or utc_now(),
            )
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Threat Reports
    # ------------------------------------------------------------------
    def save_threat_report(self, report: ThreatReport) -> int:
        generated_iso = _dt_to_iso(report.generated_at)
        assert generated_iso is not None
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO threat_reports (
                    indicator_id, risk_score, confidence_score, risk_level,
                    classification, score_breakdown_json, threat_types_json,
                    sources_checked, sources_with_evidence, summary,
                    recommended_actions_json, generated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.indicator.id,
                    report.risk_score,
                    report.confidence_score,
                    report.risk_level.value,
                    report.classification.value,
                    report.score_breakdown.model_dump_json(
                        include={
                            "source_reliability",
                            "independent_sources",
                            "recency",
                            "activity_status",
                        }
                    ),
                    json.dumps(report.threat_types, ensure_ascii=False),
                    report.sources_checked,
                    report.sources_with_evidence,
                    report.summary,
                    json.dumps(report.recommended_actions, ensure_ascii=False),
                    generated_iso,
                ),
            )
            assert cursor.lastrowid is not None
            return int(cursor.lastrowid)

    def get_latest_threat_report(self, indicator_id: int) -> ThreatReport | None:
        indicator = self.get_indicator_by_id(indicator_id)
        if indicator is None:
            return None
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM threat_reports
                WHERE indicator_id = ?
                ORDER BY generated_at DESC, id DESC
                LIMIT 1
                """,
                (indicator_id,),
            ).fetchone()
        if row is None:
            return None
        return self._hydrate_report(row, indicator)

    def list_latest_reports(
        self,
        risk_level: RiskLevel | None = None,
        ioc_type: IOCType | None = None,
        search: str | None = None,
        limit: int = 100,
    ) -> list[ThreatReport]:
        """List the most recent ThreatReport for each indicator with optional filters."""
        clauses: list[str] = []
        params: list[object] = []
        if risk_level is not None:
            clauses.append("tr.risk_level = ?")
            params.append(risk_level.value)
        if ioc_type is not None:
            clauses.append("i.type = ?")
            params.append(ioc_type.value)
        if search:
            clauses.append("(i.normalized_value LIKE ? OR i.value LIKE ? OR tr.summary LIKE ?)")
            pattern = f"%{search.strip()}%"
            params.extend([pattern, pattern, pattern])

        extra_where = f"AND {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)

        query = f"""
            SELECT tr.*, i.id AS ind_id, i.value AS ind_value,
                   i.normalized_value AS ind_normalized_value, i.type AS ind_type,
                   i.raw_input AS ind_raw_input, i.is_reserved_ip AS ind_is_reserved_ip,
                   i.ip_scope_note AS ind_ip_scope_note,
                   i.first_seen AS ind_first_seen, i.last_seen AS ind_last_seen,
                   i.created_at AS ind_created_at, i.updated_at AS ind_updated_at
            FROM threat_reports tr
            JOIN indicators i ON i.id = tr.indicator_id
            WHERE tr.id IN (
                SELECT MAX(id) FROM threat_reports GROUP BY indicator_id
            )
            {extra_where}
            ORDER BY tr.risk_score DESC, tr.generated_at DESC
            LIMIT ?
        """
        with self._connection() as conn:
            rows = conn.execute(query, params).fetchall()

        reports: list[ThreatReport] = []
        for row in rows:
            indicator = IndicatorRecord(
                id=row["ind_id"],
                value=row["ind_value"],
                normalized_value=row["ind_normalized_value"],
                ioc_type=IOCType(row["ind_type"]),
                raw_input=row["ind_raw_input"],
                is_reserved_ip=bool(row["ind_is_reserved_ip"]),
                ip_scope_note=row["ind_ip_scope_note"],
                first_seen=_iso_to_dt(row["ind_first_seen"]),
                last_seen=_iso_to_dt(row["ind_last_seen"]),
                created_at=_iso_to_dt(row["ind_created_at"]) or utc_now(),
                updated_at=_iso_to_dt(row["ind_updated_at"]) or utc_now(),
            )
            reports.append(self._hydrate_report(row, indicator))
        return reports

    # ------------------------------------------------------------------
    # SOC Log Matches
    # ------------------------------------------------------------------
    def save_log_match(self, match: LogMatch) -> int:
        matched_iso = _dt_to_iso(match.matched_at)
        assert matched_iso is not None
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO log_matches (
                    indicator_id, log_source, log_timestamp,
                    matched_field, raw_log_line, matched_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    match.indicator_id,
                    match.log_source,
                    match.log_timestamp,
                    match.matched_field,
                    match.raw_log_line,
                    matched_iso,
                ),
            )
            assert cursor.lastrowid is not None
            return int(cursor.lastrowid)

    def list_log_matches(self, limit: int = 200) -> list[LogMatch]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT
                    lm.*,
                    i.normalized_value AS ind_value,
                    i.type AS ind_type,
                    (
                        SELECT tr.risk_level
                        FROM threat_reports tr
                        WHERE tr.indicator_id = lm.indicator_id
                        ORDER BY tr.generated_at DESC, tr.id DESC
                        LIMIT 1
                    ) AS latest_risk_level
                FROM log_matches lm
                JOIN indicators i ON i.id = lm.indicator_id
                ORDER BY lm.matched_at DESC, lm.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            LogMatch(
                id=row["id"],
                indicator_id=row["indicator_id"],
                indicator_value=row["ind_value"],
                indicator_type=IOCType(row["ind_type"]),
                risk_level=RiskLevel(row["latest_risk_level"])
                if row["latest_risk_level"]
                else None,
                log_source=row["log_source"],
                log_timestamp=row["log_timestamp"],
                matched_field=row["matched_field"],
                raw_log_line=row["raw_log_line"],
                matched_at=_iso_to_dt(row["matched_at"]) or utc_now(),
            )
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Measured Telemetry & Evaluation Metrics
    # ------------------------------------------------------------------
    def get_system_metrics(self) -> SystemMetrics:
        with self._connection() as conn:
            total_indicators = conn.execute(
                "SELECT COUNT(*) FROM indicators"
            ).fetchone()[0]
            total_reports = conn.execute(
                "SELECT COUNT(*) FROM threat_reports"
            ).fetchone()[0]
            total_enrichments = conn.execute(
                "SELECT COUNT(*) FROM enrichment_results"
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT type, COUNT(*) AS cnt FROM indicators GROUP BY type"
            ).fetchall()
            type_distribution = {row["type"]: int(row["cnt"]) for row in type_rows}

            risk_rows = conn.execute(
                """
                SELECT risk_level, COUNT(*) AS cnt
                FROM threat_reports
                WHERE id IN (SELECT MAX(id) FROM threat_reports GROUP BY indicator_id)
                GROUP BY risk_level
                """
            ).fetchall()
            risk_distribution = {row["risk_level"]: int(row["cnt"]) for row in risk_rows}

            source_rows = conn.execute(
                """
                SELECT
                    s.name AS source_name,
                    COUNT(er.id) AS total_queries,
                    SUM(CASE WHEN er.status = 'ok' THEN 1 ELSE 0 END) AS ok_count,
                    SUM(CASE WHEN er.status = 'not_found' THEN 1 ELSE 0 END) AS not_found_count,
                    SUM(CASE WHEN er.status = 'error' THEN 1 ELSE 0 END) AS error_count,
                    SUM(CASE WHEN er.status = 'timeout' THEN 1 ELSE 0 END) AS timeout_count,
                    SUM(
                        CASE WHEN er.status = 'skipped_no_key' THEN 1 ELSE 0 END
                    ) AS skipped_count,
                    SUM(
                        CASE WHEN er.status = 'unsupported_type' THEN 1 ELSE 0 END
                    ) AS unsupported_count,
                    AVG(CASE WHEN er.status IN ('ok', 'not_found', 'error', 'timeout')
                        THEN er.latency_ms END) AS avg_latency_ms
                FROM enrichment_results er
                JOIN sources s ON s.id = er.source_id
                GROUP BY s.name
                ORDER BY s.name ASC
                """
            ).fetchall()

            overall_row = conn.execute(
                """
                SELECT
                    SUM(CASE WHEN status IN ('ok', 'not_found') THEN 1 ELSE 0 END) AS success_cnt,
                    SUM(CASE WHEN status IN ('error', 'timeout') THEN 1 ELSE 0 END) AS fail_cnt,
                    AVG(CASE WHEN status IN ('ok', 'not_found', 'error', 'timeout')
                        THEN latency_ms END) AS avg_latency_ms
                FROM enrichment_results
                """
            ).fetchone()

        by_source: list[SourceMetrics] = []
        for row in source_rows:
            ok_c = int(row["ok_count"] or 0)
            nf_c = int(row["not_found_count"] or 0)
            err_c = int(row["error_count"] or 0)
            to_c = int(row["timeout_count"] or 0)
            attempted = ok_c + nf_c + err_c + to_c
            fail_rate = round(((err_c + to_c) / attempted) * 100.0, 2) if attempted else 0.0
            by_source.append(
                SourceMetrics(
                    source_name=row["source_name"],
                    total_queries=int(row["total_queries"]),
                    ok_count=ok_c,
                    not_found_count=nf_c,
                    error_count=err_c,
                    timeout_count=to_c,
                    skipped_count=int(row["skipped_count"] or 0),
                    unsupported_count=int(row["unsupported_count"] or 0),
                    avg_latency_ms=round(float(row["avg_latency_ms"] or 0.0), 2),
                    api_failure_rate=fail_rate,
                )
            )

        success_cnt = int(overall_row["success_cnt"] or 0) if overall_row else 0
        fail_cnt = int(overall_row["fail_cnt"] or 0) if overall_row else 0
        attempted_total = success_cnt + fail_cnt
        enrichment_success_rate = (
            round((success_cnt / attempted_total) * 100.0, 2) if attempted_total else 0.0
        )
        api_failure_rate = (
            round((fail_cnt / attempted_total) * 100.0, 2) if attempted_total else 0.0
        )
        avg_latency = (
            round(float(overall_row["avg_latency_ms"] or 0.0), 2) if overall_row else 0.0
        )

        return SystemMetrics(
            total_indicators=int(total_indicators),
            total_reports=int(total_reports),
            total_enrichments=int(total_enrichments),
            enrichment_success_rate=enrichment_success_rate,
            api_failure_rate=api_failure_rate,
            avg_latency_ms=avg_latency,
            risk_distribution=risk_distribution,
            type_distribution=type_distribution,
            by_source=by_source,
        )

    # ------------------------------------------------------------------
    # Row Hydrators
    # ------------------------------------------------------------------
    @staticmethod
    def _row_to_source(row: sqlite3.Row) -> SourceRecord:
        return SourceRecord(
            id=int(row["id"]),
            name=row["name"],
            source_url=row["source_url"],
            reliability_weight=int(row["reliability_weight"]),
            enabled=bool(row["enabled"]),
        )

    @staticmethod
    def _row_to_indicator(row: sqlite3.Row) -> IndicatorRecord:
        return IndicatorRecord(
            id=int(row["id"]),
            value=row["value"],
            normalized_value=row["normalized_value"],
            ioc_type=IOCType(row["type"]),
            raw_input=row["raw_input"],
            is_reserved_ip=bool(row["is_reserved_ip"]),
            ip_scope_note=row["ip_scope_note"],
            first_seen=_iso_to_dt(row["first_seen"]),
            last_seen=_iso_to_dt(row["last_seen"]),
            created_at=_iso_to_dt(row["created_at"]) or utc_now(),
            updated_at=_iso_to_dt(row["updated_at"]) or utc_now(),
        )

    @staticmethod
    def _row_to_enrichment(row: sqlite3.Row) -> EnrichmentEvidence:
        payload = json.loads(row["result_json"]) if row["result_json"] else {}
        is_active_val = row["is_active"]
        return EnrichmentEvidence(
            id=int(row["id"]),
            indicator_id=int(row["indicator_id"]),
            source_name=row["source_name"],
            source_url=row["source_url"],
            status=EnrichmentStatus(row["status"]),
            is_malicious_signal=bool(row["is_malicious_signal"]),
            is_active=None if is_active_val is None else bool(is_active_val),
            pulse_count=int(payload.get("pulse_count", 0)),
            threat_types=list(payload.get("threat_types", [])),
            malware_families=list(payload.get("malware_families", [])),
            tags=list(payload.get("tags", [])),
            attack_ids=list(payload.get("attack_ids", [])),
            references=list(payload.get("references", [])),
            source_first_seen=_iso_to_dt(row["source_first_seen"]),
            source_last_seen=_iso_to_dt(row["source_last_seen"]),
            raw_result=dict(payload.get("raw_result", {})),
            latency_ms=int(row["latency_ms"]),
            error_message=row["error_message"],
            retrieved_at=_iso_to_dt(row["retrieved_at"]) or utc_now(),
        )

    def _hydrate_report(
        self, row: sqlite3.Row, indicator: IndicatorRecord
    ) -> ThreatReport:
        breakdown_data = json.loads(row["score_breakdown_json"])
        threat_types = json.loads(row["threat_types_json"])
        actions = json.loads(row["recommended_actions_json"])
        evidence = self.get_enrichment_results(indicator.id, latest_per_source=True)
        techniques = self.get_indicator_techniques(indicator.id)
        return ThreatReport(
            id=int(row["id"]),
            indicator=indicator,
            risk_score=int(row["risk_score"]),
            confidence_score=int(row["confidence_score"]),
            risk_level=RiskLevel(row["risk_level"]),
            classification=Classification(row["classification"]),
            score_breakdown=ScoreBreakdown(**breakdown_data),
            threat_types=list(threat_types),
            sources_checked=int(row["sources_checked"]),
            sources_with_evidence=int(row["sources_with_evidence"]),
            evidence=evidence,
            attack_techniques=techniques,
            summary=row["summary"],
            recommended_actions=list(actions),
            generated_at=_iso_to_dt(row["generated_at"]) or utc_now(),
        )

