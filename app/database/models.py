"""SQLite DDL definitions and database initialization helpers."""

from __future__ import annotations

import sqlite3
from pathlib import Path

DEFAULT_SOURCES: tuple[tuple[str, str, int, int], ...] = (
    ("AlienVault OTX", "https://otx.alienvault.com/api/v1", 35, 1),
    ("URLhaus", "https://urlhaus-api.abuse.ch/v1", 40, 1),
    ("MITRE ATT&CK", "https://attack.mitre.org/", 40, 1),
    ("CSV Dataset", "local://csv", 15, 1),
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    type TEXT NOT NULL,
    raw_input TEXT NOT NULL,
    is_reserved_ip INTEGER NOT NULL DEFAULT 0,
    ip_scope_note TEXT,
    first_seen TEXT,
    last_seen TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(normalized_value, type)
);

CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    source_url TEXT NOT NULL,
    reliability_weight INTEGER NOT NULL DEFAULT 20,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS enrichment_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_id INTEGER NOT NULL,
    source_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    is_malicious_signal INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER,
    result_json TEXT NOT NULL,
    source_first_seen TEXT,
    source_last_seen TEXT,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    retrieved_at TEXT NOT NULL,
    FOREIGN KEY(indicator_id) REFERENCES indicators(id) ON DELETE CASCADE,
    FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS threat_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_id INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    confidence_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    classification TEXT NOT NULL,
    score_breakdown_json TEXT NOT NULL,
    threat_types_json TEXT NOT NULL,
    sources_checked INTEGER NOT NULL DEFAULT 0,
    sources_with_evidence INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL,
    recommended_actions_json TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    FOREIGN KEY(indicator_id) REFERENCES indicators(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attack_techniques (
    technique_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS indicator_attack_techniques (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_id INTEGER NOT NULL,
    technique_id TEXT NOT NULL,
    source_name TEXT NOT NULL,
    evidence TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'medium',
    matched_at TEXT NOT NULL,
    UNIQUE(indicator_id, technique_id, source_name),
    FOREIGN KEY(indicator_id) REFERENCES indicators(id) ON DELETE CASCADE,
    FOREIGN KEY(technique_id) REFERENCES attack_techniques(technique_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS log_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_id INTEGER NOT NULL,
    log_source TEXT NOT NULL,
    log_timestamp TEXT,
    matched_field TEXT NOT NULL,
    raw_log_line TEXT NOT NULL,
    matched_at TEXT NOT NULL,
    FOREIGN KEY(indicator_id) REFERENCES indicators(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_indicators_type
    ON indicators(type);
CREATE INDEX IF NOT EXISTS idx_enrichment_indicator_source
    ON enrichment_results(indicator_id, source_id, retrieved_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_indicator_generated
    ON threat_reports(indicator_id, generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_risk_level
    ON threat_reports(risk_level);
CREATE INDEX IF NOT EXISTS idx_log_matches_indicator
    ON log_matches(indicator_id, matched_at DESC);
"""


def apply_schema(conn: sqlite3.Connection) -> None:
    """Apply DDL statements and seed default Threat Intelligence sources."""
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.executescript(SCHEMA_SQL)
    conn.executemany(
        """
        INSERT OR IGNORE INTO sources (name, source_url, reliability_weight, enabled)
        VALUES (?, ?, ?, ?)
        """,
        DEFAULT_SOURCES,
    )
    conn.commit()


def init_database(db_path: Path | str) -> None:
    """Ensure parent directory exists and initialize the SQLite schema."""
    path_str = str(db_path)
    if path_str != ":memory:":
        Path(path_str).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path_str) as conn:
        if path_str != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL;")
        apply_schema(conn)

