"""Tests for application configuration and shared Pydantic schemas."""

from __future__ import annotations

from pathlib import Path

from app.config import Settings
from app.schemas import ScoreBreakdown


def test_settings_blank_secrets_treated_as_missing() -> None:
    settings = Settings(
        _env_file=None,
        otx_api_key="   ",
        urlhaus_auth_key="",
    )
    assert settings.has_otx_key is False
    assert settings.has_urlhaus_key is False
    assert settings.get_otx_api_key() is None
    assert settings.get_urlhaus_auth_key() is None


def test_settings_secret_masking_and_trimming() -> None:
    settings = Settings(
        _env_file=None,
        otx_api_key="  secret-otx-token  ",
        urlhaus_auth_key="secret-urlhaus-token",
    )
    assert settings.has_otx_key is True
    assert settings.get_otx_api_key() == "secret-otx-token"
    assert settings.get_urlhaus_auth_key() == "secret-urlhaus-token"
    # Secret values must never appear in string representations
    assert "secret-otx-token" not in repr(settings)
    assert "secret-urlhaus-token" not in repr(settings)


def test_settings_ensure_directories(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        database_path=tmp_path / "db" / "ti.db",
        reports_dir=tmp_path / "out_reports",
        mitre_data_dir=tmp_path / "mitre",
    )
    settings.ensure_directories()
    assert (tmp_path / "db").is_dir()
    assert (tmp_path / "out_reports").is_dir()
    assert (tmp_path / "mitre").is_dir()


def test_score_breakdown_total() -> None:
    breakdown = ScoreBreakdown(
        source_reliability=35,
        independent_sources=25,
        recency=15,
        activity_status=15,
    )
    assert breakdown.total == 90

