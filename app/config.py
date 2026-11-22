"""Application configuration loaded from environment variables and .env."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized, validated settings for the Threat Intelligence platform."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "Automated Threat Intelligence & IOC Enrichment Platform"
    log_level: str = "INFO"

    # Storage & cache
    database_path: Path = Path("data/threat_intel.db")
    reports_dir: Path = Path("reports")
    mitre_data_dir: Path = Path("data/mitre")
    cache_ttl_hours: int = Field(default=24, ge=0, le=720)

    # Threat Intelligence APIs
    otx_api_key: SecretStr | None = None
    otx_base_url: str = "https://otx.alienvault.com/api/v1"

    urlhaus_auth_key: SecretStr | None = None
    urlhaus_base_url: str = "https://urlhaus-api.abuse.ch/v1"

    # HTTP resilience
    http_connect_timeout: float = Field(default=5.0, gt=0.0, le=60.0)
    http_read_timeout: float = Field(default=15.0, gt=0.0, le=120.0)
    http_max_retries: int = Field(default=2, ge=0, le=5)
    http_backoff_seconds: float = Field(default=1.0, ge=0.0, le=30.0)

    # Safety defaults
    default_defang_exports: bool = True

    @field_validator("otx_api_key", "urlhaus_auth_key", mode="before")
    @classmethod
    def _empty_secret_to_none(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, str) and not value.strip():
            return None
        if isinstance(value, SecretStr) and not value.get_secret_value().strip():
            return None
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalize_log_level(cls, value: Any) -> str:
        if isinstance(value, str):
            return value.strip().upper() or "INFO"
        return "INFO"

    def get_otx_api_key(self) -> str | None:
        """Return the stripped OTX API key or None if not configured."""
        if self.otx_api_key is None:
            return None
        secret = self.otx_api_key.get_secret_value().strip()
        return secret or None

    def get_urlhaus_auth_key(self) -> str | None:
        """Return the stripped URLhaus Auth-Key or None if not configured."""
        if self.urlhaus_auth_key is None:
            return None
        secret = self.urlhaus_auth_key.get_secret_value().strip()
        return secret or None

    @property
    def has_otx_key(self) -> bool:
        return self.get_otx_api_key() is not None

    @property
    def has_urlhaus_key(self) -> bool:
        return self.get_urlhaus_auth_key() is not None

    def ensure_directories(self) -> None:
        """Create required local runtime directories if they do not exist."""
        if str(self.database_path) != ":memory:":
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.mitre_data_dir.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    """Create a validated Settings instance from environment / .env."""
    return Settings()

