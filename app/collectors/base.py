"""Base class and shared HTTP resilience helpers for Threat Intelligence collectors."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx

from app.config import Settings
from app.schemas import EnrichmentEvidence, EnrichmentStatus, IOCType, NormalizedIOC, utc_now

_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})


def parse_ti_datetime(raw: str | None) -> datetime | None:
    """Parse common Threat Intelligence timestamp formats into timezone-aware UTC."""
    if not raw or not isinstance(raw, str):
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None

    # Handle ISO 8601 (including trailing 'Z')
    iso_candidate = cleaned[:-1] + "+00:00" if cleaned.endswith("Z") else cleaned
    try:
        dt = datetime.fromisoformat(iso_candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except ValueError:
        pass

    # Handle URLhaus style: '2026-11-20 14:22:10 UTC' or '2026-11-20 14:22:10'
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(cleaned, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue

    return None


def dedupe_preserve_order(items: list[str]) -> list[str]:
    """Deduplicate non-empty strings while preserving first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        cleaned = item.strip()
        if cleaned and cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            result.append(cleaned)
    return result


class BaseTICollector(ABC):
    """Abstract Threat Intelligence connector with timeout, retry, and telemetry support."""

    name: str
    source_url: str
    reliability_weight: int = 20
    supported_types: frozenset[IOCType] = frozenset()

    def __init__(
        self,
        settings: Settings,
        client: httpx.Client | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings
        self._sleep = sleep_fn
        self._owns_client = client is None
        if client is not None:
            self._client = client
        else:
            timeout = httpx.Timeout(
                connect=settings.http_connect_timeout,
                read=settings.http_read_timeout,
                write=settings.http_connect_timeout,
                pool=settings.http_connect_timeout,
            )
            self._client = httpx.Client(
                timeout=timeout,
                headers={"User-Agent": "threat-intel-enrichment/0.1"},
                follow_redirects=True,
            )

    def close(self) -> None:
        """Close the underlying HTTP client if owned by this collector."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> BaseTICollector:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported_types

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True when required credentials for this collector are available."""

    @abstractmethod
    def lookup(self, ioc: NormalizedIOC) -> EnrichmentEvidence:
        """Query the external Threat Intelligence source for a normalized IOC."""

    def _build_evidence(
        self,
        *,
        status: EnrichmentStatus,
        latency_ms: int = 0,
        error_message: str | None = None,
        **kwargs: Any,
    ) -> EnrichmentEvidence:
        return EnrichmentEvidence(
            source_name=self.name,
            source_url=self.source_url,
            status=status,
            latency_ms=latency_ms,
            error_message=error_message,
            retrieved_at=utc_now(),
            **kwargs,
        )

    def _compute_backoff(self, attempt: int, response: httpx.Response | None = None) -> float:
        if response is not None:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    parsed = float(retry_after)
                    if parsed >= 0:
                        return min(parsed, 10.0)
                except ValueError:
                    pass
        return self.settings.http_backoff_seconds * (2**attempt)

    def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> tuple[httpx.Response | None, int, EnrichmentStatus | None, str | None]:
        """Execute an HTTP request with bounded retry on timeouts, network errors, 429, and 5xx.

        Returns:
            (response, latency_ms, failure_status, error_message)
            When failure_status is None, response is guaranteed to be non-None.
        """
        max_attempts = self.settings.http_max_retries + 1
        start = time.perf_counter()
        last_status: EnrichmentStatus = EnrichmentStatus.ERROR
        last_error: str = "Unknown HTTP error"

        for attempt in range(max_attempts):
            try:
                response = self._client.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    data=data,
                )
            except httpx.TimeoutException as exc:
                last_status = EnrichmentStatus.TIMEOUT
                last_error = f"{self.name} request timed out: {exc.__class__.__name__}"
                if attempt < max_attempts - 1:
                    delay = self._compute_backoff(attempt)
                    if delay > 0:
                        self._sleep(delay)
                    continue
                latency_ms = int((time.perf_counter() - start) * 1000)
                return None, latency_ms, last_status, last_error
            except httpx.RequestError as exc:
                last_status = EnrichmentStatus.ERROR
                last_error = f"{self.name} network error: {exc.__class__.__name__}"
                if attempt < max_attempts - 1:
                    delay = self._compute_backoff(attempt)
                    if delay > 0:
                        self._sleep(delay)
                    continue
                latency_ms = int((time.perf_counter() - start) * 1000)
                return None, latency_ms, last_status, last_error

            if response.status_code in _RETRYABLE_STATUS_CODES and attempt < max_attempts - 1:
                delay = self._compute_backoff(attempt, response)
                if delay > 0:
                    self._sleep(delay)
                continue

            latency_ms = int((time.perf_counter() - start) * 1000)
            return response, latency_ms, None, None

        latency_ms = int((time.perf_counter() - start) * 1000)
        return None, latency_ms, last_status, last_error
