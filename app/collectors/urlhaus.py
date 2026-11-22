"""URLhaus Community API v1 collector for malware URL, host, and payload enrichment."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

import httpx

from app.collectors.base import BaseTICollector, dedupe_preserve_order, parse_ti_datetime
from app.config import Settings
from app.schemas import (
    EnrichmentEvidence,
    EnrichmentStatus,
    IOCInput,
    IOCType,
    NormalizedIOC,
)


class URLhausCollector(BaseTICollector):
    """Connector for abuse.ch URLhaus API v1 (requires Auth-Key header)."""

    name = "URLhaus"
    reliability_weight = 40
    supported_types = frozenset(
        {
            IOCType.IPV4,
            IOCType.IPV6,
            IOCType.DOMAIN,
            IOCType.URL,
            IOCType.MD5,
            IOCType.SHA256,
        }
    )

    def __init__(
        self,
        settings: Settings,
        client: httpx.Client | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.source_url = settings.urlhaus_base_url.rstrip("/")
        super().__init__(settings=settings, client=client, sleep_fn=sleep_fn)

    def is_configured(self) -> bool:
        return self.settings.has_urlhaus_key

    def _auth_headers(self) -> dict[str, str]:
        auth_key = self.settings.get_urlhaus_auth_key()
        headers = {"Accept": "application/json"}
        if auth_key:
            headers["Auth-Key"] = auth_key
        return headers

    def _endpoint_and_payload(self, ioc: NormalizedIOC) -> tuple[str, dict[str, str]]:
        if ioc.ioc_type == IOCType.URL:
            return f"{self.source_url}/url/", {"url": ioc.normalized_value}
        if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN):
            return f"{self.source_url}/host/", {"host": ioc.normalized_value}
        if ioc.ioc_type == IOCType.MD5:
            return f"{self.source_url}/payload/", {"md5_hash": ioc.normalized_value}
        return f"{self.source_url}/payload/", {"sha256_hash": ioc.normalized_value}

    def lookup(self, ioc: NormalizedIOC) -> EnrichmentEvidence:
        if not self.supports(ioc.ioc_type):
            return self._build_evidence(
                status=EnrichmentStatus.UNSUPPORTED_TYPE,
                error_message=f"URLhaus does not support IOC type '{ioc.ioc_type.value}'",
            )

        if not self.is_configured():
            return self._build_evidence(
                status=EnrichmentStatus.SKIPPED_NO_KEY,
                error_message="URLHAUS_AUTH_KEY is not configured in environment/.env",
            )

        endpoint, form_data = self._endpoint_and_payload(ioc)
        response, latency_ms, fail_status, fail_msg = self._request_with_retry(
            "POST",
            endpoint,
            headers=self._auth_headers(),
            data=form_data,
        )
        if fail_status is not None or response is None:
            return self._build_evidence(
                status=fail_status or EnrichmentStatus.ERROR,
                latency_ms=latency_ms,
                error_message=fail_msg,
            )

        if response.status_code in (401, 403):
            return self._build_evidence(
                status=EnrichmentStatus.ERROR,
                latency_ms=latency_ms,
                error_message=(
                    f"URLhaus authentication failed (HTTP {response.status_code}); "
                    "verify URLHAUS_AUTH_KEY"
                ),
            )

        if response.status_code >= 400:
            return self._build_evidence(
                status=EnrichmentStatus.ERROR,
                latency_ms=latency_ms,
                error_message=f"URLhaus returned HTTP {response.status_code}",
            )

        try:
            payload = response.json()
        except ValueError:
            return self._build_evidence(
                status=EnrichmentStatus.ERROR,
                latency_ms=latency_ms,
                error_message="URLhaus returned malformed JSON",
            )

        if not isinstance(payload, dict):
            return self._build_evidence(
                status=EnrichmentStatus.ERROR,
                latency_ms=latency_ms,
                error_message="URLhaus returned unexpected non-object payload",
            )

        query_status = str(payload.get("query_status") or "").lower()
        if query_status == "no_results":
            return self._build_evidence(
                status=EnrichmentStatus.NOT_FOUND,
                is_malicious_signal=False,
                latency_ms=latency_ms,
            )

        if query_status != "ok":
            return self._build_evidence(
                status=EnrichmentStatus.ERROR,
                latency_ms=latency_ms,
                error_message=f"URLhaus returned query_status='{query_status or 'unknown'}'",
            )

        if ioc.ioc_type == IOCType.URL:
            return self._parse_url_response(payload, latency_ms)
        if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN):
            return self._parse_host_response(payload, latency_ms)
        return self._parse_payload_response(payload, latency_ms)

    def _parse_url_response(
        self, payload: dict[str, Any], latency_ms: int
    ) -> EnrichmentEvidence:
        url_status = str(payload.get("url_status") or "").lower()
        is_active: bool | None = (
            True if url_status == "online" else (False if url_status == "offline" else None)
        )
        threat = payload.get("threat")
        threat_types = [str(threat)] if isinstance(threat, str) and threat.strip() else []
        tags = [str(t) for t in (payload.get("tags") or []) if isinstance(t, str)]

        malware_families: list[str] = []
        for item in payload.get("payloads") or []:
            if isinstance(item, dict):
                sig = item.get("signature")
                if isinstance(sig, str) and sig.strip():
                    malware_families.append(sig.strip())

        references: list[str] = []
        ref = payload.get("urlhaus_reference")
        if isinstance(ref, str) and ref.strip():
            references.append(ref.strip())

        first_seen = parse_ti_datetime(payload.get("date_added"))
        last_seen = parse_ti_datetime(payload.get("last_online")) or first_seen

        return self._build_evidence(
            status=EnrichmentStatus.OK,
            is_malicious_signal=True,
            is_active=is_active,
            pulse_count=1,
            threat_types=dedupe_preserve_order(threat_types or ["malware_distribution"]),
            malware_families=dedupe_preserve_order(malware_families),
            tags=dedupe_preserve_order(tags)[:30],
            references=references,
            source_first_seen=first_seen,
            source_last_seen=last_seen,
            raw_result={
                "url_status": url_status,
                "threat": threat,
                "host": payload.get("host"),
                "reporter": payload.get("reporter"),
                "blacklists": payload.get("blacklists"),
            },
            latency_ms=latency_ms,
        )

    def _parse_host_response(
        self, payload: dict[str, Any], latency_ms: int
    ) -> EnrichmentEvidence:
        urls_raw = payload.get("urls")
        urls: list[dict[str, Any]] = (
            [u for u in urls_raw if isinstance(u, dict)] if isinstance(urls_raw, list) else []
        )
        url_count = int(payload.get("url_count") or len(urls))

        if url_count == 0 and not urls:
            return self._build_evidence(
                status=EnrichmentStatus.NOT_FOUND,
                is_malicious_signal=False,
                latency_ms=latency_ms,
            )

        any_online = any(str(u.get("url_status") or "").lower() == "online" for u in urls)
        any_known_status = any(bool(u.get("url_status")) for u in urls)
        is_active: bool | None = True if any_online else (False if any_known_status else None)

        threat_types: list[str] = []
        tags: list[str] = []
        references: list[str] = []
        seen_dates: list[datetime] = []

        host_ref = payload.get("urlhaus_reference")
        if isinstance(host_ref, str) and host_ref.strip():
            references.append(host_ref.strip())

        first_seen_top = parse_ti_datetime(payload.get("firstseen"))
        if first_seen_top is not None:
            seen_dates.append(first_seen_top)

        for entry in urls:
            threat = entry.get("threat")
            if isinstance(threat, str) and threat.strip():
                threat_types.append(threat.strip())
            for tag in entry.get("tags") or []:
                if isinstance(tag, str) and tag.strip():
                    tags.append(tag.strip())
            link = entry.get("urlhaus_link")
            if isinstance(link, str) and link.strip():
                references.append(link.strip())
            dt = parse_ti_datetime(entry.get("date_added"))
            if dt is not None:
                seen_dates.append(dt)

        source_first_seen = min(seen_dates) if seen_dates else None
        source_last_seen = max(seen_dates) if seen_dates else None

        return self._build_evidence(
            status=EnrichmentStatus.OK,
            is_malicious_signal=True,
            is_active=is_active,
            pulse_count=url_count,
            threat_types=dedupe_preserve_order(threat_types or ["malware_distribution"]),
            tags=dedupe_preserve_order(tags)[:30],
            references=dedupe_preserve_order(references)[:15],
            source_first_seen=source_first_seen,
            source_last_seen=source_last_seen,
            raw_result={
                "host": payload.get("host"),
                "url_count": url_count,
                "blacklists": payload.get("blacklists"),
            },
            latency_ms=latency_ms,
        )

    def _parse_payload_response(
        self, payload: dict[str, Any], latency_ms: int
    ) -> EnrichmentEvidence:
        signature = payload.get("signature")
        malware_families = (
            [signature.strip()] if isinstance(signature, str) and signature.strip() else []
        )

        urls_raw = payload.get("urls")
        urls: list[dict[str, Any]] = (
            [u for u in urls_raw if isinstance(u, dict)] if isinstance(urls_raw, list) else []
        )
        any_online = any(str(u.get("url_status") or "").lower() == "online" for u in urls)
        any_known = any(bool(u.get("url_status")) for u in urls)
        is_active: bool | None = True if any_online else (False if any_known else None)

        references: list[str] = []
        for entry in urls:
            link = entry.get("urlhaus_reference") or entry.get("urlhaus_link")
            if isinstance(link, str) and link.strip():
                references.append(link.strip())

        first_seen = parse_ti_datetime(payload.get("firstseen"))
        last_seen = parse_ti_datetime(payload.get("lastseen")) or first_seen

        return self._build_evidence(
            status=EnrichmentStatus.OK,
            is_malicious_signal=True,
            is_active=is_active,
            pulse_count=int(payload.get("url_count") or len(urls) or 1),
            threat_types=["malware_payload"],
            malware_families=malware_families,
            tags=dedupe_preserve_order(malware_families),
            references=dedupe_preserve_order(references)[:15],
            source_first_seen=first_seen,
            source_last_seen=last_seen,
            raw_result={
                "file_type": payload.get("file_type"),
                "file_size": payload.get("file_size"),
                "signature": signature,
                "url_count": payload.get("url_count"),
            },
            latency_ms=latency_ms,
        )

    def fetch_recent_urls(self, limit: int = 20) -> list[IOCInput]:
        """Collect recent malicious URLs from URLhaus API (Module 1 collection)."""
        if not self.is_configured():
            return []

        clamped = max(1, min(limit, 100))
        url = f"{self.source_url}/urls/recent/limit/{clamped}/"
        response, _, fail_status, _ = self._request_with_retry(
            "GET",
            url,
            headers=self._auth_headers(),
        )
        if fail_status is not None or response is None or response.status_code != 200:
            return []

        try:
            data = response.json()
        except ValueError:
            return []

        urls = data.get("urls") if isinstance(data, dict) else None
        if not isinstance(urls, list):
            return []

        collected: list[IOCInput] = []
        for entry in urls:
            if not isinstance(entry, dict):
                continue
            raw_url = entry.get("url")
            if isinstance(raw_url, str) and raw_url.strip():
                tags = [str(t) for t in (entry.get("tags") or []) if isinstance(t, str)]
                collected.append(
                    IOCInput(
                        raw_value=raw_url.strip(),
                        source_hint=self.name,
                        tags=tags,
                    )
                )
        return collected
