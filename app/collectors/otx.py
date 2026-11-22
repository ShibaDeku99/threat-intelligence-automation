"""AlienVault OTX API v1 collector for IOC enrichment and pulse ingestion."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx

from app.collectors.base import BaseTICollector, dedupe_preserve_order, parse_ti_datetime
from app.config import Settings
from app.schemas import (
    EnrichmentEvidence,
    EnrichmentStatus,
    IOCInput,
    IOCType,
    NormalizedIOC,
    utc_now,
)

_OTX_TYPE_MAP: dict[IOCType, str] = {
    IOCType.IPV4: "IPv4",
    IOCType.IPV6: "IPv6",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.MD5: "file",
    IOCType.SHA1: "file",
    IOCType.SHA256: "file",
}

_ACTIVE_WINDOW_DAYS = 30


class OTXCollector(BaseTICollector):
    """Connector for AlienVault Open Threat Exchange (OTX) DirectConnect API v1."""

    name = "AlienVault OTX"
    reliability_weight = 35
    supported_types = frozenset(_OTX_TYPE_MAP.keys())

    def __init__(
        self,
        settings: Settings,
        client: httpx.Client | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.source_url = settings.otx_base_url.rstrip("/")
        super().__init__(settings=settings, client=client, sleep_fn=sleep_fn)

    def is_configured(self) -> bool:
        return self.settings.has_otx_key

    def _auth_headers(self) -> dict[str, str]:
        api_key = self.settings.get_otx_api_key()
        headers = {"Accept": "application/json"}
        if api_key:
            headers["X-OTX-API-KEY"] = api_key
        return headers

    def lookup(self, ioc: NormalizedIOC) -> EnrichmentEvidence:
        if not self.supports(ioc.ioc_type):
            return self._build_evidence(
                status=EnrichmentStatus.UNSUPPORTED_TYPE,
                error_message=f"OTX does not support IOC type '{ioc.ioc_type.value}'",
            )

        if not self.is_configured():
            return self._build_evidence(
                status=EnrichmentStatus.SKIPPED_NO_KEY,
                error_message="OTX_API_KEY is not configured in environment/.env",
            )

        otx_type = _OTX_TYPE_MAP[ioc.ioc_type]
        encoded_ioc = (
            quote(ioc.normalized_value, safe="")
            if ioc.ioc_type == IOCType.URL
            else ioc.normalized_value
        )
        url = f"{self.source_url}/indicators/{otx_type}/{encoded_ioc}/general"

        response, latency_ms, fail_status, fail_msg = self._request_with_retry(
            "GET",
            url,
            headers=self._auth_headers(),
        )
        if fail_status is not None or response is None:
            return self._build_evidence(
                status=fail_status or EnrichmentStatus.ERROR,
                latency_ms=latency_ms,
                error_message=fail_msg,
            )

        if response.status_code == 404:
            return self._build_evidence(
                status=EnrichmentStatus.NOT_FOUND,
                is_malicious_signal=False,
                latency_ms=latency_ms,
            )

        if response.status_code in (401, 403):
            return self._build_evidence(
                status=EnrichmentStatus.ERROR,
                latency_ms=latency_ms,
                error_message=(
                    f"AlienVault OTX authentication failed (HTTP {response.status_code}); "
                    "verify OTX_API_KEY"
                ),
            )

        if response.status_code >= 400:
            return self._build_evidence(
                status=EnrichmentStatus.ERROR,
                latency_ms=latency_ms,
                error_message=f"AlienVault OTX returned HTTP {response.status_code}",
            )

        try:
            payload = response.json()
        except ValueError:
            return self._build_evidence(
                status=EnrichmentStatus.ERROR,
                latency_ms=latency_ms,
                error_message="AlienVault OTX returned malformed JSON",
            )

        if not isinstance(payload, dict):
            return self._build_evidence(
                status=EnrichmentStatus.ERROR,
                latency_ms=latency_ms,
                error_message="AlienVault OTX returned unexpected non-object payload",
            )

        return self._parse_general_response(payload, latency_ms)

    def _parse_general_response(
        self, payload: dict[str, Any], latency_ms: int
    ) -> EnrichmentEvidence:
        pulse_info = payload.get("pulse_info")
        if not isinstance(pulse_info, dict):
            pulse_info = {}

        pulses_raw = pulse_info.get("pulses")
        pulses: list[dict[str, Any]] = (
            [p for p in pulses_raw if isinstance(p, dict)]
            if isinstance(pulses_raw, list)
            else []
        )
        raw_count = pulse_info.get("count")
        pulse_count = int(raw_count) if isinstance(raw_count, int) and raw_count >= 0 else len(
            pulses
        )

        # Check OTX validation list for whitelist / false-positive flags
        validations_raw = payload.get("validation")
        validation_sources: list[str] = []
        if isinstance(validations_raw, list):
            for entry in validations_raw:
                if isinstance(entry, dict) and entry.get("source"):
                    validation_sources.append(str(entry["source"]))

        if pulse_count == 0:
            return self._build_evidence(
                status=EnrichmentStatus.NOT_FOUND,
                is_malicious_signal=False,
                pulse_count=0,
                raw_result={
                    "pulse_count": 0,
                    "reputation": payload.get("reputation"),
                    "country_code": payload.get("country_code"),
                    "asn": payload.get("asn"),
                    "validation": validation_sources,
                },
                latency_ms=latency_ms,
            )

        tags: list[str] = []
        malware_families: list[str] = []
        attack_ids: list[str] = []
        threat_types: list[str] = []
        references: list[str] = []
        pulse_names: list[str] = []
        first_seen_candidates: list[datetime] = []
        last_seen_candidates: list[datetime] = []

        for pulse in pulses:
            name = pulse.get("name")
            if isinstance(name, str) and name.strip():
                pulse_names.append(name.strip())

            pulse_id = pulse.get("id")
            if isinstance(pulse_id, str) and pulse_id.strip():
                references.append(f"https://otx.alienvault.com/pulse/{pulse_id.strip()}")

            for ref in pulse.get("references") or []:
                if isinstance(ref, str) and ref.strip():
                    references.append(ref.strip())

            for tag in pulse.get("tags") or []:
                if isinstance(tag, str) and tag.strip():
                    tags.append(tag.strip())

            for mf in pulse.get("malware_families") or []:
                if isinstance(mf, str) and mf.strip():
                    malware_families.append(mf.strip())
                elif isinstance(mf, dict):
                    display = mf.get("display_name") or mf.get("id")
                    if isinstance(display, str) and display.strip():
                        malware_families.append(display.strip())

            for aid in pulse.get("attack_ids") or []:
                if isinstance(aid, str) and aid.strip():
                    attack_ids.append(aid.strip().upper())
                elif isinstance(aid, dict):
                    tid = aid.get("id")
                    if isinstance(tid, str) and tid.strip():
                        attack_ids.append(tid.strip().upper())

            adversary = pulse.get("adversary")
            if isinstance(adversary, str) and adversary.strip():
                threat_types.append(f"adversary:{adversary.strip()}")

            created_dt = parse_ti_datetime(pulse.get("created"))
            modified_dt = parse_ti_datetime(pulse.get("modified"))
            if created_dt is not None:
                first_seen_candidates.append(created_dt)
            if modified_dt is not None:
                last_seen_candidates.append(modified_dt)
            elif created_dt is not None:
                last_seen_candidates.append(created_dt)

        if malware_families:
            threat_types.append("malware")
        if any(t.lower() in {"phishing", "credential-harvesting"} for t in tags):
            threat_types.append("phishing")
        if any(t.lower() in {"c2", "c&c", "command-and-control", "botnet"} for t in tags):
            threat_types.append("c2")
        if any(t.lower() in {"ransomware", "extortion"} for t in tags):
            threat_types.append("ransomware")
        if not threat_types:
            threat_types.append("suspicious_activity")

        source_first_seen = min(first_seen_candidates) if first_seen_candidates else None
        source_last_seen = max(last_seen_candidates) if last_seen_candidates else None

        is_whitelisted = any(
            v.lower() in {"whitelist", "false_positive", "akamai", "cloudflare"}
            for v in validation_sources
        )
        is_malicious_signal = pulse_count > 0 and not is_whitelisted

        is_active: bool | None = None
        if source_last_seen is not None:
            is_active = source_last_seen >= (utc_now() - timedelta(days=_ACTIVE_WINDOW_DAYS))

        compact_raw = {
            "pulse_count": pulse_count,
            "pulse_names": pulse_names[:10],
            "reputation": payload.get("reputation"),
            "country_code": payload.get("country_code"),
            "asn": payload.get("asn"),
            "validation": validation_sources,
        }

        return self._build_evidence(
            status=EnrichmentStatus.OK,
            is_malicious_signal=is_malicious_signal,
            is_active=is_active,
            pulse_count=pulse_count,
            threat_types=dedupe_preserve_order(threat_types),
            malware_families=dedupe_preserve_order(malware_families),
            tags=dedupe_preserve_order(tags)[:30],
            attack_ids=dedupe_preserve_order(attack_ids),
            references=dedupe_preserve_order(references)[:15],
            source_first_seen=source_first_seen,
            source_last_seen=source_last_seen,
            raw_result=compact_raw,
            latency_ms=latency_ms,
        )

    def fetch_subscribed_pulses(self, limit: int = 10) -> list[IOCInput]:
        """Collect IOCs from the user's OTX subscribed pulses (Module 1 collection)."""
        if not self.is_configured():
            return []

        url = f"{self.source_url}/pulses/subscribed"
        response, _, fail_status, _ = self._request_with_retry(
            "GET",
            url,
            headers=self._auth_headers(),
            params={"limit": max(1, min(limit, 50))},
        )
        if fail_status is not None or response is None or response.status_code != 200:
            return []

        try:
            data = response.json()
        except ValueError:
            return []

        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            return []

        collected: list[IOCInput] = []
        for pulse in results:
            if not isinstance(pulse, dict):
                continue
            pulse_tags = [str(t) for t in (pulse.get("tags") or []) if isinstance(t, str)]
            for ind in pulse.get("indicators") or []:
                if not isinstance(ind, dict):
                    continue
                val = ind.get("indicator")
                if isinstance(val, str) and val.strip():
                    collected.append(
                        IOCInput(
                            raw_value=val.strip(),
                            source_hint=self.name,
                            tags=pulse_tags,
                        )
                    )
        return collected
