"""Evidence-based MITRE ATT&CK mapper backed by STIX 2.1 (stix2)."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx
from stix2 import Filter, MemoryStore

from app.database.repository import ThreatIntelRepository
from app.enrichment.enrichment_engine import EnrichmentCorrelation
from app.schemas import AttackTechnique, EnrichmentStatus, TechniqueMapping, utc_now

OFFICIAL_ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_SUBSET_PATH = Path("data/mitre/enterprise_attack_subset.json")
DEFAULT_FULL_CACHE_PATH = Path("data/mitre/enterprise-attack.json")

_ATTACK_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_CONFIDENCE_RANK: dict[str, int] = {"low": 1, "medium": 2, "high": 3}

# Strictly bounded category -> technique fallbacks (used ONLY on confirmed malicious IOCs)
_THREAT_KEYWORD_TO_TECHNIQUE: dict[str, tuple[str, str]] = {
    "malware_download": ("T1105", "URLhaus/TI confirmed malware payload download activity"),
    "malware_distribution": ("T1105", "TI confirmed malware distribution host/URL"),
    "malware_payload": ("T1204.002", "TI confirmed malicious executable/file payload"),
    "phishing": ("T1566", "TI tags/context indicate phishing activity"),
    "spearphishing": ("T1566.002", "TI tags/context indicate spearphishing link/campaign"),
    "c2": ("T1071", "TI tags/context indicate command-and-control communication"),
    "c&c": ("T1071", "TI tags/context indicate command-and-control communication"),
    "command-and-control": ("T1071", "TI tags/context indicate command-and-control communication"),
    "botnet": ("T1583.005", "TI tags/context indicate botnet infrastructure"),
    "ransomware": ("T1486", "TI tags/context indicate ransomware activity"),
    "stealer": ("T1555.003", "TI tags/context indicate credential-stealing malware"),
    "exfiltration": ("T1041", "TI tags/context indicate data exfiltration over C2"),
}


def _normalize_key(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def sync_mitre_attack_bundle(
    destination: Path = DEFAULT_FULL_CACHE_PATH,
    url: str = OFFICIAL_ENTERPRISE_ATTACK_URL,
    timeout: float = 60.0,
) -> Path:
    """Download and cache the official MITRE Enterprise ATT&CK STIX 2.1 bundle locally."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
        # Validate JSON structure before writing
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("objects"), list):
            raise ValueError("Downloaded MITRE ATT&CK file is not a valid STIX 2.1 bundle")
    destination.write_text(json.dumps(data), encoding="utf-8")
    return destination


class MitreAttackMapper:
    """Loads STIX 2.1 ATT&CK data via stix2 and maps TI evidence to ATT&CK techniques."""

    def __init__(self, stix_bundle_path: Path | str | None = None) -> None:
        self.bundle_path = self._resolve_bundle_path(stix_bundle_path)
        self._techniques_by_id: dict[str, AttackTechnique] = {}
        self._stix_id_to_technique_id: dict[str, str] = {}
        self._malware_to_techniques: dict[str, list[tuple[str, str]]] = {}
        self._load_stix_bundle(self.bundle_path)

    @staticmethod
    def _resolve_bundle_path(explicit_path: Path | str | None) -> Path:
        if explicit_path is not None:
            return Path(explicit_path)
        if DEFAULT_FULL_CACHE_PATH.exists():
            return DEFAULT_FULL_CACHE_PATH
        return DEFAULT_SUBSET_PATH

    def _load_stix_bundle(self, path: Path) -> None:
        if not path.exists():
            return

        with path.open("r", encoding="utf-8") as fh:
            bundle_data = json.load(fh)

        objects = bundle_data.get("objects", [])
        if not isinstance(objects, list):
            return

        store = MemoryStore(stix_data=objects, allow_custom=True)

        # 1. Index attack-pattern STIX objects
        patterns = store.query([Filter("type", "=", "attack-pattern")])
        for obj in patterns:
            if getattr(obj, "revoked", False) or obj.get("x_mitre_deprecated", False):
                continue
            technique = self._extract_technique(obj)
            if technique is not None:
                self._techniques_by_id[technique.technique_id] = technique
                self._stix_id_to_technique_id[obj["id"]] = technique.technique_id

        # 2. Index malware STIX objects (name + x_mitre_aliases)
        malware_objects = store.query([Filter("type", "=", "malware")])
        malware_keys_by_stix_id: dict[str, list[str]] = {}
        for mal in malware_objects:
            if getattr(mal, "revoked", False) or mal.get("x_mitre_deprecated", False):
                continue
            names: list[str] = []
            if mal.get("name"):
                names.append(str(mal["name"]))
            for alias in mal.get("x_mitre_aliases") or []:
                if isinstance(alias, str):
                    names.append(alias)
            keys = list({_normalize_key(n) for n in names if _normalize_key(n)})
            if keys:
                malware_keys_by_stix_id[mal["id"]] = keys

        # 3. Traverse STIX 2.1 'uses' relationships (malware -> attack-pattern)
        relationships = store.query(
            [Filter("type", "=", "relationship"), Filter("relationship_type", "=", "uses")]
        )
        for rel in relationships:
            src_ref = rel.get("source_ref", "")
            tgt_ref = rel.get("target_ref", "")
            if src_ref not in malware_keys_by_stix_id:
                continue
            tid = self._stix_id_to_technique_id.get(tgt_ref)
            if tid is None:
                continue
            desc = str(rel.get("description") or f"STIX 2.1 'uses' relationship to {tid}").strip()
            for mkey in malware_keys_by_stix_id[src_ref]:
                self._malware_to_techniques.setdefault(mkey, []).append((tid, desc))

    @staticmethod
    def _extract_technique(obj: Any) -> AttackTechnique | None:
        ext_refs = obj.get("external_references") or []
        technique_id: str | None = None
        url = ""
        for ref in ext_refs:
            if isinstance(ref, Mapping) and ref.get("source_name") == "mitre-attack":
                ext_id = str(ref.get("external_id") or "").strip().upper()
                if _ATTACK_ID_RE.match(ext_id):
                    technique_id = ext_id
                    url = str(ref.get("url") or "")
                    break
        if technique_id is None:
            return None

        tactics: list[str] = []
        for phase in obj.get("kill_chain_phases") or []:
            if isinstance(phase, Mapping) and phase.get("kill_chain_name") == "mitre-attack":
                pname = str(phase.get("phase_name") or "").strip()
                if pname and pname not in tactics:
                    tactics.append(pname)

        raw_desc = str(obj.get("description") or "").strip()
        short_desc = raw_desc.splitlines()[0][:320] if raw_desc else ""
        if not url:
            url = f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"

        return AttackTechnique(
            technique_id=technique_id,
            name=str(obj.get("name") or technique_id),
            tactic=", ".join(tactics) if tactics else "unknown",
            description=short_desc,
            url=url,
        )

    @property
    def technique_count(self) -> int:
        return len(self._techniques_by_id)

    def get_technique(self, technique_id: str) -> AttackTechnique | None:
        return self._techniques_by_id.get(technique_id.strip().upper())

    def _resolve_or_fallback_technique(self, technique_id: str) -> AttackTechnique:
        tid = technique_id.strip().upper()
        found = self._techniques_by_id.get(tid)
        if found is not None:
            return found
        return AttackTechnique(
            technique_id=tid,
            name=f"MITRE ATT&CK {tid}",
            tactic="unmapped-local-subset",
            description="Referenced by TI source; run MITRE bundle sync for full metadata.",
            url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        )

    def map_correlation(
        self, correlation: EnrichmentCorrelation
    ) -> list[TechniqueMapping]:
        """Map correlated Threat Intelligence evidence to ATT&CK techniques.

        Only produces mappings when at least one TI source confirms malicious evidence.
        """
        if correlation.sources_with_evidence == 0:
            return []

        best_by_tid: dict[str, TechniqueMapping] = {}

        def _record(
            technique_id: str, source_name: str, evidence: str, confidence: str
        ) -> None:
            tid = technique_id.strip().upper()
            if not _ATTACK_ID_RE.match(tid):
                return
            candidate = TechniqueMapping(
                technique=self._resolve_or_fallback_technique(tid),
                source_name=source_name,
                evidence=evidence,
                confidence=confidence,
                matched_at=utc_now(),
            )
            existing = best_by_tid.get(tid)
            if existing is None or (
                _CONFIDENCE_RANK[confidence] > _CONFIDENCE_RANK[existing.confidence]
            ):
                best_by_tid[tid] = candidate

        for ev in correlation.evidence:
            if ev.status != EnrichmentStatus.OK or not ev.is_malicious_signal:
                continue

            # Priority 1 (High): Explicit ATT&CK IDs reported by the TI source (e.g., OTX pulses)
            for aid in ev.attack_ids:
                _record(
                    aid,
                    source_name=ev.source_name,
                    evidence=f"Direct ATT&CK ID '{aid}' reported in {ev.source_name} evidence",
                    confidence="high",
                )

            # Priority 2 (Medium): Malware family -> STIX 2.1 'uses' -> attack-pattern
            for family in ev.malware_families:
                mkey = _normalize_key(family)
                for tid, rel_desc in self._malware_to_techniques.get(mkey, []):
                    _record(
                        tid,
                        source_name=ev.source_name,
                        evidence=(
                            f"Malware family '{family}' ({ev.source_name}) linked via "
                            f"STIX 2.1: {rel_desc}"
                        ),
                        confidence="medium",
                    )

            # Priority 3 (Low): Strictly bounded threat-type / tag evidence on confirmed malicious
            # indicators
            keywords = [k.strip().lower() for k in (*ev.threat_types, *ev.tags)]
            for kw in keywords:
                mapped = _THREAT_KEYWORD_TO_TECHNIQUE.get(kw)
                if mapped is not None:
                    tid, reason = mapped
                    _record(
                        tid,
                        source_name=ev.source_name,
                        evidence=f"{reason} (observed keyword '{kw}' in {ev.source_name})",
                        confidence="low",
                    )

        return sorted(
            best_by_tid.values(),
            key=lambda m: (-_CONFIDENCE_RANK[m.confidence], m.technique.technique_id),
        )

    def map_and_save(
        self,
        correlation: EnrichmentCorrelation,
        repo: ThreatIntelRepository,
    ) -> list[TechniqueMapping]:
        """Map ATT&CK techniques for an enrichment correlation and persist to SQLite."""
        mappings = self.map_correlation(correlation)
        for mapping in mappings:
            repo.link_indicator_technique(correlation.indicator.id, mapping)
        return mappings
