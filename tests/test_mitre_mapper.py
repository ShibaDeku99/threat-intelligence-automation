"""Unit tests for STIX 2.1 MITRE ATT&CK mapping (stix2)."""

from __future__ import annotations

from app.database.repository import ThreatIntelRepository
from app.enrichment.enrichment_engine import EnrichmentCorrelation
from app.enrichment.mitre_mapper import MitreAttackMapper
from app.processors.normalizer import normalize_ioc
from app.schemas import EnrichmentEvidence, EnrichmentStatus, IndicatorRecord, utc_now


def _indicator_stub() -> IndicatorRecord:
    now = utc_now()
    return IndicatorRecord(
        id=1,
        value="198.51.100.23",
        normalized_value="198.51.100.23",
        ioc_type=normalize_ioc("198.51.100.23").ioc_type,
        raw_input="198.51.100.23",
        is_reserved_ip=True,
        ip_scope_note="RFC 5737 TEST-NET-2 documentation IP (non-routable)",
        created_at=now,
        updated_at=now,
    )


def test_mitre_mapper_loads_stix2_subset_bundle() -> None:
    mapper = MitreAttackMapper()
    assert mapper.technique_count >= 10
    t1071 = mapper.get_technique("T1071")
    assert t1071 is not None
    assert t1071.name == "Application Layer Protocol"
    assert "command-and-control" in t1071.tactic


def test_mitre_mapper_direct_attack_ids_and_malware_relationships() -> None:
    mapper = MitreAttackMapper()
    ev_otx = EnrichmentEvidence(
        source_name="AlienVault OTX",
        status=EnrichmentStatus.OK,
        is_malicious_signal=True,
        pulse_count=3,
        attack_ids=["T1071", "T1566.001", "T9999"],  # T9999 tests graceful fallback
        malware_families=["Emotet"],
        tags=["c2"],
    )
    ev_uh = EnrichmentEvidence(
        source_name="URLhaus",
        status=EnrichmentStatus.OK,
        is_malicious_signal=True,
        malware_families=["AgentTesla"],  # Alias of 'Agent Tesla' in STIX
        threat_types=["malware_download"],
    )
    corr = EnrichmentCorrelation(
        indicator=_indicator_stub(),
        evidence=[ev_otx, ev_uh],
        sources_checked=2,
        sources_with_evidence=2,
        attack_ids=["T1071", "T1566.001", "T9999"],
        malware_families=["Emotet", "AgentTesla"],
        threat_types=["malware_download"],
        tags=["c2"],
    )

    mappings = mapper.map_correlation(corr)
    by_id = {m.technique.technique_id: m for m in mappings}

    # Direct OTX attack_id beats low-confidence 'c2' tag -> keeps 'high'
    assert "T1071" in by_id and by_id["T1071"].confidence == "high"
    assert "T1566.001" in by_id and by_id["T1566.001"].confidence == "high"
    # Unknown technique ID preserved cleanly with fallback metadata
    assert "T9999" in by_id and "attack.mitre.org/techniques/T9999" in by_id["T9999"].technique.url

    # Malware STIX 'uses' relationships (Emotet -> T1071.001, T1105; AgentTesla -> T1555.003, T1041)
    assert "T1071.001" in by_id and by_id["T1071.001"].confidence == "medium"
    assert "T1105" in by_id and by_id["T1105"].confidence == "medium"
    assert "T1555.003" in by_id and by_id["T1555.003"].confidence == "medium"
    assert "T1041" in by_id and by_id["T1041"].confidence == "medium"


def test_mitre_mapper_returns_empty_for_clean_or_unconfirmed_ioc() -> None:
    mapper = MitreAttackMapper()
    corr = EnrichmentCorrelation(
        indicator=_indicator_stub(),
        evidence=[
            EnrichmentEvidence(
                source_name="AlienVault OTX",
                status=EnrichmentStatus.NOT_FOUND,
                is_malicious_signal=False,
            )
        ],
        sources_checked=1,
        sources_with_evidence=0,
    )
    assert mapper.map_correlation(corr) == []


def test_mitre_mapper_persists_mappings_to_repository() -> None:
    repo = ThreatIntelRepository(":memory:")
    indicator, _ = repo.upsert_indicator(normalize_ioc("198.51.100.23"))
    corr = EnrichmentCorrelation(
        indicator=indicator,
        evidence=[
            EnrichmentEvidence(
                source_name="AlienVault OTX",
                status=EnrichmentStatus.OK,
                is_malicious_signal=True,
                malware_families=["LockBit"],
            )
        ],
        sources_checked=1,
        sources_with_evidence=1,
        malware_families=["LockBit"],
    )

    mapper = MitreAttackMapper()
    saved = mapper.map_and_save(corr, repo)
    assert any(m.technique.technique_id == "T1486" for m in saved)

    from_db = repo.get_indicator_techniques(indicator.id)
    assert len(from_db) == len(saved)
    assert from_db[0].technique.technique_id == "T1486"
    repo.close()

