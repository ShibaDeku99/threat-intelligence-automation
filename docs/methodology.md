# Threat Analysis, Risk Scoring & MITRE Mapping Methodology

## 1. Heuristic Risk Score (0–100)

The platform calculates an explainable **Heuristic Risk Score** out of 100 points across four transparent criteria. Every generated report stores the exact `score_breakdown` so a SOC analyst can inspect *why* a score was assigned.

| Criterion | Max Points | Scoring Logic |
| :--- | :---: | :--- |
| **1. Source Reliability** | 40 | Awarded only when a source returns confirmed malicious evidence (`status = ok` and `is_malicious_signal = True`). URLhaus active/payload-confirmed = 40 (historical = 35); AlienVault OTX scales by pulse corroboration (1 pulse = 22, 2–4 pulses = 30, 5+ pulses = 35). Clean / `not_found` sources contribute **0**. |
| **2. Independent Sources** | 25 | 0 confirming sources = 0; 1 confirming source = 12; 2 or more independent confirming sources = 25. |
| **3. Data Recency** | 20 | Computed strictly from TI source observation timestamps (`source_last_seen`, never `retrieved_at`), only when malicious evidence exists: <= 7 days = 20; <= 30 days = 15; <= 90 days = 10; <= 365 days = 5; > 365 days = 2; unknown timestamp = 5. |
| **4. Activity Status** | 15 | Awarded only when malicious evidence exists: active/online = 15; offline/historical = 5; unknown = 0. |
| **Total** | **100** | Sum of the four criteria above. |

### Risk Level Thresholds

| Score Range | Risk Level | Typical Analyst Action |
| :---: | :---: | :--- |
| 0 – 29 | **Low** | No immediate block; keep in watchlist if local SIEM context warrants monitoring. |
| 30 – 59 | **Medium** | Correlate with internal firewall/DNS/proxy logs and monitor for repeated hits. |
| 60 – 79 | **High** | Hunt internal logs (30 days), inspect affected endpoints, verify false-positive risk before blocking. |
| 80 – 100 | **Critical** | Immediate SOC triage, log hunting across Firewall/DNS/Proxy/EDR, verify ownership before containment. |

> **Important Disclaimer:** This scoring model is an internal **Heuristic Risk Score**, not an international CTI standard. A high score must still be validated by a human analyst before applying perimeter or endpoint blocking rules.

---

## 2. Decoupling Confidence Score from Risk Score

Risk Score and Confidence Score measure **different dimensions** and are intentionally never merged:

- **Heuristic Risk Score** answers: *"Based on available evidence, how dangerous does this IOC appear?"*
- **Confidence Score (0–100)** answers: *"How complete, reliable, and corroborated is the evidence behind that assessment?"*

Confidence Score is computed from four components:
1. **API Coverage (max 40):** Ratio of applicable sources that responded cleanly (`ok` or `not_found`) versus degraded outcomes (`timeout`, `error`, `skipped_no_key`). If **no** source returned a live response (e.g., missing API keys or full outage), Confidence is **0**, explicitly warning the analyst not to treat a `0/100` risk score as "verified benign".
2. **Corroboration (max 30):** Independent multi-source agreement (both malicious corroboration and clean multi-source agreement).
3. **Metadata Completeness (max 20):** Presence of source observation timestamps, malware family/threat context, and external references.
4. **Technical Context (max 10):** Presence of high/medium-confidence MITRE ATT&CK technique mappings.

**Example:** If URLhaus confirms an active malware URL (`Risk = 87 / Critical`) while AlienVault OTX times out, Risk remains Critical so the analyst prioritizes triage, while Confidence drops (`<= 60`) with a degraded-coverage warning prompting re-verification.

---

## 3. Evidence-Based MITRE ATT&CK Mapping (STIX 2.1)

The `MitreAttackMapper` (`app/enrichment/mitre_mapper.py`) reads MITRE Enterprise ATT&CK STIX 2.1 bundles using the official Python `stix2` library (`MemoryStore` + `Filter`) and enforces a strict **anti-hallucination rule**: clean or unconfirmed IOCs receive **zero** mapped techniques.

For confirmed malicious indicators, mappings follow three confidence tiers (deduplicated per technique ID, keeping the highest tier):

1. **High Confidence:** Explicit ATT&CK technique IDs (`Txxxx` / `Txxxx.xxx`) reported directly in AlienVault OTX pulses, enriched with official name, tactic, description, and URL from the STIX 2.1 store.
2. **Medium Confidence:** Malware families reported by OTX or URLhaus (e.g., `Emotet`, `Cobalt Strike`, `Agent Tesla`, `LockBit`, `QakBot`, `Mirai`) matched against STIX `malware` objects and `x_mitre_aliases`, then traversed through STIX 2.1 `relationship` (`uses`) edges to `attack-pattern` objects.
3. **Low Confidence:** Narrowly scoped, explicit threat-category mappings (e.g., URLhaus `malware_download` -> `T1105`, confirmed `phishing` -> `T1566`, confirmed `ransomware` -> `T1486`) applied only when `is_malicious_signal = True`.

Every mapping records the `source_name` and exact `evidence` justification for analyst auditability.

---

## 4. Evaluation Metrics & Limitations

Rather than inventing arbitrary target percentages, the platform measures and persists real operational metrics in SQLite (`app/database/repository.py` -> `get_system_metrics()`):
- **Enrichment Success Rate (%)** across attempted API queries (`ok` + `not_found` over attempted calls)
- **API Failure Rate (%)** (`error` + `timeout` over attempted calls, overall and per source)
- **Average API Latency (ms)** per source and overall
- **Deduplication Counts** at both batch ingestion and database layers

### Known Limitations
- Community TI feeds (OTX, URLhaus) can lag behind zero-day infrastructure or occasionally contain shared hosting / CDN false positives.
- Non-routable or documentation IPs (RFC 1918, RFC 5737 TEST-NET such as `198.51.100.23`) are flagged with scope warnings because external reputation lookups rarely reflect internal network context.
- The local STIX 2.1 subset covers common SOC techniques for offline testing; run `python -m app.main sync-mitre` to download the full MITRE Enterprise ATT&CK STIX 2.1 bundle (~30 MB).

