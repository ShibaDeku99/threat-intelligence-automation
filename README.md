# Automated Threat Intelligence & IOC Enrichment Platform

A Python-based Threat Intelligence automation platform designed for SOC Analysts to automatically collect, normalize, enrich, score, map to MITRE ATT&CK (STIX 2.1), correlate against SOC logs, and report on Indicators of Compromise (IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256).

## Key Features

- **Module 1 — IOC Collection:** Single IOC lookup, bulk paste, CSV batch ingestion (`pandas`), plus live feed collectors for AlienVault OTX subscribed pulses and URLhaus recent URLs.
- **Module 2 — IOC Normalization & Validation:** Automatic SOC **refanging** (`hxxps://`, `[.]`, `[:]`, `[/]`), strict format validation (preventing malformed IPs like `999.999.999.999` from falling through to domains), RFC 5737 TEST-NET / private / loopback IP scope tagging, and batch + SQLite deduplication.
- **Module 3 — Threat Intelligence Enrichment:** Integrates **AlienVault OTX API v1** (`X-OTX-API-KEY`) and **URLhaus Community API v1** (`Auth-Key`) via `httpx` with connect/read timeouts, exponential retry backoff (`429`/`5xx`), SQLite TTL caching, per-source latency telemetry, and graceful degradation when keys are missing or a source fails.
- **Module 4 — Threat Analysis:** Transparent 4-factor **Heuristic Risk Score (0–100)** (`Source Reliability 40` + `Independent Sources 25` + `Recency 20` + `Activity Status 15`), decoupled **Confidence Score (0–100)**, executive analyst summary, and recommended SOC actions.
- **Module 5 — MITRE ATT&CK Mapping (STIX 2.1):** Parses STIX 2.1 ATT&CK bundles using `stix2` (`MemoryStore` + `Filter`) to map direct ATT&CK IDs and malware `uses` relationships with explicit evidence trails.
- **Module 6 — Dashboard & Reporting:** Interactive 4-tab **Streamlit + Plotly** workbench and **JSON / CSV / XSS-safe HTML** exporters with safe IOC defanging enabled by default.
- **Bonus — SOC Log IOC Matching:** Correlates Firewall, DNS, Proxy, and EDR logs (`.csv`, `.jsonl`, `.log`) against collected Threat Intelligence indicators (including automatic domain extraction from proxy URLs).

## Tech Stack

`Python 3.12` · `httpx` · `Pydantic v2` · `SQLite` · `Pandas` · `stix2 (STIX 2.1)` · `Streamlit` · `Plotly` · `Jinja2` · `pytest` · `respx` · `ruff`

## Project Structure

```text
.
├── app/
│   ├── main.py                     # CLI entrypoint
│   ├── config.py                   # Pydantic Settings (.env)
│   ├── schemas.py                  # Shared Pydantic v2 schemas
│   ├── pipeline.py                 # Shared end-to-end orchestration pipeline
│   ├── collectors/                 # Base HTTP resilience, OTX, URLhaus, CSV loader
│   ├── processors/                 # Validator, normalizer (refang/defang), deduplicator
│   ├── enrichment/                 # EnrichmentEngine + STIX 2.1 MitreAttackMapper
│   ├── analysis/                   # Heuristic Risk Score, Confidence Score, Summaries
│   ├── matching/                   # SOC Log IOC Matcher
│   ├── reporting/                  # JSON / CSV / Jinja2 HTML exporters
│   ├── database/                   # SQLite 7-table schema & ThreatIntelRepository
│   └── dashboard/                  # Streamlit + Plotly SOC Dashboard
├── data/
│   ├── sample_iocs.csv             # Safe offline IOC dataset (RFC 5737 / RFC 2606 / EICAR)
│   ├── sample_logs.csv             # Sample Firewall/DNS/Proxy/EDR logs
│   └── mitre/                      # Bundled STIX 2.1 subset + full bundle cache target
├── docs/
│   ├── architecture.md
│   └── methodology.md
├── tests/                          # Unit, mocked HTTP (respx), integration & UI tests
├── .env.example
├── pyproject.toml
└── requirements.txt
```

## Quick Start

### 1. Environment Setup (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure API Keys (Optional for Offline Demo)

Copy `.env.example` to `.env` and add your free community API keys when ready for live TI enrichment:

```powershell
Copy-Item .env.example .env
```

- `OTX_API_KEY`: Get a free key at https://otx.alienvault.com/api
- `URLHAUS_AUTH_KEY`: Get a free Community API Auth-Key at https://urlhaus.abuse.ch/api/

> Without API keys, the platform runs cleanly in graceful-degradation mode (`skipped_no_key`, `Confidence = 0/100`) so you can demo normalization, deduplication, SQLite storage, reporting, SOC log matching, and the Dashboard immediately.

### 3. CLI Usage (SOC Demo Scenario)

```powershell
# Investigate the RFC 5737 TEST-NET demo IP and export an HTML report
python -m app.main lookup 198.51.100.23 --export html

# Process the sample CSV dataset (demonstrating refanging & deduplication)
python -m app.main batch data/sample_iocs.csv --export json

# Match collected IOCs against sample Firewall/DNS/Proxy/EDR logs
python -m app.main match-logs data/sample_logs.csv

# View stored reports and measured operational telemetry
python -m app.main list-reports
python -m app.main metrics

# Optional: Download full MITRE Enterprise ATT&CK STIX 2.1 bundle (~30 MB)
python -m app.main sync-mitre
```

### 4. Launch the Streamlit Dashboard

```powershell
streamlit run app/dashboard/dashboard.py
```

## Testing & Code Quality

```powershell
pytest -v
ruff check app tests
```

## Documentation

- [System Architecture](docs/architecture.md)
- [Risk Scoring, Confidence & MITRE Methodology](docs/methodology.md)

## Disclaimer

The **Heuristic Risk Score** is a custom decision-support model, not an international CTI standard. Always verify indicators and local business context before applying firewall, DNS, or EDR blocking controls. Sample IPs such as `198.51.100.23` belong to RFC 5737 TEST-NET documentation ranges and are not real malicious hosts.

