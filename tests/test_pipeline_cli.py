"""End-to-end integration tests for ThreatIntelPipeline and CLI commands."""

from __future__ import annotations

from pathlib import Path

import httpx
import respx

from app.collectors.otx import OTXCollector
from app.collectors.urlhaus import URLhausCollector
from app.config import Settings
from app.database.repository import ThreatIntelRepository
from app.main import main
from app.pipeline import ThreatIntelPipeline
from app.schemas import RiskLevel


def _no_sleep(_: float) -> None:
    return None


@respx.mock
def test_pipeline_end_to_end_single_and_batch_with_mocked_apis(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        database_path=tmp_path / "ti.db",
        reports_dir=tmp_path / "reports",
        otx_api_key="otx-test",
        urlhaus_auth_key="uh-test",
        http_max_retries=0,
        http_backoff_seconds=0.0,
    )
    respx.get(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/198.51.100.23/general"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "pulse_info": {
                    "count": 4,
                    "pulses": [
                        {
                            "id": "p-demo",
                            "name": "Demo C2 Pulse",
                            "created": "2026-11-18T00:00:00Z",
                            "modified": "2026-11-22T00:00:00Z",
                            "tags": ["c2"],
                            "malware_families": ["Emotet"],
                            "attack_ids": ["T1071"],
                        }
                    ],
                }
            },
        )
    )
    respx.post("https://urlhaus-api.abuse.ch/v1/host/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "host": "198.51.100.23",
                "firstseen": "2026-11-19 00:00:00 UTC",
                "url_count": 2,
                "urls": [
                    {
                        "url_status": "online",
                        "threat": "malware_download",
                        "date_added": "2026-11-22 10:00:00 UTC",
                        "tags": ["emotet"],
                    }
                ],
            },
        )
    )

    repo = ThreatIntelRepository(settings.database_path)
    collectors = [
        OTXCollector(settings, sleep_fn=_no_sleep),
        URLhausCollector(settings, sleep_fn=_no_sleep),
    ]
    with ThreatIntelPipeline(settings=settings, repo=repo, collectors=collectors) as pipeline:
        report = pipeline.investigate_single("198[.]51[.]100[.]23")
        assert report.id is not None
        assert report.risk_level == RiskLevel.CRITICAL
        assert any(t.technique.technique_id == "T1071" for t in report.attack_techniques)

        # Second call inside batch hits TTL cache cleanly and isolates invalid input
        batch_res = pipeline.investigate_batch(["198.51.100.23", "not-valid-ioc"])
        assert len(batch_res.reports) == 1
        assert batch_res.batch.invalid_count == 1
        assert batch_res.total_cache_hits == 2

    repo.close()


def test_cli_workflow_offline_without_api_keys(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_test.db"
    html_out = tmp_path / "demo_report.html"
    settings = Settings(
        _env_file=None,
        database_path=db_file,
        reports_dir=tmp_path / "reports",
        otx_api_key=None,
        urlhaus_auth_key=None,
    )

    # 1. Single lookup + HTML export
    rc1 = main(
        ["lookup", "198.51.100.23", "--export", "html", "--output", str(html_out)],
        settings=settings,
    )
    assert rc1 == 0
    assert html_out.exists()
    assert "198[.]51[.]100[.]23" in html_out.read_text(encoding="utf-8")

    # 2. Invalid IOC returns non-zero exit code gracefully
    rc_bad = main(["lookup", "999.999.999.999"], settings=settings)
    assert rc_bad == 1

    # 3. Batch sample CSV + JSON export
    json_out = tmp_path / "batch.json"
    rc2 = main(
        ["batch", "data/sample_iocs.csv", "--export", "json", "--output", str(json_out)],
        settings=settings,
    )
    assert rc2 == 0
    assert json_out.exists()

    # 4. SOC Log Matching against ingested indicators
    rc3 = main(["match-logs", "data/sample_logs.csv"], settings=settings)
    assert rc3 == 0

    # 5. List reports & metrics
    assert main(["list-reports"], settings=settings) == 0
    assert main(["metrics"], settings=settings) == 0

