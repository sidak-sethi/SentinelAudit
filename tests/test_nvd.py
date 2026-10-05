from app.collectors.nvd import NVDCollector


def test_nvd_normalization():
    payload = {
        "cve": {
            "id": "CVE-2026-0001",
            "published": "2026-01-01T00:00:00.000Z",
            "lastModified": "2026-01-02T00:00:00.000Z",
            "descriptions": [{"lang":"en","value":"Python requests issue"}],
            "references": [{"url":"https://example.invalid/advisory"}],
            "metrics": {"cvssMetricV31":[{"cvssData":{"baseScore":8.2}}]},
            "configurations": {"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:python:requests:2.0:*:*:*:*:*:*:*"}]}]},
        }
    }
    event = NVDCollector()._normalize(payload)
    assert event is not None
    assert event.identifiers["CVE"] == ["CVE-2026-0001"]
    assert event.cvss_score == 8.2
