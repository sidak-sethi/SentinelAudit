from app.llm.prompts import triage_prompt
from app.models.source_event import SourceEvent
from app.pipeline.correlate import ThreatGroup
from app.pipeline.relevance import is_python_relevant


def make_event(**kwargs):
    defaults = dict(
        event_id="test",
        source="NVD",
        source_type="test",
        identifiers={"CVE": ["CVE-TEST"]},
        summary="",
        description="",
    )
    defaults.update(kwargs)
    return SourceEvent(**defaults)


def test_requests_word_in_normal_english_is_not_python_evidence():
    event = make_event(
        summary="authentication requests can bypass a restriction",
        description="An attacker can modify request headers.",
    )
    assert is_python_relevant(event) is False


def test_requests_as_affected_package_is_python_evidence():
    event = make_event(
        affected_packages=["requests"],
        summary="requests package vulnerability",
        description="A Python package issue.",
    )
    assert is_python_relevant(event) is True


def test_sglang_python_source_path_is_python_evidence():
    event = make_event(
        summary="sgl-project sglang vulnerability",
        description=(
            "This affects python/sglang/srt/entrypoints/http_server.py "
            "and the HTTP endpoint."
        ),
    )
    assert is_python_relevant(event) is True


def test_triage_prompt_does_not_use_cvss_as_sole_discard_rule():
    group = ThreatGroup(
        threat_id="CVE-2026-105245",
        events=[
            make_event(
                affected_packages=["sglang"],
                summary="sglang vulnerability",
                description=(
                    "A low severity Python vulnerability is publicly disclosed "
                    "and may be exploited remotely."
                ),
                severity="LOW",
                cvss_score=2.9,
            )
        ],
    )
    _, user = triage_prompt(group)
    assert "CVSS severity is a prioritization signal, not a discard rule." in user
    assert "Do not discard a candidate solely because its CVSS score is low or medium." in user

def test_real_nvd_style_python_cve_without_package_metadata_triggers_safeguard():
    from app.main import _should_force_deep_analysis

    group = ThreatGroup(
        threat_id="CVE-2026-105245",
        events=[
            make_event(
                affected_packages=[],
                summary=(
                    "sgl-project sglang vulnerability"
                ),
                description=(
                    "A vulnerability has been found in sgl-project sglang "
                    "up to 0.5.21. This issue affects the function server_info "
                    "of python/sglang/srt/entrypoints/http_server.py. "
                    "It is possible to launch the attack remotely. "
                    "The exploit has been disclosed to the public and may be used."
                ),
                severity="LOW",
                cvss_score=2.9,
            )
        ],
    )

    assert _should_force_deep_analysis(group) is True

def test_low_cvss_exploitable_python_group_triggers_deterministic_deep_safeguard():
    from app.main import _should_force_deep_analysis

    group = ThreatGroup(
        threat_id="CVE-2026-105245",
        events=[
            make_event(
                affected_packages=["sglang"],
                summary="sglang vulnerability",
                description=(
                    "The vulnerability is publicly disclosed, may be exploited, "
                    "and can be launched remotely to expose an API key."
                ),
                severity="LOW",
                cvss_score=2.9,
            )
        ],
    )
    assert _should_force_deep_analysis(group) is True
