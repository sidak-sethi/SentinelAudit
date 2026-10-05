from types import SimpleNamespace

import pytest

from app.llm.providers.groq import GroqProvider
from app.models.threat_triage import ThreatTriage


@pytest.mark.asyncio
async def test_groq_provider_uses_openai_compatible_endpoint(monkeypatch):
    captured = {}

    class FakeResponses:
        async def parse(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                output_parsed=ThreatTriage(
                    should_deep_analyze=True,
                    confidence=0.91,
                    reason="relevant",
                )
            )

    class FakeClient:
        def __init__(self, **kwargs):
            captured["client_kwargs"] = kwargs
            self.responses = FakeResponses()

        async def close(self):
            pass

    import sys
    import types

    fake_openai = types.SimpleNamespace(AsyncOpenAI=FakeClient)
    monkeypatch.setitem(sys.modules, "openai", fake_openai)
    provider = GroqProvider(
        "test-key",
        "openai/gpt-oss-20b",
        reasoning_effort="low",
        max_output_tokens=800,
    )

    result = await provider.generate_json("system", "user", ThreatTriage)

    assert result.should_deep_analyze is True
    assert captured["client_kwargs"]["base_url"] == "https://api.groq.com/openai/v1"
    assert captured["client_kwargs"]["max_retries"] == 0
    assert captured["model"] == "openai/gpt-oss-20b"
    assert captured["max_output_tokens"] == 800
    await provider.close()
