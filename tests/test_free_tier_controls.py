import asyncio

import pytest

from app.llm.client import RollingTokenLimiter, estimate_tokens, ProviderRequestError, ResilientLLMClient, CircuitBreaker
from app.models.threat_triage import ThreatTriage


@pytest.mark.asyncio
async def test_token_limiter_serializes_budget():
    limiter = RollingTokenLimiter(tokens_per_minute=100)
    await limiter.reserve(60)
    task = asyncio.create_task(limiter.reserve(60))
    await asyncio.sleep(0.05)
    assert not task.done()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_estimate_tokens_includes_output_budget():
    assert estimate_tokens("1234", "1234", 100) >= 102


class BadProvider:
    model = "bad"
    max_output_tokens = 100

    async def generate_json(self, *args, **kwargs):
        raise ProviderRequestError("Groq HTTP 400: invalid schema", status_code=400)

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_400_is_not_retried():
    client = ResilientLLMClient(
        provider=BadProvider(),
        provider_name="groq",
        stage="triage",
        concurrency=1,
        max_retries=2,
        max_retry_delay=1,
        jitter=0,
        circuit_breaker=CircuitBreaker(60),
    )
    with pytest.raises(ProviderRequestError):
        await client.generate("T", "s", "u", ThreatTriage)


def test_free_tier_settings_are_clamped():
    from app.config import Settings
    settings = Settings(
        free_tier_mode=True,
        llm_provider="groq",
        llm_triage_provider="groq",
        llm_concurrency=5,
        llm_triage_concurrency=5,
        llm_tokens_per_minute=10000,
        llm_max_output_tokens=5000,
        llm_triage_max_output_tokens=2000,
        max_python_threat_groups_per_cycle=8,
        poll_interval_seconds=900,
        llm_max_retries=5,
    )
    settings.prepare_dirs()
    assert settings.llm_concurrency == 1
    assert settings.llm_triage_concurrency == 1
    assert settings.llm_tokens_per_minute == 7000
    assert settings.llm_max_output_tokens == 2400
    assert settings.llm_triage_max_output_tokens == 400
    assert settings.max_python_threat_groups_per_cycle == 2
    assert settings.poll_interval_seconds == 3600
    assert settings.llm_max_retries == 1
    assert settings.llm_thinking_level == "medium"
