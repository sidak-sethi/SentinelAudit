import pytest

from app.llm.client import CircuitBreaker, PermanentQuotaError, ResilientLLMClient
from app.models.threat_triage import ThreatTriage


class QuotaProvider:
    model = "quota"
    async def generate_json(self, system_prompt, user_prompt, response_model):
        raise PermanentQuotaError("daily quota exhausted")
    async def close(self):
        pass


@pytest.mark.asyncio
async def test_quota_opens_circuit():
    cb = CircuitBreaker(60)
    client = ResilientLLMClient(QuotaProvider(), "test", "triage", 1, 0, 1, 0, cb)
    with pytest.raises(PermanentQuotaError):
        await client.generate("T", "s", "u", ThreatTriage)
    assert cb.is_open()
