from __future__ import annotations

import asyncio
from dataclasses import dataclass

from app.config import Settings
from app.llm.client import (
    CircuitBreaker,
    ResilientLLMClient,
    RollingTokenLimiter,
)
from app.llm.prompts import analysis_prompt, triage_prompt
from app.llm.providers.gemini import GeminiProvider
from app.llm.providers.groq import GroqProvider
from app.llm.providers.openai import OpenAIProvider
from app.models.threat_analysis import ThreatAnalysis
from app.models.threat_triage import ThreatTriage
from app.pipeline.correlate import ThreatGroup


def _provider(settings: Settings, stage: str):
    if stage == "triage":
        name = settings.llm_triage_provider
        key = settings.llm_triage_api_key or settings.llm_api_key
        model = settings.llm_triage_model
        effort = settings.llm_triage_thinking_level
    else:
        name = settings.llm_provider
        key = settings.llm_api_key
        model = settings.llm_model
        effort = settings.llm_thinking_level

    if name.lower() == "openai":
        return OpenAIProvider(
            key,
            model,
            settings.llm_timeout_seconds,
            effort,
        )

    if name.lower() == "groq":
        max_output_tokens = (
            settings.llm_triage_max_output_tokens
            if stage == "triage"
            else settings.llm_max_output_tokens
        )

        return GroqProvider(
            key,
            model,
            settings.llm_timeout_seconds,
            effort,
            max_output_tokens,
        )

    if name.lower() == "gemini":
        return GeminiProvider(
            key,
            model,
            settings.llm_timeout_seconds,
        )

    raise ValueError(
        f"Unsupported LLM provider: {name}"
    )


@dataclass
class ThreatAnalyzer:
    triage_client: ResilientLLMClient
    analysis_client: ResilientLLMClient

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
    ) -> "ThreatAnalyzer":

        triage_provider = _provider(
            settings,
            "triage",
        )

        analysis_provider = _provider(
            settings,
            "analysis",
        )

        # One limiter is deliberately shared by both stages.
        #
        # This means triage + deep analysis together are constrained
        # by the configured provider token budget instead of each
        # stage receiving an independent budget.
        token_limiter = RollingTokenLimiter(
            tokens_per_minute=settings.llm_tokens_per_minute,
        )

        return cls(
            triage_client=ResilientLLMClient(
                provider=triage_provider,
                provider_name=settings.llm_triage_provider,
                stage="triage",
                concurrency=settings.llm_triage_concurrency,
                max_retries=settings.llm_max_retries,
                max_retry_delay=settings.llm_max_retry_delay_seconds,
                jitter=settings.llm_retry_jitter_seconds,
                circuit_breaker=CircuitBreaker(
                    settings.llm_circuit_breaker_cooldown_seconds
                ),
                token_limiter=token_limiter,
            ),
            analysis_client=ResilientLLMClient(
                provider=analysis_provider,
                provider_name=settings.llm_provider,
                stage="analysis",
                concurrency=settings.llm_concurrency,
                max_retries=settings.llm_max_retries,
                max_retry_delay=settings.llm_max_retry_delay_seconds,
                jitter=settings.llm_retry_jitter_seconds,
                circuit_breaker=CircuitBreaker(
                    settings.llm_circuit_breaker_cooldown_seconds
                ),
                token_limiter=token_limiter,
            ),
        )

    async def triage(
        self,
        group: ThreatGroup,
    ):
        system, user = triage_prompt(group)

        return await self.triage_client.generate(
            group.threat_id,
            system,
            user,
            ThreatTriage,
        )

    async def triage_many(
        self,
        groups: list[ThreatGroup],
    ):
        async def one(
            group: ThreatGroup,
        ):
            try:
                return (
                    group,
                    await self.triage(group),
                    None,
                )
            except Exception as exc:
                return (
                    group,
                    None,
                    exc,
                )

        return await asyncio.gather(
            *(one(group) for group in groups)
        )

    async def analyze(
        self,
        group: ThreatGroup,
        triage: ThreatTriage,
    ):
        system, user = analysis_prompt(
            group,
            triage.reason,
        )

        result = await self.analysis_client.generate(
            group.threat_id,
            system,
            user,
            ThreatAnalysis,
        )

        value = result.value.model_copy(
            update={
                "analysis_model":
                    self.analysis_client.provider.model
            }
        )

        result.value = value

        return result

    async def analyze_many(
        self,
        items: list[
            tuple[ThreatGroup, ThreatTriage]
        ],
    ):
        async def one(
            group: ThreatGroup,
            triage: ThreatTriage,
        ):
            try:
                return (
                    group,
                    await self.analyze(
                        group,
                        triage,
                    ),
                    None,
                )
            except Exception as exc:
                return (
                    group,
                    None,
                    exc,
                )

        return await asyncio.gather(
            *(
                one(group, triage)
                for group, triage in items
            )
        )

    async def close(self) -> None:
        await self.triage_client.close()
        await self.analysis_client.close()