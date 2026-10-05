from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel

from app.llm.client import PermanentQuotaError, RateLimitError

T = TypeVar("T", bound=BaseModel)


class OpenAIProvider:
    def __init__(self, api_key: str, model: str, timeout: float = 120.0, reasoning_effort: str = "low"):
        if not api_key:
            raise ValueError("OpenAI API key is required")
        from openai import AsyncOpenAI
        self.client = AsyncOpenAI(api_key=api_key, timeout=timeout, max_retries=0)
        self.model = model
        self.reasoning_effort = reasoning_effort

    async def generate_json(self, system_prompt: str, user_prompt: str, response_model: type[T]) -> T:
        try:
            response = await self.client.responses.parse(
                model=self.model,
                instructions=system_prompt,
                input=user_prompt,
                text_format=response_model,
                reasoning={"effort": self.reasoning_effort},
            )
        except Exception as exc:
            status = getattr(exc, "status_code", None)
            message = str(exc).lower()
            if status == 429:
                if any(token in message for token in ("quota", "insufficient", "billing", "daily", "exhausted")):
                    raise PermanentQuotaError(str(exc)) from exc
                raise RateLimitError(str(exc)) from exc
            if status in {500, 502, 503, 504}:
                raise RuntimeError(str(exc)) from exc
            raise
        parsed = getattr(response, "output_parsed", None)
        if parsed is None:
            raise ValueError("OpenAI returned no parsed structured output")
        return parsed

    async def close(self) -> None:
        await self.client.close()
