from __future__ import annotations

import json
from typing import TypeVar

from pydantic import BaseModel

from app.llm.client import (
    PermanentQuotaError,
    ProviderRequestError,
    RateLimitError,
)

T = TypeVar("T", bound=BaseModel)


class GroqProvider:
    """Groq provider using Groq's OpenAI-compatible Responses API."""

    BASE_URL = "https://api.groq.com/openai/v1"

    def __init__(
        self,
        api_key: str,
        model: str,
        timeout: float = 120.0,
        reasoning_effort: str = "low",
        max_output_tokens: int = 1600,
    ):
        if not api_key:
            raise ValueError("Groq API key is required")

        from openai import AsyncOpenAI

        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url=self.BASE_URL,
            timeout=timeout,
            max_retries=0,
        )

        self.model = model
        self.reasoning_effort = reasoning_effort
        self.max_output_tokens = max_output_tokens

    async def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        response_model: type[T],
    ) -> T:
        try:
            response = await self.client.responses.parse(
                model=self.model,
                instructions=system_prompt,
                input=user_prompt,
                text_format=response_model,
                reasoning={"effort": self.reasoning_effort},
                max_output_tokens=self.max_output_tokens,
            )
        except Exception as exc:
            status = getattr(exc, "status_code", None)
            message = _error_message(exc)
            lower = message.lower()

            headers = (
                getattr(getattr(exc, "response", None), "headers", {}) or {}
            )

            retry_after = _parse_retry_after(headers)

            if status == 429:
                if _is_permanent_quota(lower, headers):
                    raise PermanentQuotaError(message) from exc

                raise RateLimitError(
                    message,
                    retry_after=retry_after,
                ) from exc

            if status in {408, 409, 425, 500, 502, 503, 504}:
                raise RuntimeError(message) from exc

            if status is not None and 400 <= status < 500:
                raise ProviderRequestError(
                    f"Groq HTTP {status}: {message}",
                    status_code=status,
                ) from exc

            raise RuntimeError(message) from exc

        parsed = getattr(response, "output_parsed", None)

        if parsed is None:
            raise ProviderRequestError(
                "Groq returned no parsed structured output"
            )

        return parsed

    async def close(self) -> None:
        await self.client.close()


def _error_message(exc: Exception) -> str:
    body = getattr(exc, "body", None)

    if body is not None:
        try:
            return json.dumps(body, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(body)

    response = getattr(exc, "response", None)

    if response is not None:
        try:
            text = response.text
            if text:
                return text
        except Exception:
            pass

    return str(exc)


def _parse_retry_after(headers) -> float | None:
    if not headers:
        return None

    value = headers.get("retry-after")

    if value is None:
        value = headers.get("Retry-After")

    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _is_permanent_quota(message: str, headers) -> bool:
    permanent_markers = (
        "insufficient_quota",
        "credit_balance_exhausted",
        "quota exceeded",
        "credits remaining",
        "daily limit",
    )

    if any(marker in message for marker in permanent_markers):
        return True

    remaining_requests = _header_number(
        headers,
        "x-ratelimit-remaining-requests",
    )

    remaining_tokens = _header_number(
        headers,
        "x-ratelimit-remaining-tokens",
    )

    reset_requests = _header_number(
        headers,
        "x-ratelimit-reset-requests",
    )

    reset_tokens = _header_number(
        headers,
        "x-ratelimit-reset-tokens",
    )

    if remaining_requests == 0 and not reset_requests:
        return True

    if remaining_tokens == 0 and not reset_tokens:
        return True

    return False


def _header_number(headers, name: str) -> float | None:
    if not headers:
        return None

    value = headers.get(name)

    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None