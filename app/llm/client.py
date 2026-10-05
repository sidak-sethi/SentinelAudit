from __future__ import annotations

import asyncio
import math
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Generic, Protocol, TypeVar
from uuid import uuid4

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMClient(Protocol):
    model: str

    async def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        response_model: type[T],
    ) -> T:
        ...

    async def close(self) -> None:
        ...


@dataclass
class LLMRequestTelemetry:
    request_id: str
    provider: str
    model: str
    stage: str
    threat_id: str
    started_at: datetime
    finished_at: datetime | None = None
    latency: float | None = None
    attempt: int = 1
    status: str = "started"
    error_type: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None


@dataclass
class LLMResult(Generic[T]):
    value: T
    telemetry: LLMRequestTelemetry


class PermanentQuotaError(RuntimeError):
    pass


class RateLimitError(RuntimeError):
    def __init__(
        self,
        message: str,
        retry_after: float | None = None,
    ):
        super().__init__(message)
        self.retry_after = retry_after


class ProviderRequestError(RuntimeError):
    def __init__(
        self,
        message: str,
        status_code: int | None = None,
    ):
        super().__init__(message)
        self.status_code = status_code


class CircuitOpenError(RuntimeError):
    pass


@dataclass
class CircuitBreaker:
    cooldown_seconds: float
    opened_until: float | None = None

    def is_open(self) -> bool:
        if self.opened_until is None:
            return False

        if time.monotonic() >= self.opened_until:
            self.opened_until = None
            return False

        return True

    def open(self) -> None:
        self.opened_until = (
            time.monotonic() + self.cooldown_seconds
        )

    def close(self) -> None:
        self.opened_until = None


@dataclass
class RollingTokenLimiter:
    tokens_per_minute: int
    used_tokens: int = 0
    window_started: float = field(
        default_factory=time.monotonic
    )
    lock: asyncio.Lock = field(
        default_factory=asyncio.Lock
    )

    async def reserve(self, estimated_tokens: int) -> None:
        estimated_tokens = max(1, int(estimated_tokens))

        if estimated_tokens > self.tokens_per_minute:
            raise ValueError(
                f"Estimated request size {estimated_tokens} tokens "
                f"exceeds token budget "
                f"{self.tokens_per_minute} tokens/minute"
            )

        while True:
            async with self.lock:
                now = time.monotonic()
                elapsed = now - self.window_started

                if elapsed >= 60:
                    self.window_started = now
                    self.used_tokens = 0

                if (
                    self.used_tokens + estimated_tokens
                    <= self.tokens_per_minute
                ):
                    self.used_tokens += estimated_tokens
                    return

                wait_for = max(
                    0.05,
                    60.0 - elapsed,
                )

            await asyncio.sleep(wait_for)


def estimate_tokens(
    system_prompt: str,
    user_prompt: str,
    max_output_tokens: int,
) -> int:
    """
    Conservative rough estimate used only for throttling.

    Approximately 1 token per 4 characters, plus the
    requested maximum output budget.
    """
    prompt_chars = (
        len(system_prompt) +
        len(user_prompt)
    )

    input_estimate = math.ceil(prompt_chars / 4)

    return input_estimate + max_output_tokens


@dataclass
class ResilientLLMClient:
    provider: LLMClient
    provider_name: str
    stage: str
    concurrency: int
    max_retries: int
    max_retry_delay: float
    jitter: float
    circuit_breaker: CircuitBreaker
    token_limiter: RollingTokenLimiter | None = None

    semaphore: asyncio.Semaphore = field(
        init=False
    )

    def __post_init__(self) -> None:
        self.semaphore = asyncio.Semaphore(
            self.concurrency
        )

    async def generate(
        self,
        threat_id: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[T],
    ) -> LLMResult[T]:

        if self.circuit_breaker.is_open():
            raise CircuitOpenError(
                f"{self.provider_name}/"
                f"{self.provider.model} "
                f"circuit is open"
            )

        async with self.semaphore:
            max_output_tokens = int(
                getattr(
                    self.provider,
                    "max_output_tokens",
                    1000,
                )
            )

            estimated = estimate_tokens(
                system_prompt,
                user_prompt,
                max_output_tokens,
            )

            if self.token_limiter is not None:
                await self.token_limiter.reserve(
                    estimated
                )

            last_exc: Exception | None = None

            for attempt in range(
                1,
                self.max_retries + 2,
            ):
                request_id = str(uuid4())

                started = datetime.now(
                    timezone.utc
                )

                started_mono = time.monotonic()

                telemetry = LLMRequestTelemetry(
                    request_id=request_id,
                    provider=self.provider_name,
                    model=self.provider.model,
                    stage=self.stage,
                    threat_id=threat_id,
                    started_at=started,
                    attempt=attempt,
                )

                try:
                    value = await self.provider.generate_json(
                        system_prompt,
                        user_prompt,
                        response_model,
                    )

                    telemetry.finished_at = (
                        datetime.now(timezone.utc)
                    )

                    telemetry.latency = (
                        time.monotonic()
                        - started_mono
                    )

                    telemetry.status = "success"

                    self.circuit_breaker.close()

                    return LLMResult(
                        value=value,
                        telemetry=telemetry,
                    )

                except PermanentQuotaError as exc:
                    telemetry.status = (
                        "quota_exhausted"
                    )
                    telemetry.error_type = (
                        type(exc).__name__
                    )

                    self.circuit_breaker.open()

                    raise

                except RateLimitError as exc:
                    telemetry.status = (
                        "rate_limited"
                    )
                    telemetry.error_type = (
                        type(exc).__name__
                    )

                    last_exc = exc

                    if attempt > self.max_retries:
                        raise

                    delay = (
                        exc.retry_after
                        if exc.retry_after is not None
                        else self._delay(attempt)
                    )

                    await asyncio.sleep(delay)

                except Exception as exc:
                    telemetry.status = "failed"
                    telemetry.error_type = (
                        type(exc).__name__
                    )

                    last_exc = exc

                    if (
                        attempt > self.max_retries
                        or not _retryable_exception(exc)
                    ):
                        raise

                    await asyncio.sleep(
                        self._delay(attempt)
                    )

            assert last_exc is not None
            raise last_exc

    def _delay(self, attempt: int) -> float:
        base = min(
            self.max_retry_delay,
            2 ** (attempt - 1),
        )

        return base + random.uniform(
            0.0,
            self.jitter,
        )

    async def close(self) -> None:
        await self.provider.close()


def _retryable_exception(
    exc: Exception,
) -> bool:
    status = getattr(
        exc,
        "status_code",
        None,
    )

    if status is None:
        response = getattr(
            exc,
            "response",
            None,
        )

        status = getattr(
            response,
            "status_code",
            None,
        )

    return status in {
        408,
        409,
        425,
        500,
        502,
        503,
        504,
    }