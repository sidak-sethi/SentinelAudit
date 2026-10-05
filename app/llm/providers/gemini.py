from __future__ import annotations

import json

import httpx
from pydantic import BaseModel

from app.llm.client import PermanentQuotaError, RateLimitError


class GeminiProvider:
    """Optional provider kept for provider neutrality. Uses Gemini REST JSON output."""

    def __init__(self, api_key: str, model: str, timeout: float = 120.0):
        if not api_key:
            raise ValueError("Gemini API key is required")
        self.api_key = api_key
        self.model = model
        self.client = httpx.AsyncClient(timeout=timeout)

    async def generate_json(self, system_prompt: str, user_prompt: str, response_model: type[BaseModel]) -> BaseModel:
        schema = response_model.model_json_schema()
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        body = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": schema,
            },
        }
        try:
            response = await self.client.post(url, params={"key": self.api_key}, json=body)
        except httpx.HTTPError as exc:
            raise RuntimeError(str(exc)) from exc
        if response.status_code == 429:
            text = response.text.lower()
            if any(x in text for x in ("quota", "exhaust", "daily")):
                raise PermanentQuotaError(response.text)
            raise RateLimitError(response.text)
        response.raise_for_status()
        data = response.json()
        parts = (((data.get("candidates") or [{}])[0].get("content") or {}).get("parts") or [])
        text = next((p.get("text") for p in parts if p.get("text")), None)
        if not text:
            raise ValueError("Gemini returned no text")
        return response_model.model_validate(json.loads(text))

    async def close(self) -> None:
        await self.client.aclose()
