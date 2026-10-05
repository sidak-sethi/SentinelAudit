"""Local-only client for Gemma 4 via Ollama.

This module performs the ONLY network call anywhere in the Offline
codebase, and only to OLLAMA_HOST, which defaults to loopback and is
checked against a loopback allowlist unless explicitly overridden. No
other AI model is ever used, and there is no automatic fallback: if
Gemma 4 is unavailable, every function here fails loudly rather than
fabricating a result or silently switching models.
"""
import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlparse

DEFAULT_OLLAMA_HOST = "http://localhost:11434"
DEFAULT_GEMMA_MODEL = "gemma4:e2b"
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class GemmaUnavailableError(RuntimeError):
    """Raised when Ollama or the configured Gemma 4 model cannot be
    reached. There is no fallback -- callers must treat this as a hard
    failure (status = AI_ERROR), never fabricate a result."""


class GemmaResponseError(RuntimeError):
    """Raised when Gemma responded but never produced valid JSON even
    after a corrective retry."""


def get_ollama_host() -> str:
    return os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_HOST)


def get_gemma_model() -> str:
    return os.environ.get("GEMMA_MODEL", DEFAULT_GEMMA_MODEL)


def _log(message: str) -> None:
    print(f"MODEL: GEMMA 4 | MODEL_TAG: {get_gemma_model()} | {message}")


def _enforce_loopback(host: str) -> None:
    hostname = urlparse(host).hostname
    if hostname not in LOOPBACK_HOSTS and os.environ.get("SENTINEL_ALLOW_NON_LOOPBACK_OLLAMA") != "1":
        raise GemmaUnavailableError(
            f"OLLAMA_HOST '{host}' is not a loopback address. The Offline agent only "
            "talks to a local Ollama instance; set SENTINEL_ALLOW_NON_LOOPBACK_OLLAMA=1 "
            "to override this in a deployment where that is explicitly intended."
        )


def _request(path: str, payload: dict | None = None, method: str = "GET", timeout: int = 60) -> dict:
    host = get_ollama_host()
    _enforce_loopback(host)
    url = host.rstrip("/") + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, ConnectionError, OSError) as exc:
        raise GemmaUnavailableError(f"Could not reach Ollama at {host}: {exc}") from exc


def check_ollama_available() -> bool:
    try:
        _request("/api/tags", method="GET")
        return True
    except GemmaUnavailableError:
        return False


def list_models() -> list:
    result = _request("/api/tags", method="GET")
    return [model.get("name", "") for model in result.get("models", [])]


def check_model_available(model: str | None = None) -> bool:
    model = model or get_gemma_model()
    try:
        return model in list_models()
    except GemmaUnavailableError:
        return False


def check_runtime_status(model: str | None = None) -> tuple[bool, bool]:
    """Check Ollama reachability and the configured model with one request."""
    model = model or get_gemma_model()
    try:
        installed_models = list_models()
    except GemmaUnavailableError:
        return False, False
    return True, model in installed_models


def ensure_available() -> None:
    model = get_gemma_model()
    try:
        installed_models = list_models()
    except GemmaUnavailableError as exc:
        raise GemmaUnavailableError(
            f"ERROR:\nOllama is not reachable at {get_ollama_host()}.\n"
            "Please start Ollama before running the Offline Auditor."
        ) from exc
    if model not in installed_models:
        raise GemmaUnavailableError(
            f"ERROR:\nGemma 4 model {model} is unavailable.\n"
            f"Please install it with Ollama before starting the Offline Auditor "
            f"(e.g. `ollama pull {model}`).\n"
            "No other model will be substituted."
        )


def generate_json(system_prompt: str, user_prompt: str, max_retries: int = 1, timeout: int = 180,
                   num_predict: int | None = None) -> dict:
    """Call Gemma 4 and parse a JSON object from its response.

    Retries once with a stricter corrective prompt on malformed JSON;
    raises GemmaResponseError rather than fabricating a result if Gemma
    still cannot produce valid JSON.

    `num_predict` caps/raises the generation length (Ollama's own
    option). Pass a generous value (see offline/auditor.py and
    offline/patcher.py's code-producing calls) for responses that embed a
    full source file -- the default context budget can otherwise cut
    generation off mid-string on a larger response, which is the single
    biggest observed cause of "Unterminated string" JSON errors.
    """
    ensure_available()
    model = get_gemma_model()
    prompt = user_prompt
    last_error: Exception | None = None

    for attempt in range(max_retries + 1):
        _log(f"generate_json attempt {attempt + 1}/{max_retries + 1}")
        payload = {
            "model": model,
            "system": system_prompt,
            "prompt": prompt,
            "format": "json",
            "stream": False,
        }
        if num_predict is not None:
            payload["options"] = {"num_predict": num_predict}
        result = _request("/api/generate", payload=payload, method="POST", timeout=timeout)
        text = result.get("response", "")
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            last_error = exc
            prompt = (
                f"{user_prompt}\n\nYour previous response was not valid JSON. "
                "Respond with ONLY a single valid JSON object, no prose, no markdown fences."
            )

    raise GemmaResponseError(f"Gemma did not return valid JSON after {max_retries + 1} attempt(s): {last_error}")
