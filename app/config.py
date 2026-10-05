from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    environment: str = "development"
    log_level: str = "INFO"
    demo_mode: bool = False

    # LLM
    llm_provider: str = "groq"
    llm_api_key: str = ""
    llm_model: str = "openai/gpt-oss-120b"
    llm_thinking_level: str = "high"
    llm_concurrency: int = Field(default=1, ge=1)

    llm_triage_provider: str = "groq"
    llm_triage_api_key: str = ""
    llm_triage_model: str = "openai/gpt-oss-20b"
    llm_triage_thinking_level: str = "low"
    llm_triage_concurrency: int = Field(default=1, ge=1)
    llm_triage_min_confidence: float = Field(
        default=0.80,
        ge=0.0,
        le=1.0,
    )

    llm_max_output_tokens: int = Field(
        default=2400,
        ge=256,
    )
    llm_triage_max_output_tokens: int = Field(
        default=400,
        ge=128,
    )

    llm_timeout_seconds: float = Field(
        default=120.0,
        gt=0,
    )

    llm_max_retries: int = Field(
        default=1,
        ge=0,
    )

    llm_max_retry_delay_seconds: float = Field(
        default=60.0,
        gt=0,
    )

    llm_retry_jitter_seconds: float = Field(
        default=1.0,
        ge=0,
    )

    llm_circuit_breaker_cooldown_seconds: float = Field(
        default=900.0,
        gt=0,
    )

    # Shared provider token budget.
    llm_tokens_per_minute: int = Field(
        default=7000,
        ge=1,
    )

    # Free-tier controls.
    free_tier_mode: bool = True

    max_python_threat_groups_per_cycle: int = Field(
        default=2,
        ge=1,
    )

    # NVD
    nvd_api_key: str = ""
    max_events_per_page: int = Field(
        default=200,
        ge=1,
        le=2000,
    )
    nvd_page_delay_seconds: float = Field(
        default=1.0,
        ge=0,
    )
    initial_lookback_hours: float = Field(
        default=24.0,
        gt=0,
    )

    github_token: str = ""

    poll_interval_seconds: float = Field(
        default=3600.0,
        gt=0,
    )

    outgoing_dir: Path = Path("./data/outgoing")
    state_file: Path = Path("./data/state.json")

    enable_osv: bool = True
    enable_github_advisories: bool = True
    enable_cisa_kev: bool = True
    enable_epss: bool = True

    research_source_urls: str = (
        "https://github.blog/tag/security/feed/"
    )

    sandbox_backend: Literal[
        "docker",
        "local",
    ] = "docker"

    sandbox_timeout_seconds: float = Field(
        default=30.0,
        gt=0,
    )

    sandbox_cpu_limit: float = Field(
        default=1.0,
        gt=0,
    )

    sandbox_memory_limit_mb: int = Field(
        default=512,
        ge=64,
    )

    sandbox_pids_limit: int = Field(
        default=64,
        ge=1,
    )

    sandbox_network: bool = False
    allow_local_sandbox: bool = False

    research_work_dir: Path = Path(
        "./data/research"
    )

    @property
    def github_enabled(self) -> bool:
        return bool(
            self.github_token
        ) or self.enable_github_advisories

    @model_validator(mode="after")
    def apply_free_tier_limits(self):
        if self.free_tier_mode:
            self.llm_concurrency = 1
            self.llm_triage_concurrency = 1

            self.llm_tokens_per_minute = min(
                self.llm_tokens_per_minute,
                7000,
            )

            self.llm_max_output_tokens = min(
                self.llm_max_output_tokens,
                2400,
            )

            self.llm_triage_max_output_tokens = min(
                self.llm_triage_max_output_tokens,
                400,
            )

            self.max_python_threat_groups_per_cycle = min(
                self.max_python_threat_groups_per_cycle,
                2,
            )

            self.poll_interval_seconds = max(
                self.poll_interval_seconds,
                3600,
            )

            self.llm_max_retries = min(
                self.llm_max_retries,
                1,
            )

            self.llm_thinking_level = "medium"

        return self

    def prepare_dirs(self) -> None:
        if not self.research_source_urls.strip():
            self.research_source_urls = (
                "https://github.blog/tag/security/feed/"
            )

        self.outgoing_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.research_work_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.state_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.prepare_dirs()
    return settings
