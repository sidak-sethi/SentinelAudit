from pydantic import BaseModel, ConfigDict, Field


class ThreatTriage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    should_deep_analyze: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=1)
