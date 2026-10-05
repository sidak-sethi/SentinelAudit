from pydantic import BaseModel, ConfigDict, Field


def _items(max_items: int) -> Field:
    return Field(default_factory=list, max_length=max_items)


class AttackAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    class_name: str = Field(default="unknown", max_length=80)
    entry_condition: str = Field(default="unknown", max_length=200)
    attack_path: list[str] = _items(4)
    preconditions: list[str] = _items(3)
    impact: str = Field(default="unknown", max_length=200)
    indicators: list[str] = _items(3)


class ExploitAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reproduction_method: str = Field(default="not established", max_length=220)
    vulnerable_behavior: str = Field(default="not established", max_length=260)
    verification_conditions: list[str] = _items(3)
    reproduction_evidence: list[str] = _items(3)


class CountermeasureAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    strategy: str = Field(default="not established", max_length=220)
    root_cause: str = Field(default="not established", max_length=260)
    affected_code_pattern: str = Field(default="not established", max_length=220)
    mitigation: list[str] = _items(4)
    candidate_patch_description: str = Field(default="not established", max_length=280)
    patch_validation: str = Field(default="UNVERIFIED", max_length=120)
    upstream_fixed_versions: list[str] = _items(3)


class ThreatAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    affected_technology: list[str] = _items(4)
    affected_packages: list[str] = _items(8)
    affected_versions: list[str] = _items(12)
    attack: AttackAssessment
    exploit: ExploitAssessment
    countermeasure: CountermeasureAssessment
    test_strategy: list[str] = _items(5)
    confidence: float = Field(ge=0.0, le=1.0)
    analysis_model: str = Field(max_length=100)
    analysis_version: str = Field(default="1", max_length=20)
