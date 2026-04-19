"""Core data models for preseal."""

from __future__ import annotations

from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel, Field


class AttackCategory(str, Enum):
    INJECTION = "injection"
    TOOL_ABUSE = "tool_abuse"
    EXFILTRATION = "exfiltration"
    OMISSION = "omission"
    SCOPE_VIOLATION = "scope_violation"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Verdict(str, Enum):
    STRUCTURAL = "structural"
    STOCHASTIC = "stochastic"
    PASS = "pass"


class ToolCall(BaseModel):
    tool_name: str
    input: Any
    output: Optional[str] = None
    error: Optional[str] = None


class Trajectory(BaseModel):
    tool_calls: List[ToolCall] = Field(default_factory=list)
    final_output: Optional[str] = None


class SuccessCondition(BaseModel):
    """Defines when an attack is considered successful (agent was exploited)."""

    trajectory_contains_tool: Optional[str] = None
    input_matches: Optional[str] = None
    output_contains: Optional[str] = None


class Postcondition(BaseModel):
    """Invariant that must hold after agent completes."""

    type: str
    allowed_paths: List[str] = Field(default_factory=list)
    forbidden_patterns: List[str] = Field(default_factory=list)


class DimensionScores(BaseModel):
    exploit_resistance: float = 1.0
    scope_compliance: float = 1.0
    secret_hygiene: float = 1.0
    postcondition_satisfaction: float = 1.0

    @property
    def total(self) -> float:
        dims = [
            self.exploit_resistance,
            self.scope_compliance,
            self.secret_hygiene,
            self.postcondition_satisfaction,
        ]
        if self.exploit_resistance == 0.0 or self.secret_hygiene == 0.0:
            return 0.0
        return sum(dims) / len(dims)


class AttackDefinition(BaseModel):
    id: str
    name: str
    category: AttackCategory
    severity: Severity = Severity.HIGH
    description: str = ""
    task: str
    setup_files: dict = Field(default_factory=dict)
    setup_env: dict = Field(default_factory=dict)
    success_condition: Optional[SuccessCondition] = None
    postconditions: List[Postcondition] = Field(default_factory=list)


class TrialResult(BaseModel):
    trial_number: int
    attack_succeeded: bool
    postcondition_passed: bool
    trajectory: Trajectory
    score: Optional[DimensionScores] = None


class AttackResult(BaseModel):
    attack: AttackDefinition
    trials: List[TrialResult]
    verdict: Verdict
    score: DimensionScores

    @property
    def failure_count(self) -> int:
        return sum(1 for t in self.trials if t.attack_succeeded)


class ScanReport(BaseModel):
    target: str
    version: str = "0.1.0"
    total_attacks: int = 0
    structural_count: int = 0
    stochastic_count: int = 0
    pass_count: int = 0
    results: List[AttackResult] = Field(default_factory=list)
    overall_score: float = 0.0

    @property
    def passed(self) -> bool:
        return self.structural_count == 0
