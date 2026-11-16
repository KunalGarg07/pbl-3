"""The shared data model. Every engine's output is converted into these classes."""
from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self)


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class Finding(BaseModel):
    finding_id: str
    source: Literal["bandit", "ml"]
    rule_id: str
    rule_name: str
    category: str
    cwe: Optional[int] = None
    cwe_link: Optional[str] = None
    file: str
    line: int
    end_line: Optional[int] = None
    col: Optional[int] = None
    severity: Severity
    severity_reason: str
    # Raw values from Bandit, kept unchanged so the mapping can be audited.
    bandit_severity: Optional[str] = None
    bandit_confidence: Optional[str] = None
    # ML score for the function that contains this line. Not a probability of exploitability.
    ml_score: Optional[float] = None
    evidence: str
    code_snippet: Optional[str] = None
    more_info: Optional[str] = None
    recommendation: Optional[str] = None
    # False for ML-only findings: no rule has confirmed them.
    confirmed: bool = True
    # Context (week 10): does user input reach this line, and is it test code?
    user_input: Optional[Literal["direct", "parameter", "none"]] = None
    in_test_code: bool = False


class EngineStatus(BaseModel):
    status: Literal["ok", "error", "unavailable", "unsupported"]
    detail: Optional[str] = None


class ScanSummary(BaseModel):
    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=lambda: {s.value: 0 for s in SEVERITY_ORDER})
    by_source: dict[str, int] = Field(default_factory=lambda: {"bandit": 0, "ml": 0})


class ScanResult(BaseModel):
    scan_id: str
    filename: str
    kind: Literal["file", "repository"] = "file"
    files: list[str] = Field(default_factory=list)
    skipped_files: int = 0
    language: str = "python"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_sha256: str
    lines_of_code: int
    duration_ms: int = 0
    engines: dict[str, EngineStatus]
    findings: list[Finding]
    summary: ScanSummary
    model_version: Optional[str] = None
