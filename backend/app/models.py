from typing import Optional

from pydantic import BaseModel, Field


class RCARequest(BaseModel):
    namespace: str
    pod: str
    container: Optional[str] = None
    tail_lines: int = Field(500, ge=50, le=5000)
    since_minutes: Optional[int] = Field(None, ge=1, le=1440)
    include_previous: bool = True


class RawRCARequest(BaseModel):
    logs: str = Field(min_length=1, max_length=500_000)
    events: str = Field("", max_length=100_000)
    service: str = Field("unknown", max_length=200)


class WhyStep(BaseModel):
    level: int = Field(description="1..5, 1 = the visible symptom, 5 = the root cause")
    question: str = Field(description="The 'Why' question asked at this level")
    answer: str = Field(description="Answer grounded in the evidence")
    evidence: str = Field(description="Short log line / event / status field backing the answer")


class RCAReport(BaseModel):
    title: str = Field(description="Short incident title, max 12 words")
    severity: str = Field(description="One of: critical, high, medium, low")
    summary: str = Field(description="2-3 sentence executive summary")
    impact: str = Field(description="User / service impact")
    timeline: list[str] = Field(description="Key events in chronological order, with timestamps if available")
    five_whys: list[WhyStep] = Field(description="Exactly 5 steps, symptom -> root cause")
    root_cause: str = Field(description="One-paragraph statement of the true root cause")
    contributing_factors: list[str]
    immediate_actions: list[str] = Field(description="Concrete commands/steps to restore service now")
    preventive_actions: list[str] = Field(description="Long-term fixes, alerts, guardrails")
    confidence: float = Field(description="0.0 - 1.0 confidence in the root cause given the evidence")
    data_gaps: list[str] = Field(description="Missing data that would raise confidence")


class RCAMeta(BaseModel):
    model: str
    namespace: str
    pod: str
    containers: list[str]
    log_chars: int
    event_count: int
    latency_ms: int
    generated_at: str
    demo: bool = False


class RCAResult(BaseModel):
    report: RCAReport
    meta: RCAMeta
