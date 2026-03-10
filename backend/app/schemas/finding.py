import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    type: str
    severity: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe: Optional[str] = None
    title: str
    url: str
    parameter: Optional[str] = None
    method: Optional[str] = None
    evidence: Optional[str] = None
    confirmed: bool
    fix_recommendation: Optional[str] = None
    references: Optional[list[str]] = None
    false_positive: bool
    notes: Optional[str] = None
    discovered_at: datetime


class FindingUpdate(BaseModel):
    false_positive: Optional[bool] = None
    notes: Optional[str] = None


class FindingSummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    confirmed: int
    false_positives: int
