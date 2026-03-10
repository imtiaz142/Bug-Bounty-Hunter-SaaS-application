import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


class ScanCreate(BaseModel):
    target_url: HttpUrl
    target_scope_include: list[str] = Field(default_factory=list)
    target_scope_exclude: list[str] = Field(default_factory=list)
    scan_type: Literal["quick", "full"] = "quick"
    consent: bool

    @model_validator(mode="after")
    def validate_consent(self) -> "ScanCreate":
        if not self.consent:
            raise ValueError(
                "You must confirm you have authorization to scan this target."
            )
        return self


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    target_url: str
    status: str
    scan_type: str
    progress: int
    current_agent: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    created_at: datetime
    target_scope_include: Optional[list[str]] = None
    target_scope_exclude: Optional[list[str]] = None


class ScanListResponse(BaseModel):
    scans: list[ScanResponse]
    total: int
    page: int
    per_page: int


class ScanProgress(BaseModel):
    scan_id: uuid.UUID
    progress: int
    current_agent: Optional[str] = None
    status: str
