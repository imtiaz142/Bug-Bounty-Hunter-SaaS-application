import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict


class ReportCreate(BaseModel):
    report_type: Literal["technical", "executive"]


class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    report_type: str
    status: str
    file_path: Optional[str] = None
    share_token: Optional[str] = None
    generated_at: Optional[datetime] = None
    created_at: datetime
