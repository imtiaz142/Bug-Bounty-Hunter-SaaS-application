from typing import Optional

from pydantic import BaseModel, Field


class SettingsResponse(BaseModel):
    llm_provider: Optional[str] = None
    has_api_key: bool
    email: str
    username: str


class SettingsUpdate(BaseModel):
    llm_provider: Optional[str] = None
    llm_api_key: Optional[str] = None
    username: Optional[str] = None


class LLMTestRequest(BaseModel):
    provider: str
    api_key: str


class LLMTestResponse(BaseModel):
    success: bool
    message: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)
