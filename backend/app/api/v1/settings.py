from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.core.security import encrypt_api_key, hash_password, verify_password
from app.models import User
from app.schemas import (
    ErrorResponse,
    LLMTestRequest,
    LLMTestResponse,
    PasswordChange,
    SettingsResponse,
    SettingsUpdate,
    SuccessResponse,
)

router = APIRouter()


@router.get(
    "/",
    response_model=SuccessResponse,
)
async def get_settings(
    user: User = Depends(get_current_user),
):
    """Return the current user's settings."""
    return SuccessResponse(
        data=SettingsResponse(
            llm_provider=user.llm_provider,
            has_api_key=user.llm_api_key_encrypted is not None,
            email=user.email,
            username=user.username,
        ).model_dump(),
    )


@router.patch(
    "/",
    response_model=SuccessResponse,
    responses={400: {"model": ErrorResponse}},
)
async def update_settings(
    body: SettingsUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update user settings (provider, api_key, username)."""
    if body.llm_provider is not None:
        allowed_providers = ("openai", "claude", "anthropic")
        if body.llm_provider.lower() not in allowed_providers:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "success": False,
                    "error": {
                        "code": "INVALID_PROVIDER",
                        "message": f"Provider must be one of: {', '.join(allowed_providers)}.",
                        "details": None,
                    },
                },
            )
        user.llm_provider = body.llm_provider.lower()

    if body.llm_api_key is not None:
        user.llm_api_key_encrypted = encrypt_api_key(body.llm_api_key)

    if body.username is not None:
        user.username = body.username

    await db.flush()
    await db.refresh(user)

    return SuccessResponse(
        data=SettingsResponse(
            llm_provider=user.llm_provider,
            has_api_key=user.llm_api_key_encrypted is not None,
            email=user.email,
            username=user.username,
        ).model_dump(),
        message="Settings updated.",
    )


@router.post(
    "/llm/test",
    response_model=SuccessResponse,
    responses={400: {"model": ErrorResponse}},
)
async def test_llm_key(
    body: LLMTestRequest,
    user: User = Depends(get_current_user),
):
    """Test whether an LLM API key is valid by making a simple API call."""
    provider = body.provider.lower()

    try:
        if provider in ("openai",):
            import httpx

            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {body.api_key}"},
                )
            if resp.status_code == 200:
                result = LLMTestResponse(success=True, message="OpenAI API key is valid.")
            else:
                result = LLMTestResponse(
                    success=False,
                    message=f"OpenAI returned status {resp.status_code}.",
                )

        elif provider in ("claude", "anthropic"):
            import httpx

            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": body.api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-3-haiku-20240307",
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                )
            if resp.status_code == 200:
                result = LLMTestResponse(success=True, message="Anthropic API key is valid.")
            else:
                result = LLMTestResponse(
                    success=False,
                    message=f"Anthropic returned status {resp.status_code}.",
                )
        else:
            result = LLMTestResponse(success=False, message=f"Unsupported provider: {provider}.")

    except Exception as exc:
        result = LLMTestResponse(success=False, message=f"Connection error: {str(exc)}")

    return SuccessResponse(data=result.model_dump())


@router.delete(
    "/llm",
    response_model=SuccessResponse,
)
async def remove_llm(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the stored LLM provider and API key."""
    user.llm_provider = None
    user.llm_api_key_encrypted = None
    await db.flush()

    return SuccessResponse(message="LLM provider and API key removed.")


@router.post(
    "/password",
    response_model=SuccessResponse,
    responses={400: {"model": ErrorResponse}},
)
async def change_password(
    body: PasswordChange,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change the current user's password."""
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": {
                    "code": "WRONG_PASSWORD",
                    "message": "Current password is incorrect.",
                    "details": None,
                },
            },
        )

    user.password_hash = hash_password(body.new_password)
    await db.flush()

    return SuccessResponse(message="Password changed successfully.")
