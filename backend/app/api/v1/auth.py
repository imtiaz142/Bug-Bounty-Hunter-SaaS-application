from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.models import User
from app.schemas import (
    ErrorResponse,
    RefreshTokenRequest,
    SuccessResponse,
    TokenResponse,
    UserCreate,
    UserLogin,
    UserResponse,
)

router = APIRouter()


@router.post(
    "/register",
    response_model=SuccessResponse,
    status_code=status.HTTP_201_CREATED,
    responses={409: {"model": ErrorResponse}},
)
async def register(body: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register a new user and return access + refresh tokens."""
    result = await db.execute(select(User).where(User.email == body.email))
    existing = result.scalar_one_or_none()

    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "success": False,
                "error": {
                    "code": "EMAIL_EXISTS",
                    "message": "A user with this email already exists.",
                    "details": None,
                },
            },
        )

    user = User(
        email=body.email,
        username=body.username,
        password_hash=hash_password(body.password),
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    token_data = {"sub": str(user.id)}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return SuccessResponse(
        data={
            "user": UserResponse.model_validate(user).model_dump(mode="json"),
            "tokens": TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
            ).model_dump(),
        },
        message="Registration successful.",
    )


@router.post(
    "/login",
    response_model=SuccessResponse,
    responses={401: {"model": ErrorResponse}},
)
async def login(body: UserLogin, db: AsyncSession = Depends(get_db)):
    """Authenticate a user and return access + refresh tokens."""
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": {
                    "code": "INVALID_CREDENTIALS",
                    "message": "Invalid email or password.",
                    "details": None,
                },
            },
        )

    token_data = {"sub": str(user.id)}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return SuccessResponse(
        data={
            "user": UserResponse.model_validate(user).model_dump(mode="json"),
            "tokens": TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
            ).model_dump(),
        },
        message="Login successful.",
    )


@router.post("/logout", response_model=SuccessResponse)
async def logout():
    """Acknowledge logout. The client is responsible for discarding the token."""
    return SuccessResponse(message="Logged out successfully.")


@router.post(
    "/refresh",
    response_model=SuccessResponse,
    responses={401: {"model": ErrorResponse}},
)
async def refresh(body: RefreshTokenRequest, db: AsyncSession = Depends(get_db)):
    """Validate a refresh token and return a new access token."""
    payload = decode_token(body.refresh_token)

    if payload is None or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": {
                    "code": "INVALID_REFRESH_TOKEN",
                    "message": "Refresh token is invalid or expired.",
                    "details": None,
                },
            },
        )

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": {
                    "code": "INVALID_REFRESH_TOKEN",
                    "message": "Refresh token payload is malformed.",
                    "details": None,
                },
            },
        )

    # Verify user still exists
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": {
                    "code": "USER_NOT_FOUND",
                    "message": "User no longer exists.",
                    "details": None,
                },
            },
        )

    new_access_token = create_access_token({"sub": str(user.id)})

    return SuccessResponse(
        data={
            "access_token": new_access_token,
            "token_type": "bearer",
        },
        message="Token refreshed.",
    )
