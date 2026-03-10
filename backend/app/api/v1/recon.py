import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models import Scan, User
from app.schemas import ErrorResponse, SuccessResponse

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_scan_recon(
    scan_id: uuid.UUID, user: User, db: AsyncSession
) -> dict:
    """Fetch a scan's recon_data, verifying ownership."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": {
                    "code": "SCAN_NOT_FOUND",
                    "message": "Scan not found or does not belong to you.",
                    "details": None,
                },
            },
        )

    if scan.recon_data is None:
        return {}
    return scan.recon_data


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/subdomains",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}},
)
async def get_subdomains(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return subdomains discovered during recon."""
    recon = await _get_scan_recon(scan_id, user, db)
    return SuccessResponse(
        data={"subdomains": recon.get("subdomains", [])},
    )


@router.get(
    "/ports",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}},
)
async def get_ports(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return open ports discovered during recon."""
    recon = await _get_scan_recon(scan_id, user, db)
    return SuccessResponse(
        data={"ports": recon.get("ports", [])},
    )


@router.get(
    "/technologies",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}},
)
async def get_technologies(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return technologies detected during recon."""
    recon = await _get_scan_recon(scan_id, user, db)
    return SuccessResponse(
        data={"technologies": recon.get("technologies", [])},
    )


@router.get(
    "/emails",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}},
)
async def get_emails(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return emails discovered during recon."""
    recon = await _get_scan_recon(scan_id, user, db)
    return SuccessResponse(
        data={"emails": recon.get("emails", [])},
    )
