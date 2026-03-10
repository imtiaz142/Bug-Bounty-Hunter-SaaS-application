import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models import Finding, Scan, User
from app.schemas import (
    ErrorResponse,
    FindingResponse,
    FindingSummary,
    FindingUpdate,
    SuccessResponse,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _verify_scan_ownership(
    scan_id: uuid.UUID, user: User, db: AsyncSession
) -> Scan:
    """Ensure the scan exists and belongs to the current user."""
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
    return scan


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}},
)
async def list_findings(
    scan_id: uuid.UUID,
    severity: str | None = Query(None),
    finding_type: str | None = Query(None, alias="type"),
    confirmed: bool | None = Query(None),
    false_positive: bool | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List findings for a scan with optional filters."""
    await _verify_scan_ownership(scan_id, user, db)

    query = select(Finding).where(Finding.scan_id == scan_id)
    count_query = (
        select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
    )

    if severity is not None:
        query = query.where(Finding.severity == severity)
        count_query = count_query.where(Finding.severity == severity)
    if finding_type is not None:
        query = query.where(Finding.type == finding_type)
        count_query = count_query.where(Finding.type == finding_type)
    if confirmed is not None:
        query = query.where(Finding.confirmed == confirmed)
        count_query = count_query.where(Finding.confirmed == confirmed)
    if false_positive is not None:
        query = query.where(Finding.false_positive == false_positive)
        count_query = count_query.where(Finding.false_positive == false_positive)

    total_result = await db.execute(count_query)
    total = total_result.scalar()

    offset = (page - 1) * per_page
    result = await db.execute(
        query.order_by(Finding.discovered_at.desc()).offset(offset).limit(per_page)
    )
    findings = result.scalars().all()

    return SuccessResponse(
        data={
            "findings": [
                FindingResponse.model_validate(f).model_dump(mode="json")
                for f in findings
            ],
            "total": total,
            "page": page,
            "per_page": per_page,
        },
    )


@router.get(
    "/summary",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}},
)
async def findings_summary(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return finding counts by severity plus chart data."""
    await _verify_scan_ownership(scan_id, user, db)

    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = result.scalars().all()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    confirmed_count = 0
    false_positive_count = 0

    for f in findings:
        sev = f.severity.lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        confirmed_count += int(f.confirmed)
        false_positive_count += int(f.false_positive)

    summary = FindingSummary(
        total=len(findings),
        critical=severity_counts["critical"],
        high=severity_counts["high"],
        medium=severity_counts["medium"],
        low=severity_counts["low"],
        info=severity_counts["info"],
        confirmed=confirmed_count,
        false_positives=false_positive_count,
    )

    # Chart-friendly data
    chart_data = [
        {"label": sev.capitalize(), "value": count}
        for sev, count in severity_counts.items()
    ]

    return SuccessResponse(
        data={
            "summary": summary.model_dump(),
            "chart_data": chart_data,
        },
    )


@router.get(
    "/{finding_id}",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}},
)
async def get_finding(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single finding by ID."""
    await _verify_scan_ownership(scan_id, user, db)

    result = await db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.scan_id == scan_id)
    )
    finding = result.scalar_one_or_none()

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": {
                    "code": "FINDING_NOT_FOUND",
                    "message": "Finding not found.",
                    "details": None,
                },
            },
        )

    return SuccessResponse(
        data=FindingResponse.model_validate(finding).model_dump(mode="json"),
    )


@router.patch(
    "/{finding_id}",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}},
)
async def update_finding(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    body: FindingUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update false_positive flag and/or notes on a finding."""
    await _verify_scan_ownership(scan_id, user, db)

    result = await db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.scan_id == scan_id)
    )
    finding = result.scalar_one_or_none()

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": {
                    "code": "FINDING_NOT_FOUND",
                    "message": "Finding not found.",
                    "details": None,
                },
            },
        )

    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(finding, field, value)

    await db.flush()
    await db.refresh(finding)

    return SuccessResponse(
        data=FindingResponse.model_validate(finding).model_dump(mode="json"),
        message="Finding updated.",
    )
