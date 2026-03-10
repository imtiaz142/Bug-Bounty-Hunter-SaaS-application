import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.core.database import get_db
from app.models import Finding, Scan, User
from app.schemas import (
    ErrorResponse,
    FindingResponse,
    ScanCreate,
    ScanListResponse,
    ScanProgress,
    ScanResponse,
    SuccessResponse,
)

router = APIRouter()
settings = get_settings()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_user_scan(
    scan_id: uuid.UUID,
    user: User,
    db: AsyncSession,
) -> Scan:
    """Fetch a scan that belongs to the current user, or raise 404."""
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

@router.post(
    "/",
    response_model=SuccessResponse,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
async def create_scan(
    body: ScanCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new scan. Consent must be true. Max 3 concurrent scans."""
    # Check concurrent scan limit
    concurrent_result = await db.execute(
        select(func.count())
        .select_from(Scan)
        .where(
            Scan.user_id == user.id,
            Scan.status.in_(["queued", "running"]),
        )
    )
    concurrent_count = concurrent_result.scalar()

    if concurrent_count >= settings.MAX_CONCURRENT_SCANS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "success": False,
                "error": {
                    "code": "MAX_CONCURRENT_SCANS",
                    "message": f"You already have {concurrent_count} active scans. Maximum is {settings.MAX_CONCURRENT_SCANS}.",
                    "details": None,
                },
            },
        )

    scan = Scan(
        user_id=user.id,
        target_url=str(body.target_url),
        target_scope_include=body.target_scope_include,
        target_scope_exclude=body.target_scope_exclude,
        scan_type=body.scan_type,
        status="queued",
        progress=0,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Queue Celery task (import lazily to avoid circular imports at module level)
    try:
        from app.workers.tasks import run_scan

        run_scan.delay(str(scan.id), str(user.id))
    except Exception:
        # If Celery is unavailable, the scan stays queued and can be picked up later
        pass

    return SuccessResponse(
        data=ScanResponse.model_validate(scan).model_dump(mode="json"),
        message="Scan created and queued.",
    )


@router.get(
    "/",
    response_model=SuccessResponse,
)
async def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    scan_status: str | None = Query(None, alias="status"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List the current user's scans with pagination and optional status filter."""
    base_query = select(Scan).where(Scan.user_id == user.id)
    count_query = select(func.count()).select_from(Scan).where(Scan.user_id == user.id)

    if scan_status is not None:
        base_query = base_query.where(Scan.status == scan_status)
        count_query = count_query.where(Scan.status == scan_status)

    total_result = await db.execute(count_query)
    total = total_result.scalar()

    offset = (page - 1) * per_page
    result = await db.execute(
        base_query.order_by(Scan.created_at.desc()).offset(offset).limit(per_page)
    )
    scans = result.scalars().all()

    return SuccessResponse(
        data=ScanListResponse(
            scans=[ScanResponse.model_validate(s) for s in scans],
            total=total,
            page=page,
            per_page=per_page,
        ).model_dump(mode="json"),
    )


@router.get(
    "/diff",
    response_model=SuccessResponse,
)
async def diff_scans(
    scan1: uuid.UUID = Query(...),
    scan2: uuid.UUID = Query(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Compare findings between two scans and return the diff."""
    s1 = await _get_user_scan(scan1, user, db)
    s2 = await _get_user_scan(scan2, user, db)

    result1 = await db.execute(select(Finding).where(Finding.scan_id == s1.id))
    result2 = await db.execute(select(Finding).where(Finding.scan_id == s2.id))

    findings1 = result1.scalars().all()
    findings2 = result2.scalars().all()

    # Build sets keyed by (type, url, parameter) for comparison
    def _key(f: Finding) -> tuple:
        return (f.type, f.url, f.parameter)

    keys1 = {_key(f): f for f in findings1}
    keys2 = {_key(f): f for f in findings2}

    only_in_scan1 = [
        FindingResponse.model_validate(keys1[k]).model_dump(mode="json")
        for k in keys1
        if k not in keys2
    ]
    only_in_scan2 = [
        FindingResponse.model_validate(keys2[k]).model_dump(mode="json")
        for k in keys2
        if k not in keys1
    ]
    common = [
        FindingResponse.model_validate(keys1[k]).model_dump(mode="json")
        for k in keys1
        if k in keys2
    ]

    return SuccessResponse(
        data={
            "scan1_id": str(scan1),
            "scan2_id": str(scan2),
            "only_in_scan1": only_in_scan1,
            "only_in_scan2": only_in_scan2,
            "common": common,
        },
    )


@router.get(
    "/{scan_id}",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}},
)
async def get_scan(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get detailed information about a scan including progress."""
    scan = await _get_user_scan(scan_id, user, db)

    scan_data = ScanResponse.model_validate(scan).model_dump(mode="json")
    progress_data = ScanProgress(
        scan_id=scan.id,
        progress=scan.progress,
        current_agent=scan.current_agent,
        status=scan.status,
    ).model_dump(mode="json")

    scan_data["progress_detail"] = progress_data

    return SuccessResponse(data=scan_data)


@router.delete(
    "/{scan_id}",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}, 400: {"model": ErrorResponse}},
)
async def delete_scan(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cancel a running/queued scan or delete a completed/failed scan."""
    scan = await _get_user_scan(scan_id, user, db)

    if scan.status in ("running", "queued"):
        # Cancel the scan
        scan.status = "cancelled"
        scan.completed_at = datetime.now(timezone.utc)
        await db.flush()
        return SuccessResponse(message="Scan cancelled.")

    # Delete completed/failed/cancelled scan
    await db.delete(scan)
    await db.flush()
    return SuccessResponse(message="Scan deleted.")


@router.post(
    "/{scan_id}/pause",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}, 400: {"model": ErrorResponse}},
)
async def pause_scan(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Pause a running scan."""
    scan = await _get_user_scan(scan_id, user, db)

    if scan.status != "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": {
                    "code": "SCAN_NOT_RUNNING",
                    "message": f"Cannot pause a scan with status '{scan.status}'.",
                    "details": None,
                },
            },
        )

    scan.status = "paused"
    await db.flush()
    return SuccessResponse(
        data=ScanResponse.model_validate(scan).model_dump(mode="json"),
        message="Scan paused.",
    )


@router.post(
    "/{scan_id}/resume",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}, 400: {"model": ErrorResponse}},
)
async def resume_scan(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Resume a paused scan."""
    scan = await _get_user_scan(scan_id, user, db)

    if scan.status != "paused":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": {
                    "code": "SCAN_NOT_PAUSED",
                    "message": f"Cannot resume a scan with status '{scan.status}'.",
                    "details": None,
                },
            },
        )

    scan.status = "running"
    await db.flush()

    # Re-queue the Celery task
    try:
        from app.workers.tasks import run_scan

        run_scan.delay(str(scan.id), str(user.id))
    except Exception:
        pass

    return SuccessResponse(
        data=ScanResponse.model_validate(scan).model_dump(mode="json"),
        message="Scan resumed.",
    )


@router.get(
    "/{scan_id}/history",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}},
)
async def scan_history(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get past scans on the same target URL."""
    scan = await _get_user_scan(scan_id, user, db)

    result = await db.execute(
        select(Scan)
        .where(
            Scan.user_id == user.id,
            Scan.target_url == scan.target_url,
            Scan.id != scan.id,
        )
        .order_by(Scan.created_at.desc())
    )
    history = result.scalars().all()

    return SuccessResponse(
        data=[ScanResponse.model_validate(s).model_dump(mode="json") for s in history],
    )
