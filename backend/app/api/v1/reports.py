import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.core.database import get_db
from app.models import Report, Scan, User
from app.schemas import ErrorResponse, ReportCreate, ReportResponse, SuccessResponse

router = APIRouter()
settings = get_settings()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _verify_scan_ownership(
    scan_id: uuid.UUID, user: User, db: AsyncSession
) -> Scan:
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


async def _get_report(scan_id: uuid.UUID, db: AsyncSession) -> Report:
    """Fetch the most recent report for a scan, or raise 404."""
    result = await db.execute(
        select(Report)
        .where(Report.scan_id == scan_id)
        .order_by(Report.created_at.desc())
        .limit(1)
    )
    report = result.scalar_one_or_none()
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": {
                    "code": "REPORT_NOT_FOUND",
                    "message": "No report found for this scan.",
                    "details": None,
                },
            },
        )
    return report


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/",
    response_model=SuccessResponse,
    status_code=status.HTTP_201_CREATED,
    responses={404: {"model": ErrorResponse}, 400: {"model": ErrorResponse}},
)
async def generate_report(
    scan_id: uuid.UUID,
    body: ReportCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Queue report generation for a completed scan."""
    scan = await _verify_scan_ownership(scan_id, user, db)

    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": {
                    "code": "SCAN_NOT_COMPLETED",
                    "message": "Reports can only be generated for completed scans.",
                    "details": None,
                },
            },
        )

    report = Report(
        scan_id=scan.id,
        report_type=body.report_type,
        status="generating",
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)

    # Queue Celery task
    try:
        from app.workers.tasks import generate_report_task

        generate_report_task.delay(
            str(scan.id), str(report.id), body.report_type, str(user.id)
        )
    except Exception:
        pass

    return SuccessResponse(
        data=ReportResponse.model_validate(report).model_dump(mode="json"),
        message="Report generation queued.",
    )


@router.get(
    "/",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}},
)
async def get_report_status(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the status of the latest report for a scan."""
    await _verify_scan_ownership(scan_id, user, db)
    report = await _get_report(scan_id, db)

    return SuccessResponse(
        data=ReportResponse.model_validate(report).model_dump(mode="json"),
    )


@router.get(
    "/download",
    responses={404: {"model": ErrorResponse}, 400: {"model": ErrorResponse}},
)
async def download_report(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Download the generated PDF report."""
    await _verify_scan_ownership(scan_id, user, db)
    report = await _get_report(scan_id, db)

    if report.status != "ready":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": {
                    "code": "REPORT_NOT_READY",
                    "message": f"Report is currently '{report.status}'. Please wait until it is ready.",
                    "details": None,
                },
            },
        )

    if report.file_path is None or not Path(report.file_path).exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": {
                    "code": "REPORT_FILE_MISSING",
                    "message": "Report file not found on disk.",
                    "details": None,
                },
            },
        )

    filename = f"report_{scan_id}_{report.report_type}.pdf"
    return FileResponse(
        path=report.file_path,
        media_type="application/pdf",
        filename=filename,
    )


@router.post(
    "/share",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}, 400: {"model": ErrorResponse}},
)
async def share_report(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a unique share token for a report and return a public URL."""
    await _verify_scan_ownership(scan_id, user, db)
    report = await _get_report(scan_id, db)

    if report.status != "ready":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": {
                    "code": "REPORT_NOT_READY",
                    "message": "Report must be ready before sharing.",
                    "details": None,
                },
            },
        )

    # Generate a share token if one doesn't already exist
    if report.share_token is None:
        report.share_token = uuid.uuid4().hex
        await db.flush()
        await db.refresh(report)

    public_url = f"{settings.API_V1_PREFIX}/reports/shared/{report.share_token}"

    return SuccessResponse(
        data={
            "share_token": report.share_token,
            "public_url": public_url,
        },
        message="Report share link generated.",
    )
