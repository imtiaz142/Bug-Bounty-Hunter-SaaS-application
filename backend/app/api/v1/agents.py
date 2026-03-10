import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models import AgentLog, Scan, User
from app.schemas import ErrorResponse, SuccessResponse

router = APIRouter()


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


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}},
)
async def list_agents(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the status of all agents for a scan, derived from agent_logs."""
    scan = await _verify_scan_ownership(scan_id, user, db)

    # Get distinct agent names for the scan
    names_result = await db.execute(
        select(distinct(AgentLog.agent_name)).where(AgentLog.scan_id == scan_id)
    )
    agent_names = [row[0] for row in names_result.all()]

    agents = []
    for name in agent_names:
        # Fetch the latest log entry for this agent
        latest_result = await db.execute(
            select(AgentLog)
            .where(AgentLog.scan_id == scan_id, AgentLog.agent_name == name)
            .order_by(AgentLog.timestamp.desc())
            .limit(1)
        )
        latest_log = latest_result.scalar_one_or_none()

        # Count logs per agent
        count_result = await db.execute(
            select(func.count())
            .select_from(AgentLog)
            .where(AgentLog.scan_id == scan_id, AgentLog.agent_name == name)
        )
        log_count = count_result.scalar()

        # Determine agent status based on latest log level and scan.current_agent
        if scan.current_agent == name:
            agent_status = "running"
        elif latest_log and latest_log.level == "error":
            agent_status = "failed"
        elif latest_log and latest_log.level == "info" and "completed" in latest_log.message.lower():
            agent_status = "completed"
        else:
            agent_status = "idle"

        agents.append({
            "agent_name": name,
            "status": agent_status,
            "log_count": log_count,
            "last_message": latest_log.message if latest_log else None,
            "last_timestamp": latest_log.timestamp.isoformat() if latest_log else None,
        })

    return SuccessResponse(
        data={
            "scan_id": str(scan_id),
            "current_agent": scan.current_agent,
            "agents": agents,
        },
    )


@router.get(
    "/{agent_name}/logs",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}},
)
async def agent_logs(
    scan_id: uuid.UUID,
    agent_name: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return paginated logs for a specific agent in a scan."""
    await _verify_scan_ownership(scan_id, user, db)

    base_filter = [AgentLog.scan_id == scan_id, AgentLog.agent_name == agent_name]

    count_result = await db.execute(
        select(func.count()).select_from(AgentLog).where(*base_filter)
    )
    total = count_result.scalar()

    offset = (page - 1) * per_page
    result = await db.execute(
        select(AgentLog)
        .where(*base_filter)
        .order_by(AgentLog.timestamp.asc())
        .offset(offset)
        .limit(per_page)
    )
    logs = result.scalars().all()

    return SuccessResponse(
        data={
            "logs": [
                {
                    "id": log.id,
                    "agent_name": log.agent_name,
                    "level": log.level,
                    "message": log.message,
                    "data": log.data,
                    "timestamp": log.timestamp.isoformat(),
                }
                for log in logs
            ],
            "total": total,
            "page": page,
            "per_page": per_page,
        },
    )


@router.post(
    "/{agent_name}/restart",
    response_model=SuccessResponse,
    responses={404: {"model": ErrorResponse}, 400: {"model": ErrorResponse}},
)
async def restart_agent(
    scan_id: uuid.UUID,
    agent_name: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Restart a failed agent for a scan."""
    scan = await _verify_scan_ownership(scan_id, user, db)

    if scan.status not in ("running", "paused", "failed"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": {
                    "code": "SCAN_NOT_RESTARTABLE",
                    "message": f"Cannot restart agent on a scan with status '{scan.status}'.",
                    "details": None,
                },
            },
        )

    # Check that the agent has logs (i.e. it was part of this scan)
    count_result = await db.execute(
        select(func.count())
        .select_from(AgentLog)
        .where(AgentLog.scan_id == scan_id, AgentLog.agent_name == agent_name)
    )
    if count_result.scalar() == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": {
                    "code": "AGENT_NOT_FOUND",
                    "message": f"No agent named '{agent_name}' found for this scan.",
                    "details": None,
                },
            },
        )

    # Update scan state and queue Celery task to restart the specific agent
    scan.current_agent = agent_name
    if scan.status == "failed":
        scan.status = "running"
    await db.flush()

    try:
        from app.workers.tasks import restart_agent_task

        restart_agent_task.delay(str(scan.id), agent_name)
    except Exception:
        pass

    return SuccessResponse(
        message=f"Agent '{agent_name}' restart queued.",
        data={
            "scan_id": str(scan_id),
            "agent_name": agent_name,
        },
    )
