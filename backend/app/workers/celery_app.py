"""Celery task definitions.

When Celery/Redis are not installed (local dev with SQLite), tasks fall back
to direct inline execution via ``run_scan_inline`` / ``generate_report_inline``.
"""

import asyncio
import logging
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session, sessionmaker
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

sync_engine = create_engine(settings.DATABASE_URL_SYNC)
SyncSession = sessionmaker(bind=sync_engine)


def get_sync_session() -> Session:
    return SyncSession()


# ---------------------------------------------------------------------------
# Try to set up Celery.  If Redis / Celery aren't installed we still expose
# the same function signatures but they run inline (blocking).
# ---------------------------------------------------------------------------

try:
    from celery import Celery

    if not settings.CELERY_BROKER_URL:
        raise ImportError("No broker URL configured")

    celery_app = Celery(
        "bug_bounty_worker",
        broker=settings.CELERY_BROKER_URL,
        backend=settings.CELERY_RESULT_BACKEND,
    )
    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
    )
    _USE_CELERY = True
except (ImportError, Exception):
    celery_app = None
    _USE_CELERY = False
    logger.info("Celery/Redis not available; scans will run inline")


# ---------------------------------------------------------------------------
# Scan execution (works with or without Celery)
# ---------------------------------------------------------------------------

def _run_scan_impl(scan_id: str, user_id: str):
    """Run the full scan pipeline."""
    from app.models.scan import Scan
    from app.models.user import User
    from app.core.security import decrypt_api_key

    session = get_sync_session()
    try:
        scan = session.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if not scan:
            return {"error": "Scan not found"}

        user = session.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
        if not user:
            return {"error": "User not found"}

        user_settings = {
            "llm_provider": user.llm_provider,
            "llm_api_key": decrypt_api_key(user.llm_api_key_encrypted) if user.llm_api_key_encrypted else None,
        }
        session.close()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            from app.agents.orchestrator import ScanOrchestrator
            from app.core.database import async_session

            async def _run():
                async with async_session() as db:
                    orchestrator = ScanOrchestrator(
                        scan_id=scan_id,
                        db_session=db,
                        user_settings=user_settings,
                    )
                    await orchestrator.run()

            loop.run_until_complete(_run())
            return {"status": "completed"}
        finally:
            loop.close()

    except Exception as e:
        logger.exception("Scan %s failed", scan_id)
        session = get_sync_session()
        try:
            session.execute(
                update(Scan).where(Scan.id == scan_id).values(status="failed", current_agent="error")
            )
            session.commit()
        finally:
            session.close()
        return {"error": str(e)}
    finally:
        if session and session.is_active:
            session.close()


def _generate_report_impl(scan_id: str, report_id: str, report_type: str, user_id: str):
    """Generate a PDF report for a scan."""
    from app.models.scan import Scan
    from app.models.finding import Finding
    from app.models.report import Report
    from app.models.user import User
    from app.core.security import decrypt_api_key
    from app.llm.factory import get_llm_provider

    session = get_sync_session()
    try:
        scan = session.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        user = session.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
        findings = session.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all()
        report = session.execute(select(Report).where(Report.id == report_id)).scalar_one_or_none()

        if not scan or not report:
            return {"error": "Scan or report not found"}

        user_settings = {
            "llm_provider": user.llm_provider if user else None,
            "llm_api_key": decrypt_api_key(user.llm_api_key_encrypted) if user and user.llm_api_key_encrypted else None,
        }

        llm_provider = get_llm_provider(user_settings.get("llm_provider"), user_settings.get("llm_api_key"))

        findings_data = []
        for f in findings:
            findings_data.append({
                "id": str(f.id),
                "type": f.type,
                "severity": f.severity,
                "title": f.title,
                "url": f.url,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "cwe": f.cwe,
                "evidence": f.evidence,
                "confirmed": f.confirmed,
                "fix_recommendation": f.fix_recommendation,
                "parameter": f.parameter,
                "method": f.method,
                "false_positive": f.false_positive,
            })

        scan_data = {
            "id": str(scan.id),
            "target_url": scan.target_url,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "started_at": str(scan.started_at) if scan.started_at else None,
            "completed_at": str(scan.completed_at) if scan.completed_at else None,
            "duration_seconds": scan.duration_seconds,
        }

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            from app.agents.reporter_agent import ReporterAgent
            reporter = ReporterAgent(llm_provider=llm_provider)

            async def log_cb(level, message, data=None):
                pass

            file_path = loop.run_until_complete(
                reporter.run(scan_data, findings_data, report_type, log_callback=log_cb)
            )

            from datetime import datetime, timezone
            session.execute(
                update(Report).where(Report.id == report_id).values(
                    status="ready",
                    file_path=file_path,
                    generated_at=datetime.now(timezone.utc),
                )
            )
            session.commit()
            return {"file_path": file_path}
        except Exception as e:
            session.execute(
                update(Report).where(Report.id == report_id).values(status="failed")
            )
            session.commit()
            return {"error": str(e)}
        finally:
            loop.close()
    finally:
        if session.is_active:
            session.close()


# ---------------------------------------------------------------------------
# Celery tasks (when available) or inline wrappers
# ---------------------------------------------------------------------------

if _USE_CELERY and celery_app is not None:
    @celery_app.task(bind=True, name="run_scan")
    def run_scan_task(self, scan_id: str, user_id: str):
        return _run_scan_impl(scan_id, user_id)

    @celery_app.task(bind=True, name="generate_report")
    def generate_report_task(self, scan_id: str, report_id: str, report_type: str, user_id: str):
        return _generate_report_impl(scan_id, report_id, report_type, user_id)
else:
    # Stubs that run inline when called with .delay()
    class _InlineTask:
        def __init__(self, fn):
            self._fn = fn

        def delay(self, *args, **kwargs):
            """Run synchronously in a background thread to not block the event loop."""
            import threading
            t = threading.Thread(target=self._fn, args=args, kwargs=kwargs, daemon=True)
            t.start()

    run_scan_task = _InlineTask(_run_scan_impl)
    generate_report_task = _InlineTask(_generate_report_impl)
