"""Re-export tasks for convenience."""

from app.workers.celery_app import run_scan_task as run_scan
from app.workers.celery_app import generate_report_task

__all__ = ["run_scan", "generate_report_task"]
