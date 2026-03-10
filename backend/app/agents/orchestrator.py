"""Scan orchestrator that coordinates the multi-agent pipeline.

Runs agents sequentially:
    ReconAgent -> ScannerAgent -> ExploitAgent -> AnalyzerAgent -> ReporterAgent

Each agent's output feeds into the next.  Progress and status are persisted
in the database and broadcast to connected WebSocket clients via Redis pub/sub.
"""

from __future__ import annotations

import json
import logging
import traceback
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.agent_log import AgentLog
from app.models.scan import Scan
from app.agents.recon_agent import ReconAgent
from app.agents.scanner_agent import ScannerAgent
from app.agents.exploit_agent import ExploitAgent
from app.agents.analyzer_agent import AnalyzerAgent
from app.agents.reporter_agent import ReporterAgent
from app.llm.factory import get_llm_provider

logger = logging.getLogger(__name__)

# Progress milestones (%) after each agent completes.
_PROGRESS_MAP: dict[str, int] = {
    "recon": 20,
    "scanner": 45,
    "exploit": 65,
    "analyzer": 80,
    "reporter": 100,
}


class ScanOrchestrator:
    """Coordinates the full scan pipeline for a single target."""

    def __init__(
        self,
        scan_id: str,
        db_session: AsyncSession,
        user_settings: dict,
    ) -> None:
        self.scan_id = scan_id
        self.db = db_session
        self.user_settings = user_settings
        self._settings = get_settings()
        self._redis: aioredis.Redis | None = None

        # Build optional LLM provider from user settings.
        self._llm = get_llm_provider(
            provider=user_settings.get("llm_provider"),
            api_key=user_settings.get("llm_api_key"),
        )

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Execute the full agent pipeline."""
        try:
            self._redis = aioredis.from_url(
                self._settings.REDIS_URL, decode_responses=True
            )
        except Exception:
            logger.warning("Redis unavailable; WebSocket notifications disabled")
            self._redis = None

        scan = await self._get_scan()
        if scan is None:
            logger.error("Scan %s not found", self.scan_id)
            return

        target_url: str = scan.target_url
        scan_type: str = scan.scan_type

        # Mark scan as running.
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        await self._commit()

        await self.log("orchestrator", "info", "Scan pipeline started", {
            "target": target_url, "scan_type": scan_type,
        })
        await self.notify("scan_started", {"scan_id": self.scan_id})

        recon_data: dict = {}
        raw_findings: list[dict] = []
        verified_findings: list[dict] = []
        analyzed_findings: list[dict] = []
        report_path: str = ""

        # --- Agent 1: Recon ---
        if await self._should_continue():
            recon_data = await self._run_agent(
                "recon",
                ReconAgent().run,
                target_url=target_url,
                scan_type=scan_type,
            )
            # Persist recon data on the scan row.
            scan = await self._get_scan()
            if scan is not None:
                scan.recon_data = recon_data
                await self._commit()

        # --- Agent 2: Scanner ---
        if await self._should_continue():
            raw_findings = await self._run_agent(
                "scanner",
                ScannerAgent().run,
                target_url=target_url,
                recon_data=recon_data,
                scan_type=scan_type,
            )

        # --- Agent 3: Exploit (verification) ---
        if await self._should_continue():
            verified_findings = await self._run_agent(
                "exploit",
                ExploitAgent().run,
                target_url=target_url,
                findings=raw_findings,
            )

        # --- Agent 4: Analyzer ---
        if await self._should_continue():
            analyzer = AnalyzerAgent(llm_provider=self._llm)
            analyzed_findings = await self._run_agent(
                "analyzer",
                analyzer.run,
                findings=verified_findings,
                scan_data={
                    "target_url": target_url,
                    "scan_type": scan_type,
                    "recon_data": recon_data,
                },
            )

        # --- Agent 5: Reporter ---
        if await self._should_continue():
            reporter = ReporterAgent(llm_provider=self._llm)
            report_path = await self._run_agent(
                "reporter",
                reporter.run,
                scan_data={
                    "scan_id": self.scan_id,
                    "target_url": target_url,
                    "scan_type": scan_type,
                    "recon_data": recon_data,
                    "started_at": (
                        scan.started_at.isoformat() if scan and scan.started_at else ""
                    ),
                },
                findings=analyzed_findings,
                report_type="technical",
            )

        # --- Finalize ---
        scan = await self._get_scan()
        if scan is not None:
            now = datetime.now(timezone.utc)
            if scan.status not in ("cancelled", "failed"):
                scan.status = "completed"
            scan.completed_at = now
            if scan.started_at:
                scan.duration_seconds = int(
                    (now - scan.started_at).total_seconds()
                )
            await self._commit()

        await self.log("orchestrator", "info", "Scan pipeline finished", {
            "report_path": report_path,
            "findings_count": len(analyzed_findings),
        })
        await self.notify("scan_completed", {
            "scan_id": self.scan_id,
            "findings_count": len(analyzed_findings),
        })

        if self._redis:
            await self._redis.aclose()

    # ------------------------------------------------------------------
    # Agent runner helper
    # ------------------------------------------------------------------

    async def _run_agent(
        self, agent_name: str, coro_fn: Any, **kwargs: Any
    ) -> Any:
        """Run a single agent, handle errors, log transitions, update progress."""
        await self.update_progress(_progress_before(agent_name), agent_name)
        await self.log(agent_name, "info", f"Agent '{agent_name}' starting")
        await self.notify("agent_started", {
            "scan_id": self.scan_id, "agent": agent_name,
        })

        async def _log_cb(level: str, message: str, data: Any = None) -> None:
            await self.log(agent_name, level, message, data)

        try:
            result = await coro_fn(log_callback=_log_cb, **kwargs)
        except Exception as exc:
            tb = traceback.format_exc()
            await self.log(agent_name, "error", f"Agent failed: {exc}", {"traceback": tb})
            logger.exception("Agent '%s' raised an exception", agent_name)

            # Mark scan as failed but allow pipeline to continue with
            # whatever data the remaining agents can work with.
            scan = await self._get_scan()
            if scan is not None and scan.status == "running":
                scan.status = "failed"
                await self._commit()

            # Return safe default so subsequent agents can still run.
            result = [] if agent_name in ("scanner", "exploit", "analyzer") else {}
            if agent_name == "reporter":
                result = ""

        await self.update_progress(_PROGRESS_MAP.get(agent_name, 0), agent_name)
        await self.log(agent_name, "info", f"Agent '{agent_name}' completed")
        await self.notify("agent_completed", {
            "scan_id": self.scan_id, "agent": agent_name,
        })
        return result

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------

    async def _get_scan(self) -> Scan | None:
        result = await self.db.execute(
            select(Scan).where(Scan.id == self.scan_id)
        )
        return result.scalar_one_or_none()

    async def _commit(self) -> None:
        try:
            await self.db.commit()
        except Exception:
            await self.db.rollback()
            raise

    async def _should_continue(self) -> bool:
        """Check whether the scan has been paused or cancelled."""
        scan = await self._get_scan()
        if scan is None:
            return False
        if scan.status in ("cancelled", "paused"):
            await self.log(
                "orchestrator", "warning",
                f"Scan status is '{scan.status}'; stopping pipeline",
            )
            return False
        return True

    # ------------------------------------------------------------------
    # Logging / progress / notifications
    # ------------------------------------------------------------------

    async def log(
        self,
        agent_name: str,
        level: str,
        message: str,
        data: dict | None = None,
    ) -> None:
        """Persist an :class:`AgentLog` entry."""
        try:
            entry = AgentLog(
                scan_id=self.scan_id,
                agent_name=agent_name,
                level=level,
                message=message,
                data=data,
            )
            self.db.add(entry)
            await self._commit()
        except Exception:
            logger.exception("Failed to write agent log for %s", agent_name)

    async def update_progress(self, progress: int, agent: str) -> None:
        """Update the scan's progress percentage and current agent name."""
        scan = await self._get_scan()
        if scan is not None:
            scan.progress = progress
            scan.current_agent = agent
            await self._commit()
        await self.notify("progress", {
            "scan_id": self.scan_id,
            "progress": progress,
            "agent": agent,
        })

    async def notify(self, event_type: str, data: dict) -> None:
        """Publish a notification to the Redis pub/sub channel."""
        if self._redis is None:
            return
        try:
            payload = json.dumps({"event": event_type, **data})
            await self._redis.publish(f"scan:{self.scan_id}", payload)
        except Exception:
            logger.debug("Redis notification failed for event '%s'", event_type)


def _progress_before(agent_name: str) -> int:
    """Return the starting progress % when an agent begins."""
    order = ["recon", "scanner", "exploit", "analyzer", "reporter"]
    idx = order.index(agent_name) if agent_name in order else 0
    if idx == 0:
        return 1
    prev = order[idx - 1]
    return _PROGRESS_MAP.get(prev, 0) + 1
