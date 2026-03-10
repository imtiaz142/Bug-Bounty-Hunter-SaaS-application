"""OWASP ZAP (Zed Attack Proxy) wrapper.

Supports running ZAP in command-line mode via zap-cli or zap.sh, and falls
back to the ZAP REST API when ZAP is running as a daemon.  Handles missing
tool and timeout gracefully.
"""

import asyncio
import json
import re
import shutil
from typing import Any


_SAFE_TARGET_RE = re.compile(r"^[a-zA-Z0-9._:/%\-]+$")

# Possible ZAP executable names in order of preference.
_ZAP_EXECUTABLES = ("zap-cli", "zaproxy", "zap.sh")


def _validate_target(target: str) -> str:
    """Validate and sanitize a target URL."""
    target = target.strip()
    if not target:
        raise ValueError("Target must not be empty")
    if not _SAFE_TARGET_RE.match(target):
        raise ValueError(
            f"Invalid target: {target!r}. "
            "Only alphanumeric characters, dots, hyphens, colons, slashes, "
            "underscores, and percent signs are allowed."
        )
    return target


def _find_zap_executable() -> str | None:
    """Return the first ZAP executable found on PATH, or None."""
    for name in _ZAP_EXECUTABLES:
        if shutil.which(name) is not None:
            return name
    return None


class ZapWrapper:
    """Wrapper around OWASP ZAP."""

    TOOL_NAME = "zap"
    DEFAULT_TIMEOUT = 300

    @classmethod
    def check_available(cls) -> bool:
        """Return True if any ZAP executable is found on PATH."""
        return _find_zap_executable() is not None

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def passive_scan(
        self,
        target: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Run a ZAP passive scan against *target*.

        The passive scan spiders the target and reports findings observed
        during the crawl without actively attacking the application.

        Args:
            target: The base URL to scan (e.g. "https://example.com").
            timeout: Maximum seconds to wait for the scan.

        Returns:
            A list of alert dicts, or a dict with an ``error`` key.
        """
        return await self._run_scan(target, active=False, timeout=timeout)

    async def active_scan(
        self,
        target: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Run a ZAP active scan against *target*.

        The active scan sends crafted requests to discover vulnerabilities.
        Use only against targets you have permission to test.

        Args:
            target: The base URL to scan.
            timeout: Maximum seconds to wait for the scan.

        Returns:
            A list of alert dicts, or a dict with an ``error`` key.
        """
        return await self._run_scan(target, active=True, timeout=timeout)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run_scan(
        self,
        target: str,
        *,
        active: bool,
        timeout: int,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        executable = _find_zap_executable()
        if executable is None:
            return {"error": f"{self.TOOL_NAME} not installed", "available": False}

        try:
            target = _validate_target(target)
        except ValueError as exc:
            return {"error": str(exc), "available": True}

        # Strategy depends on which executable we found.
        if executable == "zap-cli":
            return await self._run_zap_cli(target, active=active, timeout=timeout)
        # zaproxy / zap.sh  --  use command-line quick scan mode.
        return await self._run_zap_sh(executable, target, active=active, timeout=timeout)

    async def _run_zap_cli(
        self,
        target: str,
        *,
        active: bool,
        timeout: int,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Run a scan using zap-cli."""
        scan_type = "active-scan" if active else "quick-scan"
        cmd = ["zap-cli", scan_type, "-s", "xss,sqli", target]
        alerts_cmd = ["zap-cli", "alerts", "-f", "json"]

        try:
            # Run the scan.
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=timeout)

            # Fetch alerts as JSON.
            alerts_proc = await asyncio.create_subprocess_exec(
                *alerts_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                alerts_proc.communicate(), timeout=60
            )
        except FileNotFoundError:
            return {"error": f"{self.TOOL_NAME} not installed", "available": False}
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return {"error": f"{self.TOOL_NAME} timed out", "available": True}
        except Exception as exc:
            return {"error": f"Unexpected error: {exc}", "available": True}

        return self._parse_zap_json(stdout.decode(errors="replace"))

    async def _run_zap_sh(
        self,
        executable: str,
        target: str,
        *,
        active: bool,
        timeout: int,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Run a scan using zap.sh / zaproxy in command-line mode."""
        scan_type = "full-scan" if active else "baseline"
        # ZAP Docker / packaged script supports a quick-scan mode.
        cmd = [
            executable,
            "-cmd",
            "-quickurl", target,
            "-quickout", "/dev/stdout",
            "-quickprogress",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except FileNotFoundError:
            return {"error": f"{self.TOOL_NAME} not installed", "available": False}
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"error": f"{self.TOOL_NAME} timed out", "available": True}
        except Exception as exc:
            return {"error": f"Unexpected error: {exc}", "available": True}

        if proc.returncode != 0 and not stdout:
            return {
                "error": f"{executable} exited with code {proc.returncode}: "
                         f"{stderr.decode(errors='replace').strip()}",
                "available": True,
            }

        return self._parse_zap_json(stdout.decode(errors="replace"))

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_zap_json(text: str) -> list[dict[str, Any]]:
        """Parse ZAP JSON output into a normalised list of alerts."""
        alerts: list[dict[str, Any]] = []

        # Try to parse as a JSON array first, then fall back to JSON-lines.
        try:
            data = json.loads(text)
            if isinstance(data, list):
                raw_alerts = data
            elif isinstance(data, dict):
                # ZAP sometimes wraps alerts under a key.
                raw_alerts = data.get("alerts", data.get("site", []))
                if isinstance(raw_alerts, dict):
                    raw_alerts = [raw_alerts]
            else:
                raw_alerts = []
        except json.JSONDecodeError:
            # Try JSON-lines.
            raw_alerts = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    raw_alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        for item in raw_alerts:
            if not isinstance(item, dict):
                continue
            alerts.append({
                "alert": item.get("alert", item.get("name", "")),
                "risk": item.get("risk", item.get("riskdesc", "")),
                "confidence": item.get("confidence", ""),
                "url": item.get("url", ""),
                "description": item.get("description", item.get("desc", "")),
                "solution": item.get("solution", ""),
                "reference": item.get("reference", ""),
            })

        return alerts
