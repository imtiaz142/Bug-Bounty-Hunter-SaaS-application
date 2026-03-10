"""Nuclei vulnerability scanner wrapper.

Runs nuclei via subprocess with JSON-line output parsing, timeout handling,
and graceful degradation when nuclei is not installed.
"""

import asyncio
import json
import re
import shlex
import shutil
from typing import Any


_SAFE_TARGET_RE = re.compile(r"^[a-zA-Z0-9._:/%\-]+$")
_SAFE_SEVERITY_RE = re.compile(r"^[a-zA-Z,]+$")
_SAFE_TEMPLATE_RE = re.compile(r"^[a-zA-Z0-9._/\-]+$")


def _validate_target(target: str) -> str:
    """Validate and sanitize a target string."""
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


def _validate_severity(severity: str) -> str:
    """Validate the severity filter string."""
    severity = severity.strip()
    if not _SAFE_SEVERITY_RE.match(severity):
        raise ValueError(f"Invalid severity: {severity!r}")
    return severity


def _validate_templates(templates: str) -> str:
    """Validate the templates string."""
    templates = templates.strip()
    if not _SAFE_TEMPLATE_RE.match(templates):
        raise ValueError(f"Invalid templates: {templates!r}")
    return templates


class NucleiWrapper:
    """Wrapper around the nuclei vulnerability scanner."""

    TOOL_NAME = "nuclei"
    DEFAULT_TIMEOUT = 300

    @classmethod
    def check_available(cls) -> bool:
        """Return True if nuclei is found on PATH."""
        return shutil.which(cls.TOOL_NAME) is not None

    async def scan(
        self,
        target: str,
        templates: str = "owasp-top-10",
        severity: str = "critical,high,medium,low",
        timeout: int = DEFAULT_TIMEOUT,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Run a nuclei scan against the target.

        Args:
            target: URL or host to scan.
            templates: Template directory or tag to use.
            severity: Comma-separated severity levels to include.
            timeout: Maximum seconds to wait for the scan.

        Returns:
            A list of finding dicts, or a dict with an ``error`` key.
        """
        if not self.check_available():
            return {"error": f"{self.TOOL_NAME} not installed", "available": False}

        try:
            target = _validate_target(target)
            templates = _validate_templates(templates)
            severity = _validate_severity(severity)
        except ValueError as exc:
            return {"error": str(exc), "available": True}

        cmd = [
            self.TOOL_NAME,
            "-u", target,
            "-t", shlex.quote(templates),
            "-severity", shlex.quote(severity),
            "-json",
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
                "error": f"nuclei exited with code {proc.returncode}: "
                         f"{stderr.decode(errors='replace').strip()}",
                "available": True,
            }

        return self._parse_json_lines(stdout.decode(errors="replace"))

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_json_lines(text: str) -> list[dict[str, Any]]:
        """Parse nuclei JSON-line output into a list of finding dicts."""
        findings: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = data.get("info", {})
            findings.append({
                "template_id": data.get("template-id", data.get("templateID", "")),
                "name": info.get("name", ""),
                "severity": info.get("severity", ""),
                "url": data.get("matched-at", data.get("matchedAt", "")),
                "matched_at": data.get("matched-at", data.get("matchedAt", "")),
                "description": info.get("description", ""),
                "reference": info.get("reference", []),
            })

        return findings
