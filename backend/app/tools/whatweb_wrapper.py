"""WhatWeb technology fingerprinting wrapper.

Runs WhatWeb via subprocess with JSON output, timeout handling, and graceful
degradation when WhatWeb is not installed.
"""

import asyncio
import json
import re
import shutil
from typing import Any


_SAFE_TARGET_RE = re.compile(r"^[a-zA-Z0-9._:/%\-]+$")


def _validate_target(target: str) -> str:
    """Validate and sanitize a target URL or hostname."""
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


class WhatWebWrapper:
    """Wrapper around the WhatWeb fingerprinting tool."""

    TOOL_NAME = "whatweb"
    DEFAULT_TIMEOUT = 300

    @classmethod
    def check_available(cls) -> bool:
        """Return True if whatweb is found on PATH."""
        return shutil.which(cls.TOOL_NAME) is not None

    async def fingerprint(
        self,
        target: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> dict[str, Any]:
        """Identify technologies running on *target*.

        Args:
            target: URL or hostname to fingerprint (e.g. "https://example.com").
            timeout: Maximum seconds to wait for the process.

        Returns:
            A dict with ``url`` and ``technologies`` keys, or a dict with an
            ``error`` key if something went wrong.
        """
        if not self.check_available():
            return {"error": f"{self.TOOL_NAME} not installed", "available": False}

        try:
            target = _validate_target(target)
        except ValueError as exc:
            return {"error": str(exc), "available": True}

        cmd = [self.TOOL_NAME, "-q", "--log-json=-", target]

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
                "error": f"whatweb exited with code {proc.returncode}: "
                         f"{stderr.decode(errors='replace').strip()}",
                "available": True,
            }

        return self._parse_json(stdout.decode(errors="replace"), target)

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_json(text: str, fallback_url: str) -> dict[str, Any]:
        """Parse WhatWeb JSON output into a structured dict."""
        technologies: list[dict[str, str]] = []
        url = fallback_url

        # WhatWeb outputs a JSON array (one element per target).
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try to find the first valid JSON object in the output.
            data = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                    if isinstance(parsed, list):
                        data.extend(parsed)
                    else:
                        data.append(parsed)
                except json.JSONDecodeError:
                    continue

        if isinstance(data, dict):
            data = [data]

        for entry in data:
            if not isinstance(entry, dict):
                continue

            url = entry.get("target", fallback_url)

            # WhatWeb stores plugin results under a "plugins" key.
            plugins = entry.get("plugins", {})
            for plugin_name, plugin_info in plugins.items():
                if not isinstance(plugin_info, dict):
                    continue
                version_list = plugin_info.get("version", [])
                version = version_list[0] if version_list else ""
                technologies.append({
                    "name": plugin_name,
                    "version": str(version),
                })

        return {
            "url": url,
            "technologies": technologies,
        }
