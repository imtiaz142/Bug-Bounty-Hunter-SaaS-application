"""theHarvester OSINT wrapper.

Runs theHarvester via subprocess to gather emails, hostnames, and IP
addresses for a given domain.  Handles missing tool and timeout gracefully.
"""

import asyncio
import json
import os
import re
import shutil
import tempfile
from typing import Any


_SAFE_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9._\-]+$")


def _validate_domain(domain: str) -> str:
    """Validate and sanitize a domain name."""
    domain = domain.strip()
    if not domain:
        raise ValueError("Domain must not be empty")
    if not _SAFE_DOMAIN_RE.match(domain):
        raise ValueError(
            f"Invalid domain: {domain!r}. "
            "Only alphanumeric characters, dots, hyphens, and underscores "
            "are allowed."
        )
    return domain


class HarvesterWrapper:
    """Wrapper around theHarvester OSINT tool."""

    TOOL_NAME = "theHarvester"
    DEFAULT_TIMEOUT = 300

    @classmethod
    def check_available(cls) -> bool:
        """Return True if theHarvester is found on PATH."""
        # The tool may be installed as 'theHarvester' or 'theharvester'.
        return (
            shutil.which(cls.TOOL_NAME) is not None
            or shutil.which("theharvester") is not None
        )

    @classmethod
    def _executable(cls) -> str | None:
        """Return the actual executable name, if available."""
        for name in (cls.TOOL_NAME, "theharvester"):
            if shutil.which(name) is not None:
                return name
        return None

    async def gather(
        self,
        domain: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> dict[str, Any]:
        """Run theHarvester and return gathered intelligence.

        Args:
            domain: The domain to search for (e.g. "example.com").
            timeout: Maximum seconds to wait for the process.

        Returns:
            A dict with ``emails``, ``hosts``, and ``ips`` lists, or a dict
            with an ``error`` key if something went wrong.
        """
        executable = self._executable()
        if executable is None:
            return {"error": f"{self.TOOL_NAME} not installed", "available": False}

        try:
            domain = _validate_domain(domain)
        except ValueError as exc:
            return {"error": str(exc), "available": True}

        # Use a temporary file for structured output.
        tmp_dir = tempfile.mkdtemp(prefix="harvester_")
        output_base = os.path.join(tmp_dir, f"harvester_{domain}")

        cmd = [
            executable,
            "-d", domain,
            "-b", "all",
            "-f", output_base,
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
            self._cleanup(tmp_dir)
            return {"error": f"{self.TOOL_NAME} timed out", "available": True}
        except Exception as exc:
            self._cleanup(tmp_dir)
            return {"error": f"Unexpected error: {exc}", "available": True}

        # theHarvester writes JSON to <output_base>.json
        json_path = f"{output_base}.json"
        result = self._parse_json_output(json_path)
        if result is not None:
            self._cleanup(tmp_dir)
            return result

        # Fall back to parsing stdout.
        parsed = self._parse_stdout(stdout.decode(errors="replace"))
        self._cleanup(tmp_dir)
        return parsed

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_json_output(json_path: str) -> dict[str, Any] | None:
        """Attempt to parse the JSON file written by theHarvester."""
        try:
            with open(json_path, "r") as fh:
                data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

        return {
            "emails": sorted(set(data.get("emails", []))),
            "hosts": sorted(set(data.get("hosts", []))),
            "ips": sorted(set(data.get("ips", []))),
        }

    @staticmethod
    def _parse_stdout(text: str) -> dict[str, Any]:
        """Best-effort parse of theHarvester console output."""
        emails: set[str] = set()
        hosts: set[str] = set()
        ips: set[str] = set()

        email_re = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
        ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        host_re = re.compile(r"[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}")

        for line in text.splitlines():
            for match in email_re.findall(line):
                emails.add(match.lower())
            for match in ip_re.findall(line):
                ips.add(match)
            # Only grab hostnames from lines that look like discovery output.
            stripped = line.strip()
            if stripped and host_re.fullmatch(stripped):
                hosts.add(stripped.lower())

        return {
            "emails": sorted(emails),
            "hosts": sorted(hosts),
            "ips": sorted(ips),
        }

    @staticmethod
    def _cleanup(path: str) -> None:
        """Remove a temporary directory tree, ignoring errors."""
        import shutil as _shutil
        try:
            _shutil.rmtree(path, ignore_errors=True)
        except Exception:
            pass
