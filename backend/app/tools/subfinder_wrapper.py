"""Subfinder subdomain enumeration wrapper.

Runs subfinder via subprocess, returning discovered subdomains as a list.
Handles missing tool and timeout gracefully.
"""

import asyncio
import re
import shutil
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


class SubfinderWrapper:
    """Wrapper around the subfinder subdomain enumeration tool."""

    TOOL_NAME = "subfinder"
    DEFAULT_TIMEOUT = 300

    @classmethod
    def check_available(cls) -> bool:
        """Return True if subfinder is found on PATH."""
        return shutil.which(cls.TOOL_NAME) is not None

    async def enumerate_subdomains(
        self,
        domain: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> list[str] | dict[str, Any]:
        """Discover subdomains for the given domain.

        Args:
            domain: The root domain to enumerate (e.g. "example.com").
            timeout: Maximum seconds to wait for the process.

        Returns:
            A sorted list of unique subdomains, or a dict with an ``error``
            key if something went wrong.
        """
        if not self.check_available():
            return {"error": f"{self.TOOL_NAME} not installed", "available": False}

        try:
            domain = _validate_domain(domain)
        except ValueError as exc:
            return {"error": str(exc), "available": True}

        cmd = [self.TOOL_NAME, "-d", domain, "-silent"]

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
                "error": f"subfinder exited with code {proc.returncode}: "
                         f"{stderr.decode(errors='replace').strip()}",
                "available": True,
            }

        # Each line of stdout is a subdomain.
        subdomains: set[str] = set()
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if line:
                subdomains.add(line.lower())

        return sorted(subdomains)
