"""Nmap port scanner wrapper.

Runs nmap via subprocess with XML output parsing, timeout handling,
and graceful degradation when nmap is not installed.
"""

import asyncio
import re
import shlex
import shutil
import xml.etree.ElementTree as ET
from typing import Any


_SAFE_TARGET_RE = re.compile(r"^[a-zA-Z0-9._:/%\-]+$")


def _validate_target(target: str) -> str:
    """Validate and sanitize a target string (hostname, IP, or CIDR)."""
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


class NmapWrapper:
    """Wrapper around the nmap port scanner."""

    TOOL_NAME = "nmap"
    DEFAULT_TIMEOUT = 300

    @classmethod
    def check_available(cls) -> bool:
        """Return True if nmap is found on PATH."""
        return shutil.which(cls.TOOL_NAME) is not None

    async def scan_ports(
        self,
        target: str,
        ports: str = "--top-ports 1000",
        timeout: int = DEFAULT_TIMEOUT,
    ) -> dict[str, Any]:
        """Run an nmap service-version scan and return structured results.

        Args:
            target: Hostname, IP address, or CIDR range to scan.
            ports: Port specification passed to nmap (e.g. "--top-ports 1000"
                   or "-p 80,443,8080").
            timeout: Maximum seconds to wait for the scan to complete.

        Returns:
            A dict with a ``hosts`` key containing per-host port information,
            or an ``error`` key if something went wrong.
        """
        if not self.check_available():
            return {"error": f"{self.TOOL_NAME} not installed", "available": False}

        try:
            target = _validate_target(target)
        except ValueError as exc:
            return {"error": str(exc), "available": True}

        # Build the command.  We split the user-supplied *ports* string so
        # that each token becomes a separate exec argument (safe from shell
        # injection because we never invoke a shell).
        cmd = [
            self.TOOL_NAME,
            "-sV",
            "-oX", "-",
            *shlex.split(ports),
            target,
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
                "error": f"nmap exited with code {proc.returncode}: "
                         f"{stderr.decode(errors='replace').strip()}",
                "available": True,
            }

        return self._parse_xml(stdout.decode(errors="replace"))

    # ------------------------------------------------------------------
    # XML parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_xml(xml_text: str) -> dict[str, Any]:
        """Parse nmap XML output into a structured dict."""
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            return {"error": f"Failed to parse nmap XML: {exc}", "available": True}

        hosts: list[dict[str, Any]] = []

        for host_el in root.findall("host"):
            # IP address
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find("address[@addrtype='ipv6']")
            ip = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

            # Hostname
            hostname = ""
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                hn_el = hostnames_el.find("hostname")
                if hn_el is not None:
                    hostname = hn_el.get("name", "")

            # Ports
            ports: list[dict[str, Any]] = []
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    service_el = port_el.find("service")
                    ports.append({
                        "port": int(port_el.get("portid", 0)),
                        "protocol": port_el.get("protocol", ""),
                        "state": state_el.get("state", "") if state_el is not None else "",
                        "service": service_el.get("name", "") if service_el is not None else "",
                        "version": (
                            f"{service_el.get('product', '')} "
                            f"{service_el.get('version', '')}"
                        ).strip() if service_el is not None else "",
                    })

            hosts.append({
                "ip": ip,
                "hostname": hostname,
                "ports": ports,
            })

        return {"hosts": hosts}
