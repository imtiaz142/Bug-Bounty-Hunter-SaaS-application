"""Reconnaissance agent.

Enumerates subdomains, discovers open ports, fingerprints technologies,
gathers email addresses, and performs DNS lookups on the target.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any, Callable, Coroutine
from urllib.parse import urlparse

from app.tools.subfinder_wrapper import SubfinderWrapper
from app.tools.nmap_wrapper import NmapWrapper

logger = logging.getLogger(__name__)

# Type alias for the logging callback every agent receives.
LogCallback = Callable[[str, str, Any], Coroutine[Any, Any, None]]


def _extract_domain(url: str) -> str:
    """Return the bare domain (no scheme / port / path) from a URL."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or parsed.path.split("/")[0]
    return host.lower().strip()


async def _noop_log(level: str, message: str, data: Any = None) -> None:
    """Fallback logger when no callback is provided."""


class ReconAgent:
    """Phase-1 agent: reconnaissance and information gathering."""

    async def run(
        self,
        target_url: str,
        scan_type: str = "quick",
        log_callback: LogCallback | None = None,
    ) -> dict[str, Any]:
        log = log_callback or _noop_log
        domain = _extract_domain(target_url)

        await log("info", f"Recon starting for domain: {domain}")

        results: dict[str, Any] = {
            "subdomains": [],
            "ports": {},
            "technologies": {},
            "emails": [],
            "dns_records": {},
        }

        # ----- Subdomain enumeration (subfinder) -----
        results["subdomains"] = await self._enumerate_subdomains(domain, log)

        # ----- Email / host gathering (theHarvester) -----
        results["emails"] = await self._gather_emails(domain, log)

        # ----- Port scanning (nmap) -----
        results["ports"] = await self._scan_ports(
            domain, results["subdomains"], scan_type, log
        )

        # ----- Technology fingerprinting (WhatWeb) -----
        results["technologies"] = await self._fingerprint_tech(target_url, log)

        # ----- DNS lookups -----
        results["dns_records"] = await self._dns_lookup(domain, log)

        await log("info", "Recon phase completed", {
            "subdomains_count": len(results["subdomains"]),
            "ports_hosts": len(results["ports"]),
            "emails_count": len(results["emails"]),
        })
        return results

    # ------------------------------------------------------------------
    # Subdomain enumeration
    # ------------------------------------------------------------------

    async def _enumerate_subdomains(
        self, domain: str, log: LogCallback
    ) -> list[str]:
        await log("info", "Running subfinder for subdomain enumeration")
        try:
            wrapper = SubfinderWrapper()
            result = await wrapper.enumerate_subdomains(domain)
            if isinstance(result, dict) and "error" in result:
                await log("warning", f"Subfinder unavailable: {result['error']}")
                return []
            await log("info", f"Subfinder found {len(result)} subdomains")
            return result
        except Exception as exc:
            await log("warning", f"Subfinder failed: {exc}")
            return []

    # ------------------------------------------------------------------
    # Email / host harvesting
    # ------------------------------------------------------------------

    async def _gather_emails(
        self, domain: str, log: LogCallback
    ) -> list[str]:
        await log("info", "Running theHarvester for email/host gathering")
        try:
            from app.tools.harvester_wrapper import HarvesterWrapper

            wrapper = HarvesterWrapper()
            result = await wrapper.harvest(domain)
            if isinstance(result, dict) and "error" in result:
                await log("warning", f"theHarvester unavailable: {result['error']}")
                return []
            emails = result.get("emails", []) if isinstance(result, dict) else []
            await log("info", f"theHarvester found {len(emails)} emails")
            return emails
        except ImportError:
            await log("warning", "HarvesterWrapper not available, skipping")
            return []
        except Exception as exc:
            await log("warning", f"theHarvester failed: {exc}")
            return []

    # ------------------------------------------------------------------
    # Port scanning
    # ------------------------------------------------------------------

    async def _scan_ports(
        self,
        domain: str,
        subdomains: list[str],
        scan_type: str,
        log: LogCallback,
    ) -> dict[str, Any]:
        await log("info", "Running nmap port scan")
        ports_data: dict[str, Any] = {}
        wrapper = NmapWrapper()

        # Build list of targets: main domain + limited subdomains.
        targets = [domain]
        max_subs = 5 if scan_type == "quick" else 20
        targets.extend(subdomains[:max_subs])
        # Deduplicate while preserving order.
        seen: set[str] = set()
        unique_targets: list[str] = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique_targets.append(t)

        for target in unique_targets:
            await log("info", f"Scanning ports on {target}")
            try:
                result = await wrapper.scan_ports(target)
                if isinstance(result, dict) and "error" in result:
                    await log("warning", f"Nmap error for {target}: {result['error']}")
                    ports_data[target] = {"error": result["error"]}
                    continue
                ports_data[target] = result
            except Exception as exc:
                await log("warning", f"Nmap scan failed for {target}: {exc}")
                ports_data[target] = {"error": str(exc)}

        await log("info", f"Port scanning complete for {len(ports_data)} hosts")
        return ports_data

    # ------------------------------------------------------------------
    # Technology fingerprinting
    # ------------------------------------------------------------------

    async def _fingerprint_tech(
        self, target_url: str, log: LogCallback
    ) -> dict[str, Any]:
        await log("info", "Running WhatWeb for technology fingerprinting")
        try:
            from app.tools.whatweb_wrapper import WhatWebWrapper

            wrapper = WhatWebWrapper()
            result = await wrapper.fingerprint(target_url)
            if isinstance(result, dict) and "error" in result:
                await log("warning", f"WhatWeb unavailable: {result['error']}")
                return {}
            await log("info", "WhatWeb fingerprinting complete")
            return result if isinstance(result, dict) else {}
        except ImportError:
            await log("warning", "WhatWebWrapper not available, skipping")
            return {}
        except Exception as exc:
            await log("warning", f"WhatWeb failed: {exc}")
            return {}

    # ------------------------------------------------------------------
    # DNS lookups
    # ------------------------------------------------------------------

    async def _dns_lookup(
        self, domain: str, log: LogCallback
    ) -> dict[str, Any]:
        await log("info", f"Performing DNS lookups for {domain}")
        records: dict[str, Any] = {
            "A": [],
            "MX": [],
            "TXT": [],
            "CNAME": [],
        }

        loop = asyncio.get_running_loop()

        # A records
        try:
            addrs = await loop.getaddrinfo(
                domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM
            )
            records["A"] = list({addr[4][0] for addr in addrs})
        except socket.gaierror:
            await log("info", f"No A records found for {domain}")
        except Exception as exc:
            await log("warning", f"A record lookup failed: {exc}")

        # MX, TXT, CNAME via dns.resolver if available, otherwise skip
        try:
            import dns.resolver  # type: ignore[import-untyped]

            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            resolver.lifetime = 10

            # MX
            try:
                answers = resolver.resolve(domain, "MX")
                records["MX"] = [
                    {"priority": r.preference, "exchange": str(r.exchange).rstrip(".")}
                    for r in answers
                ]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass

            # TXT
            try:
                answers = resolver.resolve(domain, "TXT")
                records["TXT"] = [str(r).strip('"') for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass

            # CNAME
            try:
                answers = resolver.resolve(domain, "CNAME")
                records["CNAME"] = [str(r.target).rstrip(".") for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass

        except ImportError:
            await log("info", "dnspython not installed; MX/TXT/CNAME lookups skipped")
        except Exception as exc:
            await log("warning", f"DNS resolver error: {exc}")

        await log("info", "DNS lookups complete", records)
        return records
