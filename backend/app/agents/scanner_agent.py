"""Vulnerability scanner agent.

Runs automated vulnerability scanners (Nuclei, ZAP) against the target,
checks for common misconfigurations, validates security headers, and
inspects SSL/TLS certificates.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import socket
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine
from urllib.parse import urlparse, urljoin

import httpx

from app.tools.nuclei_wrapper import NucleiWrapper

logger = logging.getLogger(__name__)

LogCallback = Callable[[str, str, Any], Coroutine[Any, Any, None]]

# Paths to probe for misconfigurations.
_SENSITIVE_PATHS: list[dict[str, str]] = [
    {"path": "/.env", "type": "info_disclosure", "title": ".env file exposure"},
    {"path": "/.git/HEAD", "type": "info_disclosure", "title": ".git directory exposure"},
    {"path": "/backup.sql.bak", "type": "info_disclosure", "title": "Backup file exposure (.bak)"},
    {"path": "/index.php.old", "type": "info_disclosure", "title": "Old file exposure (.old)"},
    {"path": "/index.php.swp", "type": "info_disclosure", "title": "Swap file exposure (.swp)"},
    {"path": "/index.php~", "type": "info_disclosure", "title": "Editor backup file exposure (~)"},
    {"path": "/admin", "type": "info_disclosure", "title": "Admin panel detected (/admin)"},
    {"path": "/wp-admin", "type": "info_disclosure", "title": "WordPress admin panel detected"},
    {"path": "/administrator", "type": "info_disclosure", "title": "Administrator panel detected"},
]

# Required security headers and their descriptions.
_SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "x-xss-protection": "X-XSS-Protection",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


async def _noop_log(level: str, message: str, data: Any = None) -> None:
    pass


class ScannerAgent:
    """Phase-2 agent: automated vulnerability scanning and misconfiguration checks."""

    async def run(
        self,
        target_url: str,
        recon_data: dict,
        scan_type: str = "quick",
        log_callback: LogCallback | None = None,
    ) -> list[dict[str, Any]]:
        log = log_callback or _noop_log
        findings: list[dict[str, Any]] = []

        # Normalize target.
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        await log("info", f"Scanner agent starting for {target_url}")

        # Collect all hosts to scan (target + subdomains).
        subdomains: list[str] = recon_data.get("subdomains", [])
        hosts = [target_url]
        for sub in subdomains[:10]:
            if not sub.startswith(("http://", "https://")):
                hosts.append(f"https://{sub}")
            else:
                hosts.append(sub)

        # --- Nuclei scan ---
        nuclei_findings = await self._run_nuclei(target_url, subdomains, scan_type, log)
        findings.extend(nuclei_findings)

        # --- ZAP scan ---
        zap_findings = await self._run_zap(target_url, scan_type, log)
        findings.extend(zap_findings)

        # --- Misconfiguration checks ---
        for host in hosts:
            misconfig = await self._check_misconfigs(host, log)
            findings.extend(misconfig)

        # --- Security header checks ---
        for host in hosts:
            header_findings = await self._check_security_headers(host, log)
            findings.extend(header_findings)

        # --- SSL/TLS checks ---
        ssl_findings = await self._check_ssl(target_url, log)
        findings.extend(ssl_findings)

        await log("info", f"Scanner agent finished with {len(findings)} raw findings")
        return findings

    # ------------------------------------------------------------------
    # Nuclei
    # ------------------------------------------------------------------

    async def _run_nuclei(
        self,
        target_url: str,
        subdomains: list[str],
        scan_type: str,
        log: LogCallback,
    ) -> list[dict[str, Any]]:
        await log("info", "Running Nuclei vulnerability scanner")
        wrapper = NucleiWrapper()
        findings: list[dict[str, Any]] = []

        targets = [target_url]
        limit = 5 if scan_type == "quick" else 20
        for sub in subdomains[:limit]:
            url = f"https://{sub}" if not sub.startswith("http") else sub
            targets.append(url)

        for target in targets:
            try:
                result = await wrapper.scan(target)
                if isinstance(result, dict) and "error" in result:
                    await log("warning", f"Nuclei unavailable: {result['error']}")
                    break  # Tool not installed; no point retrying.
                for item in result:
                    severity = item.get("severity", "info").lower()
                    finding = {
                        "type": self._nuclei_type(item),
                        "severity": severity,
                        "title": item.get("name", "Nuclei Finding"),
                        "url": item.get("url", target),
                        "evidence": item.get("description", ""),
                        "parameter": None,
                        "method": "GET",
                        "source": "nuclei",
                        "references": item.get("reference", []),
                    }
                    findings.append(finding)
                    await log("info", f"Nuclei finding: {finding['title']}", {
                        "severity": severity, "url": finding["url"],
                    })
            except Exception as exc:
                await log("warning", f"Nuclei scan error for {target}: {exc}")

        return findings

    @staticmethod
    def _nuclei_type(item: dict) -> str:
        """Map a nuclei template-id to a vulnerability type."""
        tid = item.get("template_id", "").lower()
        mapping = {
            "sqli": "sqli", "sql-injection": "sqli",
            "xss": "xss", "cross-site": "xss",
            "ssrf": "ssrf", "rce": "rce",
            "lfi": "lfi", "rfi": "rfi",
            "open-redirect": "open_redirect",
            "cve-": "cve",
        }
        for key, vuln_type in mapping.items():
            if key in tid:
                return vuln_type
        return "misconfiguration"

    # ------------------------------------------------------------------
    # ZAP
    # ------------------------------------------------------------------

    async def _run_zap(
        self,
        target_url: str,
        scan_type: str,
        log: LogCallback,
    ) -> list[dict[str, Any]]:
        await log("info", "Running OWASP ZAP scanner")
        findings: list[dict[str, Any]] = []
        try:
            from app.tools.zap_wrapper import ZapWrapper

            wrapper = ZapWrapper()
            # Passive scan always.
            passive = await wrapper.passive_scan(target_url)
            if isinstance(passive, dict) and "error" in passive:
                await log("warning", f"ZAP unavailable: {passive['error']}")
                return []
            if isinstance(passive, list):
                for alert in passive:
                    findings.append(self._zap_alert_to_finding(alert))

            # Active scan only for full scans.
            if scan_type == "full":
                active = await wrapper.active_scan(target_url)
                if isinstance(active, list):
                    for alert in active:
                        findings.append(self._zap_alert_to_finding(alert))

            await log("info", f"ZAP produced {len(findings)} findings")
        except ImportError:
            await log("warning", "ZapWrapper not available, skipping ZAP scan")
        except Exception as exc:
            await log("warning", f"ZAP scan failed: {exc}")
        return findings

    @staticmethod
    def _zap_alert_to_finding(alert: dict) -> dict[str, Any]:
        risk_map = {"3": "high", "2": "medium", "1": "low", "0": "info"}
        return {
            "type": alert.get("cweid", "misconfiguration"),
            "severity": risk_map.get(str(alert.get("risk", "0")), "info"),
            "title": alert.get("name", "ZAP Alert"),
            "url": alert.get("url", ""),
            "evidence": alert.get("evidence", alert.get("description", "")),
            "parameter": alert.get("param"),
            "method": alert.get("method", "GET"),
            "source": "zap",
            "references": [],
        }

    # ------------------------------------------------------------------
    # Misconfiguration checks
    # ------------------------------------------------------------------

    async def _check_misconfigs(
        self, host: str, log: LogCallback
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        await log("info", f"Checking misconfigurations on {host}")

        async with httpx.AsyncClient(
            timeout=10, follow_redirects=False, verify=False
        ) as client:
            for item in _SENSITIVE_PATHS:
                url = urljoin(host, item["path"])
                try:
                    resp = await client.get(url)
                    if self._is_sensitive_hit(resp, item["path"]):
                        finding = {
                            "type": item["type"],
                            "severity": self._misconfig_severity(item["path"]),
                            "title": item["title"],
                            "url": url,
                            "evidence": f"HTTP {resp.status_code} - "
                                        f"Content-Length: {len(resp.content)} bytes",
                            "parameter": None,
                            "method": "GET",
                            "source": "misconfig_check",
                            "references": [],
                        }
                        findings.append(finding)
                        await log("info", f"Misconfiguration found: {item['title']}", {
                            "url": url, "status": resp.status_code,
                        })
                except httpx.RequestError:
                    pass
                except Exception:
                    pass

            # Directory listing check on root.
            try:
                resp = await client.get(host)
                body = resp.text.lower()
                if "index of /" in body or "directory listing" in body:
                    findings.append({
                        "type": "info_disclosure",
                        "severity": "medium",
                        "title": "Directory listing enabled",
                        "url": host,
                        "evidence": "Server response contains directory listing indicators",
                        "parameter": None,
                        "method": "GET",
                        "source": "misconfig_check",
                        "references": [],
                    })
                    await log("info", "Directory listing detected", {"url": host})
            except Exception:
                pass

        return findings

    @staticmethod
    def _is_sensitive_hit(resp: httpx.Response, path: str) -> bool:
        """Heuristic: response is a real hit rather than a custom 404."""
        if resp.status_code >= 400:
            return False
        # Avoid counting generic redirect-to-login as a finding.
        if resp.status_code in (301, 302, 307, 308):
            return False
        body = resp.text
        # .env files typically contain KEY=value pairs.
        if path == "/.env" and ("=" in body and len(body) > 10):
            return True
        # .git/HEAD should start with "ref: ".
        if path == "/.git/HEAD" and body.strip().startswith("ref:"):
            return True
        # Admin panels: if 200 and body > 500 bytes it's likely real.
        if "/admin" in path and resp.status_code == 200 and len(body) > 500:
            return True
        # Backup / swap / old files.
        if any(path.endswith(ext) for ext in (".bak", ".old", ".swp", "~")):
            if resp.status_code == 200 and len(body) > 0:
                return True
        return False

    @staticmethod
    def _misconfig_severity(path: str) -> str:
        if path in ("/.env", "/.git/HEAD"):
            return "high"
        if "/admin" in path:
            return "medium"
        return "low"

    # ------------------------------------------------------------------
    # Security headers
    # ------------------------------------------------------------------

    async def _check_security_headers(
        self, host: str, log: LogCallback
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        await log("info", f"Checking security headers on {host}")

        try:
            async with httpx.AsyncClient(
                timeout=10, follow_redirects=True, verify=False
            ) as client:
                resp = await client.get(host)

            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            for header_key, header_name in _SECURITY_HEADERS.items():
                if header_key not in resp_headers:
                    findings.append({
                        "type": "missing_header",
                        "severity": self._header_severity(header_key),
                        "title": f"Missing security header: {header_name}",
                        "url": host,
                        "evidence": f"The response did not include the {header_name} header",
                        "parameter": None,
                        "method": "GET",
                        "source": "header_check",
                        "references": [],
                    })

        except httpx.RequestError as exc:
            await log("warning", f"Could not fetch headers from {host}: {exc}")
        except Exception as exc:
            await log("warning", f"Header check failed for {host}: {exc}")

        if findings:
            await log("info", f"Found {len(findings)} missing headers on {host}")
        return findings

    @staticmethod
    def _header_severity(header_key: str) -> str:
        critical_headers = {
            "strict-transport-security",
            "content-security-policy",
        }
        if header_key in critical_headers:
            return "medium"
        return "low"

    # ------------------------------------------------------------------
    # SSL/TLS checks
    # ------------------------------------------------------------------

    async def _check_ssl(
        self, target_url: str, log: LogCallback
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname or ""
        port = parsed.port or 443

        if parsed.scheme == "http":
            await log("info", "Target uses HTTP; skipping SSL/TLS checks")
            return findings

        await log("info", f"Checking SSL/TLS on {hostname}:{port}")

        loop = asyncio.get_running_loop()
        try:
            cert_info = await loop.run_in_executor(
                None, self._get_cert_info, hostname, port
            )
        except Exception as exc:
            await log("warning", f"SSL check failed: {exc}")
            return findings

        # Check certificate expiry.
        if cert_info.get("expired"):
            findings.append({
                "type": "ssl_issue",
                "severity": "high",
                "title": "SSL certificate expired",
                "url": target_url,
                "evidence": f"Certificate expired on {cert_info.get('not_after', 'unknown')}",
                "parameter": None,
                "method": "GET",
                "source": "ssl_check",
                "references": [],
            })
            await log("info", "Expired SSL certificate detected")

        # Check days until expiry.
        days_left = cert_info.get("days_until_expiry")
        if days_left is not None and 0 < days_left <= 30:
            findings.append({
                "type": "ssl_issue",
                "severity": "medium",
                "title": f"SSL certificate expires in {days_left} days",
                "url": target_url,
                "evidence": f"Certificate valid until {cert_info.get('not_after', 'unknown')}",
                "parameter": None,
                "method": "GET",
                "source": "ssl_check",
                "references": [],
            })

        # Check for weak protocol versions.
        for proto_name, proto_const in [
            ("TLSv1.0", ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None),
            ("TLSv1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None),
        ]:
            if proto_const is None:
                continue
            weak = await loop.run_in_executor(
                None, self._test_weak_protocol, hostname, port, proto_const
            )
            if weak:
                findings.append({
                    "type": "ssl_issue",
                    "severity": "medium",
                    "title": f"Weak TLS protocol supported: {proto_name}",
                    "url": target_url,
                    "evidence": f"Server accepted connection using {proto_name}",
                    "parameter": None,
                    "method": "GET",
                    "source": "ssl_check",
                    "references": [],
                })
                await log("info", f"Weak protocol {proto_name} accepted")

        return findings

    @staticmethod
    def _get_cert_info(hostname: str, port: int) -> dict[str, Any]:
        """Fetch certificate details using the ssl module."""
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return {}

        not_after_str = cert.get("notAfter", "")
        result: dict[str, Any] = {
            "subject": dict(x[0] for x in cert.get("subject", ())),
            "issuer": dict(x[0] for x in cert.get("issuer", ())),
            "not_before": cert.get("notBefore", ""),
            "not_after": not_after_str,
            "expired": False,
        }

        if not_after_str:
            try:
                not_after = datetime.strptime(
                    not_after_str, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                result["expired"] = now > not_after
                result["days_until_expiry"] = (not_after - now).days
            except ValueError:
                pass

        return result

    @staticmethod
    def _test_weak_protocol(hostname: str, port: int, protocol: int) -> bool:
        """Return True if the server accepts the given (weak) TLS protocol."""
        try:
            ctx = ssl.SSLContext(protocol)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    return True
        except (ssl.SSLError, OSError, ConnectionError):
            return False
