"""Analyzer agent.

Uses an LLM provider (when available) to enrich vulnerability findings with
better descriptions, impact assessments, CVSS estimates, CWE mappings, and
fix recommendations.  When no LLM is configured, falls back to rule-based
heuristics so the pipeline can still complete.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Coroutine, Optional

from app.llm.base import LLMProvider

logger = logging.getLogger(__name__)

LogCallback = Callable[[str, str, Any], Coroutine[Any, Any, None]]

# ---------------------------------------------------------------------------
# Heuristic severity → CVSS score mapping (fallback when no LLM)
# ---------------------------------------------------------------------------
_SEVERITY_CVSS: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.0,
}

# Type → CWE mapping for common vulnerability classes.
_TYPE_CWE: dict[str, str] = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "ssrf": "CWE-918",
    "rce": "CWE-78",
    "lfi": "CWE-22",
    "rfi": "CWE-98",
    "open_redirect": "CWE-601",
    "info_disclosure": "CWE-200",
    "missing_header": "CWE-693",
    "ssl_issue": "CWE-295",
    "misconfiguration": "CWE-16",
    "cve": "CWE-1035",
}

_TYPE_FIX: dict[str, str] = {
    "sqli": "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.",
    "xss": "Sanitize and encode all user-supplied data before rendering it in HTML. Use Content-Security-Policy headers.",
    "ssrf": "Validate and whitelist allowed URLs on the server side. Block requests to internal/private IP ranges.",
    "rce": "Never pass user input to system commands. Use safe APIs and input validation.",
    "lfi": "Validate file paths against an allow-list. Avoid using user input in file system operations.",
    "rfi": "Disable remote file inclusion in server configuration. Validate all file paths.",
    "open_redirect": "Validate redirect URLs against an allow-list of trusted domains.",
    "info_disclosure": "Remove or restrict access to sensitive files. Configure the web server to deny access to dot-files and backups.",
    "missing_header": "Add the missing security header to your web server or application response configuration.",
    "ssl_issue": "Renew expired certificates. Disable weak TLS protocols (TLS 1.0, 1.1). Enforce TLS 1.2+.",
    "misconfiguration": "Review and harden server configuration according to security best practices.",
}


async def _noop_log(level: str, message: str, data: Any = None) -> None:
    pass


class AnalyzerAgent:
    """Phase-4 agent: AI-powered (or heuristic) analysis and prioritisation."""

    def __init__(self, llm_provider: Optional[LLMProvider] = None) -> None:
        self._llm = llm_provider

    async def run(
        self,
        findings: list[dict[str, Any]],
        scan_data: dict[str, Any],
        log_callback: LogCallback | None = None,
    ) -> list[dict[str, Any]]:
        log = log_callback or _noop_log
        await log("info", f"Analyzer agent starting with {len(findings)} findings")

        if not findings:
            await log("info", "No findings to analyze")
            return findings

        # --- Step 1: Enrich with LLM or heuristics ---
        if self._llm is not None:
            findings = await self._llm_analyze(findings, log)
        else:
            await log("info", "No LLM configured; using heuristic analysis")

        # --- Step 2: Apply heuristic enrichment for any gaps ---
        for finding in findings:
            self._heuristic_enrich(finding)

        # --- Step 3: Generate fix recommendations ---
        if self._llm is not None:
            findings = await self._llm_fixes(findings, log)

        # --- Step 4: Prioritize / sort ---
        findings = self._prioritize(findings)

        confirmed = sum(1 for f in findings if f.get("confirmed"))
        await log("info", f"Analysis complete: {len(findings)} findings ({confirmed} confirmed)")
        return findings

    # ------------------------------------------------------------------
    # LLM-powered analysis
    # ------------------------------------------------------------------

    async def _llm_analyze(
        self, findings: list[dict], log: LogCallback
    ) -> list[dict]:
        await log("info", "Sending findings to LLM for analysis")
        try:
            enhanced = await self._llm.analyze_findings(findings)
            await log("info", "LLM analysis complete")
            return enhanced
        except Exception as exc:
            await log("warning", f"LLM analysis failed, falling back to heuristics: {exc}")
            return findings

    async def _llm_fixes(
        self, findings: list[dict], log: LogCallback
    ) -> list[dict]:
        """Generate fix recommendations for high/critical findings via LLM."""
        await log("info", "Generating LLM fix recommendations for high-severity findings")
        for finding in findings:
            sev = finding.get("severity", "").lower()
            if sev not in ("critical", "high"):
                continue
            if finding.get("fix_recommendation"):
                continue
            try:
                fix = await self._llm.generate_fix(finding)
                if fix:
                    finding["fix_recommendation"] = fix
            except Exception as exc:
                await log("warning", f"LLM fix generation failed for '{finding.get('title', '')}': {exc}")
        return findings

    # ------------------------------------------------------------------
    # Heuristic enrichment (fills gaps left by LLM or used standalone)
    # ------------------------------------------------------------------

    @staticmethod
    def _heuristic_enrich(finding: dict) -> None:
        vuln_type = finding.get("type", "").lower()

        # CVSS score estimate
        if not finding.get("cvss_score"):
            sev = finding.get("severity", "info").lower()
            finding["cvss_score"] = _SEVERITY_CVSS.get(sev, 0.0)

        # CWE mapping
        if not finding.get("cwe"):
            finding["cwe"] = _TYPE_CWE.get(vuln_type)

        # Fix recommendation fallback
        if not finding.get("fix_recommendation"):
            finding["fix_recommendation"] = _TYPE_FIX.get(
                vuln_type,
                "Review and remediate according to the vulnerability type and industry best practices.",
            )

    # ------------------------------------------------------------------
    # Prioritization
    # ------------------------------------------------------------------

    @staticmethod
    def _prioritize(findings: list[dict]) -> list[dict]:
        """Sort findings: confirmed first, then by severity."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        def sort_key(f: dict) -> tuple:
            confirmed = 0 if f.get("confirmed") else 1
            sev = severity_order.get(f.get("severity", "info").lower(), 5)
            return (confirmed, sev)

        return sorted(findings, key=sort_key)
