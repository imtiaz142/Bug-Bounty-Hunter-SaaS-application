import json
import logging
from typing import Any

import anthropic

from app.llm.base import LLMProvider

logger = logging.getLogger(__name__)

_MODEL = "claude-sonnet-4-20250514"
_MAX_TOKENS = 4096


def _findings_to_text(findings: list[dict]) -> str:
    """Serialize findings to a compact text block for the prompt."""
    parts: list[str] = []
    for i, f in enumerate(findings, 1):
        lines = [
            f"Finding #{i}",
            f"  Type: {f.get('type', 'unknown')}",
            f"  Severity: {f.get('severity', 'unknown')}",
            f"  Title: {f.get('title', '')}",
            f"  URL: {f.get('url', '')}",
        ]
        if f.get("parameter"):
            lines.append(f"  Parameter: {f['parameter']}")
        if f.get("method"):
            lines.append(f"  Method: {f['method']}")
        if f.get("evidence"):
            lines.append(f"  Evidence: {f['evidence'][:500]}")
        if f.get("cwe"):
            lines.append(f"  CWE: {f['cwe']}")
        parts.append("\n".join(lines))
    return "\n\n".join(parts)


class ClaudeProvider(LLMProvider):
    """LLM provider backed by Anthropic's Claude API."""

    def __init__(self, api_key: str) -> None:
        self._client = anthropic.AsyncAnthropic(api_key=api_key)

    async def _call(self, system: str, user: str) -> str | None:
        """Make a single API call and return the text response."""
        try:
            message = await self._client.messages.create(
                model=_MODEL,
                max_tokens=_MAX_TOKENS,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            return message.content[0].text
        except anthropic.APIError as exc:
            logger.error("Claude API error: %s", exc)
            return None
        except Exception as exc:
            logger.error("Unexpected error calling Claude: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def analyze_findings(self, findings: list[dict]) -> list[dict]:
        system = (
            "You are an expert application security engineer. "
            "You will be given raw vulnerability findings from automated scanners. "
            "For each finding, produce an enhanced version with:\n"
            "- An improved, specific title\n"
            "- A clear, technically accurate description\n"
            "- An impact assessment explaining what an attacker could achieve\n\n"
            "Return ONLY a JSON array where each element has the keys: "
            "index (1-based), title, description, impact_assessment. "
            "Do not include any text outside the JSON array."
        )
        user = (
            "Enhance the following vulnerability findings:\n\n"
            + _findings_to_text(findings)
        )

        raw = await self._call(system, user)
        if raw is None:
            return findings

        try:
            enhanced: list[dict] = json.loads(raw)
            for item in enhanced:
                idx = item.get("index", 0) - 1
                if 0 <= idx < len(findings):
                    findings[idx]["title"] = item.get("title", findings[idx].get("title", ""))
                    findings[idx]["description"] = item.get("description", "")
                    findings[idx]["impact_assessment"] = item.get("impact_assessment", "")
            return findings
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("Failed to parse Claude analyze_findings response: %s", exc)
            return findings

    async def generate_fix(self, finding: dict) -> str:
        system = (
            "You are an expert application security engineer. "
            "Provide a step-by-step remediation guide for the given vulnerability. "
            "Include code examples where applicable. Use Markdown formatting."
        )
        user = (
            f"Vulnerability type: {finding.get('type', 'unknown')}\n"
            f"Severity: {finding.get('severity', 'unknown')}\n"
            f"Title: {finding.get('title', '')}\n"
            f"URL: {finding.get('url', '')}\n"
            f"Parameter: {finding.get('parameter', 'N/A')}\n"
            f"Evidence: {finding.get('evidence', 'N/A')}\n"
            f"CWE: {finding.get('cwe', 'N/A')}\n\n"
            "Provide a detailed, step-by-step remediation plan."
        )

        result = await self._call(system, user)
        return result or ""

    async def generate_executive_summary(self, scan_data: dict) -> str:
        system = (
            "You are a senior security consultant writing an executive summary "
            "for a non-technical audience. Be professional, concise, and "
            "highlight business risk. Use Markdown formatting."
        )
        user = (
            "Write an executive summary for this security assessment:\n\n"
            f"Target: {scan_data.get('target_url', 'N/A')}\n"
            f"Scan date: {scan_data.get('scan_date', 'N/A')}\n"
            f"Duration: {scan_data.get('duration', 'N/A')}\n"
            f"Scanners used: {', '.join(scan_data.get('scanners', []))}\n\n"
            "Findings by severity:\n"
            f"  Critical: {scan_data.get('critical', 0)}\n"
            f"  High: {scan_data.get('high', 0)}\n"
            f"  Medium: {scan_data.get('medium', 0)}\n"
            f"  Low: {scan_data.get('low', 0)}\n"
            f"  Info: {scan_data.get('info', 0)}\n"
            f"Total findings: {scan_data.get('total', 0)}\n"
        )

        result = await self._call(system, user)
        return result or ""

    async def generate_report_narrative(self, findings: list[dict]) -> str:
        system = (
            "You are a senior penetration tester writing the detailed findings "
            "section of a security assessment report. For each finding, write:\n"
            "- A section heading\n"
            "- Description of the vulnerability\n"
            "- How it was discovered (evidence)\n"
            "- Potential impact\n"
            "- Recommended remediation\n\n"
            "Use professional Markdown formatting."
        )
        user = (
            "Write a detailed narrative for the following findings:\n\n"
            + _findings_to_text(findings)
        )

        result = await self._call(system, user)
        return result or ""
