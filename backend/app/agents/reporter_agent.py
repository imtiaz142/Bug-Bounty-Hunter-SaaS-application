"""Reporter agent.

Generates a PDF security assessment report from scan data and findings.
Uses an LLM provider (when available) to write executive summaries and
detailed narratives.  Falls back to structured templates when no LLM is
configured.

The generated PDF is saved to the configured reports directory and the
file path is returned.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Coroutine, Optional

from app.core.config import get_settings
from app.llm.base import LLMProvider

logger = logging.getLogger(__name__)

LogCallback = Callable[[str, str, Any], Coroutine[Any, Any, None]]

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_COLORS = {
    "critical": (220, 53, 69),
    "high": (255, 128, 0),
    "medium": (255, 193, 7),
    "low": (23, 162, 184),
    "info": (108, 117, 125),
}


async def _noop_log(level: str, message: str, data: Any = None) -> None:
    pass


class ReporterAgent:
    """Phase-5 agent: PDF report generation."""

    def __init__(self, llm_provider: Optional[LLMProvider] = None) -> None:
        self._llm = llm_provider
        self._settings = get_settings()

    async def run(
        self,
        scan_data: dict[str, Any],
        findings: list[dict[str, Any]],
        report_type: str = "technical",
        log_callback: LogCallback | None = None,
    ) -> str:
        log = log_callback or _noop_log
        await log("info", f"Reporter agent starting ({report_type} report)")

        # Compute severity counts
        severity_counts = {s: 0 for s in _SEVERITY_ORDER}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Prepare summary data for LLM
        summary_data = {
            "target_url": scan_data.get("target_url", "Unknown"),
            "scan_type": scan_data.get("scan_type", "quick"),
            "scan_date": scan_data.get("started_at", datetime.now(timezone.utc).isoformat()),
            "duration": f"{scan_data.get('duration_seconds', 0) or 0}s",
            "scanners": ["Nuclei", "ZAP", "Nmap", "Subfinder"],
            "total": len(findings),
            **severity_counts,
        }

        # --- Generate content ---
        executive_summary = await self._generate_summary(summary_data, log)
        narrative = ""
        if report_type == "technical":
            narrative = await self._generate_narrative(findings, log)

        # --- Build PDF ---
        file_path = await self._build_pdf(
            scan_data=scan_data,
            findings=findings,
            severity_counts=severity_counts,
            executive_summary=executive_summary,
            narrative=narrative,
            report_type=report_type,
            log=log,
        )

        await log("info", f"Report saved to {file_path}")
        return file_path

    # ------------------------------------------------------------------
    # Content generation
    # ------------------------------------------------------------------

    async def _generate_summary(
        self, summary_data: dict, log: LogCallback
    ) -> str:
        if self._llm is not None:
            try:
                await log("info", "Generating executive summary with LLM")
                text = await self._llm.generate_executive_summary(summary_data)
                if text:
                    return text
            except Exception as exc:
                await log("warning", f"LLM summary generation failed: {exc}")

        # Fallback template
        target = summary_data.get("target_url", "the target")
        total = summary_data.get("total", 0)
        critical = summary_data.get("critical", 0)
        high = summary_data.get("high", 0)
        medium = summary_data.get("medium", 0)

        return (
            f"Security Assessment Summary\n\n"
            f"A security assessment was performed against {target}. "
            f"The scan identified a total of {total} findings.\n\n"
            f"Severity Breakdown:\n"
            f"  - Critical: {critical}\n"
            f"  - High: {high}\n"
            f"  - Medium: {medium}\n"
            f"  - Low: {summary_data.get('low', 0)}\n"
            f"  - Informational: {summary_data.get('info', 0)}\n\n"
            f"{'Immediate remediation is recommended for critical and high severity findings.' if critical + high > 0 else 'No critical issues were found.'}"
        )

    async def _generate_narrative(
        self, findings: list[dict], log: LogCallback
    ) -> str:
        if not findings:
            return "No findings to report."

        if self._llm is not None:
            try:
                await log("info", "Generating detailed narrative with LLM")
                text = await self._llm.generate_report_narrative(findings)
                if text:
                    return text
            except Exception as exc:
                await log("warning", f"LLM narrative generation failed: {exc}")

        # Fallback: structured text
        parts: list[str] = []
        for i, f in enumerate(findings, 1):
            parts.append(
                f"{i}. {f.get('title', 'Finding')}\n"
                f"   Severity: {f.get('severity', 'unknown').upper()}\n"
                f"   Type: {f.get('type', 'unknown')}\n"
                f"   URL: {f.get('url', 'N/A')}\n"
                f"   Confirmed: {'Yes' if f.get('confirmed') else 'No'}\n"
                f"   Evidence: {(f.get('evidence') or 'N/A')[:200]}\n"
                f"   Recommendation: {(f.get('fix_recommendation') or 'N/A')[:200]}\n"
            )
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # PDF generation
    # ------------------------------------------------------------------

    async def _build_pdf(
        self,
        scan_data: dict,
        findings: list[dict],
        severity_counts: dict,
        executive_summary: str,
        narrative: str,
        report_type: str,
        log: LogCallback,
    ) -> str:
        reports_dir = self._settings.REPORTS_DIR
        os.makedirs(reports_dir, exist_ok=True)

        scan_id = scan_data.get("scan_id", scan_data.get("id", uuid.uuid4().hex))
        filename = f"report_{scan_id}_{report_type}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
        file_path = os.path.join(reports_dir, filename)

        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.units import mm
            from reportlab.lib.colors import HexColor, black, white
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
                Table,
                TableStyle,
            )
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

            await log("info", "Building PDF with ReportLab")

            doc = SimpleDocTemplate(
                file_path,
                pagesize=A4,
                leftMargin=20 * mm,
                rightMargin=20 * mm,
                topMargin=20 * mm,
                bottomMargin=20 * mm,
            )

            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                "ReportTitle",
                parent=styles["Title"],
                fontSize=24,
                spaceAfter=20,
                textColor=HexColor("#1e293b"),
            )
            heading_style = ParagraphStyle(
                "ReportHeading",
                parent=styles["Heading2"],
                fontSize=16,
                spaceBefore=20,
                spaceAfter=10,
                textColor=HexColor("#334155"),
            )
            body_style = ParagraphStyle(
                "ReportBody",
                parent=styles["BodyText"],
                fontSize=10,
                leading=14,
                textColor=HexColor("#475569"),
            )
            small_style = ParagraphStyle(
                "Small",
                parent=styles["BodyText"],
                fontSize=8,
                textColor=HexColor("#94a3b8"),
            )

            elements: list = []

            # Title
            target = scan_data.get("target_url", "Unknown Target")
            elements.append(Paragraph("Security Assessment Report", title_style))
            elements.append(Paragraph(f"Target: {target}", body_style))
            elements.append(Paragraph(
                f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                small_style,
            ))
            elements.append(Spacer(1, 20))

            # Severity summary table
            elements.append(Paragraph("Findings Overview", heading_style))
            table_data = [["Severity", "Count"]]
            for sev in _SEVERITY_ORDER:
                table_data.append([sev.capitalize(), str(severity_counts.get(sev, 0))])
            table_data.append(["Total", str(len(findings))])

            table = Table(table_data, colWidths=[100 * mm, 50 * mm])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -2), [HexColor("#f8fafc"), white]),
                ("BACKGROUND", (0, -1), (-1, -1), HexColor("#f1f5f9")),
                ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ]))
            elements.append(table)
            elements.append(Spacer(1, 20))

            # Executive summary
            elements.append(Paragraph("Executive Summary", heading_style))
            for line in executive_summary.split("\n"):
                line = line.strip()
                if line:
                    # Escape XML-special chars for ReportLab
                    safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    elements.append(Paragraph(safe, body_style))
            elements.append(Spacer(1, 15))

            # Detailed findings
            if report_type == "technical" and narrative:
                elements.append(Paragraph("Detailed Findings", heading_style))
                for line in narrative.split("\n"):
                    line = line.strip()
                    if line:
                        safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        if line.startswith("#") or line[0:1].isdigit():
                            elements.append(Paragraph(safe, ParagraphStyle(
                                "FindingTitle",
                                parent=body_style,
                                fontSize=11,
                                spaceBefore=12,
                                spaceAfter=4,
                                textColor=HexColor("#1e293b"),
                                fontName="Helvetica-Bold",
                            )))
                        else:
                            elements.append(Paragraph(safe, body_style))

            # Findings table
            if findings:
                elements.append(Spacer(1, 20))
                elements.append(Paragraph("Findings Summary Table", heading_style))
                f_table_data = [["#", "Title", "Severity", "Confirmed", "Type"]]
                for idx, f in enumerate(findings[:50], 1):  # Cap at 50 for PDF size
                    f_table_data.append([
                        str(idx),
                        (f.get("title", "N/A"))[:60],
                        f.get("severity", "info").upper(),
                        "Yes" if f.get("confirmed") else "No",
                        f.get("type", "N/A"),
                    ])

                f_table = Table(
                    f_table_data,
                    colWidths=[10 * mm, 75 * mm, 25 * mm, 20 * mm, 30 * mm],
                )
                f_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1e293b")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("ALIGN", (0, 0), (0, -1), "CENTER"),
                    ("ALIGN", (2, 0), (-1, -1), "CENTER"),
                    ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#f8fafc"), white]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]))
                elements.append(f_table)

            # Footer
            elements.append(Spacer(1, 30))
            elements.append(Paragraph(
                "This report was generated by Bug Bounty Hunter. "
                "Findings should be verified by a qualified security professional.",
                small_style,
            ))

            doc.build(elements)
            await log("info", f"PDF generated: {file_path}")

        except ImportError:
            await log("warning", "ReportLab not installed; generating plain text report")
            file_path = file_path.replace(".pdf", ".txt")
            content = self._build_text_report(
                scan_data, findings, severity_counts, executive_summary, narrative
            )
            with open(file_path, "w") as f:
                f.write(content)
            await log("info", f"Text report saved to {file_path}")

        return file_path

    @staticmethod
    def _build_text_report(
        scan_data: dict,
        findings: list[dict],
        severity_counts: dict,
        executive_summary: str,
        narrative: str,
    ) -> str:
        lines = [
            "=" * 70,
            "SECURITY ASSESSMENT REPORT",
            "=" * 70,
            f"Target: {scan_data.get('target_url', 'Unknown')}",
            f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"Scan Type: {scan_data.get('scan_type', 'quick')}",
            "",
            "-" * 70,
            "SEVERITY SUMMARY",
            "-" * 70,
        ]
        for sev in _SEVERITY_ORDER:
            lines.append(f"  {sev.capitalize():12s} {severity_counts.get(sev, 0)}")
        lines.append(f"  {'Total':12s} {len(findings)}")
        lines.append("")
        lines.append("-" * 70)
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 70)
        lines.append(executive_summary)
        lines.append("")

        if narrative:
            lines.append("-" * 70)
            lines.append("DETAILED FINDINGS")
            lines.append("-" * 70)
            lines.append(narrative)

        lines.append("")
        lines.append("=" * 70)
        lines.append("Generated by Bug Bounty Hunter")
        lines.append("=" * 70)
        return "\n".join(lines)
