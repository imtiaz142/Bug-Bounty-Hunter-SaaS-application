from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Abstract base class for LLM providers used in vulnerability analysis."""

    @abstractmethod
    async def analyze_findings(self, findings: list[dict]) -> list[dict]:
        """Enhance findings with better titles, descriptions, and impact assessments.

        Args:
            findings: Raw findings from scanners, each with keys like
                type, severity, title, url, parameter, evidence.

        Returns:
            Enhanced findings with improved title, description, and
            impact_assessment fields added to each dict.  Returns the
            original list unchanged on failure.
        """

    @abstractmethod
    async def generate_fix(self, finding: dict) -> str:
        """Generate a step-by-step remediation recommendation for a finding.

        Args:
            finding: A single finding dict with type, severity, title, url,
                parameter, and evidence.

        Returns:
            Markdown-formatted fix recommendation string, or empty string
            on failure.
        """

    @abstractmethod
    async def generate_executive_summary(self, scan_data: dict) -> str:
        """Generate a professional executive summary of scan results.

        Args:
            scan_data: Scan metadata including target_url, findings count
                by severity, scan duration, and scanner modules used.

        Returns:
            Executive summary text suitable for inclusion in a PDF report.
        """

    @abstractmethod
    async def generate_report_narrative(self, findings: list[dict]) -> str:
        """Generate a full narrative covering all findings for a report.

        Args:
            findings: List of finding dicts to narrate.

        Returns:
            Markdown-formatted narrative with sections per finding.
        """
