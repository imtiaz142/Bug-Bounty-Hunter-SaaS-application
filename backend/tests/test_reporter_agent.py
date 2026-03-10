"""Tests for the ReporterAgent."""

import os
import pytest
from unittest.mock import AsyncMock

from app.agents.reporter_agent import ReporterAgent


@pytest.fixture
def sample_findings():
    return [
        {
            "type": "xss",
            "severity": "high",
            "title": "Reflected XSS",
            "url": "https://example.com/search",
            "parameter": "q",
            "evidence": "Payload reflected",
            "confirmed": True,
            "fix_recommendation": "Sanitize input",
            "cvss_score": 7.5,
        },
        {
            "type": "missing_header",
            "severity": "low",
            "title": "Missing CSP",
            "url": "https://example.com",
            "confirmed": True,
            "fix_recommendation": "Add CSP header",
        },
    ]


@pytest.fixture
def scan_data():
    return {
        "scan_id": "test-scan-123",
        "target_url": "https://example.com",
        "scan_type": "quick",
        "started_at": "2024-01-01T00:00:00",
        "duration_seconds": 120,
    }


@pytest.mark.asyncio
async def test_reporter_generates_file(scan_data, sample_findings, tmp_path):
    """ReporterAgent should generate a report file."""
    os.environ["REPORTS_DIR"] = str(tmp_path)

    agent = ReporterAgent(llm_provider=None)
    # Override reports dir
    agent._settings.REPORTS_DIR = str(tmp_path)

    result = await agent.run(
        scan_data=scan_data,
        findings=sample_findings,
        report_type="technical",
    )

    assert result  # Should return a file path
    assert os.path.exists(result)


@pytest.mark.asyncio
async def test_reporter_empty_findings(scan_data, tmp_path):
    """ReporterAgent should handle empty findings."""
    agent = ReporterAgent(llm_provider=None)
    agent._settings.REPORTS_DIR = str(tmp_path)

    result = await agent.run(
        scan_data=scan_data,
        findings=[],
        report_type="executive",
    )

    assert result
    assert os.path.exists(result)


@pytest.mark.asyncio
async def test_reporter_with_llm(scan_data, sample_findings, tmp_path):
    """ReporterAgent should use LLM for content generation."""
    from tests.conftest import make_mock_llm

    mock_llm = make_mock_llm()
    agent = ReporterAgent(llm_provider=mock_llm)
    agent._settings.REPORTS_DIR = str(tmp_path)

    result = await agent.run(
        scan_data=scan_data,
        findings=sample_findings,
        report_type="technical",
    )

    assert result
    mock_llm.generate_executive_summary.assert_called_once()
    mock_llm.generate_report_narrative.assert_called_once()


@pytest.mark.asyncio
async def test_reporter_fallback_summary(scan_data, sample_findings, tmp_path):
    """ReporterAgent should generate fallback summary without LLM."""
    agent = ReporterAgent(llm_provider=None)
    agent._settings.REPORTS_DIR = str(tmp_path)

    summary = await agent._generate_summary(
        {
            "target_url": "https://example.com",
            "total": 2,
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 1,
            "info": 0,
        },
        log=AsyncMock(),
    )

    assert "example.com" in summary
    assert "2" in summary  # total findings
