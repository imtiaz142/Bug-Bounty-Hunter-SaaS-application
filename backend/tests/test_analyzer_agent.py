"""Tests for the AnalyzerAgent."""

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock

from app.agents.analyzer_agent import AnalyzerAgent


@pytest.fixture
def sample_findings():
    return [
        {
            "type": "xss",
            "severity": "high",
            "title": "XSS in search",
            "url": "https://example.com/search",
            "parameter": "q",
            "method": "GET",
            "evidence": "Reflected payload",
            "confirmed": True,
        },
        {
            "type": "missing_header",
            "severity": "low",
            "title": "Missing CSP header",
            "url": "https://example.com",
            "confirmed": True,
        },
        {
            "type": "sqli",
            "severity": "critical",
            "title": "SQL Injection",
            "url": "https://example.com/api/users",
            "parameter": "id",
            "confirmed": False,
        },
    ]


@pytest.fixture
def scan_data():
    return {
        "target_url": "https://example.com",
        "scan_type": "quick",
        "recon_data": {},
    }


@pytest.mark.asyncio
async def test_analyzer_without_llm(sample_findings, scan_data):
    """AnalyzerAgent should enrich findings with heuristics when no LLM."""
    agent = AnalyzerAgent(llm_provider=None)
    result = await agent.run(findings=sample_findings, scan_data=scan_data)

    assert len(result) == 3
    # Check CVSS scores were added
    for f in result:
        assert f.get("cvss_score") is not None
    # Check CWE mappings
    xss = next(f for f in result if f["type"] == "xss")
    assert xss["cwe"] == "CWE-79"
    sqli = next(f for f in result if f["type"] == "sqli")
    assert sqli["cwe"] == "CWE-89"
    # Check fix recommendations
    for f in result:
        assert f.get("fix_recommendation") is not None


@pytest.mark.asyncio
async def test_analyzer_prioritization(sample_findings, scan_data):
    """Findings should be sorted: confirmed first, then by severity."""
    agent = AnalyzerAgent(llm_provider=None)
    result = await agent.run(findings=sample_findings, scan_data=scan_data)

    # The confirmed critical/high findings should come before unconfirmed
    confirmed = [f for f in result if f.get("confirmed")]
    assert len(confirmed) >= 1
    # First finding should be confirmed (sorted by confirmed first)
    assert result[0]["confirmed"] is True


@pytest.mark.asyncio
async def test_analyzer_empty_findings(scan_data):
    """AnalyzerAgent should handle empty findings list."""
    agent = AnalyzerAgent(llm_provider=None)
    result = await agent.run(findings=[], scan_data=scan_data)
    assert result == []


@pytest.mark.asyncio
async def test_analyzer_with_mock_llm(sample_findings, scan_data):
    """AnalyzerAgent should call LLM when provided."""
    from tests.conftest import make_mock_llm

    mock_llm = make_mock_llm()
    agent = AnalyzerAgent(llm_provider=mock_llm)
    result = await agent.run(findings=sample_findings, scan_data=scan_data)

    assert len(result) == 3
    mock_llm.analyze_findings.assert_called_once()
    # High severity findings should get LLM fix recommendations
    mock_llm.generate_fix.assert_called()


@pytest.mark.asyncio
async def test_analyzer_llm_failure_fallback(sample_findings, scan_data):
    """AnalyzerAgent should fallback to heuristics when LLM fails."""
    mock_llm = AsyncMock()
    mock_llm.analyze_findings = AsyncMock(side_effect=Exception("API Error"))
    mock_llm.generate_fix = AsyncMock(side_effect=Exception("API Error"))

    agent = AnalyzerAgent(llm_provider=mock_llm)
    result = await agent.run(findings=sample_findings, scan_data=scan_data)

    # Should still return enriched findings (heuristic fallback)
    assert len(result) == 3
    for f in result:
        assert f.get("cvss_score") is not None
        assert f.get("fix_recommendation") is not None
