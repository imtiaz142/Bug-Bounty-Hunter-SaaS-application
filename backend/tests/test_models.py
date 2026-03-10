"""Tests for database models."""

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.report import Report
from app.models.agent_log import AgentLog
from app.core.security import hash_password


@pytest.mark.asyncio
async def test_create_user(db_session: AsyncSession):
    user = User(
        email="model_test@example.com",
        username="modeltest",
        password_hash=hash_password("TestPass123!"),
    )
    db_session.add(user)
    await db_session.commit()

    result = await db_session.execute(select(User).where(User.email == "model_test@example.com"))
    fetched = result.scalar_one()
    assert fetched.username == "modeltest"
    assert fetched.id is not None


@pytest.mark.asyncio
async def test_create_scan(db_session: AsyncSession, test_user):
    scan = Scan(
        user_id=test_user.id,
        target_url="https://test.example.com",
        scan_type="full",
        status="queued",
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    assert scan.id is not None
    assert scan.progress == 0
    assert scan.target_url == "https://test.example.com"


@pytest.mark.asyncio
async def test_create_finding(db_session: AsyncSession, test_scan):
    finding = Finding(
        scan_id=test_scan.id,
        type="xss",
        severity="high",
        title="Test XSS Finding",
        url="https://example.com/test",
    )
    db_session.add(finding)
    await db_session.commit()
    await db_session.refresh(finding)

    assert finding.id is not None
    assert finding.confirmed is False
    assert finding.false_positive is False


@pytest.mark.asyncio
async def test_create_report(db_session: AsyncSession, test_scan):
    report = Report(
        scan_id=test_scan.id,
        report_type="technical",
        status="generating",
    )
    db_session.add(report)
    await db_session.commit()
    await db_session.refresh(report)

    assert report.id is not None
    assert report.file_path is None


@pytest.mark.asyncio
async def test_create_agent_log(db_session: AsyncSession, test_scan):
    log = AgentLog(
        scan_id=test_scan.id,
        agent_name="recon",
        level="info",
        message="Recon started",
    )
    db_session.add(log)
    await db_session.commit()
    await db_session.refresh(log)

    assert log.id is not None
    assert log.timestamp is not None


@pytest.mark.asyncio
async def test_scan_finding_relationship(db_session: AsyncSession, test_scan):
    f1 = Finding(scan_id=test_scan.id, type="xss", severity="high", title="F1", url="http://a.com")
    f2 = Finding(scan_id=test_scan.id, type="sqli", severity="critical", title="F2", url="http://b.com")
    db_session.add_all([f1, f2])
    await db_session.commit()

    result = await db_session.execute(
        select(Finding).where(Finding.scan_id == test_scan.id)
    )
    findings = result.scalars().all()
    assert len(findings) == 2
