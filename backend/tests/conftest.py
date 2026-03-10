"""Shared test fixtures for the Bug Bounty Hunter backend."""

import asyncio
import os
import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


# Use SQLite for tests so we don't need a real Postgres.
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///test.db"
os.environ["DATABASE_URL_SYNC"] = "sqlite:///test.db"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ["CELERY_BROKER_URL"] = "redis://localhost:6379/15"
os.environ["CELERY_RESULT_BACKEND"] = "redis://localhost:6379/15"
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"
os.environ["ENCRYPTION_KEY"] = "test-encryption-key-32bytes!!"
os.environ["REPORTS_DIR"] = "/tmp/bbh_test_reports"


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def db_session():
    """Create a fresh in-memory database for each test."""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
    from app.core.database import Base

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def test_user(db_session):
    """Create a test user in the database."""
    from app.models.user import User
    from app.core.security import hash_password

    user = User(
        id=uuid.uuid4(),
        email="test@example.com",
        username="testuser",
        password_hash=hash_password("TestPass123!"),
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def test_scan(db_session, test_user):
    """Create a test scan in the database."""
    from app.models.scan import Scan

    scan = Scan(
        id=uuid.uuid4(),
        user_id=test_user.id,
        target_url="https://example.com",
        scan_type="quick",
        status="queued",
        progress=0,
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)
    return scan


@pytest_asyncio.fixture
async def test_finding(db_session, test_scan):
    """Create a test finding."""
    from app.models.finding import Finding

    finding = Finding(
        id=uuid.uuid4(),
        scan_id=test_scan.id,
        type="xss",
        severity="high",
        title="Reflected XSS in search parameter",
        url="https://example.com/search?q=test",
        parameter="q",
        method="GET",
        evidence="Payload reflected in response",
        confirmed=True,
    )
    db_session.add(finding)
    await db_session.commit()
    await db_session.refresh(finding)
    return finding


def make_mock_llm():
    """Create a mock LLM provider for testing."""
    mock = AsyncMock()
    mock.analyze_findings = AsyncMock(side_effect=lambda f: f)
    mock.generate_fix = AsyncMock(return_value="Use parameterized queries.")
    mock.generate_executive_summary = AsyncMock(return_value="Test executive summary.")
    mock.generate_report_narrative = AsyncMock(return_value="Test narrative.")
    return mock
