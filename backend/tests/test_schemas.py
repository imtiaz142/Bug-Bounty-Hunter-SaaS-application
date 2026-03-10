"""Tests for Pydantic schemas."""

import uuid
import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from app.schemas.scan import ScanCreate, ScanResponse
from app.schemas.finding import FindingResponse, FindingUpdate, FindingSummary
from app.schemas.user import UserCreate, UserLogin
from app.schemas.report import ReportCreate
from app.schemas.settings import SettingsUpdate, PasswordChange


def test_scan_create_valid():
    scan = ScanCreate(
        target_url="https://example.com",
        scan_type="quick",
        consent=True,
    )
    assert str(scan.target_url) == "https://example.com/"
    assert scan.scan_type == "quick"


def test_scan_create_no_consent():
    with pytest.raises(ValidationError) as exc_info:
        ScanCreate(
            target_url="https://example.com",
            scan_type="quick",
            consent=False,
        )
    assert "authorization" in str(exc_info.value).lower()


def test_scan_create_invalid_url():
    with pytest.raises(ValidationError):
        ScanCreate(
            target_url="not-a-url",
            scan_type="quick",
            consent=True,
        )


def test_scan_create_invalid_type():
    with pytest.raises(ValidationError):
        ScanCreate(
            target_url="https://example.com",
            scan_type="invalid",
            consent=True,
        )


def test_user_create_valid():
    user = UserCreate(
        email="test@example.com",
        password="SecurePass1!",
        username="testuser",
    )
    assert user.email == "test@example.com"


def test_user_create_short_password():
    with pytest.raises(ValidationError):
        UserCreate(
            email="test@example.com",
            password="short",
            username="testuser",
        )


def test_user_create_invalid_email():
    with pytest.raises(ValidationError):
        UserCreate(
            email="not-an-email",
            password="SecurePass1!",
            username="testuser",
        )


def test_finding_update():
    update = FindingUpdate(false_positive=True, notes="False alarm")
    assert update.false_positive is True
    assert update.notes == "False alarm"


def test_finding_update_partial():
    update = FindingUpdate(notes="Just a note")
    assert update.false_positive is None


def test_report_create():
    report = ReportCreate(report_type="technical")
    assert report.report_type == "technical"

    with pytest.raises(ValidationError):
        ReportCreate(report_type="invalid")


def test_password_change_validation():
    pc = PasswordChange(current_password="old", new_password="NewSecure1!")
    assert pc.new_password == "NewSecure1!"

    with pytest.raises(ValidationError):
        PasswordChange(current_password="old", new_password="short")


def test_finding_summary():
    summary = FindingSummary(
        total=10,
        critical=1,
        high=2,
        medium=3,
        low=2,
        info=2,
        confirmed=5,
        false_positives=1,
    )
    assert summary.total == 10
