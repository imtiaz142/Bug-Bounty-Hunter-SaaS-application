"""Initial migration

Revision ID: 001
Revises:
Create Date: 2024-01-01 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), unique=True, nullable=False, index=True),
        sa.Column("username", sa.String(100), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("llm_provider", sa.String(20), nullable=True),
        sa.Column("llm_api_key_encrypted", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), onupdate=sa.func.now()),
    )

    op.create_table(
        "scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_url", sa.String(500), nullable=False),
        sa.Column("target_scope_include", sa.JSON, default=[]),
        sa.Column("target_scope_exclude", sa.JSON, default=[]),
        sa.Column("status", sa.String(20), default="queued", nullable=False),
        sa.Column("scan_type", sa.String(20), default="quick", nullable=False),
        sa.Column("progress", sa.Integer, default=0),
        sa.Column("current_agent", sa.String(50), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Integer, nullable=True),
        sa.Column("recon_data", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("cvss_vector", sa.String(200), nullable=True),
        sa.Column("cwe", sa.String(50), nullable=True),
        sa.Column("url", sa.String(1000), nullable=False),
        sa.Column("parameter", sa.String(200), nullable=True),
        sa.Column("method", sa.String(10), nullable=True),
        sa.Column("evidence", sa.Text, nullable=True),
        sa.Column("confirmed", sa.Boolean, default=False),
        sa.Column("fix_recommendation", sa.Text, nullable=True),
        sa.Column("references", sa.JSON, nullable=True),
        sa.Column("false_positive", sa.Boolean, default=False),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "reports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("report_type", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), default="generating", nullable=False),
        sa.Column("file_path", sa.String(500), nullable=True),
        sa.Column("share_token", sa.String(100), nullable=True, unique=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "agent_logs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("agent_name", sa.String(50), nullable=False),
        sa.Column("level", sa.String(20), nullable=False),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("data", sa.JSON, nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_index("ix_scans_user_id", "scans", ["user_id"])
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_agent_logs_scan_id", "agent_logs", ["scan_id"])


def downgrade() -> None:
    op.drop_table("agent_logs")
    op.drop_table("reports")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("users")
