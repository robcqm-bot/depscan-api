"""Initial schema — all tables for Fase 0-3.

Revision ID: 001
Revises:
Create Date: 2026-02-26 00:00:00.000000 UTC

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # api_keys
    # ------------------------------------------------------------------
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("tier", sa.String(20), nullable=False, server_default="single"),
        sa.Column("credits_remaining", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("stripe_customer_id", sa.String(255), nullable=True),
        sa.Column("stripe_session_id", sa.String(255), nullable=True),
        sa.Column("stripe_subscription_id", sa.String(255), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)
    op.create_index("ix_api_keys_stripe_subscription_id", "api_keys", ["stripe_subscription_id"])

    # ------------------------------------------------------------------
    # scans
    # ------------------------------------------------------------------
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.String(40), nullable=False),
        sa.Column(
            "api_key_id",
            sa.Integer(),
            sa.ForeignKey("api_keys.id"),
            nullable=True,
        ),
        sa.Column("skill_url", sa.Text(), nullable=True),
        sa.Column("overall_score", sa.Integer(), nullable=True),
        sa.Column("scan_status", sa.String(20), nullable=True),
        sa.Column("recommendation", sa.String(50), nullable=True),
        sa.Column("scan_type", sa.String(20), nullable=False, server_default="single"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("processing_time_ms", sa.Integer(), nullable=True),
    )
    op.create_index("ix_scans_scan_id", "scans", ["scan_id"], unique=True)

    # ------------------------------------------------------------------
    # endpoint_results
    # ------------------------------------------------------------------
    op.create_table(
        "endpoint_results",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id"),
            nullable=False,
        ),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("ssl_expires_days", sa.Integer(), nullable=True),
        sa.Column("ssl_valid", sa.Boolean(), nullable=True),
        sa.Column("domain_age_days", sa.Integer(), nullable=True),
        sa.Column("domain_owner_changed", sa.Boolean(), nullable=True),
        sa.Column("abuse_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("in_blacklist", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("flags", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("score", sa.Integer(), nullable=False, server_default="50"),
    )

    # ------------------------------------------------------------------
    # subscriptions
    # ------------------------------------------------------------------
    op.create_table(
        "subscriptions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("subscription_id", sa.String(40), nullable=False),
        sa.Column(
            "api_key_id",
            sa.Integer(),
            sa.ForeignKey("api_keys.id"),
            nullable=False,
        ),
        sa.Column("skill_url", sa.Text(), nullable=True),
        sa.Column("endpoints_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("webhook_url", sa.Text(), nullable=True),
        sa.Column("alert_threshold", sa.Integer(), nullable=False, server_default="20"),
        sa.Column("last_score", sa.Integer(), nullable=True),
        sa.Column("last_scan_id", sa.String(40), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_subscriptions_subscription_id", "subscriptions", ["subscription_id"], unique=True
    )

    # ------------------------------------------------------------------
    # alert_history
    # ------------------------------------------------------------------
    op.create_table(
        "alert_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "subscription_id",
            sa.Integer(),
            sa.ForeignKey("subscriptions.id"),
            nullable=False,
        ),
        sa.Column("previous_score", sa.Integer(), nullable=False),
        sa.Column("new_score", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.String(40), nullable=False),
        sa.Column("webhook_url", sa.Text(), nullable=True),
        sa.Column(
            "webhook_status", sa.String(20), nullable=False, server_default="pending"
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("alert_history")
    op.drop_table("subscriptions")
    op.drop_table("endpoint_results")
    op.drop_table("scans")
    op.drop_index("ix_api_keys_stripe_subscription_id", "api_keys")
    op.drop_index("ix_api_keys_key_hash", "api_keys")
    op.drop_table("api_keys")
