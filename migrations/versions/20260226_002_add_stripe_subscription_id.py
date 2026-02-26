"""Add stripe_subscription_id to api_keys.

Column was added in Fase 2 billing subscriptions. This migration adds it to
databases that were created by create_all() before Alembic was initialized.

Revision ID: 002
Revises: 001
Create Date: 2026-02-26 00:00:00.000000 UTC

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add stripe_subscription_id if it doesn't already exist.
    # Uses a DO block so the migration is safe to run on DBs that were
    # bootstrapped by create_all() and already have the column.
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'api_keys'
                  AND column_name = 'stripe_subscription_id'
            ) THEN
                ALTER TABLE api_keys
                    ADD COLUMN stripe_subscription_id VARCHAR(255);
            END IF;
        END
        $$;
    """)

    # Create index if not exists
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_api_keys_stripe_subscription_id
            ON api_keys (stripe_subscription_id);
    """)


def downgrade() -> None:
    op.execute(
        "DROP INDEX IF EXISTS ix_api_keys_stripe_subscription_id;"
    )
    op.execute("""
        ALTER TABLE api_keys
            DROP COLUMN IF EXISTS stripe_subscription_id;
    """)
