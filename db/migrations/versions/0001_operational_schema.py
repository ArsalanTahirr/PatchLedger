"""Create the operational namespace, without domain tables.

Revision ID: 0001_operational_schema
Revises:
"""

from alembic import op
from sqlalchemy.schema import CreateSchema, DropSchema

revision = "0001_operational_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Fail if already present: do not silently adopt an unmanaged schema.
    op.execute(CreateSchema("operational"))


def downgrade() -> None:
    # RESTRICT is deliberate. Unknown objects must never be cascade-deleted.
    op.execute(DropSchema("operational", cascade=False))
