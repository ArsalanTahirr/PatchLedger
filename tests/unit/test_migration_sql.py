from io import StringIO
from pathlib import Path

from alembic import command
from alembic.config import Config


def test_offline_migration_has_no_domain_ddl_or_password(monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://u:p%25ss%40word@localhost/offline"
    )
    output = StringIO()
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"), output_buffer=output)
    command.upgrade(config, "head", sql=True)
    sql = output.getvalue()
    assert "CREATE SCHEMA operational" in sql
    assert "public.alembic_version" in sql
    assert "CREATE TABLE operational." not in sql
    assert "p%ss@word" not in sql
    assert "p%25ss%40word" not in sql
