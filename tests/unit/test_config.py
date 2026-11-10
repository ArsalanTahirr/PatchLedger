import pytest
from pydantic import ValidationError

from patchledger.core.config import Settings


def test_database_url_is_required(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError, match="database_url"):
        Settings(_env_file=None)


@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///example.db",
        "postgresql+asyncpg://user:secret@localhost/example",
        "postgresql+psycopg://user:secret@localhost",
        "not-a-url-secret",
    ],
)
def test_invalid_database_url_does_not_expose_input(url):
    with pytest.raises(ValidationError) as error:
        Settings(database_url=url, _env_file=None)
    assert "secret" not in str(error.value)


def test_environment_overrides_dotenv_and_keeps_password_private(tmp_path, monkeypatch):
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "DATABASE_URL=postgresql+psycopg://u:file-secret@localhost/from_file\n"
        "NVD_API_KEY=unused\n"
    )
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://u:p%25ss%40word@localhost/from_env"
    )
    settings = Settings(_env_file=dotenv)
    assert settings.sqlalchemy_url.database == "from_env"
    assert settings.sqlalchemy_url.password == "p%ss@word"
    assert "p%ss@word" not in repr(settings)
    assert "p%25ss%40word" not in repr(settings)
