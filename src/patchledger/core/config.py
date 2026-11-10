"""Environment configuration without import-time connections or secret logging."""

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError


def parse_database_url(value: str | URL) -> URL:
    """Require the project's synchronous PostgreSQL/psycopg driver."""
    try:
        url = make_url(value)
    except (ArgumentError, ValueError):
        raise ValueError("DATABASE_URL must be a valid SQLAlchemy URL") from None
    if url.drivername != "postgresql+psycopg" or not url.database:
        raise ValueError("DATABASE_URL must use postgresql+psycopg and name a database")
    return url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        hide_input_in_errors=True,
    )

    database_url: SecretStr

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: SecretStr) -> SecretStr:
        parse_database_url(value.get_secret_value())
        return value

    @property
    def sqlalchemy_url(self) -> URL:
        return parse_database_url(self.database_url.get_secret_value())
