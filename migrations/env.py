"""Alembic environment for CloudSentry platform schema migrations."""
from logging.config import fileConfig
import os

from alembic import context
from sqlalchemy import engine_from_config, pool

from scanner.platform.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def database_url() -> str:
    value = os.getenv("CLOUDSENTRY_DATABASE_URL")
    if not value:
        raise RuntimeError("CLOUDSENTRY_DATABASE_URL must be set before running migrations")
    if value.startswith("postgresql://"):
        value = value.replace("postgresql://", "postgresql+psycopg://", 1)
    if not value.startswith("postgresql+psycopg://"):
        raise RuntimeError("Alembic migrations require PostgreSQL via psycopg")
    return value


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(), target_metadata=target_metadata,
        literal_binds=True, dialect_opts={"paramstyle": "named"}, compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = database_url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
