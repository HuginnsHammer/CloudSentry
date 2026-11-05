"""Explicit database configuration for the enterprise platform layer."""
from __future__ import annotations

import os

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker


def build_engine(database_url: str | None = None, *, allow_sqlite: bool = False) -> Engine:
    """Create an engine without silently selecting a database or creating tables.

    Production deployments must use PostgreSQL via psycopg. SQLite is available
    only when a caller explicitly opts in for isolated tests and local tooling.
    """
    value = database_url or os.getenv("CLOUDSENTRY_DATABASE_URL")
    if not value:
        raise RuntimeError("CLOUDSENTRY_DATABASE_URL must be configured")

    url = make_url(value)
    if url.drivername == "postgresql":
        url = url.set(drivername="postgresql+psycopg")
    if url.drivername in {"sqlite", "sqlite+pysqlite"} and allow_sqlite:
        pass
    elif url.drivername != "postgresql+psycopg":
        raise ValueError(
            "CloudSentry platform storage requires PostgreSQL; SQLite is only "
            "available with allow_sqlite=True for tests"
        )

    engine = create_engine(url, pool_pre_ping=True)
    if url.drivername in {"sqlite", "sqlite+pysqlite"}:
        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    return engine


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return sessions with explicit transaction ownership."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
