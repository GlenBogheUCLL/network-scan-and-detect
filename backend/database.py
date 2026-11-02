import os
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def create_database(database_url=None):
    url = database_url or os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://scanner:scanner@localhost:5432/network_scan",
    )
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine_args = {"connect_args": connect_args}
    if url == "sqlite+pysqlite:///:memory:":
        engine_args["poolclass"] = StaticPool
    engine = create_engine(url, **engine_args)
    return engine, sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_session_factory(database_url=None):
    return create_database(database_url)[1]


def session_dependency(session_factory) -> Generator[Session, None, None]:
    with session_factory() as session:
        yield session
