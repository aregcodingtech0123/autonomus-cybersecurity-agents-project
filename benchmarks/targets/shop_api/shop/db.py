"""Database access: an ORM session for most routes, a plain connection for catalog reads."""

import os
import sqlite3
from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from shop.settings import DATABASE_URL

_engine = create_engine(DATABASE_URL)
_session_factory = sessionmaker(bind=_engine)


def get_session() -> Iterator[Session]:
    session = _session_factory()
    try:
        yield session
    finally:
        session.close()


def get_connection() -> sqlite3.Connection:
    return sqlite3.connect(os.environ.get("SHOP_CATALOG_DB", ":memory:"))
