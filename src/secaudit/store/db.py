"""SQLite engine, private file permissions, and programmatic Alembic migrations.

Concurrency: WAL journal + a busy timeout, and every write transaction starts with BEGIN
IMMEDIATE so two processes serialize on the write lock instead of failing half way (a deferred
BEGIN that later upgrades to a write lock can get SQLITE_BUSY at once, busy timeout or not).

Permissions: the DB holds derived data only (masked snippets, no raw output) but it is still an
index of where a codebase is weak, so it is created owner-only where the OS allows it:
  * POSIX: the file is created 0600 before SQLite touches it; SQLite gives the -wal/-shm files
    the same mode.
  * Windows: the file (and, for the default location, its directory, so the -wal/-shm files
    inherit the same ACL) is restricted to the current user with the Phase 2A icacls approach.
    Administrators and SYSTEM can still take ownership.
"""

from __future__ import annotations

import os
import random
import sqlite3
import time
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, create_engine, event

from secaudit.core.retention import restrict_to_owner

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
BUSY_TIMEOUT_MS = 30_000
DB_FILENAME = "secaudit.db"


def sqlite_url(path: Path) -> str:
    return "sqlite:///" + Path(path).resolve().as_posix()


def make_engine(path: Path) -> Engine:
    """An engine for `path` with WAL, busy timeout, foreign keys and explicit BEGIN control."""
    engine = create_engine(sqlite_url(path))

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection, _record):  # noqa: ANN001 - driver objects
        dbapi_connection.isolation_level = None  # SQLAlchemy decides when to BEGIN (see below)
        cursor = dbapi_connection.cursor()
        cursor.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    @event.listens_for(engine, "begin")
    def _on_begin(connection):  # noqa: ANN001
        write = connection.get_execution_options().get("write", False)
        connection.exec_driver_sql("BEGIN IMMEDIATE" if write else "BEGIN")

    return engine


def enable_wal(path: Path, attempts: int = 400) -> None:
    """Switch the file to WAL once (the mode is stored in the file and persists).

    Changing the journal mode needs an exclusive moment and, unlike ordinary statements, does not
    wait on the busy handler: two processes creating the database at once got "database is locked".
    So it is retried here, briefly and with jitter, instead of being repeated on every connection.
    """
    last: Exception | None = None
    for _ in range(attempts):
        try:
            connection = sqlite3.connect(path, timeout=BUSY_TIMEOUT_MS / 1000)
            try:
                if (
                    str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
                    == "wal"
                ):
                    return
            finally:
                connection.close()
        except sqlite3.OperationalError as exc:
            last = exc
        time.sleep(0.02 + random.random() * 0.05)  # noqa: S311 - jitter, not security
    raise sqlite3.OperationalError(f"could not switch the database to WAL: {last}")


def write_engine(engine: Engine) -> Engine:
    """The same pool, but every transaction takes the write lock up front."""
    return engine.execution_options(write=True)


def create_private_file(path: Path) -> None:
    """Create an empty file that only the owner can use (POSIX 0600). SQLite accepts empty files."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        flags = os.O_CREAT | os.O_WRONLY | getattr(os, "O_BINARY", 0)
        os.close(os.open(path, flags, 0o600))


def secure_database(path: Path, *, restrict_parent: bool = False) -> bool:
    """Owner-only access to the DB file and its WAL sidecars; True if all of it applied."""
    path = Path(path)
    ok = True
    for candidate in (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
        if candidate.exists():
            ok = restrict_to_owner(candidate) and ok
    if restrict_parent and os.name == "nt":
        ok = restrict_to_owner(path.parent) and ok
    return ok


def alembic_config(connection=None) -> Config:  # noqa: ANN001
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.attributes["connection"] = connection
    return config


def head_revision() -> str:
    return ScriptDirectory.from_config(alembic_config()).get_current_head() or ""


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def upgrade_to_head(engine: Engine) -> bool:
    """Bring the schema to the newest revision. True if anything changed; re-running is a no-op.

    The check-and-upgrade happens inside one write transaction, so two processes starting together
    do not both try to create the tables.
    """
    if current_revision(engine) == head_revision():
        return False
    with write_engine(engine).begin() as connection:
        before = MigrationContext.configure(connection).get_current_revision()
        if before == head_revision():
            return False
        command.upgrade(alembic_config(connection), "head")
    return True


def downgrade_to_base(engine: Engine) -> None:
    """Development helper (and the round-trip test): drops everything this package created."""
    with write_engine(engine).begin() as connection:
        command.downgrade(alembic_config(connection), "base")


def open_database(path: Path, *, restrict_parent: bool = False) -> Engine:
    """Create (private) if needed, migrate to head, secure, and return the engine."""
    path = Path(path)
    create_private_file(path)
    enable_wal(path)
    engine = make_engine(path)
    upgrade_to_head(engine)
    secure_database(path, restrict_parent=restrict_parent)
    return engine
