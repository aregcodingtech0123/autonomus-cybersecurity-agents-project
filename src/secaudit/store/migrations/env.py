"""Alembic environment. Migrations are run programmatically by secaudit.store.db.upgrade_to_head()
with a connection that already holds the write lock; there is no alembic.ini and no offline mode.
`render_as_batch` keeps `alembic revision --autogenerate` output SQLite-safe (ALTER via batch)."""

from alembic import context
from sqlmodel import SQLModel

from secaudit.store import orm  # noqa: F401 - registers the tables on SQLModel.metadata

config = context.config
connection = config.attributes.get("connection")

if context.is_offline_mode() or connection is None:
    raise RuntimeError("run migrations through secaudit.store.db.upgrade_to_head()")

context.configure(
    connection=connection,
    target_metadata=SQLModel.metadata,
    render_as_batch=True,
)
with context.begin_transaction():
    context.run_migrations()
