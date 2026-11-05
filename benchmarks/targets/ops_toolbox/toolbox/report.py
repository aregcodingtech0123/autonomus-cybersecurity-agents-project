"""Report generation."""

import ast
import hashlib
import sqlite3

MAX_OPTIONS_LENGTH = 4096


def parse_options(raw: str) -> dict:
    if len(raw) > MAX_OPTIONS_LENGTH:
        raise ValueError("options too long")
    options = ast.literal_eval(raw)
    if not isinstance(options, dict):
        raise ValueError("options must be a mapping")
    return options


def shard_for(customer_id: str, shards: int = 16) -> int:
    # Load balancing only: reports are spread over shards. A collision just puts two customers on the
    # same shard, and the shard grants nothing, so a broken hash has no security consequence here.
    digest = hashlib.sha1(customer_id.encode()).digest()
    return digest[0] % shards


_REPORT_TABLES = {"daily": "report_daily", "weekly": "report_weekly"}


def load_rows(connection: sqlite3.Connection, kind: str) -> list:
    table = _REPORT_TABLES[kind]  # any other value raises KeyError before a query exists
    return connection.execute(f"SELECT name, total FROM {table}").fetchall()


def render_report(kind: str, database: str, raw_options: str) -> str:
    options = parse_options(raw_options)
    connection = sqlite3.connect(database)
    rows = load_rows(connection, kind)
    connection.close()
    limit = int(options.get("limit", len(rows)))
    return "\n".join(f"{name}: {total}" for name, total in rows[:limit])
