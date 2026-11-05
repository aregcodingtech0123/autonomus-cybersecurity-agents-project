"""Database connections and the account lookup used by login."""

import os

import psycopg2

from portal.config import DATABASE_HOST


def connect(login: str | None = None):
    return psycopg2.connect(
        host=DATABASE_HOST,
        dbname="portal",
        user="portal_app",
        password=login or os.environ["PORTAL_DB_PASSWORD"],
    )


def load_account(email: str) -> tuple | None:
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT email, password_hash, tenant FROM portal_users WHERE email = %s", (email,)
        )
        return cursor.fetchone()


def update_password(email: str, password_hash: str) -> None:
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "UPDATE portal_users SET password_hash = %s WHERE email = %s", (password_hash, email)
        )
