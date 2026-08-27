"""Schema installation and transaction boundary."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager, suppress
from pathlib import Path

BUSY_TIMEOUT_MS = 5_000


def configure_connection(
    connection: sqlite3.Connection,
    *,
    enable_wal: bool = True,
) -> sqlite3.Connection:
    """Apply the repository-wide SQLite safety and concurrency settings."""
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    if enable_wal:
        with suppress(sqlite3.OperationalError):
            connection.execute("PRAGMA journal_mode = WAL")
    return connection


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = str(path)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=BUSY_TIMEOUT_MS / 1_000)
        return configure_connection(connection)

    def initialize(self) -> None:
        schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        with closing(self.connect()) as connection:
            connection.executescript(schema)
            connection.execute(
                """CREATE TABLE IF NOT EXISTS schema_migrations (
                       version INTEGER PRIMARY KEY,
                       name TEXT NOT NULL,
                       applied_at TEXT NOT NULL
                   )"""
            )
            migrations = Path(__file__).with_name("migrations")
            for path in sorted(migrations.glob("*.sql")):
                version_text, _, name = path.stem.partition("_")
                version = int(version_text)
                applied = connection.execute(
                    "SELECT 1 FROM schema_migrations WHERE version=?",
                    (version,),
                ).fetchone()
                if applied is not None:
                    continue
                escaped_name = name.replace("'", "''")
                migration = path.read_text(encoding="utf-8")
                connection.executescript(
                    "BEGIN IMMEDIATE;\n"
                    f"{migration}\n"
                    "INSERT INTO schema_migrations(version,name,applied_at) "
                    f"VALUES ({version},'{escaped_name}',strftime('%Y-%m-%dT%H:%M:%fZ','now'));\n"
                    f"PRAGMA user_version = {version};\n"
                    "COMMIT;\n"
                )
            connection.commit()

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
