#!/usr/bin/env python3
import argparse
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from database import Database


TABLES = [
    "tenants",
    "users",
    "sessions",
    "auth_login_limits",
    "password_reset_tokens",
    "password_history",
    "invitations",
    "oidc_login_states",
    "oidc_identities",
    "workspace_state",
    "files",
    "audit_log",
    "tenant_workspace_state",
    "workspace_state_snapshots",
    "operational_alerts",
    "notification_states",
    "notification_deliveries",
]
SERIAL_TABLES = ["users", "audit_log", "workspace_state_snapshots"]


def source_tables(connection):
    return {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }


def source_columns(connection, table):
    return [row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()]


def migrate(source_path, database_url):
    source_path = Path(source_path).resolve()
    if not source_path.is_file():
        raise RuntimeError(f"SQLite source not found: {source_path}")
    target = Database(source_path, database_url)
    if target.dialect != "postgres":
        raise RuntimeError("target DATABASE_URL must use postgresql://")

    result = {}
    with closing(sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)) as source:
        source.row_factory = sqlite3.Row
        available = source_tables(source)
        with target.connect() as destination:
            target.initialize_schema(destination)
            occupied = {
                table: destination.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in TABLES
                if table in available
            }
            non_empty = {table: count for table, count in occupied.items() if count}
            if non_empty:
                raise RuntimeError(f"PostgreSQL target is not empty: {non_empty}")

            for table in TABLES:
                if table not in available:
                    result[table] = 0
                    continue
                source_names = source_columns(source, table)
                target_names = target.table_columns(destination, table)
                columns = [name for name in source_names if name in target_names]
                if not columns:
                    result[table] = 0
                    continue
                quoted = ",".join(f'"{name}"' for name in columns)
                placeholders = ",".join("?" for _ in columns)
                rows = source.execute(f"SELECT {quoted} FROM {table}").fetchall()
                for row in rows:
                    destination.execute(
                        f"INSERT INTO {table} ({quoted}) VALUES ({placeholders})",
                        tuple(row[name] for name in columns),
                    )
                result[table] = len(rows)

            for table in SERIAL_TABLES:
                if result.get(table):
                    destination.execute(
                        f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), (SELECT MAX(id) FROM {table}), true)"
                    )

            for table, expected in result.items():
                actual = destination.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                if actual != expected:
                    raise RuntimeError(f"count mismatch for {table}: source={expected}, target={actual}")
    return result


def main():
    parser = argparse.ArgumentParser(description="Migrate an SFM Compliance SQLite database into an empty PostgreSQL database.")
    parser.add_argument("--source", required=True, help="Path to the source isms.db")
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL", ""), help="PostgreSQL URL; defaults to DATABASE_URL")
    parser.add_argument("--confirm", required=True, help="Must be MIGRATE_TO_POSTGRES")
    args = parser.parse_args()
    if args.confirm != "MIGRATE_TO_POSTGRES":
        raise SystemExit("Migration confirmation missing")
    counts = migrate(args.source, args.database_url)
    print("PostgreSQL migration completed and verified.")
    for table in TABLES:
        print(f"{table}: {counts.get(table, 0)}")


if __name__ == "__main__":
    main()
