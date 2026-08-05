import tempfile
import unittest
from pathlib import Path

from database import Database, POSTGRES_SCHEMA, SQLITE_SCHEMA, postgres_placeholders


class DatabaseAdapterTests(unittest.TestCase):
    def test_sqlite_schema_and_transaction_adapter(self):
        with tempfile.TemporaryDirectory(prefix="sfm-database-") as temp_dir:
            database = Database(Path(temp_dir) / "test.db")
            self.assertEqual(database.dialect, "sqlite")
            with database.connect() as connection:
                database.initialize_schema(connection)
                self.assertIn("tenant_events", {
                    row["name"] for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                })
                tables = {
                    row["name"] for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                self.assertIn("auth_login_limits", tables)
                self.assertIn("password_reset_tokens", tables)
                self.assertIn("password_history", tables)
                user_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(users)").fetchall()
                }
                self.assertIn("password_change_required", user_columns)
                invitation_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(invitations)").fetchall()
                }
                self.assertTrue({
                    "delivery_status",
                    "delivery_attempts",
                    "last_sent_at",
                    "delivered_at",
                    "delivery_error",
                }.issubset(invitation_columns))
                connection.execute(
                    "INSERT INTO tenants (id,name,slug,status,created_at) VALUES (?,?,?,?,?)",
                    ("tenant-a", "Tenant A", "tenant-a", "active", 1),
                )
                user_id = database.insert_returning_id(
                    connection,
                    "INSERT INTO users (username,password_hash,role,created_at,tenant_id) VALUES (?,?,?,?,?)",
                    ("admin.a", "hash", "admin", 1, "tenant-a"),
                )
                self.assertGreater(user_id, 0)
                self.assertEqual(database.integrity_check(connection), "ok")
                self.assertIn("tenant_id", database.table_columns(connection, "users"))

            with database.connect() as connection:
                row = connection.execute(
                    "SELECT id,username FROM users WHERE tenant_id = ?", ("tenant-a",)
                ).fetchone()
                self.assertEqual(row[0], user_id)
                self.assertEqual(row["username"], "admin.a")

    def test_postgres_configuration_and_placeholder_translation(self):
        database = Database(
            Path("unused.db"),
            "postgresql://sfm:secret@postgres:5432/sfm_compliance",
        )
        self.assertEqual(database.dialect, "postgres")
        self.assertEqual(
            postgres_placeholders("SELECT '?' AS literal, id FROM users WHERE id = ? AND role = ?"),
            "SELECT '?' AS literal, id FROM users WHERE id = %s AND role = %s",
        )
        self.assertIn("BIGSERIAL PRIMARY KEY", POSTGRES_SCHEMA)
        self.assertNotIn("AUTOINCREMENT", POSTGRES_SCHEMA)
        self.assertIn("AUTOINCREMENT", SQLITE_SCHEMA)


if __name__ == "__main__":
    unittest.main(verbosity=2)
