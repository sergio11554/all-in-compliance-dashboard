import os
import re
import shutil
import sqlite3
import subprocess
import urllib.parse
from contextlib import closing
from pathlib import Path


AUTO_ID_TABLES = {"users", "audit_log", "workspace_state_snapshots", "tenant_events"}


def _schema(auto_id):
    return f"""
    CREATE TABLE IF NOT EXISTS tenants (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      created_at BIGINT NOT NULL,
      updated_at BIGINT,
      retention_until BIGINT,
      legal_hold INTEGER NOT NULL DEFAULT 0,
      lifecycle_note TEXT,
      archived_at BIGINT
    );
    CREATE TABLE IF NOT EXISTS users (
      id {auto_id},
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      mfa_secret TEXT,
      mfa_enabled INTEGER NOT NULL DEFAULT 0,
      updated_at BIGINT,
      last_login_at BIGINT,
      email TEXT,
      tenant_id TEXT NOT NULL DEFAULT 'default',
      platform_admin INTEGER NOT NULL DEFAULT 0,
      password_change_required INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY(tenant_id) REFERENCES tenants(id)
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id BIGINT NOT NULL,
      tenant_id TEXT,
      csrf_token TEXT NOT NULL,
      expires_at BIGINT NOT NULL,
      created_at BIGINT NOT NULL,
      ip TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS auth_login_limits (
      scope_key TEXT PRIMARY KEY,
      scope TEXT NOT NULL,
      attempt_count INTEGER NOT NULL DEFAULT 0,
      window_started_at BIGINT NOT NULL,
      blocked_until BIGINT,
      updated_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id TEXT PRIMARY KEY,
      token_hash TEXT UNIQUE NOT NULL,
      user_id BIGINT NOT NULL,
      requested_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      used_at BIGINT,
      requested_ip_hash TEXT,
      delivered_at BIGINT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS password_history (
      id TEXT PRIMARY KEY,
      user_id BIGINT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      changed_by BIGINT,
      reason TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(changed_by) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS invitations (
      id TEXT PRIMARY KEY,
      token_hash TEXT UNIQUE NOT NULL,
      email TEXT NOT NULL,
      display_name TEXT,
      role TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      invited_by BIGINT,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      accepted_at BIGINT,
      accepted_user_id BIGINT,
      revoked_at BIGINT,
      delivery_status TEXT NOT NULL DEFAULT 'manual',
      delivery_attempts INTEGER NOT NULL DEFAULT 0,
      last_sent_at BIGINT,
      delivered_at BIGINT,
      delivery_error TEXT,
      FOREIGN KEY(tenant_id) REFERENCES tenants(id),
      FOREIGN KEY(invited_by) REFERENCES users(id),
      FOREIGN KEY(accepted_user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS oidc_login_states (
      state_hash TEXT PRIMARY KEY,
      provider_id TEXT NOT NULL,
      code_verifier TEXT NOT NULL,
      nonce TEXT NOT NULL,
      redirect_after TEXT,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      ip TEXT
    );
    CREATE TABLE IF NOT EXISTS oidc_identities (
      provider_id TEXT NOT NULL,
      subject TEXT NOT NULL,
      user_id BIGINT NOT NULL,
      email TEXT,
      created_at BIGINT NOT NULL,
      last_login_at BIGINT,
      PRIMARY KEY(provider_id, subject),
      UNIQUE(provider_id, user_id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS workspace_state (
      id INTEGER PRIMARY KEY CHECK(id = 1),
      state_json TEXT NOT NULL,
      updated_at BIGINT NOT NULL,
      updated_by BIGINT,
      tenant_id TEXT
    );
    CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY,
      tenant_id TEXT,
      original_name TEXT NOT NULL,
      stored_name TEXT NOT NULL,
      content_type TEXT NOT NULL,
      size BIGINT NOT NULL,
      sha256 TEXT NOT NULL,
      nonce TEXT NOT NULL,
      uploaded_by BIGINT,
      uploaded_at BIGINT NOT NULL,
      document_id TEXT,
      version_label TEXT,
      previous_file_id TEXT,
      linked_to TEXT,
      classification TEXT,
      scan_status TEXT NOT NULL DEFAULT 'unscanned',
      scan_engine TEXT,
      scan_signature TEXT,
      scan_detail TEXT,
      scanned_at BIGINT,
      quarantined INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id {auto_id},
      ts BIGINT NOT NULL,
      tenant_id TEXT,
      user_id BIGINT,
      username TEXT,
      action TEXT NOT NULL,
      target_type TEXT,
      target_id TEXT,
      detail_json TEXT,
      ip TEXT,
      previous_hash TEXT,
      event_hash TEXT
    );
    CREATE TABLE IF NOT EXISTS tenant_workspace_state (
      tenant_id TEXT PRIMARY KEY,
      state_json TEXT NOT NULL,
      updated_at BIGINT NOT NULL,
      updated_by BIGINT,
      revision INTEGER NOT NULL DEFAULT 1,
      FOREIGN KEY(tenant_id) REFERENCES tenants(id)
    );
    CREATE TABLE IF NOT EXISTS workspace_record_ownership (
      tenant_id TEXT NOT NULL,
      section TEXT NOT NULL,
      record_key TEXT NOT NULL,
      owner_user_id BIGINT NOT NULL,
      owner_username TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL,
      PRIMARY KEY(tenant_id, section, record_key),
      FOREIGN KEY(tenant_id) REFERENCES tenants(id),
      FOREIGN KEY(owner_user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS intune_connections (
      tenant_id TEXT PRIMARY KEY,
      config_key TEXT,
      enabled INTEGER NOT NULL DEFAULT 0,
      approved_by BIGINT,
      last_attempt_at BIGINT,
      last_success_at BIGINT,
      last_error TEXT,
      next_run_at BIGINT,
      preview_id TEXT,
      preview_nonce TEXT,
      preview_data TEXT,
      preview_revision INTEGER,
      preview_expires BIGINT,
      FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS intune_credentials (
      tenant_id TEXT PRIMARY KEY,
      nonce TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      verified_at BIGINT,
      FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS tenant_events (
      id {auto_id},
      tenant_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id TEXT,
      actor_user_id BIGINT,
      actor_username TEXT,
      created_at BIGINT NOT NULL,
      workspace_revision INTEGER,
      FOREIGN KEY(tenant_id) REFERENCES tenants(id),
      FOREIGN KEY(actor_user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS workspace_state_snapshots (
      id {auto_id},
      tenant_id TEXT NOT NULL,
      state_json TEXT NOT NULL,
      saved_at BIGINT NOT NULL,
      saved_by BIGINT,
      reason TEXT NOT NULL,
      bytes BIGINT NOT NULL,
      sha256 TEXT NOT NULL,
      FOREIGN KEY(tenant_id) REFERENCES tenants(id)
    );
    CREATE TABLE IF NOT EXISTS operational_alerts (
      alert_key TEXT PRIMARY KEY,
      severity TEXT NOT NULL,
      source TEXT NOT NULL,
      scope TEXT NOT NULL,
      title TEXT NOT NULL,
      detail TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      action_view TEXT,
      remediation_action TEXT,
      remediation_label TEXT,
      first_seen_at BIGINT NOT NULL,
      last_seen_at BIGINT NOT NULL,
      acknowledged_at BIGINT,
      acknowledged_by BIGINT,
      resolved_at BIGINT
    );
    CREATE TABLE IF NOT EXISTS notification_states (
      tenant_id TEXT NOT NULL,
      user_id BIGINT NOT NULL,
      notification_id TEXT NOT NULL,
      read_at BIGINT,
      dismissed_at BIGINT,
      escalated_at BIGINT,
      updated_at BIGINT NOT NULL,
      PRIMARY KEY(tenant_id,user_id,notification_id),
      FOREIGN KEY(tenant_id) REFERENCES tenants(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS notification_deliveries (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      notification_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      destination_label TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'queued',
      attempt_count INTEGER NOT NULL DEFAULT 0,
      next_attempt_at BIGINT,
      created_at BIGINT NOT NULL,
      created_by BIGINT,
      last_attempt_at BIGINT,
      sent_at BIGINT,
      last_error TEXT,
      response_code INTEGER,
      FOREIGN KEY(tenant_id) REFERENCES tenants(id),
      FOREIGN KEY(created_by) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS background_jobs (
      id TEXT PRIMARY KEY,
      tenant_id TEXT,
      job_type TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'queued',
      priority INTEGER NOT NULL DEFAULT 50,
      payload_json TEXT NOT NULL DEFAULT '{{}}',
      result_json TEXT,
      attempts INTEGER NOT NULL DEFAULT 0,
      max_attempts INTEGER NOT NULL DEFAULT 3,
      next_run_at BIGINT,
      locked_at BIGINT,
      locked_by TEXT,
      created_at BIGINT NOT NULL,
      created_by BIGINT,
      updated_at BIGINT,
      finished_at BIGINT,
      last_error TEXT,
      FOREIGN KEY(tenant_id) REFERENCES tenants(id),
      FOREIGN KEY(created_by) REFERENCES users(id)
    );
    CREATE INDEX IF NOT EXISTS idx_workspace_state_snapshots_tenant ON workspace_state_snapshots(tenant_id, id DESC);
    CREATE INDEX IF NOT EXISTS idx_invitations_tenant ON invitations(tenant_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_invitations_status ON invitations(status, expires_at);
    CREATE INDEX IF NOT EXISTS idx_oidc_states_expiry ON oidc_login_states(expires_at);
    CREATE INDEX IF NOT EXISTS idx_oidc_identities_user ON oidc_identities(user_id);
    CREATE INDEX IF NOT EXISTS idx_operational_alerts_status ON operational_alerts(status, severity, last_seen_at DESC);
    CREATE INDEX IF NOT EXISTS idx_notification_states_user ON notification_states(tenant_id, user_id, updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_notification_deliveries_queue ON notification_deliveries(status, next_attempt_at, created_at);
    CREATE INDEX IF NOT EXISTS idx_notification_deliveries_tenant ON notification_deliveries(tenant_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_background_jobs_queue ON background_jobs(status, next_run_at, priority, created_at);
    CREATE INDEX IF NOT EXISTS idx_background_jobs_tenant ON background_jobs(tenant_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_files_tenant_uploaded ON files(tenant_id, uploaded_at DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON audit_log(tenant_id, ts DESC);
    CREATE INDEX IF NOT EXISTS idx_tenant_events_stream ON tenant_events(tenant_id, id);
    CREATE INDEX IF NOT EXISTS idx_tenant_events_created ON tenant_events(created_at);
    CREATE INDEX IF NOT EXISTS idx_workspace_record_owner ON workspace_record_ownership(tenant_id, owner_user_id, section);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
    CREATE INDEX IF NOT EXISTS idx_auth_login_limits_expiry ON auth_login_limits(blocked_until, updated_at);
    CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user ON password_reset_tokens(user_id, requested_at DESC);
    CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expiry ON password_reset_tokens(expires_at, used_at);
    CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id, created_at DESC);
    """


SQLITE_SCHEMA = _schema("INTEGER PRIMARY KEY AUTOINCREMENT")
POSTGRES_SCHEMA = _schema("BIGSERIAL PRIMARY KEY")


class CompatRow:
    def __init__(self, columns, values):
        self._columns = tuple(columns)
        self._values = tuple(values)
        self._index = {name: index for index, name in enumerate(self._columns)}

    def __getitem__(self, key):
        if isinstance(key, (int, slice)):
            return self._values[key]
        return self._values[self._index[key]]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def keys(self):
        return self._columns

    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, IndexError):
            return default


def postgres_placeholders(sql):
    output = []
    quote = None
    index = 0
    while index < len(sql):
        char = sql[index]
        if quote:
            output.append(char)
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    output.append(sql[index + 1])
                    index += 1
                else:
                    quote = None
            elif char == "\\" and index + 1 < len(sql):
                output.append(sql[index + 1])
                index += 1
        elif char in {"'", '"'}:
            quote = char
            output.append(char)
        elif char == "?":
            output.append("%s")
        else:
            output.append(char)
        index += 1
    return "".join(output)


def split_sql_script(script):
    return [statement.strip() for statement in script.split(";") if statement.strip()]


class CursorAdapter:
    def __init__(self, cursor, dialect):
        self._cursor = cursor
        self.dialect = dialect
        self.lastrowid = getattr(cursor, "lastrowid", None)

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def _columns(self):
        return [getattr(column, "name", None) or column[0] for column in (self._cursor.description or [])]

    def _row(self, values):
        if values is None or self.dialect == "sqlite":
            return values
        return CompatRow(self._columns(), values)

    def fetchone(self):
        return self._row(self._cursor.fetchone())

    def fetchall(self):
        rows = self._cursor.fetchall()
        if self.dialect == "sqlite":
            return rows
        columns = self._columns()
        return [CompatRow(columns, row) for row in rows]


class ConnectionAdapter:
    def __init__(self, connection, dialect):
        self._connection = connection
        self.dialect = dialect

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        try:
            if exc_type is None:
                self._connection.commit()
            else:
                self._connection.rollback()
        finally:
            self._connection.close()
        return False

    def execute(self, sql, params=()):
        statement = postgres_placeholders(sql) if self.dialect == "postgres" else sql
        cursor = self._connection.cursor()
        cursor.execute(statement, tuple(params or ()))
        return CursorAdapter(cursor, self.dialect)

    def executescript(self, script):
        if self.dialect == "sqlite":
            self._connection.executescript(script)
            return
        for statement in split_sql_script(script):
            self.execute(statement)


class Database:
    def __init__(self, sqlite_path, database_url=None):
        self.sqlite_path = Path(sqlite_path)
        self.database_url = str(database_url or "").strip()
        self.dialect = "postgres" if self.database_url.startswith(("postgres://", "postgresql://")) else "sqlite"
        self._psycopg = None
        self.integrity_errors = (sqlite3.IntegrityError,)

    @classmethod
    def from_env(cls, sqlite_path):
        return cls(sqlite_path, os.environ.get("DATABASE_URL"))

    def _postgres_driver(self):
        if self._psycopg is None:
            try:
                import psycopg
            except ImportError as exc:
                raise RuntimeError(
                    "DATABASE_URL requires psycopg. Install project requirements before starting PostgreSQL mode."
                ) from exc
            self._psycopg = psycopg
            self.integrity_errors = (sqlite3.IntegrityError, psycopg.IntegrityError)
        return self._psycopg

    def connect(self):
        if self.dialect == "sqlite":
            connection = sqlite3.connect(self.sqlite_path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            return ConnectionAdapter(connection, "sqlite")
        psycopg = self._postgres_driver()
        return ConnectionAdapter(psycopg.connect(self.database_url), "postgres")

    def initialize_schema(self, connection):
        connection.executescript(POSTGRES_SCHEMA if self.dialect == "postgres" else SQLITE_SCHEMA)

    def table_columns(self, connection, table):
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", table):
            raise ValueError("invalid table identifier")
        if self.dialect == "sqlite":
            return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
        rows = connection.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = ?",
            (table,),
        ).fetchall()
        return {row["column_name"] for row in rows}

    def integrity_check(self, connection):
        if self.dialect == "sqlite":
            return connection.execute("PRAGMA quick_check").fetchone()[0]
        connection.execute("SELECT 1").fetchone()
        return "ok"

    def storage_ready(self):
        if self.dialect == "postgres":
            return True
        return self.sqlite_path.exists() and os.access(self.sqlite_path, os.R_OK | os.W_OK)

    def insert_returning_id(self, connection, sql, params):
        if self.dialect == "postgres":
            row = connection.execute(f"{sql.rstrip()} RETURNING id", params).fetchone()
            return row["id"]
        return connection.execute(sql, params).lastrowid

    def begin_workspace_write(self, connection):
        if self.dialect == "sqlite":
            connection.execute("BEGIN IMMEDIATE")
            return
        connection.execute("LOCK TABLE tenant_workspace_state IN SHARE ROW EXCLUSIVE MODE")

    def backup_to(self, directory):
        directory = Path(directory)
        if self.dialect == "sqlite":
            target = directory / "isms.db"
            with closing(sqlite3.connect(self.sqlite_path)) as source, closing(sqlite3.connect(target)) as destination:
                source.backup(destination)
            return target

        executable = shutil.which("pg_dump")
        if not executable:
            raise RuntimeError("PostgreSQL backup requires pg_dump on the application host")
        parsed = urllib.parse.urlparse(self.database_url)
        target = directory / "database.sql"
        command = [
            executable,
            "--no-owner",
            "--no-privileges",
            "--file",
            str(target),
            "--host",
            parsed.hostname or "localhost",
            "--port",
            str(parsed.port or 5432),
            "--username",
            urllib.parse.unquote(parsed.username or ""),
            urllib.parse.unquote((parsed.path or "/").lstrip("/")),
        ]
        environment = os.environ.copy()
        if parsed.password:
            environment["PGPASSWORD"] = urllib.parse.unquote(parsed.password)
        subprocess.run(command, env=environment, check=True, capture_output=True, timeout=300)
        return target
