#!/usr/bin/env python3
import base64
import hashlib
import hmac
import io
import json
import mimetypes
import os
import re
import secrets
import shutil
import smtplib
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from email.message import EmailMessage
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from database import Database
from intune_connector import IntuneError, setup_transport_allowed
from intune_sync import IntuneSync
from malware_scan import scanner_from_env
from oidc_auth import OIDCError, authorization_url, exchange_code, load_providers, new_login_values, public_provider
from storage import StorageError, storage_from_env

def env_int(name, default, minimum=None, maximum=None):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


APP_DIR = Path(__file__).resolve().parent
STATIC_BASE = Path(os.environ.get("ISMS_STATIC_BASE", APP_DIR)).resolve()
DATA = Path(os.environ.get("ISMS_DATA_DIR", APP_DIR / "data")).resolve()
UPLOADS = DATA / "uploads"
BACKUPS = DATA / "backups"
JOB_ARTIFACTS = DATA / "job-artifacts"
DB = DATA / "isms.db"
DEV_PASS = DATA / "dev_admin_password.txt"
FILE_KEY = DATA / "file_key.bin"
DATABASE = Database.from_env(DB)
FILE_STORAGE = storage_from_env(UPLOADS)
OIDC_PROVIDERS = load_providers()
MALWARE_SCANNER = scanner_from_env()
COOKIE = "isms_session"
DEFAULT_TENANT_ID = "default"
APP_NAME = "SFM Compliance"
DEFAULT_TENANT_NAME = "SFM Compliance Internal"
SESSION_SECONDS = env_int("ISMS_SESSION_SECONDS", 60 * 60 * 8, 15 * 60, 24 * 60 * 60)
MAX_JSON = env_int("ISMS_MAX_JSON_BYTES", 8 * 1024 * 1024, 256 * 1024, 32 * 1024 * 1024)
MAX_UPLOAD = env_int("ISMS_MAX_UPLOAD_BYTES", 40 * 1024 * 1024, 1 * 1024 * 1024, 200 * 1024 * 1024)
MAX_TENANT_EXPORT = env_int("ISMS_MAX_TENANT_EXPORT_BYTES", 256 * 1024 * 1024, 8 * 1024 * 1024, 1024 * 1024 * 1024)
ITERATIONS = 260_000
READ_ROLES = {"admin", "consultant", "manager", "contributor", "customer", "auditor", "viewer"}
WRITE_ROLES = {"admin", "consultant", "manager"}
ROLE_ORDER = ["admin", "consultant", "manager", "customer", "contributor", "auditor", "viewer"]
TENANT_INVITE_ROLES = {"manager", "customer", "contributor", "auditor", "viewer"}
ROLE_PERMISSIONS = {
    "admin": {
        "readWorkspace",
        "saveWorkspace",
        "restoreWorkspace",
        "uploadFile",
        "versionFile",
        "downloadFile",
        "reviewDocument",
        "admin",
    },
    "consultant": {
        "readWorkspace",
        "saveWorkspace",
        "restoreWorkspace",
        "uploadFile",
        "versionFile",
        "downloadFile",
        "reviewDocument",
    },
    "manager": {
        "readWorkspace",
        "saveWorkspace",
        "restoreWorkspace",
        "uploadFile",
        "versionFile",
        "downloadFile",
        "reviewDocument",
    },
    "contributor": {
        "readWorkspace",
        "submitWorkspace",
        "uploadFile",
        "versionFile",
        "downloadFile",
    },
    "customer": {
        "readWorkspace",
        "submitWorkspace",
        "uploadFile",
        "versionFile",
        "downloadFile",
    },
    "auditor": {
        "readWorkspace",
        "downloadFile",
    },
    "viewer": {
        "readWorkspace",
        "downloadFile",
    },
}
ROLE_DETAILS = {
    "admin": {
        "label": "Admin",
        "purpose": "Benutzer, Rollen, Workspace, Reviews, Uploads und Mandantenbetrieb steuern.",
        "recommendedFor": "Interne Plattformverantwortliche",
    },
    "consultant": {
        "label": "Berater",
        "purpose": "Kundenprojekt fachlich aufbauen, Nachweise prüfen und Dokumente freigeben.",
        "recommendedFor": "ISMS-/NIS-2-Berater",
    },
    "manager": {
        "label": "Management",
        "purpose": "Workspace bearbeiten, Entscheidungen dokumentieren und Reviews freigeben.",
        "recommendedFor": "Geschäftsleitung, ISB, Projektleitung",
    },
    "customer": {
        "label": "Kunde",
        "purpose": "Nachweise hochladen, neue Versionen einreichen und eigenen Projektstand sehen.",
        "recommendedFor": "Kundenansprechpartner",
    },
    "contributor": {
        "label": "Mitwirkender",
        "purpose": "Eigene oder zugewiesene Fachbeiträge und Nachweise bearbeiten, ohne Freigaben oder Adminrechte.",
        "recommendedFor": "IT, HR, Einkauf, Datenschutz, Fachbereiche",
    },
    "auditor": {
        "label": "Auditor",
        "purpose": "Workspace und Nachweise lesen sowie Dateien herunterladen, ohne Änderungen.",
        "recommendedFor": "Interne oder externe Prüfer",
    },
    "viewer": {
        "label": "Nur Lesen",
        "purpose": "Informationen und freigegebene Nachweise einsehen, ohne Upload oder Änderung.",
        "recommendedFor": "Stakeholder mit Informationsbedarf",
    },
}
PLATFORM_ADMIN_PERMISSIONS = {"platformAdmin", "manageTenants", "manageBackups", "runRetention"}
MUTATING_PERMISSIONS = {
    "saveWorkspace",
    "submitWorkspace",
    "restoreWorkspace",
    "uploadFile",
    "versionFile",
    "reviewDocument",
    "admin",
    "platformAdmin",
    "manageTenants",
    "manageBackups",
    "runRetention",
}
MFA_ENFORCEMENT = str(os.environ.get("ISMS_MFA_ENFORCEMENT", "off")).strip().lower()
if MFA_ENFORCEMENT not in {"off", "write"}:
    MFA_ENFORCEMENT = "off"
MFA_REQUIRED_ROLES = frozenset(
    role
    for role in (
        item.strip().lower()
        for item in str(os.environ.get("ISMS_MFA_REQUIRED_ROLES", "admin,consultant,manager")).split(",")
    )
    if role in READ_ROLES
)
LOGIN_ACCOUNT_MAX_ATTEMPTS = env_int("ISMS_LOGIN_ACCOUNT_MAX_ATTEMPTS", 8, 3, 50)
LOGIN_IP_MAX_ATTEMPTS = env_int("ISMS_LOGIN_IP_MAX_ATTEMPTS", 30, 5, 500)
LOGIN_ATTEMPT_WINDOW_SECONDS = env_int("ISMS_LOGIN_ATTEMPT_WINDOW_SECONDS", 15 * 60, 60, 24 * 60 * 60)
LOGIN_LOCK_SECONDS = env_int("ISMS_LOGIN_LOCK_SECONDS", 15 * 60, 60, 24 * 60 * 60)
ACCOUNT_RECOVERY_ENABLED = str(os.environ.get("ISMS_ACCOUNT_RECOVERY_ENABLED", "0")).strip().lower() in {"1", "true", "yes", "on"}
ACCOUNT_RECOVERY_TOKEN_SECONDS = env_int("ISMS_ACCOUNT_RECOVERY_TOKEN_SECONDS", 60 * 60, 10 * 60, 24 * 60 * 60)
INVITATION_EMAIL_ENABLED = str(os.environ.get("ISMS_INVITATION_EMAIL_ENABLED", "0")).strip().lower() in {"1", "true", "yes", "on"}
PASSWORD_MIN_LENGTH = env_int("ISMS_PASSWORD_MIN_LENGTH", 12, 12, 64)
PASSWORD_MAX_LENGTH = env_int("ISMS_PASSWORD_MAX_LENGTH", 256, 64, 1024)
PASSWORD_HISTORY_COUNT = env_int("ISMS_PASSWORD_HISTORY_COUNT", 5, 1, 24)
STATIC_EXT = {".html", ".css", ".js", ".json", ".md", ".pdf", ".docx", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2"}
UPLOAD_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt", ".md", ".json", ".png", ".jpg", ".jpeg"}
LOGIN_ATTEMPTS = {}
LEGACY_WORKSPACE_REQUIRED_ARRAYS = {"documents", "soa", "gaps", "tasks"}
SFM_WORKSPACE_REQUIRED_ARRAYS = {
    "documents",
    "assets",
    "risks",
    "legal",
    "suppliers",
    "policies",
    "incidents",
    "contracts",
    "integrations",
    "tasks",
    "projectPlan",
    "templateDrafts",
}
CUSTOMER_SUBMISSION_SECTIONS = {
    "setup",
    "documents",
    "assets",
    "risks",
    "legal",
    "suppliers",
    "policies",
    "incidents",
    "contracts",
    "tasks",
    "projectPlan",
    "templateDrafts",
    "socReports",
    "onboarding",
    "soa",
    "gaps",
    "auditFindings",
    "managementReview",
    "internalAuditPlan",
    "evidence",
}
CONTRIBUTOR_SUBMISSION_SECTIONS = CUSTOMER_SUBMISSION_SECTIONS - {"setup", "onboarding", "managementReview", "internalAuditPlan"}
CUSTOMER_IMMUTABLE_REVIEW_FIELDS = {
    "approved",
    "approvedat",
    "approvedby",
    "auditrelevance",
    "auditrelevant",
    "beraterkommentarintern",
    "consultantdecision",
    "consultantinternalcomment",
    "effectivenessassessment",
    "effectivenessverifiedat",
    "effectivenessverifiedby",
    "internalcomment",
    "internalconsultantcomment",
    "rejectedat",
    "rejectedby",
    "reviewassignee",
    "reviewed",
    "reviewedat",
    "reviewedby",
    "reviewer",
    "reviewowner",
}
CONTRIBUTOR_IMMUTABLE_ASSIGNMENT_FIELDS = {
    "assignedtouserid",
    "assignedusername",
    "assigneeuserid",
    "assigneeusername",
    "contributoruserid",
    "contributorusername",
}
CUSTOMER_CONTROLLED_STATUS_FIELDS = {
    "approval",
    "approvalstatus",
    "decisionstatus",
    "reviewdecision",
    "reviewstatus",
    "status",
}
CUSTOMER_FORBIDDEN_STATUS_VALUES = {
    "abgelehnt",
    "approved",
    "auditrelevant",
    "freigegeben",
    "freigegeben durch berater/admin",
    "in beraterpruefung",
    "in beraterprüfung",
    "rejected",
    "spaeter pruefen",
    "später prüfen",
}
WORKSPACE_SNAPSHOT_LIMIT = env_int("ISMS_WORKSPACE_SNAPSHOT_LIMIT", 50, 5, 500)
EVENT_RETENTION_DAYS = env_int("ISMS_EVENT_RETENTION_DAYS", 7, 1, 90)
OIDC_STATE_SECONDS = env_int("ISMS_OIDC_STATE_SECONDS", 600, 120, 1800)
OPERATIONS_MONITOR_SECONDS = env_int("ISMS_OPERATIONS_MONITOR_SECONDS", 300, 30, 86400)
OPERATIONS_MONITOR_ENABLED = str(os.environ.get("ISMS_OPERATIONS_MONITOR_ENABLED", "1")).strip().lower() not in {"0", "false", "no", "off"}
OPERATIONS_RUNTIME_LOCK = threading.Lock()
OPERATIONS_MONITOR_STOP = threading.Event()
OPERATIONS_RUNTIME = {
    "enabled": OPERATIONS_MONITOR_ENABLED,
    "intervalSeconds": OPERATIONS_MONITOR_SECONDS,
    "startedAt": None,
    "lastRunAt": None,
    "lastSuccessAt": None,
    "lastError": "",
    "nextRunAt": None,
    "runCount": 0,
}
NOTIFICATION_DELIVERY_ENABLED = str(os.environ.get("ISMS_NOTIFICATION_DELIVERY_ENABLED", "0")).strip().lower() in {"1", "true", "yes", "on"}
NOTIFICATION_DELIVERY_SECONDS = env_int("ISMS_NOTIFICATION_DELIVERY_SECONDS", 30, 5, 3600)
NOTIFICATION_DELIVERY_MAX_ATTEMPTS = env_int("ISMS_NOTIFICATION_MAX_ATTEMPTS", 5, 1, 20)
NOTIFICATION_WEBHOOK_URL = os.environ.get("ISMS_NOTIFICATION_WEBHOOK_URL", "").strip()
NOTIFICATION_WEBHOOK_SECRET = os.environ.get("ISMS_NOTIFICATION_WEBHOOK_SECRET", "").strip()
NOTIFICATION_SMTP_HOST = os.environ.get("ISMS_NOTIFICATION_SMTP_HOST", "").strip()
NOTIFICATION_SMTP_PORT = env_int("ISMS_NOTIFICATION_SMTP_PORT", 587, 1, 65535)
NOTIFICATION_SMTP_USER = os.environ.get("ISMS_NOTIFICATION_SMTP_USER", "").strip()
NOTIFICATION_SMTP_PASSWORD = os.environ.get("ISMS_NOTIFICATION_SMTP_PASSWORD", "")
NOTIFICATION_SMTP_FROM = os.environ.get("ISMS_NOTIFICATION_SMTP_FROM", "").strip()
NOTIFICATION_SMTP_TO = os.environ.get("ISMS_NOTIFICATION_SMTP_TO", "").strip()
NOTIFICATION_SMTP_TLS = str(os.environ.get("ISMS_NOTIFICATION_SMTP_TLS", "1")).strip().lower() not in {"0", "false", "no", "off"}
NOTIFICATION_DELIVERY_STOP = threading.Event()
BACKGROUND_JOB_WORKER_ENABLED = str(os.environ.get("ISMS_JOB_WORKER_ENABLED", "1")).strip().lower() not in {"0", "false", "no", "off"}
BACKGROUND_JOB_WORKER_SECONDS = env_int("ISMS_JOB_WORKER_SECONDS", 15, 2, 3600)
BACKGROUND_JOB_MAX_ATTEMPTS = env_int("ISMS_JOB_MAX_ATTEMPTS", 3, 1, 10)
BACKGROUND_JOB_STOP = threading.Event()
BACKGROUND_JOB_WORKER_ID = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
BACKGROUND_JOB_TYPES = {
    "intune_preview": {
        "label": "Intune-Importvorschau",
        "description": "Liest das Intune-Inventar ohne den Workspace zu veraendern.",
        "tenantScoped": True,
    },
    "intune_sync": {
        "label": "Intune-Geraete synchronisieren",
        "description": "Aktualisiert technische Asset-Daten nach expliziter Freigabe.",
        "tenantScoped": True,
    },
    "operations_alert_refresh": {
        "label": "Betriebsprüfung aktualisieren",
        "description": "Prüft technische Betriebsalarme im Hintergrund.",
        "tenantScoped": False,
    },
    "backup_create": {
        "label": "Backup erstellen",
        "description": "Erstellt ein verschlüsseltes Systembackup im Hintergrund.",
        "tenantScoped": False,
    },
    "quarantine_rescan": {
        "label": "Quarantäne-Datei erneut prüfen",
        "description": "Prüft einen isolierten Upload erneut und gibt ihn nur bei sauberem Scan frei.",
        "tenantScoped": True,
    },
    "tenant_export_preflight": {
        "label": "Mandantenexport prüfen",
        "description": "Prüft Größe, Dateiablage und Integrität vor einem kontrollierten Kundenraum-Export.",
        "tenantScoped": True,
    },
    "tenant_export_create": {
        "label": "Mandantenexport erstellen",
        "description": "Erstellt ein kontrolliertes ZIP-Exportpaket als geschütztes Job-Artefakt.",
        "tenantScoped": True,
    },
}
NOTIFICATION_DELIVERY_RUNTIME_LOCK = threading.Lock()
NOTIFICATION_DELIVERY_RUNTIME = {
    "enabled": NOTIFICATION_DELIVERY_ENABLED,
    "intervalSeconds": NOTIFICATION_DELIVERY_SECONDS,
    "maxAttempts": NOTIFICATION_DELIVERY_MAX_ATTEMPTS,
    "startedAt": None,
    "lastRunAt": None,
    "lastSuccessAt": None,
    "lastError": "",
    "nextRunAt": None,
    "runCount": 0,
}


def now():
    return int(time.time())


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def conn():
    return DATABASE.connect()


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${b64(salt)}${b64(digest)}"


def password_ok(password, encoded):
    try:
        algo, iterations, salt, digest = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), unb64(salt), int(iterations))
        return hmac.compare_digest(b64(calc), digest)
    except Exception:
        return False


COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "passwort", "passwort1", "passwort123",
    "admin", "administrator", "qwerty", "qwertz", "12345678", "123456789",
    "welcome", "welcome1", "willkommen", "changeme", "change-me-now",
})


def password_policy_public():
    return {
        "minLength": PASSWORD_MIN_LENGTH,
        "maxLength": PASSWORD_MAX_LENGTH,
        "historyCount": PASSWORD_HISTORY_COUNT,
        "checks": [
            "minimum_length",
            "not_account_identity",
            "not_common_password",
            "not_recently_used",
        ],
        "compositionRequired": False,
    }


def password_policy_error(password, username="", email=""):
    value = str(password or "")
    if len(value) < PASSWORD_MIN_LENGTH:
        return "password_too_short", f"password must contain at least {PASSWORD_MIN_LENGTH} characters"
    if len(value) > PASSWORD_MAX_LENGTH:
        return "password_too_long", f"password must contain at most {PASSWORD_MAX_LENGTH} characters"
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return "password_contains_control_character", "password must not contain control characters"
    normalized = value.casefold()
    if normalized in COMMON_PASSWORDS:
        return "password_too_common", "password is too common"
    identity_tokens = {str(username or "").strip().casefold()}
    email_value = str(email or "").strip().casefold()
    if email_value:
        identity_tokens.add(email_value)
        identity_tokens.add(email_value.split("@", 1)[0])
    for token in identity_tokens:
        compact = re.sub(r"[^a-z0-9]", "", token)
        if len(compact) >= 4 and compact in re.sub(r"[^a-z0-9]", "", normalized):
            return "password_contains_account_identity", "password must not contain the username or email identity"
    return None


def password_reuse_error(db, user_id, password, current_hash=None):
    hashes = []
    if current_hash:
        hashes.append(current_hash)
    hashes.extend(
        row["password_hash"]
        for row in db.execute(
            "SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, PASSWORD_HISTORY_COUNT),
        ).fetchall()
    )
    if any(password_ok(password, encoded) for encoded in hashes):
        return "password_recently_used", f"password must differ from the current and previous {PASSWORD_HISTORY_COUNT} passwords"
    return None


def update_user_password(db, user_id, password, username="", email="", changed_by=None, reason="password_change", require_change=False):
    row = db.execute("SELECT password_hash,username,email FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return "user_not_found", "user not found"
    error = password_policy_error(password, username or row["username"], email or row["email"])
    if error:
        return error
    error = password_reuse_error(db, user_id, password, row["password_hash"])
    if error:
        return error
    changed_at = now()
    db.execute(
        "INSERT INTO password_history (id,user_id,password_hash,created_at,changed_by,reason) VALUES (?,?,?,?,?,?)",
        (uuid.uuid4().hex, user_id, row["password_hash"], changed_at, changed_by, reason),
    )
    stale = db.execute(
        "SELECT id FROM password_history WHERE user_id = ? ORDER BY created_at DESC, id DESC",
        (user_id,),
    ).fetchall()[PASSWORD_HISTORY_COUNT:]
    for history_row in stale:
        db.execute("DELETE FROM password_history WHERE id = ?", (history_row["id"],))
    db.execute(
        "UPDATE users SET password_hash = ?,password_change_required = ?,updated_at = ? WHERE id = ?",
        (password_hash(password), 1 if require_change else 0, changed_at, user_id),
    )
    return None


def ensure_column(db, table, column, ddl):
    existing = DATABASE.table_columns(db, table)
    if column not in existing:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def tenant_slug(value):
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")
    return slug[:60] or f"tenant-{uuid.uuid4().hex[:8]}"


def valid_email(value):
    text = str(value or "").strip()
    return bool(re.fullmatch(r"[^@\s]{1,120}@[^@\s]{1,120}\.[^@\s]{2,40}", text))


def invite_role_allowed(user, role):
    if role not in READ_ROLES:
        return False
    if user and user.get("platform_admin"):
        return True
    return role in TENANT_INVITE_ROLES


def init_db():
    DATA.mkdir(exist_ok=True)
    BACKUPS.mkdir(exist_ok=True)
    JOB_ARTIFACTS.mkdir(exist_ok=True)
    with conn() as db:
        DATABASE.initialize_schema(db)
        db.execute(
            "INSERT INTO tenants (id,name,slug,status,created_at,updated_at) VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING",
            (DEFAULT_TENANT_ID, DEFAULT_TENANT_NAME, "internal", "active", now(), now()),
        )
        db.execute(
            "UPDATE tenants SET name = ?, updated_at = ? WHERE id = ? AND name = ?",
            (DEFAULT_TENANT_NAME, now(), DEFAULT_TENANT_ID, "ISMS Catalyst Internal"),
        )
        ensure_column(db, "users", "active", "INTEGER NOT NULL DEFAULT 1")
        ensure_column(db, "users", "mfa_secret", "TEXT")
        ensure_column(db, "users", "mfa_enabled", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(db, "users", "updated_at", "INTEGER")
        ensure_column(db, "users", "last_login_at", "INTEGER")
        ensure_column(db, "users", "email", "TEXT")
        db.execute("CREATE INDEX IF NOT EXISTS idx_users_tenant_email ON users(tenant_id, email)")
        ensure_column(db, "users", "tenant_id", "TEXT NOT NULL DEFAULT 'default'")
        ensure_column(db, "users", "platform_admin", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(db, "users", "password_change_required", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(db, "invitations", "delivery_status", "TEXT NOT NULL DEFAULT 'manual'")
        ensure_column(db, "invitations", "delivery_attempts", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(db, "invitations", "last_sent_at", "BIGINT")
        ensure_column(db, "invitations", "delivered_at", "BIGINT")
        ensure_column(db, "invitations", "delivery_error", "TEXT")
        ensure_column(db, "tenants", "retention_until", "INTEGER")
        ensure_column(db, "tenants", "legal_hold", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(db, "tenants", "lifecycle_note", "TEXT")
        ensure_column(db, "tenants", "archived_at", "INTEGER")
        ensure_column(db, "operational_alerts", "remediation_action", "TEXT")
        ensure_column(db, "operational_alerts", "remediation_label", "TEXT")
        ensure_column(db, "sessions", "tenant_id", "TEXT")
        ensure_column(db, "workspace_state", "tenant_id", "TEXT")
        ensure_column(db, "tenant_workspace_state", "revision", "INTEGER NOT NULL DEFAULT 1")
        ensure_column(db, "files", "tenant_id", "TEXT")
        ensure_column(db, "files", "document_id", "TEXT")
        ensure_column(db, "files", "version_label", "TEXT")
        ensure_column(db, "files", "previous_file_id", "TEXT")
        ensure_column(db, "files", "linked_to", "TEXT")
        ensure_column(db, "files", "classification", "TEXT")
        ensure_column(db, "files", "scan_status", "TEXT NOT NULL DEFAULT 'unscanned'")
        ensure_column(db, "files", "scan_engine", "TEXT")
        ensure_column(db, "files", "scan_signature", "TEXT")
        ensure_column(db, "files", "scan_detail", "TEXT")
        ensure_column(db, "files", "scanned_at", "INTEGER")
        ensure_column(db, "files", "quarantined", "INTEGER NOT NULL DEFAULT 0")
        db.execute("CREATE INDEX IF NOT EXISTS idx_files_tenant_quarantine ON files(tenant_id, quarantined, uploaded_at DESC)")
        ensure_column(db, "background_jobs", "tenant_id", "TEXT")
        ensure_column(db, "background_jobs", "priority", "INTEGER NOT NULL DEFAULT 50")
        ensure_column(db, "background_jobs", "result_json", "TEXT")
        ensure_column(db, "background_jobs", "attempts", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(db, "background_jobs", "max_attempts", f"INTEGER NOT NULL DEFAULT {BACKGROUND_JOB_MAX_ATTEMPTS}")
        ensure_column(db, "background_jobs", "next_run_at", "INTEGER")
        ensure_column(db, "background_jobs", "locked_at", "INTEGER")
        ensure_column(db, "background_jobs", "locked_by", "TEXT")
        ensure_column(db, "background_jobs", "updated_at", "INTEGER")
        ensure_column(db, "background_jobs", "finished_at", "INTEGER")
        ensure_column(db, "background_jobs", "last_error", "TEXT")
        db.execute("CREATE INDEX IF NOT EXISTS idx_background_jobs_queue ON background_jobs(status, next_run_at, priority, created_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_background_jobs_tenant ON background_jobs(tenant_id, created_at DESC)")
        ensure_column(db, "audit_log", "tenant_id", "TEXT")
        ensure_column(db, "audit_log", "previous_hash", "TEXT")
        ensure_column(db, "audit_log", "event_hash", "TEXT")
        db.execute(
            "UPDATE audit_log SET tenant_id = ? "
            "WHERE (tenant_id IS NULL OR tenant_id = '') AND (event_hash IS NULL OR event_hash = '')",
            (DEFAULT_TENANT_ID,),
        )
        backfill_audit_hash_chain(db)
        db.execute("UPDATE users SET tenant_id = ? WHERE tenant_id IS NULL OR tenant_id = ''", (DEFAULT_TENANT_ID,))
        db.execute("UPDATE files SET tenant_id = ? WHERE tenant_id IS NULL OR tenant_id = ''", (DEFAULT_TENANT_ID,))
        old_state = db.execute("SELECT state_json, updated_at, updated_by FROM workspace_state WHERE id = 1").fetchone()
        migrated_state = db.execute("SELECT tenant_id FROM tenant_workspace_state WHERE tenant_id = ?", (DEFAULT_TENANT_ID,)).fetchone()
        if old_state and not migrated_state:
            db.execute(
                "INSERT INTO tenant_workspace_state (tenant_id,state_json,updated_at,updated_by) VALUES (?,?,?,?)",
                (DEFAULT_TENANT_ID, old_state["state_json"], old_state["updated_at"], old_state["updated_by"]),
            )
        row = db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
        if not row:
            env_password = os.environ.get("ISMS_ADMIN_PASSWORD")
            password = env_password or secrets.token_urlsafe(18)
            db.execute(
                "INSERT INTO users (username,password_hash,role,created_at,tenant_id,platform_admin) VALUES (?,?,?,?,?,1)",
                ("admin", password_hash(password), "admin", now(), DEFAULT_TENANT_ID),
            )
            if not env_password:
                DEV_PASS.write_text(f"username: admin\npassword: {password}\n", encoding="utf-8")
            else:
                DEV_PASS.write_text("username: admin\npassword: configured via ISMS_ADMIN_PASSWORD\n", encoding="utf-8")
            try:
                DEV_PASS.chmod(0o600)
            except OSError:
                pass
        else:
            db.execute("UPDATE users SET tenant_id = COALESCE(NULLIF(tenant_id, ''), ?), platform_admin = 1 WHERE username = 'admin'", (DEFAULT_TENANT_ID,))


def file_key():
    env_key = os.environ.get("ISMS_FILE_KEY")
    if env_key:
        return hashlib.sha256(env_key.encode()).digest()
    if not FILE_KEY.exists():
        FILE_KEY.write_bytes(secrets.token_bytes(32))
        try:
            FILE_KEY.chmod(0o600)
        except OSError:
            pass
    return FILE_KEY.read_bytes()


def stream(key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def encrypt(data):
    key = file_key()
    nonce = secrets.token_bytes(16)
    cipher = xor_bytes(data, stream(key, nonce, len(data)))
    tag = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
    return nonce, cipher + tag


def decrypt(nonce, payload):
    key = file_key()
    cipher, tag = payload[:-32], payload[-32:]
    expected = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("file integrity check failed")
    return xor_bytes(cipher, stream(key, nonce, len(cipher)))


def intune_service():
    return IntuneSync(
        database=DATABASE, connect=conn,
        seal=lambda content: tuple(b64(part) for part in encrypt(content)),
        unseal=lambda nonce, content: decrypt(unb64(nonce), unb64(content)),
        audit=audit, snapshot=insert_state_snapshot,
        validate=workspace_state_validation_report, max_bytes=MAX_JSON,
    )


def cookie_value(token, max_age=SESSION_SECONDS):
    secure_cookie = os.environ.get("ISMS_COOKIE_SECURE") == "1" or os.environ.get("ISMS_PUBLIC_URL", "").startswith("https://")
    same_site = os.environ.get("ISMS_COOKIE_SAMESITE", "Lax")
    if same_site not in {"Lax", "Strict"}:
        same_site = "Lax"
    secure = "; Secure" if secure_cookie else ""
    return f"{COOKIE}={token}; HttpOnly; SameSite={same_site}; Path=/; Max-Age={max_age}{secure}"


def read_cookie(header):
    jar = cookies.SimpleCookie()
    if header:
        jar.load(header)
    item = jar.get(COOKIE)
    return item.value if item else ""


def rate_limited(key, limit=8, window=60):
    t = time.time()
    bucket = [seen for seen in LOGIN_ATTEMPTS.get(key, []) if t - seen < window]
    if len(bucket) >= limit:
        LOGIN_ATTEMPTS[key] = bucket
        return True
    bucket.append(t)
    LOGIN_ATTEMPTS[key] = bucket
    return False


def persistent_login_scope_key(scope, value):
    normalized = str(value or "").strip().lower()
    return f"{scope}:{sha(normalized.encode('utf-8'))}"


def login_limit_keys(username, ip):
    return (
        (persistent_login_scope_key("account", username), "account", LOGIN_ACCOUNT_MAX_ATTEMPTS),
        (persistent_login_scope_key("ip", ip), "ip", LOGIN_IP_MAX_ATTEMPTS),
    )


def login_limit_status(db, username, ip, current=None):
    current = current or now()
    retry_after = 0
    blocked_scopes = []
    for scope_key, scope, _limit in login_limit_keys(username, ip):
        row = db.execute(
            "SELECT blocked_until FROM auth_login_limits WHERE scope_key = ?",
            (scope_key,),
        ).fetchone()
        blocked_until = int(row["blocked_until"] or 0) if row else 0
        if blocked_until > current:
            retry_after = max(retry_after, blocked_until - current)
            blocked_scopes.append(scope)
    return {"blocked": retry_after > 0, "retryAfter": retry_after, "scopes": blocked_scopes}


def record_login_failure(db, username, ip, current=None):
    current = current or now()
    result = {"blocked": False, "retryAfter": 0, "scopes": []}
    for scope_key, scope, limit in login_limit_keys(username, ip):
        row = db.execute(
            "SELECT attempt_count,window_started_at,blocked_until FROM auth_login_limits WHERE scope_key = ?",
            (scope_key,),
        ).fetchone()
        if row and int(row["blocked_until"] or 0) > current:
            attempts = int(row["attempt_count"] or 0)
            window_started = int(row["window_started_at"] or current)
            blocked_until = int(row["blocked_until"] or 0)
        else:
            within_window = bool(row and current - int(row["window_started_at"] or 0) < LOGIN_ATTEMPT_WINDOW_SECONDS)
            attempts = int(row["attempt_count"] or 0) + 1 if within_window else 1
            window_started = int(row["window_started_at"] or current) if within_window else current
            blocked_until = current + LOGIN_LOCK_SECONDS if attempts >= limit else None
        if row:
            db.execute(
                "UPDATE auth_login_limits SET attempt_count = ?,window_started_at = ?,blocked_until = ?,updated_at = ? WHERE scope_key = ?",
                (attempts, window_started, blocked_until, current, scope_key),
            )
        else:
            db.execute(
                "INSERT INTO auth_login_limits (scope_key,scope,attempt_count,window_started_at,blocked_until,updated_at) VALUES (?,?,?,?,?,?)",
                (scope_key, scope, attempts, window_started, blocked_until, current),
            )
        if blocked_until and blocked_until > current:
            result["blocked"] = True
            result["retryAfter"] = max(result["retryAfter"], blocked_until - current)
            result["scopes"].append(scope)
    return result


def clear_login_failures(db, username, ip=None):
    keys = [persistent_login_scope_key("account", username)]
    if ip:
        keys.append(persistent_login_scope_key("ip", ip))
    placeholders = ",".join("?" for _ in keys)
    db.execute(f"DELETE FROM auth_login_limits WHERE scope_key IN ({placeholders})", tuple(keys))


def account_login_lock(db, username, current=None):
    current = current or now()
    row = db.execute(
        "SELECT attempt_count,blocked_until FROM auth_login_limits WHERE scope_key = ?",
        (persistent_login_scope_key("account", username),),
    ).fetchone()
    blocked_until = int(row["blocked_until"] or 0) if row else 0
    return {
        "locked": blocked_until > current,
        "lockedUntil": blocked_until or None,
        "failedAttempts": int(row["attempt_count"] or 0) if row else 0,
    }


def safe_filename(name):
    base = Path(name or "upload.bin").name
    clean = re.sub(r"[^A-Za-z0-9._ -]", "_", base).strip(" .")
    return clean[:140] or "upload.bin"


def is_within(base, target):
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def is_valid_workspace_state(state):
    return bool(workspace_state_validation_report(state).get("valid"))


def workspace_state_validation_report(state, state_json=None):
    report = {
        "valid": False,
        "format": "unknown",
        "errors": [],
        "warnings": [],
        "requiredMissing": [],
        "requiredInvalid": [],
        "unknownTopLevelKeys": [],
        "counts": {},
        "bytes": 0,
        "snapshotRecommended": False,
    }
    if not isinstance(state, dict) or not state:
        report["errors"].append("Workspace-State muss ein nicht leeres Objekt sein.")
        return report
    if state_json is None:
        try:
            state_json = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            report["errors"].append("Workspace-State kann nicht serialisiert werden.")
            return report
    report["bytes"] = len(str(state_json).encode("utf-8"))
    if report["bytes"] > MAX_JSON:
        report["errors"].append("Workspace-State überschreitet die konfigurierte Maximalgröße.")

    sfm_missing = [key for key in SFM_WORKSPACE_REQUIRED_ARRAYS if key not in state]
    sfm_invalid = [key for key in SFM_WORKSPACE_REQUIRED_ARRAYS if key in state and not isinstance(state.get(key), list)]
    legacy_missing = [key for key in LEGACY_WORKSPACE_REQUIRED_ARRAYS if key not in state]
    legacy_invalid = [key for key in LEGACY_WORKSPACE_REQUIRED_ARRAYS if key in state and not isinstance(state.get(key), list)]
    legacy_setup_ok = isinstance(state.get("setup"), dict)

    if not sfm_missing and not sfm_invalid:
        report["valid"] = True
        report["format"] = "sfm-compliance"
        required_keys = set(SFM_WORKSPACE_REQUIRED_ARRAYS)
    elif legacy_setup_ok and not legacy_missing and not legacy_invalid:
        report["valid"] = True
        report["format"] = "legacy"
        required_keys = set(LEGACY_WORKSPACE_REQUIRED_ARRAYS) | {"setup"}
        report["warnings"].append("Legacy-Workspace erkannt; beim nächsten Speichern wird die Oberfläche fehlende SFM-Bereiche normalisieren.")
    else:
        report["requiredMissing"] = sfm_missing
        report["requiredInvalid"] = sfm_invalid
        if sfm_missing:
            report["errors"].append("Pflichtbereiche fehlen: " + ", ".join(sfm_missing[:12]))
        if sfm_invalid:
            report["errors"].append("Pflichtbereiche haben ein falsches Format: " + ", ".join(sfm_invalid[:12]))
        if not legacy_setup_ok and not legacy_missing:
            report["warnings"].append("Legacy-Format unvollständig: setup fehlt oder ist kein Objekt.")

    known_optional = {
        "setup", "soa", "gaps", "evidence", "socReports", "onboarding", "consultantGenerator", "auditTrail", "auditPackage",
        "notifications", "reviewCenter", "managementReview", "internalAuditPlan", "securityReviews", "invitationState", "auditFindings",
    }
    known_keys = required_keys if report["valid"] else set(SFM_WORKSPACE_REQUIRED_ARRAYS) | set(LEGACY_WORKSPACE_REQUIRED_ARRAYS) | {"setup"}
    unknown = sorted(set(state.keys()).difference(known_keys | known_optional))
    report["unknownTopLevelKeys"] = unknown[:25]
    if unknown:
        report["warnings"].append(f"{len(unknown)} unbekannte Top-Level-Felder werden gespeichert, aber nicht fachlich bewertet.")

    for key, value in state.items():
        if isinstance(value, list):
            report["counts"][key] = len(value)
    if report["errors"]:
        report["valid"] = False
    if report["valid"]:
        relevant_total = sum(report["counts"].get(key, 0) for key in SFM_WORKSPACE_REQUIRED_ARRAYS)
        if relevant_total == 0:
            report["warnings"].append("Workspace enthält noch keine Register- oder Dokumentationsdaten.")
        report["snapshotRecommended"] = report["bytes"] > 256 * 1024 or relevant_total > 50
    return report


_SUBMISSION_MISSING = object()


def canonical_workspace_value(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def normalized_submission_key(value):
    return "".join(character for character in str(value or "").lower() if character.isalnum())


def normalized_submission_status(value):
    return " ".join(str(value or "").strip().lower().replace("_", "-").replace("-", " ").split())


def submission_item_identity(item, index):
    if isinstance(item, dict):
        for key in ("id", "controlId", "control", "key", "code", "slug"):
            value = str(item.get(key) or "").strip()
            if value:
                return f"{key}:{value}"
    return f"index:{index}"


def stable_submission_item_identity(item):
    if not isinstance(item, dict):
        return None
    for key in ("id", "controlId", "control", "key", "code", "slug"):
        value = str(item.get(key) or "").strip()
        if value:
            return f"{key}:{value}"
    return None


def workspace_record_has_final_status(value):
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = normalized_submission_key(key)
            if normalized_key in CUSTOMER_CONTROLLED_STATUS_FIELDS:
                if normalized_submission_status(item) in CUSTOMER_FORBIDDEN_STATUS_VALUES:
                    return True
            if workspace_record_has_final_status(item):
                return True
    elif isinstance(value, list):
        return any(workspace_record_has_final_status(item) for item in value)
    return False


def validate_customer_submission_value(previous, proposed, path, violations):
    if len(violations) >= 25:
        return
    if isinstance(proposed, dict):
        previous_dict = previous if isinstance(previous, dict) else {}
        for key in set(previous_dict) | set(proposed):
            before = previous_dict.get(key, _SUBMISSION_MISSING)
            after = proposed.get(key, _SUBMISSION_MISSING)
            if before is not _SUBMISSION_MISSING and after is not _SUBMISSION_MISSING:
                if canonical_workspace_value(before) == canonical_workspace_value(after):
                    continue
            normalized_key = normalized_submission_key(key)
            field_path = f"{path}.{key}"
            if normalized_key in CUSTOMER_IMMUTABLE_REVIEW_FIELDS:
                if before is _SUBMISSION_MISSING and after in (None, False, 0, ""):
                    continue
                violations.append({"path": field_path, "reason": "review_field_protected"})
                continue
            if normalized_key in CUSTOMER_CONTROLLED_STATUS_FIELDS and after is not _SUBMISSION_MISSING:
                if normalized_submission_status(after) in CUSTOMER_FORBIDDEN_STATUS_VALUES:
                    violations.append({"path": field_path, "reason": "advisor_status_required"})
                    continue
            if after is not _SUBMISSION_MISSING:
                validate_customer_submission_value(before, after, field_path, violations)
    elif isinstance(proposed, list):
        previous_list = previous if isinstance(previous, list) else []
        for index, item in enumerate(proposed):
            before = previous_list[index] if index < len(previous_list) else _SUBMISSION_MISSING
            validate_customer_submission_value(before, item, f"{path}[{index}]", violations)


def validate_customer_submission_collection(section, previous, proposed, violations):
    if not isinstance(previous, list) or not isinstance(proposed, list):
        validate_customer_submission_value(previous, proposed, section, violations)
        return

    previous_records = {
        submission_item_identity(item, index): item
        for index, item in enumerate(previous)
    }
    proposed_records = {}
    for index, item in enumerate(proposed):
        identity = submission_item_identity(item, index)
        if identity in proposed_records:
            violations.append({"path": f"{section}[{index}]", "reason": "duplicate_record_identity"})
            continue
        proposed_records[identity] = item

    for identity, old_record in previous_records.items():
        if identity not in proposed_records:
            violations.append({"path": f"{section}.{identity}", "reason": "existing_record_cannot_be_deleted"})
            continue
        new_record = proposed_records[identity]
        if canonical_workspace_value(old_record) == canonical_workspace_value(new_record):
            continue
        if workspace_record_has_final_status(old_record):
            violations.append({"path": f"{section}.{identity}", "reason": "approved_record_is_immutable"})
            continue
        validate_customer_submission_value(old_record, new_record, f"{section}.{identity}", violations)

    for identity, new_record in proposed_records.items():
        if identity not in previous_records:
            validate_customer_submission_value(_SUBMISSION_MISSING, new_record, f"{section}.{identity}", violations)


def customer_submission_policy_report(previous_state, proposed_state):
    report = {"allowed": False, "changedSections": [], "violations": []}
    if not isinstance(previous_state, dict) or not isinstance(proposed_state, dict):
        report["violations"].append({"path": "state", "reason": "workspace_state_required"})
        return report

    for section in sorted(set(previous_state) | set(proposed_state)):
        before = previous_state.get(section, _SUBMISSION_MISSING)
        after = proposed_state.get(section, _SUBMISSION_MISSING)
        if before is not _SUBMISSION_MISSING and after is not _SUBMISSION_MISSING:
            if canonical_workspace_value(before) == canonical_workspace_value(after):
                continue
        report["changedSections"].append(section)
        if section not in CUSTOMER_SUBMISSION_SECTIONS:
            report["violations"].append({"path": section, "reason": "section_requires_advisor"})
            continue
        if after is _SUBMISSION_MISSING:
            report["violations"].append({"path": section, "reason": "section_cannot_be_deleted"})
            continue
        validate_customer_submission_collection(section, before, after, report["violations"])

    report["violations"] = report["violations"][:25]
    report["allowed"] = not report["violations"]
    return report


def validate_contributor_assignment_fields(previous, proposed, path, violations):
    if len(violations) >= 25 or not isinstance(proposed, dict):
        return
    previous_dict = previous if isinstance(previous, dict) else {}
    for key, after in proposed.items():
        before = previous_dict.get(key, _SUBMISSION_MISSING)
        if before is not _SUBMISSION_MISSING and canonical_workspace_value(before) == canonical_workspace_value(after):
            continue
        field_path = f"{path}.{key}"
        if normalized_submission_key(key) in CONTRIBUTOR_IMMUTABLE_ASSIGNMENT_FIELDS:
            violations.append({"path": field_path, "reason": "assignment_requires_coordinator"})
            continue
        if isinstance(after, dict):
            validate_contributor_assignment_fields(before, after, field_path, violations)
        elif isinstance(after, list):
            previous_list = before if isinstance(before, list) else []
            for index, item in enumerate(after):
                old_item = previous_list[index] if index < len(previous_list) else _SUBMISSION_MISSING
                validate_contributor_assignment_fields(old_item, item, f"{field_path}[{index}]", violations)


def workspace_submission_record_changes(previous_state, proposed_state, changed_sections):
    changes = []
    violations = []
    for section in changed_sections:
        previous = previous_state.get(section, _SUBMISSION_MISSING)
        proposed = proposed_state.get(section, _SUBMISSION_MISSING)
        if not isinstance(previous, list) or not isinstance(proposed, list):
            violations.append({"path": section, "reason": "contributor_record_scope_required"})
            continue
        previous_records = {}
        for index, item in enumerate(previous):
            identity = stable_submission_item_identity(item)
            if identity:
                previous_records[identity] = item
        for index, item in enumerate(proposed):
            identity = stable_submission_item_identity(item)
            fallback_path = f"{section}[{index}]"
            if not identity:
                old_item = previous[index] if index < len(previous) else _SUBMISSION_MISSING
                if old_item is _SUBMISSION_MISSING or canonical_workspace_value(old_item) != canonical_workspace_value(item):
                    violations.append({"path": fallback_path, "reason": "stable_record_id_required"})
                continue
            old_item = previous_records.get(identity, _SUBMISSION_MISSING)
            if old_item is not _SUBMISSION_MISSING and canonical_workspace_value(old_item) == canonical_workspace_value(item):
                continue
            changes.append({
                "section": section,
                "recordKey": identity,
                "change": "created" if old_item is _SUBMISSION_MISSING else "updated",
                "previous": None if old_item is _SUBMISSION_MISSING else old_item,
                "proposed": item,
            })
    return changes, violations


def contributor_record_assigned_to_user(record, user):
    if not isinstance(record, dict):
        return False
    user_id = str(user.get("id") or "").strip()
    username = str(user.get("username") or "").strip().lower()
    id_fields = {"assignedtouserid", "assigneeuserid", "contributoruserid"}
    username_fields = {"assignedusername", "assigneeusername", "contributorusername"}
    for key, value in record.items():
        normalized_key = normalized_submission_key(key)
        if normalized_key in id_fields and str(value or "").strip() == user_id:
            return True
        if normalized_key in username_fields and str(value or "").strip().lower() == username:
            return True
    return False


def contributor_submission_policy_report(db, user, previous_state, proposed_state, base_report):
    if user.get("role") != "contributor":
        return base_report, []

    report = {
        "allowed": bool(base_report.get("allowed")),
        "changedSections": list(base_report.get("changedSections") or []),
        "violations": list(base_report.get("violations") or []),
        "ownershipEnforced": True,
    }
    for section in report["changedSections"]:
        if section not in CONTRIBUTOR_SUBMISSION_SECTIONS:
            report["violations"].append({"path": section, "reason": "contributor_section_restricted"})

    allowed_sections = [
        section for section in report["changedSections"]
        if section in CONTRIBUTOR_SUBMISSION_SECTIONS
    ]
    changes, identity_violations = workspace_submission_record_changes(
        previous_state,
        proposed_state,
        allowed_sections,
    )
    report["violations"].extend(identity_violations)

    for change in changes:
        path = f"{change['section']}.{change['recordKey']}"
        validate_contributor_assignment_fields(
            change["previous"] if change["previous"] is not None else {},
            change["proposed"],
            path,
            report["violations"],
        )
        ownership = db.execute(
            "SELECT owner_user_id, owner_username FROM workspace_record_ownership "
            "WHERE tenant_id = ? AND section = ? AND record_key = ?",
            (user["tenant_id"], change["section"], change["recordKey"]),
        ).fetchone()
        if change["change"] == "created":
            if ownership and int(ownership["owner_user_id"]) != int(user["id"]):
                report["violations"].append({"path": path, "reason": "record_owned_by_another_user"})
            continue
        is_owner = ownership and int(ownership["owner_user_id"]) == int(user["id"])
        is_assigned = contributor_record_assigned_to_user(change["previous"], user)
        if not is_owner and not is_assigned:
            report["violations"].append({"path": path, "reason": "record_owned_by_another_user"})

    report["violations"] = report["violations"][:25]
    report["recordChanges"] = {
        "created": sum(1 for change in changes if change["change"] == "created"),
        "updated": sum(1 for change in changes if change["change"] == "updated"),
    }
    report["allowed"] = not report["violations"]
    return report, changes


def persist_submission_record_ownership(db, user, changes, saved_at):
    for change in changes:
        if change["change"] == "created":
            db.execute(
                "INSERT INTO workspace_record_ownership "
                "(tenant_id,section,record_key,owner_user_id,owner_username,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(tenant_id,section,record_key) DO NOTHING",
                (
                    user["tenant_id"],
                    change["section"],
                    change["recordKey"],
                    user["id"],
                    user["username"],
                    saved_at,
                    saved_at,
                ),
            )
        else:
            db.execute(
                "UPDATE workspace_record_ownership SET updated_at = ? "
                "WHERE tenant_id = ? AND section = ? AND record_key = ?",
                (saved_at, user["tenant_id"], change["section"], change["recordKey"]),
            )


def prune_workspace_record_ownership(db, tenant_id, state):
    rows = db.execute(
        "SELECT section, record_key FROM workspace_record_ownership WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchall()
    if not rows:
        return 0
    identities_by_section = {}
    for section, values in state.items():
        if not isinstance(values, list):
            continue
        identities_by_section[section] = {
            identity
            for item in values
            for identity in (stable_submission_item_identity(item),)
            if identity
        }
    deleted = 0
    for row in rows:
        if row["record_key"] in identities_by_section.get(row["section"], set()):
            continue
        db.execute(
            "DELETE FROM workspace_record_ownership WHERE tenant_id = ? AND section = ? AND record_key = ?",
            (tenant_id, row["section"], row["record_key"]),
        )
        deleted += 1
    return deleted


def today_iso(offset_days=0):
    return time.strftime("%Y-%m-%d", time.localtime(now() + offset_days * 86400))


def parse_iso_date_epoch(value):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(time.mktime(time.strptime(text, "%Y-%m-%d")))
    except ValueError:
        return None


def workspace_item_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def create_starter_workspace_state(tenant_name, admin_username=""):
    owner = admin_username or "Mandanten-Admin"
    added = today_iso()
    return {
        "documents": [
            {
                "id": workspace_item_id("doc"),
                "name": "ISMS Scope",
                "area": "ISO 27001",
                "status": "Entwurf",
                "owner": owner,
                "linkedTo": "Clause 4.3",
                "size": "",
                "note": f"Startanker für {tenant_name}: Anwendungsbereich, Grenzen, Schnittstellen und Ausschlüsse erfassen.",
                "added": added,
                "version": "0.1",
                "review": today_iso(30),
                "approval": "Nicht gestartet",
                "classification": "Intern",
                "evidenceFor": "Clause 4.3",
            },
            {
                "id": workspace_item_id("doc"),
                "name": "Risikomethodik",
                "area": "Risiko",
                "status": "Entwurf",
                "owner": owner,
                "linkedTo": "Clause 6.1",
                "size": "",
                "note": "Bewertungslogik, Kriterien, Risikoakzeptanz und Behandlungsweg festlegen.",
                "added": added,
                "version": "0.1",
                "review": today_iso(30),
                "approval": "Nicht gestartet",
                "classification": "Intern",
                "evidenceFor": "Clause 6.1",
            },
            {
                "id": workspace_item_id("doc"),
                "name": "Statement of Applicability",
                "area": "ISO 27001",
                "status": "Entwurf",
                "owner": owner,
                "linkedTo": "Clause 6.1.3 / Annex A",
                "size": "",
                "note": "Control-Entscheidungen, Begründungen und Umsetzungsstatus dokumentieren.",
                "added": added,
                "version": "0.1",
                "review": today_iso(45),
                "approval": "Nicht gestartet",
                "classification": "Intern",
                "evidenceFor": "Clause 6.1.3 / Annex A",
            },
            {
                "id": workspace_item_id("doc"),
                "name": "NIS-2 Einordnungsnotiz",
                "area": "NIS-2",
                "status": "Prüfen",
                "owner": owner,
                "linkedTo": "NIS-2",
                "size": "",
                "note": "Betroffenheit, Einrichtungsart, Ansprechpartner und nächste regulatorische Schritte festhalten.",
                "added": added,
                "version": "0.1",
                "review": today_iso(30),
                "approval": "Nicht gestartet",
                "classification": "Intern",
                "evidenceFor": "NIS-2",
            },
        ],
        "assets": [
            {
                "id": workspace_item_id("asset"),
                "name": "Kritische Systeme erfassen",
                "type": "To-do",
                "owner": "IT / ISB",
                "criticality": "Hoch",
                "protection": "CIA prüfen",
                "status": "Offen",
            }
        ],
        "risks": [
            {
                "id": workspace_item_id("risk"),
                "scenario": "Risikomethodik und erste Top-Risiken festlegen",
                "asset": "ISMS",
                "impact": 4,
                "likelihood": 3,
                "owner": owner,
                "treatment": "Bewertungskriterien, Akzeptanzlogik und erste Behandlungsmaßnahmen dokumentieren.",
                "status": "Offen",
            }
        ],
        "legal": [
            {
                "id": workspace_item_id("legal"),
                "requirement": "NIS-2-Einordnung und Zuständigkeit klären",
                "source": "NIS-2-Dokument",
                "owner": "Geschäftsleitung / Legal",
                "status": "Prüfen",
                "due": today_iso(21),
            }
        ],
        "suppliers": [
            {
                "id": workspace_item_id("supplier"),
                "name": "Kritische Dienstleister erfassen",
                "service": "IKT / Cloud / SaaS",
                "criticality": "Hoch",
                "owner": "Einkauf / ISB",
                "review": "Nicht gestartet",
                "nextReview": today_iso(45),
            }
        ],
        "policies": [
            {
                "id": workspace_item_id("policy"),
                "title": "Information Security Policy",
                "owner": "Geschäftsleitung",
                "version": "0.1",
                "status": "Entwurf",
                "review": today_iso(60),
            },
            {
                "id": workspace_item_id("policy"),
                "title": "Access Control Policy",
                "owner": "IT / ISB",
                "version": "0.1",
                "status": "Entwurf",
                "review": today_iso(60),
            },
            {
                "id": workspace_item_id("policy"),
                "title": "Incident Management Policy",
                "owner": "IT / ISB",
                "version": "0.1",
                "status": "Entwurf",
                "review": today_iso(60),
            },
        ],
        "incidents": [
            {
                "id": workspace_item_id("incident"),
                "title": "Incident-Meldewege und Erstbewertung testen",
                "severity": "Mittel",
                "owner": "ISB / IT",
                "status": "Offen",
                "detected": "",
                "due": today_iso(30),
                "note": "Meldekette, Bewertung und Nachweise einmal praktisch durchspielen.",
            }
        ],
        "contracts": [
            {
                "id": workspace_item_id("contract"),
                "title": "Sicherheitsanforderungen in Lieferantenverträgen prüfen",
                "vendor": "Kritischer Dienstleister",
                "owner": "Einkauf / Legal",
                "status": "Prüfen",
                "review": today_iso(45),
                "linkedTo": "Lieferantenmanagement",
            }
        ],
        "socReports": [],
        "integrations": [],
        "onboarding": {
            "completed": False,
            "lastUpdated": "",
            "answers": {},
        },
        "consultantGenerator": {
            "lastAnswers": {},
            "lastGeneratedAt": "",
        },
        "projectPlan": [
            {"id": "iso-01", "status": "In Arbeit", "owner": owner, "due": today_iso(14)},
            {"id": "iso-02", "status": "In Arbeit", "owner": "Geschäftsleitung", "due": today_iso(21)},
            {"id": "iso-03", "status": "Offen", "owner": owner, "due": today_iso(30)},
            {"id": "nis-01", "status": "In Arbeit", "owner": "Legal / Geschäftsleitung", "due": today_iso(21)},
            {"id": "shared-01", "status": "Offen", "owner": owner, "due": today_iso(30)},
            {"id": "shared-02", "status": "Offen", "owner": "Einkauf / ISB", "due": today_iso(45)},
        ],
        "templateDrafts": [],
        "tasks": [
            {
                "id": workspace_item_id("task"),
                "title": "Kunden-Onboarding ausfüllen",
                "module": "Dashboard",
                "owner": owner,
                "due": today_iso(7),
                "status": "Offen",
            },
            {
                "id": workspace_item_id("task"),
                "title": "Scope, Grenzen und Schnittstellen vorbereiten",
                "module": "ISO 27001",
                "owner": owner,
                "due": today_iso(14),
                "status": "Offen",
            },
            {
                "id": workspace_item_id("task"),
                "title": "Assetliste und kritische Dienstleister sammeln",
                "module": "Gemeinsam",
                "owner": "IT / Einkauf",
                "due": today_iso(21),
                "status": "Offen",
            },
            {
                "id": workspace_item_id("task"),
                "title": "NIS-2-Einordnung im Rechtsregister dokumentieren",
                "module": "NIS-2",
                "owner": "Legal / Geschäftsleitung",
                "due": today_iso(21),
                "status": "Offen",
            },
        ],
        "auditFindings": [],
        "managementReview": {
            "id": "management-review",
            "title": "Managementbewertung",
            "status": "offen",
            "reviewStatus": "offen",
            "auditRelevant": True,
            "workflowHistory": [],
        },
        "internalAuditPlan": {
            "id": "internal-audit-plan",
            "title": "Interne Auditplanung Informationssicherheit",
            "status": "offen",
            "reviewStatus": "offen",
            "auditRelevant": False,
            "workflowHistory": [],
        },
    }


def starter_workspace_summary(state):
    return {
        "documents": len(state.get("documents", [])),
        "tasks": len(state.get("tasks", [])),
        "policies": len(state.get("policies", [])),
        "projectPlan": len(state.get("projectPlan", [])),
        "assets": len(state.get("assets", [])),
        "risks": len(state.get("risks", [])),
        "legal": len(state.get("legal", [])),
        "suppliers": len(state.get("suppliers", [])),
    }


def percent(done, total):
    return int(round((done / max(total, 1)) * 100))


def workspace_list(state, key):
    value = state.get(key) if isinstance(state, dict) else []
    return value if isinstance(value, list) else []


def workspace_overview_metrics(state):
    if not isinstance(state, dict):
        return {
            "readiness": 0,
            "health": "critical",
            "healthLabel": "Kein Workspace",
            "projectPercent": 0,
            "openTasks": 0,
            "documents": 0,
            "openPolicies": 0,
            "openRisks": 0,
            "onboardingCompleted": False,
        }

    project_plan = workspace_list(state, "projectPlan")
    tasks = workspace_list(state, "tasks")
    documents = workspace_list(state, "documents")
    policies = workspace_list(state, "policies")
    risks = workspace_list(state, "risks")
    onboarding = state.get("onboarding") if isinstance(state.get("onboarding"), dict) else {}

    project_done = sum(1 for item in project_plan if item.get("status") == "Erledigt")
    tasks_done = sum(1 for item in tasks if item.get("status") == "Erledigt")
    policies_done = sum(1 for item in policies if item.get("status") == "Freigegeben")
    customer_documents = [item for item in documents if item.get("status") != "Quelle"]
    open_tasks = sum(1 for item in tasks if item.get("status") != "Erledigt")
    open_policies = sum(1 for item in policies if item.get("status") != "Freigegeben")
    open_risks = sum(1 for item in risks if item.get("status") not in {"Akzeptiert", "Erledigt", "Geschlossen"})

    project_percent = percent(project_done, len(project_plan))
    task_percent = percent(tasks_done, len(tasks))
    policy_percent = percent(policies_done, len(policies))
    evidence_percent = min(100, len(customer_documents) * 20)
    onboarding_percent = 100 if onboarding.get("completed") else 0
    risk_percent = 100 if risks else 0
    readiness = percent(
        project_percent + task_percent + policy_percent + evidence_percent + onboarding_percent + risk_percent,
        600,
    )
    if readiness >= 70 and open_tasks <= 3:
        health = "good"
        health_label = "Gut"
    elif readiness >= 35:
        health = "watch"
        health_label = "Aufmerksam"
    else:
        health = "critical"
        health_label = "Kritisch"

    return {
        "readiness": readiness,
        "health": health,
        "healthLabel": health_label,
        "projectPercent": project_percent,
        "taskPercent": task_percent,
        "policyPercent": policy_percent,
        "evidencePercent": evidence_percent,
        "openTasks": open_tasks,
        "documents": len(customer_documents),
        "openPolicies": open_policies,
        "openRisks": open_risks,
        "onboardingCompleted": bool(onboarding.get("completed")),
    }


AUDIT_PACKAGE_MATERIAL_KEYS = (
    "documents",
    "assets",
    "risks",
    "legal",
    "suppliers",
    "policies",
    "incidents",
    "contracts",
    "tasks",
    "projectPlan",
    "templateDrafts",
    "soa",
    "gaps",
    "auditFindings",
    "managementReview",
    "internalAuditPlan",
)
AUDIT_PACKAGE_INTERNAL_FIELDS = {
    "beraterkommentarintern",
    "consultantinternalcomment",
    "internalcomment",
    "internalconsultantcomment",
}


def audit_package_record_title(record, fallback):
    if not isinstance(record, dict):
        return fallback
    for key in ("name", "title", "riskId", "scenario", "controlId", "id"):
        value = str(record.get(key) or "").strip()
        if value:
            return value[:240]
    return fallback


def audit_package_record_approved(record):
    if not isinstance(record, dict):
        return False
    values = (
        record.get("reviewStatus"),
        record.get("approval"),
        record.get("approvalStatus"),
        record.get("status"),
    )
    approved = {
        "approved",
        "beraterfreigegeben",
        "freigegeben",
        "freigegeben durch berater/admin",
    }
    return any(normalized_submission_status(value) in approved for value in values)


def audit_package_record_relevant(record):
    if not isinstance(record, dict):
        return False
    return bool(record.get("auditRelevant") or record.get("auditRelevance")) \
        or normalized_submission_status(record.get("reviewStatus")) == "auditrelevant"


def audit_package_risk_is_critical(record):
    if not isinstance(record, dict):
        return False
    try:
        score = float(record.get("likelihood") or 0) * float(record.get("impact") or 0)
    except (TypeError, ValueError):
        score = 0
    labels = {
        normalized_submission_status(record.get("level")),
        normalized_submission_status(record.get("status")),
        normalized_submission_status(record.get("criticality")),
    }
    return score >= 10 or bool(labels.intersection({"hoch", "sehr hoch", "kritisch", "high", "critical"}))


def audit_package_material_state(state):
    if not isinstance(state, dict):
        return {}
    return {
        key: state.get(key)
        for key in AUDIT_PACKAGE_MATERIAL_KEYS
        if key in state
    }


def audit_package_fingerprint(state):
    payload = canonical_workspace_value(audit_package_material_state(state)).encode("utf-8")
    return f"pkg-{sha(payload)[:32]}"


def audit_package_public_value(value):
    if isinstance(value, dict):
        return {
            key: audit_package_public_value(item)
            for key, item in value.items()
            if normalized_submission_key(key) not in AUDIT_PACKAGE_INTERNAL_FIELDS
        }
    if isinstance(value, list):
        return [audit_package_public_value(item) for item in value]
    return value


def audit_package_gate_report(state):
    state = state if isinstance(state, dict) else {}
    blockers = []
    category_counts = {
        "auditRelevantEvidence": 0,
        "criticalRisks": 0,
        "soa": 0,
        "policies": 0,
        "workTemplates": 0,
        "capa": 0,
        "explicit": 0,
    }

    def add(category, code, record, message, fallback):
        title = audit_package_record_title(record, fallback)
        blocker_id = str((record or {}).get("id") or (record or {}).get("controlId") or title)
        key = f"{category}:{blocker_id}"
        if any(item["key"] == key for item in blockers):
            return
        category_counts[category] += 1
        blockers.append({
            "key": key,
            "code": code,
            "category": category,
            "title": title,
            "message": message,
        })

    for document in workspace_list(state, "documents"):
        if document.get("status") == "Quelle":
            continue
        if audit_package_record_relevant(document) and not audit_package_record_approved(document):
            add("auditRelevantEvidence", "evidence_not_approved", document, "Auditrelevanter Nachweis ist nicht durch Berater/Admin freigegeben.", "Nachweis")

    for risk in workspace_list(state, "risks"):
        treatment = str(risk.get("treatment") or risk.get("measure") or "").strip()
        if audit_package_risk_is_critical(risk) and (not treatment or not audit_package_record_approved(risk)):
            add("criticalRisks", "critical_risk_open", risk, "Kritisches Risiko hat keine geprüfte Behandlung und Freigabe.", "Risiko")

    for record in workspace_list(state, "soa"):
        if audit_package_record_relevant(record) and not audit_package_record_approved(record):
            add("soa", "soa_not_approved", record, "Auditrelevanter SoA-Eintrag ist nicht geprüft.", "SoA-Eintrag")

    for policy in workspace_list(state, "policies"):
        if audit_package_record_relevant(policy) and not audit_package_record_approved(policy):
            add("policies", "policy_not_approved", policy, "Policy mit Auditbezug ist nicht freigegeben.", "Policy")

    open_review_statuses = {
        "abgelehnt",
        "auditrelevant",
        "in beraterpruefung",
        "in beraterprüfung",
        "nacharbeit noetig",
        "nacharbeit nötig",
        "vom kunden eingereicht",
    }
    for draft in workspace_list(state, "templateDrafts"):
        status = normalized_submission_status(draft.get("reviewStatus") or draft.get("status"))
        if (audit_package_record_relevant(draft) or status in open_review_statuses) and not audit_package_record_approved(draft):
            add("workTemplates", "template_not_approved", draft, "Arbeitsvorlage wartet auf Prüfung oder Nacharbeit.", "Arbeitsvorlage")

    for finding in workspace_list(state, "auditFindings"):
        if audit_package_record_relevant(finding) and not audit_package_record_approved(finding):
            add("capa", "capa_not_approved", finding, "Auditrelevante Korrekturmaßnahme ist nicht freigegeben.", "Korrekturmaßnahme")

    for singleton_key, fallback in (("managementReview", "Managementbewertung"), ("internalAuditPlan", "Interne Auditplanung")):
        record = state.get(singleton_key)
        if isinstance(record, dict) and audit_package_record_relevant(record) and not audit_package_record_approved(record):
            add("explicit", f"{singleton_key}_not_approved", record, f"{fallback} ist auditrelevant und nicht freigegeben.", fallback)

    explicit_collections = (
        "documents", "assets", "risks", "legal", "suppliers", "policies",
        "incidents", "contracts", "tasks", "projectPlan", "soa", "gaps",
    )
    for collection in explicit_collections:
        for record in workspace_list(state, collection):
            if record.get("auditBlocker") and not audit_package_record_approved(record):
                add("explicit", "explicit_audit_blocker", record, "Expliziter Audit-Blocker ist noch offen.", "Audit-Blocker")

    criteria = [
        {"key": key, "open": category_counts[key]}
        for key in ("auditRelevantEvidence", "criticalRisks", "soa", "policies", "workTemplates", "capa", "explicit")
    ]
    return {
        "formalGateClear": not blockers,
        "blockerCount": len(blockers),
        "blockers": blockers,
        "criteria": criteria,
    }


def audit_package_status(state, revision=None):
    gate = audit_package_gate_report(state)
    fingerprint = audit_package_fingerprint(state)
    package = state.get("auditPackage") if isinstance(state, dict) and isinstance(state.get("auditPackage"), dict) else {}
    approvals = package.get("approvals") if isinstance(package.get("approvals"), list) else []
    current = next(
        (
            item for item in approvals
            if isinstance(item, dict)
            and item.get("status") == "beraterfreigegeben"
            and item.get("fingerprint") == fingerprint
        ),
        None,
    )
    latest = approvals[0] if approvals and isinstance(approvals[0], dict) else None
    advisor_approved = bool(current and gate["formalGateClear"])
    if advisor_approved:
        label = "beraterfreigegeben"
    elif gate["formalGateClear"]:
        label = "formal_vorbereitet"
    else:
        label = "vorbereitet_mit_blockern"
    return {
        **gate,
        "fingerprint": fingerprint,
        "workspaceRevision": revision,
        "advisorApproved": advisor_approved,
        "exportReady": advisor_approved,
        "approvalStale": bool(latest and not current),
        "status": label,
        "approval": current,
        "latestApproval": latest,
        "message": (
            "Auditpaket ist durch Berater/Admin freigegeben und exportbereit."
            if advisor_approved
            else "Auditpaket ist vorbereitet, aber noch nicht durch den Berater freigegeben."
        ),
    }


def tenant_recommendations(metrics, active_users=0, mfa_users=0, files=0, last_activity_at=None):
    recommendations = []

    def add(priority, title, detail, view):
        recommendations.append({
            "priority": priority,
            "title": title,
            "detail": detail,
            "view": view,
        })

    if not metrics.get("onboardingCompleted"):
        add(
            100,
            "Kunden-Onboarding abschließen",
            "Grunddaten, Scope, Assets und Zuständigkeiten fehlen sonst als Arbeitsgrundlage.",
            "dashboard",
        )
    if metrics.get("projectPercent", 0) < 35:
        add(
            90,
            "Projektstrukturplan priorisieren",
            "Owner, Fristen und Status für die nächsten ISO-/NIS-2-Arbeitspakete setzen.",
            "project",
        )
    if metrics.get("documents", 0) < 3 or files == 0:
        add(
            85,
            "Nachweise sammeln",
            "Scope, Risikomethodik, SoA, NIS-2-Einordnung und erste Uploads nachziehen.",
            "documents",
        )
    if metrics.get("openPolicies", 0) > 0:
        add(
            75,
            "Policy-Entwürfe prüfen",
            "Offene Policies mit Owner, Version, Review-Datum und Freigabestatus versehen.",
            "policies",
        )
    if metrics.get("openRisks", 0) > 0:
        add(
            70,
            "Risiken bewerten",
            "Offene Risiken behandeln, Restrisikoentscheidung dokumentieren und Nachweise verknüpfen.",
            "risks",
        )
    if active_users and mfa_users < active_users:
        add(
            60,
            "MFA nachziehen",
            "Aktive Benutzer ohne MFA prüfen und Absicherung im Produktivbetrieb verbessern.",
            "production",
        )
    if not last_activity_at or now() - int(last_activity_at) > 14 * 86400:
        add(
            55,
            "Kundenkontakt anstoßen",
            "Seit mehr als 14 Tagen ist keine Aktivität sichtbar. Nächsten Termin oder Aufgabe setzen.",
            "tasks",
        )

    return sorted(recommendations, key=lambda item: item["priority"], reverse=True)[:5]


def tenant_security_checks(
    metrics,
    active_users=0,
    admin_users=0,
    privileged_users=0,
    privileged_mfa_users=0,
    files=0,
    pending_invitations=0,
    stale_invitations=0,
    active_sessions=0,
    expired_sessions=0,
    snapshots=0,
    last_snapshot_at=None,
    last_activity_at=None,
    state_updated_at=None,
):
    checks = []
    current = now()
    privileged_without_mfa = max(int(privileged_users or 0) - int(privileged_mfa_users or 0), 0)

    def add(key, label, status, detail, view):
        checks.append({
            "key": key,
            "label": label,
            "status": status,
            "detail": detail,
            "view": view,
        })

    add(
        "workspace",
        "Workspace",
        "good" if state_updated_at else "critical",
        "Kundenraum gespeichert." if state_updated_at else "Kundenraum wurde noch nicht initial gespeichert.",
        "dashboard",
    )
    add(
        "admin",
        "Admin",
        "good" if admin_users else "critical",
        f"{admin_users} aktive Admin-Rolle(n)." if admin_users else "Kein aktiver Admin im Kundenraum.",
        "production",
    )
    add(
        "mfa",
        "MFA",
        "good" if privileged_users and privileged_without_mfa == 0 else ("watch" if privileged_users else "critical"),
        "Privilegierte Konten mit MFA." if privileged_users and privileged_without_mfa == 0 else (
            f"{privileged_without_mfa} privilegierte Konto/Konten ohne MFA." if privileged_users else "Keine aktive privilegierte Rolle sichtbar."
        ),
        "account",
    )
    add(
        "users",
        "Benutzer",
        "good" if active_users else "critical",
        f"{active_users} aktive Benutzer." if active_users else "Kein aktiver Benutzer im Kundenraum.",
        "production",
    )

    if not last_activity_at:
        activity_status = "watch"
        activity_detail = "Noch keine Aktivität sichtbar."
    else:
        inactive_days = int((current - int(last_activity_at)) / 86400)
        activity_status = "critical" if inactive_days > 30 else ("watch" if inactive_days > 14 else "good")
        activity_detail = f"Letzte Aktivität vor {inactive_days} Tag(en)."
    add("activity", "Aktivität", activity_status, activity_detail, "tasks")

    evidence_count = max(int(files or 0), int(metrics.get("documents", 0) or 0))
    add(
        "evidence",
        "Nachweise",
        "good" if evidence_count else "watch",
        f"{evidence_count} Nachweis(e)/Upload(s) sichtbar." if evidence_count else "Noch keine Kundennachweise sichtbar.",
        "documents",
    )

    invite_status = "watch" if stale_invitations else "good"
    invite_detail = f"{pending_invitations} offene Einladung(en)." if pending_invitations else "Keine offenen Einladungen."
    if stale_invitations:
        invite_detail = f"{stale_invitations} Einladung(en) länger offen."
    add("invitations", "Einladungen", invite_status, invite_detail, "production")

    session_status = "watch" if expired_sessions > max(10, active_sessions * 3) else "good"
    add(
        "sessions",
        "Sessions",
        session_status,
        f"{active_sessions} aktiv, {expired_sessions} abgelaufen.",
        "account",
    )

    snapshot_status = "good" if snapshots else "watch"
    snapshot_detail = f"{snapshots} Snapshot(s) vorhanden." if snapshots else "Noch kein Workspace-Snapshot."
    add("snapshots", "Snapshots", snapshot_status, snapshot_detail, "production")

    blocker_count = sum(1 for item in checks if item["status"] == "critical")
    problem_count = sum(1 for item in checks if item["status"] in {"critical", "watch"})
    status = "critical" if blocker_count else ("watch" if problem_count else "good")
    label = "Blocker prüfen" if blocker_count else ("Hinweise prüfen" if problem_count else "Unauffällig")
    return {
        "checks": checks,
        "problemCount": problem_count,
        "blockerCount": blocker_count,
        "status": status,
        "label": label,
    }


def insert_state_snapshot(db, tenant_id, state_json, saved_by, reason):
    if not state_json:
        return None
    snapshot_at = now()
    state_bytes = state_json.encode("utf-8")
    snapshot_id = DATABASE.insert_returning_id(
        db,
        "INSERT INTO workspace_state_snapshots (tenant_id,state_json,saved_at,saved_by,reason,bytes,sha256) "
        "VALUES (?,?,?,?,?,?,?)",
        (tenant_id, state_json, snapshot_at, saved_by, reason, len(state_bytes), sha(state_bytes)),
    )
    db.execute(
        "DELETE FROM workspace_state_snapshots WHERE tenant_id = ? AND id NOT IN ("
        "SELECT id FROM workspace_state_snapshots WHERE tenant_id = ? ORDER BY id DESC LIMIT ?"
        ")",
        (tenant_id, tenant_id, WORKSPACE_SNAPSHOT_LIMIT),
    )
    return snapshot_id


def tenant_lifecycle_summary(db, tenant, user):
    tenant_id = tenant["id"]
    counts = {
        "users": db.execute("SELECT COUNT(*) FROM users WHERE tenant_id = ?", (tenant_id,)).fetchone()[0],
        "platformAdmins": db.execute("SELECT COUNT(*) FROM users WHERE tenant_id = ? AND platform_admin = 1", (tenant_id,)).fetchone()[0],
        "sessions": db.execute("SELECT COUNT(*) FROM sessions WHERE tenant_id = ?", (tenant_id,)).fetchone()[0],
        "invitations": db.execute("SELECT COUNT(*) FROM invitations WHERE tenant_id = ?", (tenant_id,)).fetchone()[0],
        "files": db.execute("SELECT COUNT(*) FROM files WHERE tenant_id = ?", (tenant_id,)).fetchone()[0],
        "snapshots": db.execute("SELECT COUNT(*) FROM workspace_state_snapshots WHERE tenant_id = ?", (tenant_id,)).fetchone()[0],
        "auditEvents": db.execute("SELECT COUNT(*) FROM audit_log WHERE tenant_id = ?", (tenant_id,)).fetchone()[0],
        "notificationStates": db.execute("SELECT COUNT(*) FROM notification_states WHERE tenant_id = ?", (tenant_id,)).fetchone()[0],
        "notificationDeliveries": db.execute("SELECT COUNT(*) FROM notification_deliveries WHERE tenant_id = ?", (tenant_id,)).fetchone()[0],
        "workspaces": db.execute("SELECT COUNT(*) FROM tenant_workspace_state WHERE tenant_id = ?", (tenant_id,)).fetchone()[0],
    }
    file_bytes = db.execute("SELECT COALESCE(SUM(size), 0) FROM files WHERE tenant_id = ?", (tenant_id,)).fetchone()[0] or 0
    latest_activity = db.execute(
        "SELECT MAX(value) FROM ("
        "SELECT MAX(updated_at) AS value FROM tenant_workspace_state WHERE tenant_id = ? "
        "UNION ALL SELECT MAX(uploaded_at) FROM files WHERE tenant_id = ? "
        "UNION ALL SELECT MAX(ts) FROM audit_log WHERE tenant_id = ? "
        "UNION ALL SELECT MAX(updated_at) FROM notification_states WHERE tenant_id = ? "
        "UNION ALL SELECT MAX(COALESCE(sent_at,last_attempt_at,created_at)) FROM notification_deliveries WHERE tenant_id = ?"
        ")",
        (tenant_id, tenant_id, tenant_id, tenant_id, tenant_id),
    ).fetchone()[0]
    latest_backup = max((path.stat().st_mtime for path in BACKUPS.glob("*.ismsbak")), default=0)
    latest_backup_age_days = int((time.time() - latest_backup) // 86400) if latest_backup else None
    blockers = []
    if tenant_id == DEFAULT_TENANT_ID:
        blockers.append("Interner Standardmandant ist geschützt.")
    if tenant_id == user.get("tenant_id"):
        blockers.append("Aktuell geöffneter Mandant kann nicht bereinigt werden.")
    if tenant_id == user.get("home_tenant_id"):
        blockers.append("Heimatmandant des Platform Admins ist geschützt.")
    if counts["platformAdmins"]:
        blockers.append("Mandant ist Heimatmandant mindestens eines Platform Admins.")
    if tenant["status"] != "archived":
        blockers.append("Mandant muss zuerst archiviert werden.")
    if bool(tenant["legal_hold"]):
        blockers.append("Legal Hold verhindert die Bereinigung.")
    retention_until = tenant["retention_until"]
    if not retention_until:
        blockers.append("Aufbewahrungsende ist nicht festgelegt.")
    elif retention_until > now():
        blockers.append("Aufbewahrungsfrist ist noch nicht abgelaufen.")
    if latest_backup_age_days is None or latest_backup_age_days > 7:
        blockers.append("Aktuelles System-Backup der letzten 7 Tage fehlt.")
    return {
        "id": tenant_id,
        "name": tenant["name"],
        "slug": tenant["slug"],
        "status": tenant["status"],
        "createdAt": tenant["created_at"],
        "updatedAt": tenant["updated_at"],
        "archivedAt": tenant["archived_at"],
        "retentionUntil": retention_until,
        "legalHold": bool(tenant["legal_hold"]),
        "lifecycleNote": tenant["lifecycle_note"] or "",
        "lastActivityAt": latest_activity,
        "fileBytes": file_bytes,
        "counts": counts,
        "latestBackupAt": int(latest_backup) if latest_backup else None,
        "latestBackupAgeDays": latest_backup_age_days,
        "purgeEligible": not blockers,
        "purgeBlockers": blockers,
    }


def collect_operational_signals(db):
    signals = []

    def add(
        key,
        severity,
        source,
        title,
        detail,
        scope="Plattform",
        action_view="production",
        remediation_action=None,
        remediation_label=None,
    ):
        signals.append({
            "key": key,
            "severity": severity,
            "source": source,
            "scope": scope,
            "title": title,
            "detail": detail,
            "actionView": action_view,
            "remediationAction": remediation_action,
            "remediationLabel": remediation_label,
        })

    data_dir_ready = DATA.exists() and os.access(DATA, os.W_OK)
    if not data_dir_ready:
        add("platform:data-directory", "critical", "Systemdiagnose", "Datenverzeichnis ist nicht beschreibbar", str(DATA))

    db_ready = DATABASE.storage_ready()
    try:
        quick_check_result = DATABASE.integrity_check(db)
    except Exception as exc:
        quick_check_result = str(exc)
    if not db_ready or quick_check_result != "ok":
        add("platform:database-integrity", "critical", "Systemdiagnose", "Datenbankintegrität prüfen", f"{DATABASE.dialect} check={quick_check_result}")

    audit_integrity = verify_audit_hash_chain(db, all_tenants=True)
    if not audit_integrity["valid"]:
        affected_chains = [chain for chain in audit_integrity["chains"] if not chain["valid"]]
        invalid_events = sum(len(chain["invalidEvents"]) for chain in affected_chains)
        tenant_labels = ", ".join(str(chain["tenantId"]) for chain in affected_chains[:5])
        suffix = f" Betroffene Ketten: {tenant_labels}." if tenant_labels else ""
        add(
            "platform:audit-chain-integrity",
            "critical",
            "Audit Trail",
            "Integritätsabweichung im Audit Trail",
            f"Die Hash-Verkettung meldet {invalid_events} auffällige Ereignis(se) in {len(affected_chains)} Mandantenkette(n).{suffix}",
            action_view="audittrail",
        )

    backup_files = sorted(BACKUPS.glob("*.ismsbak"), key=lambda item: item.stat().st_mtime, reverse=True)
    latest_backup = backup_files[0] if backup_files else None
    latest_backup_age_days = int((time.time() - latest_backup.stat().st_mtime) // 86400) if latest_backup else None
    if latest_backup_age_days is None:
        add("platform:system-backup", "critical", "Backup & Recovery", "Kein System-Backup vorhanden", "Vor produktiver Nutzung ein verschlüsseltes System-Backup erstellen.", action_view="backup")
    elif latest_backup_age_days > 30:
        severity = "critical" if latest_backup_age_days > 45 else "warning"
        add("platform:system-backup", severity, "Backup & Recovery", "System-Backup ist veraltet", f"Letztes System-Backup vor {latest_backup_age_days} Tagen.", action_view="backup")

    last_restore_at = db.execute(
        "SELECT MAX(ts) FROM audit_log WHERE action IN ('state_restored','restore_drill_verified')"
    ).fetchone()[0]
    if not last_restore_at:
        add("platform:restore-drill", "warning", "Backup & Recovery", "Restore-Drill fehlt", "Es wurde noch keine Wiederherstellung im Audit Trail protokolliert.", action_view="backup")
    elif now() - int(last_restore_at) > 180 * 86400:
        age = int((now() - int(last_restore_at)) // 86400)
        add("platform:restore-drill", "warning", "Backup & Recovery", "Restore-Drill erneut durchführen", f"Letzter protokollierter Restore vor {age} Tagen.", action_view="backup")

    privileged_without_mfa = db.execute(
        "SELECT COUNT(*) FROM users WHERE active = 1 AND (role IN ('admin','consultant','manager') OR platform_admin = 1) AND mfa_enabled = 0"
    ).fetchone()[0]
    if MFA_ENFORCEMENT != "write":
        add(
            "platform:mfa-write-enforcement",
            "critical",
            "Zugriffsschutz",
            "MFA-Schreibschutz für privilegierte Rollen ist deaktiviert",
            "Privilegierte Änderungen werden technisch noch nicht von einer aktivierten MFA-Einrichtung abhängig gemacht.",
            action_view="account",
        )
    if privileged_without_mfa:
        add("platform:privileged-mfa", "critical", "Zugriffsschutz", "Privilegierte Konten ohne MFA", f"{privileged_without_mfa} privilegierte aktive Konten sind noch nicht durch MFA geschützt.", action_view="team")

    scanner_health = MALWARE_SCANNER.health()
    if not scanner_health["ready"]:
        add(
            "platform:malware-scanner",
            "critical" if scanner_health["required"] else "warning",
            "Dateiablage",
            "Malware-Scanner ist nicht einsatzbereit",
            scanner_health["detail"],
            action_view="quarantine",
        )
    quarantine_count = db.execute("SELECT COUNT(*) FROM files WHERE quarantined = 1").fetchone()[0]
    if quarantine_count:
        add(
            "platform:file-quarantine",
            "critical",
            "Dateiablage",
            "Dateien befinden sich in Quarantäne",
            f"{quarantine_count} isolierte Datei(en) müssen administrativ geprüft oder gelöscht werden.",
            action_view="quarantine",
        )

    file_rows = db.execute("SELECT id,stored_name FROM files").fetchall()
    try:
        missing_blobs = sum(1 for row in file_rows if not FILE_STORAGE.exists(row["stored_name"]))
        physical_blobs = set(FILE_STORAGE.list_names(suffix=".bin"))
    except StorageError as exc:
        missing_blobs = len(file_rows)
        physical_blobs = set()
        add("platform:file-storage", "critical", "Dateiablage", "Dateiablage ist nicht erreichbar", str(exc), action_view="production")
    if missing_blobs:
        add("platform:missing-file-blobs", "critical", "Dateiablage", "Nachweisdateien fehlen in der Ablage", f"{missing_blobs} Datei-Metadatensätze haben keine passende verschlüsselte Datei.", action_view="production")
    db_blobs = {row["stored_name"] for row in file_rows}
    orphan_blobs = len(physical_blobs.difference(db_blobs))
    if orphan_blobs:
        add("platform:orphan-file-blobs", "warning", "Dateiablage", "Verwaiste verschlüsselte Dateien prüfen", f"{orphan_blobs} verschlüsselte Blob-Dateien haben keinen Datenbankeintrag.", action_view="production")

    missing_workspace = db.execute(
        "SELECT COUNT(*) FROM tenants t LEFT JOIN tenant_workspace_state w ON w.tenant_id = t.id WHERE t.status = 'active' AND w.tenant_id IS NULL"
    ).fetchone()[0]
    if missing_workspace:
        add("platform:missing-workspace", "critical", "Mandantenbetrieb", "Aktive Kundenräume ohne Workspace", f"{missing_workspace} aktive Kundenräume besitzen keinen Workspace-Datensatz.", action_view="production")

    tenants_without_admin = db.execute(
        "SELECT COUNT(*) FROM tenants t WHERE t.status = 'active' AND NOT EXISTS ("
        "SELECT 1 FROM users u WHERE u.tenant_id = t.id AND u.active = 1 AND u.role = 'admin'"
        ")"
    ).fetchone()[0]
    if tenants_without_admin:
        add("platform:tenant-admin", "critical", "Mandantenbetrieb", "Aktive Kundenräume ohne Admin", f"{tenants_without_admin} aktive Kundenräume haben keinen aktiven Kundenraum-Admin.", action_view="team")

    expired_sessions = db.execute("SELECT COUNT(*) FROM sessions WHERE expires_at <= ?", (now(),)).fetchone()[0]
    if expired_sessions:
        add(
            "platform:expired-sessions",
            "warning",
            "Sitzungsbetrieb",
            "Abgelaufene Sessions bereinigen",
            f"{expired_sessions} abgelaufene Sessions können kontrolliert entfernt werden.",
            action_view="operations",
            remediation_action="cleanup-expired-sessions",
            remediation_label="Sessions sicher bereinigen",
        )

    expired_invitations = db.execute(
        "SELECT COUNT(*) FROM invitations WHERE status = 'pending' AND expires_at <= ?",
        (now(),),
    ).fetchone()[0]
    if expired_invitations:
        add(
            "platform:expired-invitations",
            "warning",
            "Einladungsbetrieb",
            "Abgelaufene Einladungen aktualisieren",
            f"{expired_invitations} nicht mehr gültige Einladungen sind noch als offen markiert.",
            action_view="operations",
            remediation_action="expire-stale-invitations",
            remediation_label="Einladungen aktualisieren",
        )

    delivery_config = notification_delivery_config_payload()
    delivery_counts = db.execute(
        "SELECT "
        "SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failed, "
        "SUM(CASE WHEN status IN ('queued','retry') AND COALESCE(next_attempt_at,0) <= ? THEN 1 ELSE 0 END) AS due, "
        "SUM(CASE WHEN status='delivering' AND COALESCE(last_attempt_at,created_at) < ? THEN 1 ELSE 0 END) AS stale, "
        "MIN(CASE WHEN status IN ('queued','retry','delivering') THEN created_at END) AS oldest_pending_at "
        "FROM notification_deliveries",
        (now(), now() - 600),
    ).fetchone()
    if delivery_config["enabled"] and not delivery_config["configured"]:
        add(
            "platform:notification-delivery-unconfigured",
            "critical",
            "Benachrichtigungszustellung",
            "Externe Zustellung aktiv, aber kein Kanal konfiguriert",
            "Serverseitige Zustellung ist aktiviert. Webhook oder SMTP sind jedoch nicht vollständig konfiguriert.",
            action_view="operations",
        )
    if delivery_config["enabled"] and delivery_config["runtime"].get("lastError"):
        add(
            "platform:notification-delivery-runtime",
            "warning",
            "Benachrichtigungszustellung",
            "Zustellqueue meldet einen Laufzeitfehler",
            str(delivery_config["runtime"].get("lastError"))[:500],
            action_view="operations",
        )
    stale_deliveries = int(delivery_counts["stale"] or 0)
    if stale_deliveries:
        add(
            "platform:notification-delivery-stale",
            "critical",
            "Benachrichtigungszustellung",
            "Zustellversuche hängen fest",
            f"{stale_deliveries} Zustellversuch(e) sind seit mehr als 10 Minuten im Status 'wird zugestellt'.",
            action_view="operations",
        )
    failed_deliveries = int(delivery_counts["failed"] or 0)
    if failed_deliveries:
        add(
            "platform:notification-delivery-failed",
            "warning",
            "Benachrichtigungszustellung",
            "Fehlgeschlagene externe Zustellungen prüfen",
            f"{failed_deliveries} Zustellung(en) sind fehlgeschlagen und benötigen eine bewusste Prüfung oder einen erneuten Versuch.",
            action_view="notifications",
        )
    due_deliveries = int(delivery_counts["due"] or 0)
    oldest_pending_at = delivery_counts["oldest_pending_at"]
    if delivery_config["enabled"] and due_deliveries and oldest_pending_at and oldest_pending_at < now() - max(300, NOTIFICATION_DELIVERY_SECONDS * 3):
        add(
            "platform:notification-delivery-backlog",
            "warning",
            "Benachrichtigungszustellung",
            "Zustellqueue arbeitet Rückstand ab",
            f"{due_deliveries} Zustellung(en) sind fällig. Ältester offener Eintrag seit {int((now() - oldest_pending_at) // 60)} Minute(n).",
            action_view="operations",
        )

    job_counts = db.execute(
        "SELECT "
        "SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failed, "
        "SUM(CASE WHEN status='running' AND COALESCE(locked_at,updated_at,created_at) < ? THEN 1 ELSE 0 END) AS stale, "
        "SUM(CASE WHEN status IN ('queued','retry') AND COALESCE(next_run_at,0) <= ? THEN 1 ELSE 0 END) AS due, "
        "MIN(CASE WHEN status IN ('queued','retry') THEN created_at END) AS oldest_pending_at "
        "FROM background_jobs",
        (now() - 900, now()),
    ).fetchone()
    failed_jobs = int(job_counts["failed"] or 0)
    if failed_jobs:
        add(
            "platform:background-jobs-failed",
            "warning",
            "Hintergrundjobs",
            "Fehlgeschlagene Hintergrundjobs prüfen",
            f"{failed_jobs} Hintergrundjob(s) sind fehlgeschlagen und benötigen Retry, fachliche Einordnung oder Retention.",
            action_view="jobs",
        )
    stale_jobs = int(job_counts["stale"] or 0)
    if stale_jobs:
        add(
            "platform:background-jobs-stale",
            "critical",
            "Hintergrundjobs",
            "Hintergrundjobs hängen im Status 'Läuft'",
            f"{stale_jobs} Job(s) sind seit mehr als 15 Minuten gesperrt. Worker-Status und Serverlog prüfen.",
            action_view="jobs",
        )
    due_jobs = int(job_counts["due"] or 0)
    oldest_job_at = job_counts["oldest_pending_at"]
    if due_jobs and oldest_job_at and oldest_job_at < now() - max(300, BACKGROUND_JOB_WORKER_SECONDS * 6):
        add(
            "platform:background-jobs-backlog",
            "warning",
            "Hintergrundjobs",
            "Job-Queue arbeitet Rückstand ab",
            f"{due_jobs} Job(s) sind fällig. Ältester offener Job seit {int((now() - oldest_job_at) // 60)} Minute(n).",
            action_view="jobs",
        )
    artifact_count = 0
    artifact_bytes = 0
    for artifact in JOB_ARTIFACTS.glob("*.zip"):
        if artifact.is_file():
            artifact_count += 1
            artifact_bytes += artifact.stat().st_size
    if artifact_bytes > 500 * 1024 * 1024:
        add(
            "platform:job-artifact-storage",
            "warning",
            "Hintergrundjobs",
            "Export-Artefakte belegen viel Speicher",
            f"{artifact_count} Job-Artefakt(e) belegen {artifact_bytes} Byte. Retention im Backup-&-Recovery-Bereich prüfen.",
            action_view="backup",
        )

    return signals


def sync_operational_alerts(db, actor=None, ip=None):
    signals = collect_operational_signals(db)
    timestamp = now()
    active_keys = set()
    for signal in signals:
        key = signal["key"]
        active_keys.add(key)
        existing = db.execute(
            "SELECT status,severity,title FROM operational_alerts WHERE alert_key = ?",
            (key,),
        ).fetchone()
        if existing:
            status = "open" if existing["status"] == "resolved" else existing["status"]
            db.execute(
                "UPDATE operational_alerts SET severity=?,source=?,scope=?,title=?,detail=?,status=?,action_view=?,remediation_action=?,"
                "remediation_label=?,last_seen_at=?,resolved_at=NULL "
                "WHERE alert_key=?",
                (
                    signal["severity"], signal["source"], signal["scope"], signal["title"], signal["detail"],
                    status, signal["actionView"], signal["remediationAction"], signal["remediationLabel"], timestamp, key,
                ),
            )
            if existing["status"] == "resolved":
                audit(db, actor, "operational_alert_reopened", "operational_alert", key, {
                    "severity": signal["severity"],
                    "title": signal["title"],
                    "previousStatus": "resolved",
                    "status": "open",
                }, ip)
        else:
            db.execute(
                "INSERT INTO operational_alerts (alert_key,severity,source,scope,title,detail,status,action_view,remediation_action,"
                "remediation_label,first_seen_at,last_seen_at) VALUES (?,?,?,?,?,?,'open',?,?,?,?,?)",
                (
                    key, signal["severity"], signal["source"], signal["scope"], signal["title"], signal["detail"],
                    signal["actionView"], signal["remediationAction"], signal["remediationLabel"], timestamp, timestamp,
                ),
            )
            audit(db, actor, "operational_alert_opened", "operational_alert", key, {
                "severity": signal["severity"],
                "title": signal["title"],
                "status": "open",
            }, ip)
    open_rows = db.execute(
        "SELECT alert_key,severity,title,status FROM operational_alerts WHERE status <> 'resolved'"
    ).fetchall()
    for row in open_rows:
        if row["alert_key"] not in active_keys:
            db.execute(
                "UPDATE operational_alerts SET status='resolved',resolved_at=?,last_seen_at=? WHERE alert_key=?",
                (timestamp, timestamp, row["alert_key"]),
            )
            audit(db, actor, "operational_alert_resolved", "operational_alert", row["alert_key"], {
                "severity": row["severity"],
                "title": row["title"],
                "previousStatus": row["status"],
                "status": "resolved",
            }, ip)
    return timestamp


def operations_runtime_payload():
    with OPERATIONS_RUNTIME_LOCK:
        return dict(OPERATIONS_RUNTIME)


def mark_operations_runtime_success(refreshed_at, schedule_next=True):
    with OPERATIONS_RUNTIME_LOCK:
        OPERATIONS_RUNTIME["lastSuccessAt"] = refreshed_at
        OPERATIONS_RUNTIME["runCount"] += 1
        if schedule_next:
            OPERATIONS_RUNTIME["nextRunAt"] = refreshed_at + OPERATIONS_MONITOR_SECONDS if OPERATIONS_MONITOR_ENABLED else None


def run_operational_monitor(actor=None, ip="system-monitor", schedule_next=True):
    started = now()
    with OPERATIONS_RUNTIME_LOCK:
        OPERATIONS_RUNTIME["lastRunAt"] = started
        OPERATIONS_RUNTIME["lastError"] = ""
    try:
        with conn() as db:
            refreshed_at = sync_operational_alerts(db, actor=actor, ip=ip)
        mark_operations_runtime_success(refreshed_at, schedule_next=schedule_next)
        return refreshed_at
    except Exception as exc:
        with OPERATIONS_RUNTIME_LOCK:
            OPERATIONS_RUNTIME["lastError"] = str(exc)[:500]
            if schedule_next:
                OPERATIONS_RUNTIME["nextRunAt"] = now() + OPERATIONS_MONITOR_SECONDS if OPERATIONS_MONITOR_ENABLED else None
        return None


def operations_monitor_loop():
    while not OPERATIONS_MONITOR_STOP.wait(OPERATIONS_MONITOR_SECONDS):
        run_operational_monitor()


def start_operations_monitor():
    timestamp = now()
    with OPERATIONS_RUNTIME_LOCK:
        OPERATIONS_RUNTIME["startedAt"] = timestamp
        OPERATIONS_RUNTIME["nextRunAt"] = timestamp if OPERATIONS_MONITOR_ENABLED else None
    run_operational_monitor()
    if not OPERATIONS_MONITOR_ENABLED:
        return None
    thread = threading.Thread(target=operations_monitor_loop, name="sfm-operations-monitor", daemon=True)
    thread.start()
    return thread


def operational_alerts_payload(db, refreshed_at=None):
    rows = db.execute(
        "SELECT a.alert_key,a.severity,a.source,a.scope,a.title,a.detail,a.status,a.action_view,a.remediation_action,"
        "a.remediation_label,a.first_seen_at,a.last_seen_at,"
        "a.acknowledged_at,a.resolved_at,u.username AS acknowledged_by_username "
        "FROM operational_alerts a LEFT JOIN users u ON u.id = a.acknowledged_by "
        "ORDER BY CASE a.status WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 ELSE 2 END,"
        "CASE a.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,a.last_seen_at DESC"
    ).fetchall()
    alerts = [{
        "key": row["alert_key"],
        "severity": row["severity"],
        "source": row["source"],
        "scope": row["scope"],
        "title": row["title"],
        "detail": row["detail"],
        "status": row["status"],
        "actionView": row["action_view"] or "production",
        "remediationAction": row["remediation_action"] or "",
        "remediationLabel": row["remediation_label"] or "",
        "firstSeenAt": row["first_seen_at"],
        "lastSeenAt": row["last_seen_at"],
        "acknowledgedAt": row["acknowledged_at"],
        "acknowledgedBy": row["acknowledged_by_username"] or "",
        "resolvedAt": row["resolved_at"],
    } for row in rows]
    active = [row for row in alerts if row["status"] != "resolved"]
    return {
        "alerts": alerts,
        "summary": {
            "open": sum(1 for row in alerts if row["status"] == "open"),
            "acknowledged": sum(1 for row in alerts if row["status"] == "acknowledged"),
            "resolved": sum(1 for row in alerts if row["status"] == "resolved"),
            "critical": sum(1 for row in active if row["severity"] == "critical"),
            "warning": sum(1 for row in active if row["severity"] == "warning"),
            "active": len(active),
        },
        "refreshedAt": refreshed_at or now(),
        "maintenance": maintenance_status_payload(db),
        "runtime": operations_runtime_payload(),
        "notificationDelivery": notification_delivery_operations_payload(db),
    }


def notification_states_payload(db, user):
    rows = db.execute(
        "SELECT notification_id,read_at,dismissed_at,escalated_at,updated_at "
        "FROM notification_states WHERE tenant_id = ? AND user_id = ? "
        "ORDER BY updated_at DESC LIMIT 2000",
        (user["tenant_id"], user["id"]),
    ).fetchall()
    states = [{
        "id": row["notification_id"],
        "readAt": row["read_at"],
        "dismissedAt": row["dismissed_at"],
        "escalatedAt": row["escalated_at"],
        "updatedAt": row["updated_at"],
    } for row in rows]
    return {
        "states": states,
        "summary": {
            "stored": len(states),
            "read": sum(1 for row in rows if row["read_at"]),
            "dismissed": sum(1 for row in rows if row["dismissed_at"]),
            "escalated": sum(1 for row in rows if row["escalated_at"]),
        },
    }


def masked_email(value):
    local, separator, domain = str(value or "").partition("@")
    if not separator:
        return "Konfigurierter Empfänger"
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}{'*' * max(2, len(local) - len(visible))}@{domain}"


def notification_delivery_channel_config(channel):
    if channel == "webhook":
        return {
            "configured": bool(NOTIFICATION_WEBHOOK_URL and NOTIFICATION_WEBHOOK_SECRET),
            "destinationLabel": "Konfigurierter, signierter Webhook",
        }
    if channel == "smtp":
        return {
            "configured": bool(NOTIFICATION_SMTP_HOST and NOTIFICATION_SMTP_FROM and NOTIFICATION_SMTP_TO),
            "destinationLabel": masked_email(NOTIFICATION_SMTP_TO),
        }
    return {"configured": False, "destinationLabel": "Nicht konfiguriert"}


def notification_delivery_runtime_payload():
    with NOTIFICATION_DELIVERY_RUNTIME_LOCK:
        return dict(NOTIFICATION_DELIVERY_RUNTIME)


def notification_delivery_config_payload():
    webhook = notification_delivery_channel_config("webhook")
    smtp = notification_delivery_channel_config("smtp")
    return {
        "enabled": NOTIFICATION_DELIVERY_ENABLED,
        "channels": {
            "webhook": webhook,
            "smtp": smtp,
        },
        "configured": bool(webhook["configured"] or smtp["configured"]),
        "runtime": notification_delivery_runtime_payload(),
    }


def notification_delivery_public(row):
    return {
        "id": row["id"],
        "notificationId": row["notification_id"],
        "channel": row["channel"],
        "destinationLabel": row["destination_label"],
        "status": row["status"],
        "attemptCount": int(row["attempt_count"] or 0),
        "nextAttemptAt": row["next_attempt_at"],
        "createdAt": row["created_at"],
        "createdBy": row["created_by_username"] or "",
        "lastAttemptAt": row["last_attempt_at"],
        "sentAt": row["sent_at"],
        "lastError": row["last_error"] or "",
        "responseCode": row["response_code"],
    }


def notification_delivery_operations_payload(db):
    timestamp = now()
    rows = db.execute(
        "SELECT d.id,d.tenant_id,d.notification_id,d.channel,d.destination_label,d.status,d.attempt_count,"
        "d.next_attempt_at,d.created_at,d.last_attempt_at,d.sent_at,d.last_error,d.response_code,"
        "u.username AS created_by_username,t.name AS tenant_name,t.slug AS tenant_slug "
        "FROM notification_deliveries d "
        "LEFT JOIN users u ON u.id = d.created_by "
        "LEFT JOIN tenants t ON t.id = d.tenant_id "
        "ORDER BY COALESCE(d.sent_at,d.last_attempt_at,d.created_at) DESC LIMIT 20"
    ).fetchall()
    counts = db.execute(
        "SELECT "
        "SUM(CASE WHEN status IN ('queued','retry','delivering') THEN 1 ELSE 0 END) AS pending, "
        "SUM(CASE WHEN status='sent' THEN 1 ELSE 0 END) AS sent, "
        "SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failed, "
        "SUM(CASE WHEN status IN ('queued','retry') AND COALESCE(next_attempt_at,0) <= ? THEN 1 ELSE 0 END) AS due, "
        "SUM(CASE WHEN status='delivering' AND COALESCE(last_attempt_at,created_at) < ? THEN 1 ELSE 0 END) AS stale, "
        "MIN(CASE WHEN status IN ('queued','retry','delivering') THEN created_at END) AS oldest_pending_at, "
        "MAX(CASE WHEN status='sent' THEN sent_at END) AS last_sent_at, "
        "MAX(CASE WHEN status='failed' THEN last_attempt_at END) AS last_failed_at "
        "FROM notification_deliveries",
        (timestamp, timestamp - 600),
    ).fetchone()
    return {
        "config": notification_delivery_config_payload(),
        "summary": {
            "pending": int(counts["pending"] or 0),
            "sent": int(counts["sent"] or 0),
            "failed": int(counts["failed"] or 0),
            "due": int(counts["due"] or 0),
            "stale": int(counts["stale"] or 0),
            "oldestPendingAt": counts["oldest_pending_at"],
            "lastSentAt": counts["last_sent_at"],
            "lastFailedAt": counts["last_failed_at"],
        },
        "recent": [{
            **notification_delivery_public(row),
            "tenantId": row["tenant_id"],
            "tenantName": row["tenant_name"] or row["tenant_id"],
            "tenantSlug": row["tenant_slug"] or "",
        } for row in rows],
    }


def notification_deliveries_payload(db, user):
    rows = db.execute(
        "SELECT d.id,d.notification_id,d.channel,d.destination_label,d.status,d.attempt_count,d.next_attempt_at,"
        "d.created_at,d.last_attempt_at,d.sent_at,d.last_error,d.response_code,u.username AS created_by_username "
        "FROM notification_deliveries d LEFT JOIN users u ON u.id = d.created_by "
        "WHERE d.tenant_id = ? ORDER BY d.created_at DESC LIMIT 250",
        (user["tenant_id"],),
    ).fetchall()
    deliveries = [notification_delivery_public(row) for row in rows]
    return {
        "config": notification_delivery_config_payload(),
        "deliveries": deliveries,
        "summary": {
            "queued": sum(1 for row in rows if row["status"] in {"queued", "retry", "delivering"}),
            "sent": sum(1 for row in rows if row["status"] == "sent"),
            "failed": sum(1 for row in rows if row["status"] == "failed"),
            "total": len(rows),
        },
    }


def clean_delivery_notification(payload):
    if not isinstance(payload, dict):
        payload = {}
    try:
        priority = int(payload.get("priority") or 0)
    except (TypeError, ValueError):
        priority = 0
    return {
        "id": metadata_value(payload.get("id"), 300),
        "type": metadata_value(payload.get("type"), 120),
        "title": metadata_value(payload.get("title"), 300),
        "text": metadata_value(payload.get("text"), 1200),
        "status": metadata_value(payload.get("status"), 120),
        "priority": max(0, min(100, priority)),
        "module": metadata_value(payload.get("module") or payload.get("view"), 120),
        "meta": metadata_value(payload.get("meta"), 500),
        "date": metadata_value(payload.get("date"), 120),
    }


def send_notification_webhook(delivery_id, payload):
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(NOTIFICATION_WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        NOTIFICATION_WEBHOOK_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "SFM-Compliance-Notification-Delivery/1.0",
            "X-SFM-Delivery-Id": delivery_id,
            "X-SFM-Signature": f"sha256={signature}",
        },
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        return int(response.getcode() or 200)


def send_notification_email(delivery_id, payload):
    notification = payload.get("notification") or {}
    message = EmailMessage()
    message["From"] = NOTIFICATION_SMTP_FROM
    message["To"] = NOTIFICATION_SMTP_TO
    message["Subject"] = f"SFM Compliance: {notification.get('title') or 'Benachrichtigung'}"
    message["X-SFM-Delivery-Id"] = delivery_id
    message.set_content(
        "\n".join([
            "SFM Compliance Benachrichtigung",
            "",
            f"Typ: {notification.get('type') or '-'}",
            f"Titel: {notification.get('title') or '-'}",
            f"Status: {notification.get('status') or '-'}",
            f"Priorität: {notification.get('priority') or 0}",
            f"Bereich: {notification.get('module') or '-'}",
            "",
            notification.get("text") or "",
            "",
            f"Hinweis: {notification.get('meta') or '-'}",
            "",
            "Diese Zustellung ist ein Hinweis und keine fachliche Freigabe.",
        ])
    )
    with smtplib.SMTP(NOTIFICATION_SMTP_HOST, NOTIFICATION_SMTP_PORT, timeout=12) as client:
        client.ehlo()
        if NOTIFICATION_SMTP_TLS:
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
        if NOTIFICATION_SMTP_USER:
            client.login(NOTIFICATION_SMTP_USER, NOTIFICATION_SMTP_PASSWORD)
        client.send_message(message)
    return 250


def account_recovery_delivery_configured():
    return bool(ACCOUNT_RECOVERY_ENABLED and NOTIFICATION_SMTP_HOST and NOTIFICATION_SMTP_FROM)


def invitation_delivery_configured():
    return bool(INVITATION_EMAIL_ENABLED and NOTIFICATION_SMTP_HOST and NOTIFICATION_SMTP_FROM)


def send_invitation_email(destination, display_name, tenant_name, role_label, accept_url, expires_at):
    message = EmailMessage()
    message["From"] = NOTIFICATION_SMTP_FROM
    message["To"] = destination
    message["Subject"] = f"SFM Compliance: Einladung zu {tenant_name}"
    message["Auto-Submitted"] = "auto-generated"
    greeting = f"Hallo {display_name}," if display_name else "Hallo,"
    message.set_content(
        "\n".join([
            greeting,
            "",
            f"du wurdest zum SFM-Compliance-Workspace „{tenant_name}“ eingeladen.",
            f"Vorgesehene Rolle: {role_label}",
            "",
            "Über diesen einmaligen Link legst du deinen Benutzernamen und dein eigenes Passwort fest:",
            accept_url,
            "",
            f"Der Link ist bis {datetime.fromtimestamp(expires_at, tz=timezone.utc).strftime('%d.%m.%Y %H:%M UTC')} gültig.",
            "Bei einem erneuten Versand wird dieser Link automatisch ungültig.",
            "",
            "Wenn du diese Einladung nicht erwartest, öffne den Link nicht und informiere den Absender.",
            "Fachliche Freigaben in der Plattform bleiben beim Berater/Admin.",
        ])
    )
    with smtplib.SMTP(NOTIFICATION_SMTP_HOST, NOTIFICATION_SMTP_PORT, timeout=12) as client:
        client.ehlo()
        if NOTIFICATION_SMTP_TLS:
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
        if NOTIFICATION_SMTP_USER:
            client.login(NOTIFICATION_SMTP_USER, NOTIFICATION_SMTP_PASSWORD)
        client.send_message(message)


def deliver_invitation(invitation_id, destination, display_name, tenant_name, role, accept_url, expires_at, actor, ip):
    if not invitation_delivery_configured():
        with conn() as db:
            db.execute(
                "UPDATE invitations SET delivery_status = 'manual', delivery_error = NULL WHERE id = ?",
                (invitation_id,),
            )
            audit(db, actor, "invitation_manual_delivery", "invitation", invitation_id, {
                "email": destination,
                "reason": "smtp_not_configured",
            }, ip)
        return "manual"
    sent_at = now()
    try:
        send_invitation_email(
            destination,
            display_name,
            tenant_name,
            ROLE_DETAILS.get(role, {}).get("label", role),
            accept_url,
            expires_at,
        )
    except Exception as exc:
        error_detail = type(exc).__name__
        with conn() as db:
            db.execute(
                "UPDATE invitations SET delivery_status = 'failed', delivery_attempts = delivery_attempts + 1, "
                "last_sent_at = ?, delivery_error = ? WHERE id = ?",
                (sent_at, error_detail, invitation_id),
            )
            audit(db, actor, "invitation_delivery_failed", "invitation", invitation_id, {
                "email": destination,
                "error": error_detail,
            }, ip)
        return "failed"
    with conn() as db:
        db.execute(
            "UPDATE invitations SET delivery_status = 'delivered', delivery_attempts = delivery_attempts + 1, "
            "last_sent_at = ?, delivered_at = ?, delivery_error = NULL WHERE id = ?",
            (sent_at, sent_at, invitation_id),
        )
        audit(db, actor, "invitation_delivered", "invitation", invitation_id, {
            "email": destination,
            "deliveredAt": sent_at,
        }, ip)
    return "delivered"


def send_account_recovery_email(destination, recovery_url):
    message = EmailMessage()
    message["From"] = NOTIFICATION_SMTP_FROM
    message["To"] = destination
    message["Subject"] = "SFM Compliance: Passwort wiederherstellen"
    message.set_content(
        "\n".join([
            "SFM Compliance Kontowiederherstellung",
            "",
            "Für dein Konto wurde eine Passwort-Wiederherstellung angefordert.",
            f"Der Link ist {ACCOUNT_RECOVERY_TOKEN_SECONDS // 60} Minuten gültig und kann nur einmal verwendet werden:",
            "",
            recovery_url,
            "",
            "Wenn du diese Anfrage nicht gestellt hast, ignoriere diese Nachricht und informiere bei Bedarf deinen Administrator.",
            "MFA und bestehende Rollenrechte werden durch die Wiederherstellung nicht verändert.",
        ])
    )
    with smtplib.SMTP(NOTIFICATION_SMTP_HOST, NOTIFICATION_SMTP_PORT, timeout=12) as client:
        client.ehlo()
        if NOTIFICATION_SMTP_TLS:
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
        if NOTIFICATION_SMTP_USER:
            client.login(NOTIFICATION_SMTP_USER, NOTIFICATION_SMTP_PASSWORD)
        client.send_message(message)


def deliver_account_recovery(reset_id, user_id, destination, recovery_url, ip):
    delivered_at = None
    error_detail = ""
    try:
        send_account_recovery_email(destination, recovery_url)
        delivered_at = now()
    except Exception as exc:
        error_detail = f"{type(exc).__name__}: {str(exc)[:240]}"
    with conn() as db:
        row = db.execute("SELECT id,used_at FROM password_reset_tokens WHERE id = ? AND user_id = ?", (reset_id, user_id)).fetchone()
        if not row:
            return
        if delivered_at:
            db.execute("UPDATE password_reset_tokens SET delivered_at = ? WHERE id = ?", (delivered_at, reset_id))
            audit(db, None, "password_recovery_delivered", "user", str(user_id), {"resetId": reset_id}, ip)
        else:
            db.execute("UPDATE password_reset_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL", (now(), reset_id))
            audit(db, None, "password_recovery_delivery_failed", "user", str(user_id), {
                "resetId": reset_id,
                "error": error_detail,
            }, ip)


def process_notification_delivery(delivery_id):
    attempt_at = now()
    with conn() as db:
        row = db.execute(
            "SELECT d.*,u.username AS created_by_username FROM notification_deliveries d "
            "LEFT JOIN users u ON u.id = d.created_by WHERE d.id = ?",
            (delivery_id,),
        ).fetchone()
        if not row or row["status"] not in {"queued", "retry"}:
            return False
        attempt_count = int(row["attempt_count"] or 0) + 1
        db.execute(
            "UPDATE notification_deliveries SET status='delivering',attempt_count=?,last_attempt_at=?,last_error=NULL "
            "WHERE id=?",
            (attempt_count, attempt_at, delivery_id),
        )
        delivery = dict(row)
        delivery["attempt_count"] = attempt_count

    actor = {
        "id": delivery.get("created_by"),
        "username": delivery.get("created_by_username") or "system-delivery",
        "tenant_id": delivery["tenant_id"],
    }
    try:
        payload = json.loads(delivery["payload_json"])
        if delivery["channel"] == "webhook":
            response_code = send_notification_webhook(delivery_id, payload)
        elif delivery["channel"] == "smtp":
            response_code = send_notification_email(delivery_id, payload)
        else:
            raise ValueError("unsupported delivery channel")
        with conn() as db:
            db.execute(
                "UPDATE notification_deliveries SET status='sent',sent_at=?,next_attempt_at=NULL,last_error=NULL,response_code=? "
                "WHERE id=?",
                (now(), response_code, delivery_id),
            )
            audit(db, actor, "notification_delivery_sent", "notification_delivery", delivery_id, {
                "notificationId": delivery["notification_id"],
                "channel": delivery["channel"],
                "attemptCount": delivery["attempt_count"],
                "responseCode": response_code,
            }, "system-delivery")
        return True
    except Exception as exc:
        error_text = metadata_value(str(exc), 500) or "delivery failed"
        final_failure = delivery["attempt_count"] >= NOTIFICATION_DELIVERY_MAX_ATTEMPTS
        next_attempt = None if final_failure else now() + min(3600, 30 * (2 ** max(0, delivery["attempt_count"] - 1)))
        status = "failed" if final_failure else "retry"
        response_code = exc.code if isinstance(exc, urllib.error.HTTPError) else None
        with conn() as db:
            db.execute(
                "UPDATE notification_deliveries SET status=?,next_attempt_at=?,last_error=?,response_code=? WHERE id=?",
                (status, next_attempt, error_text, response_code, delivery_id),
            )
            audit(db, actor, "notification_delivery_failed" if final_failure else "notification_delivery_retried", "notification_delivery", delivery_id, {
                "notificationId": delivery["notification_id"],
                "channel": delivery["channel"],
                "attemptCount": delivery["attempt_count"],
                "nextAttemptAt": next_attempt,
                "error": error_text,
            }, "system-delivery")
        return False


def run_notification_delivery_queue():
    timestamp = now()
    with NOTIFICATION_DELIVERY_RUNTIME_LOCK:
        NOTIFICATION_DELIVERY_RUNTIME["lastRunAt"] = timestamp
        NOTIFICATION_DELIVERY_RUNTIME["lastError"] = ""
    if not NOTIFICATION_DELIVERY_ENABLED:
        return 0
    processed = 0
    try:
        with conn() as db:
            db.execute(
                "UPDATE notification_deliveries SET status='retry',next_attempt_at=? "
                "WHERE status='delivering' AND last_attempt_at < ?",
                (timestamp, timestamp - 600),
            )
            rows = db.execute(
                "SELECT id FROM notification_deliveries WHERE status IN ('queued','retry') "
                "AND COALESCE(next_attempt_at,0) <= ? ORDER BY created_at LIMIT 20",
                (timestamp,),
            ).fetchall()
        for row in rows:
            process_notification_delivery(row["id"])
            processed += 1
        with NOTIFICATION_DELIVERY_RUNTIME_LOCK:
            NOTIFICATION_DELIVERY_RUNTIME["lastSuccessAt"] = now()
            NOTIFICATION_DELIVERY_RUNTIME["runCount"] += 1
            NOTIFICATION_DELIVERY_RUNTIME["nextRunAt"] = now() + NOTIFICATION_DELIVERY_SECONDS
        return processed
    except Exception as exc:
        with NOTIFICATION_DELIVERY_RUNTIME_LOCK:
            NOTIFICATION_DELIVERY_RUNTIME["lastError"] = metadata_value(str(exc), 500)
            NOTIFICATION_DELIVERY_RUNTIME["nextRunAt"] = now() + NOTIFICATION_DELIVERY_SECONDS
        return processed


def notification_delivery_loop():
    while not NOTIFICATION_DELIVERY_STOP.wait(NOTIFICATION_DELIVERY_SECONDS):
        run_notification_delivery_queue()


def start_notification_delivery_worker():
    timestamp = now()
    with NOTIFICATION_DELIVERY_RUNTIME_LOCK:
        NOTIFICATION_DELIVERY_RUNTIME["startedAt"] = timestamp
        NOTIFICATION_DELIVERY_RUNTIME["nextRunAt"] = timestamp + NOTIFICATION_DELIVERY_SECONDS if NOTIFICATION_DELIVERY_ENABLED else None
    if not NOTIFICATION_DELIVERY_ENABLED:
        return None
    run_notification_delivery_queue()
    thread = threading.Thread(target=notification_delivery_loop, name="sfm-notification-delivery", daemon=True)
    thread.start()
    return thread


def job_actor(row):
    return {
        "id": row["created_by"],
        "username": row["created_by_username"] or "system-job",
        "role": row["created_by_role"] or "admin",
        "tenant_id": row["tenant_id"] or DEFAULT_TENANT_ID,
        "platform_admin": bool(row["created_by_platform_admin"]),
    }


def background_job_public(row):
    result = {}
    payload = {}
    try:
        payload = json.loads(row["payload_json"] or "{}")
    except (TypeError, ValueError):
        payload = {}
    try:
        result = json.loads(row["result_json"] or "{}")
    except (TypeError, ValueError):
        result = {}
    return {
        "id": row["id"],
        "tenantId": row["tenant_id"],
        "tenantName": row["tenant_name"] or row["tenant_id"] or "Plattform",
        "jobType": row["job_type"],
        "label": BACKGROUND_JOB_TYPES.get(row["job_type"], {}).get("label", row["job_type"]),
        "description": BACKGROUND_JOB_TYPES.get(row["job_type"], {}).get("description", ""),
        "status": row["status"],
        "priority": int(row["priority"] or 50),
        "payload": payload,
        "result": result,
        "attempts": int(row["attempts"] or 0),
        "maxAttempts": int(row["max_attempts"] or 0),
        "nextRunAt": row["next_run_at"],
        "lockedAt": row["locked_at"],
        "lockedBy": row["locked_by"] or "",
        "createdAt": row["created_at"],
        "createdBy": row["created_by_username"] or "",
        "updatedAt": row["updated_at"],
        "finishedAt": row["finished_at"],
        "lastError": row["last_error"] or "",
    }


def background_jobs_payload(db):
    rows = db.execute(
        "SELECT j.*,u.username AS created_by_username,t.name AS tenant_name "
        "FROM background_jobs j "
        "LEFT JOIN users u ON u.id = j.created_by "
        "LEFT JOIN tenants t ON t.id = j.tenant_id "
        "ORDER BY COALESCE(j.finished_at,j.updated_at,j.created_at) DESC LIMIT 250"
    ).fetchall()
    counts = {
        "queued": 0,
        "running": 0,
        "succeeded": 0,
        "failed": 0,
        "cancelled": 0,
        "retry": 0,
        "total": len(rows),
    }
    for row in rows:
        status = row["status"]
        counts[status] = counts.get(status, 0) + 1
    return {
        "enabled": BACKGROUND_JOB_WORKER_ENABLED,
        "intervalSeconds": BACKGROUND_JOB_WORKER_SECONDS,
        "workerId": BACKGROUND_JOB_WORKER_ID,
        "types": BACKGROUND_JOB_TYPES,
        "summary": counts,
        "jobs": [background_job_public(row) for row in rows],
    }


def enqueue_background_job(db, job_type, actor, payload=None, priority=50, next_run_at=None, max_attempts=None):
    if job_type not in BACKGROUND_JOB_TYPES:
        raise ValueError("unsupported background job type")
    payload = payload or {}
    job_id = f"job-{uuid.uuid4().hex}"
    tenant_id = None if not BACKGROUND_JOB_TYPES[job_type].get("tenantScoped") else metadata_value(payload.get("tenantId") or actor.get("tenant_id"), 200)
    timestamp = now()
    db.execute(
        "INSERT INTO background_jobs (id,tenant_id,job_type,status,priority,payload_json,attempts,max_attempts,next_run_at,created_at,created_by,updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            job_id,
            tenant_id,
            job_type,
            "queued",
            max(0, min(100, int(priority or 50))),
            json.dumps(payload, ensure_ascii=False, sort_keys=True),
            0,
            int(max_attempts or BACKGROUND_JOB_MAX_ATTEMPTS),
            int(next_run_at or timestamp),
            timestamp,
            actor.get("id"),
            timestamp,
        ),
    )
    audit(db, actor, "background_job_queued", "background_job", job_id, {
        "jobType": job_type,
        "priority": priority,
    }, "api")
    return job_id


def create_encrypted_backup(actor, ip="system-job"):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    temp_dir = DATA / f".backup-{stamp}-{uuid.uuid4().hex}"
    temp_dir.mkdir()
    archive_path = None
    try:
        database_backup = DATABASE.backup_to(temp_dir)
        FILE_STORAGE.copy_to_directory(temp_dir / "uploads")
        payload_files = []
        for path in sorted(item for item in temp_dir.rglob("*") if item.is_file()):
            payload = path.read_bytes()
            payload_files.append({
                "path": path.relative_to(temp_dir).as_posix(),
                "bytes": len(payload),
                "sha256": sha(payload),
            })
        (temp_dir / "backup-manifest.json").write_text(json.dumps({
            "formatVersion": 1,
            "application": APP_NAME,
            "createdAt": now(),
            "database": {
                "dialect": DATABASE.dialect,
                "file": database_backup.relative_to(temp_dir).as_posix(),
            },
            "storage": {
                "backend": FILE_STORAGE.backend,
                "directory": "uploads",
                "objects": sum(1 for item in payload_files if item["path"].startswith("uploads/")),
            },
            "files": payload_files,
        }, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        (temp_dir / "README_RESTORE.txt").write_text(
            f"Encrypted {APP_NAME} backup payload. Restore requires the same local file_key.bin or ISMS_FILE_KEY. Protect both separately.\n",
            encoding="utf-8",
        )
        archive_path = Path(shutil.make_archive(str(DATA / f".backup-plain-{stamp}"), "zip", temp_dir))
        nonce, encrypted = encrypt(archive_path.read_bytes())
        backup_name = f"isms-backup-{stamp}.ismsbak"
        backup_path = BACKUPS / backup_name
        backup_path.write_bytes(nonce + encrypted)
        with conn() as db:
            audit(db, actor, "backup_created", "backup", backup_name, {"bytes": backup_path.stat().st_size}, ip)
        return {"name": backup_name, "size": backup_path.stat().st_size, "createdAt": now()}
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        if archive_path and archive_path.exists():
            archive_path.unlink()


def rescan_quarantined_file(actor, file_id, ip="system-job"):
    with conn() as db:
        tenant_clause = "" if actor.get("platform_admin") else " AND tenant_id = ?"
        params = (file_id,) if actor.get("platform_admin") else (file_id, actor["tenant_id"])
        row = db.execute(
            f"SELECT * FROM files WHERE id = ? AND quarantined = 1{tenant_clause}",
            params,
        ).fetchone()
        if not row:
            raise FileNotFoundError("quarantined file not found")
        try:
            content = decrypt(unb64(row["nonce"]), FILE_STORAGE.get(row["stored_name"]))
        except Exception as exc:
            raise RuntimeError("quarantined file could not be decrypted") from exc
        result = MALWARE_SCANNER.scan(content)
        released = result.clean
        scanned_at = now()
        db.execute(
            "UPDATE files SET scan_status = ?,scan_engine = ?,scan_signature = ?,scan_detail = ?,scanned_at = ?,quarantined = ? WHERE id = ?",
            (result.status, result.engine, result.signature, result.detail, scanned_at, 0 if released else 1, file_id),
        )
        audit(db, actor, "file_quarantine_released" if released else "file_quarantine_rescanned", "file", file_id, {
            "scanStatus": result.status,
            "scanEngine": result.engine,
            "released": released,
        }, ip)
    return {
        "fileId": file_id,
        "released": released,
        "scanStatus": result.status,
        "scanEngine": result.engine,
        "signature": result.signature,
        "scannedAt": scanned_at,
    }


def preflight_tenant_export(actor, tenant_id, ip="system-job"):
    if not actor.get("platform_admin") and tenant_id != actor.get("tenant_id"):
        raise PermissionError("tenant export is limited to the active tenant")
    with conn() as db:
        tenant = db.execute(
            "SELECT id,name,slug,status FROM tenants WHERE id = ?",
            (tenant_id,),
        ).fetchone()
        if not tenant:
            raise FileNotFoundError("tenant not found")
        workspace = db.execute(
            "SELECT state_json FROM tenant_workspace_state WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        snapshots = db.execute(
            "SELECT state_json FROM workspace_state_snapshots WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
        files = db.execute(
            "SELECT id,original_name,stored_name,size,sha256,nonce FROM files "
            "WHERE tenant_id = ? AND quarantined = 0 ORDER BY uploaded_at,id",
            (tenant_id,),
        ).fetchall()
        quarantined_count = db.execute(
            "SELECT COUNT(*) FROM files WHERE tenant_id = ? AND quarantined = 1",
            (tenant_id,),
        ).fetchone()[0]
        audit_count = db.execute(
            "SELECT COUNT(*) FROM audit_log WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()[0]
        notification_payload_bytes = db.execute(
            "SELECT COALESCE(SUM(LENGTH(payload_json)),0) FROM notification_deliveries WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()[0]
        estimated_bytes = sum(int(row["size"] or 0) for row in files)
        estimated_bytes += len(workspace["state_json"].encode("utf-8")) if workspace else 0
        estimated_bytes += sum(len(row["state_json"].encode("utf-8")) for row in snapshots)
        estimated_bytes += int(notification_payload_bytes or 0)
        blockers = []
        checked_files = 0
        if estimated_bytes > MAX_TENANT_EXPORT:
            blockers.append({
                "type": "size_limit",
                "message": "Mandantenexport überschreitet das konfigurierte Größenlimit.",
                "estimatedBytes": estimated_bytes,
                "limitBytes": MAX_TENANT_EXPORT,
            })
        for row in files:
            try:
                blob_exists = FILE_STORAGE.exists(row["stored_name"])
            except StorageError:
                blob_exists = False
            if not blob_exists:
                blockers.append({"type": "missing_blob", "fileId": row["id"], "name": row["original_name"]})
                continue
            try:
                content = decrypt(unb64(row["nonce"]), FILE_STORAGE.get(row["stored_name"]))
            except Exception:
                blockers.append({"type": "decrypt_failed", "fileId": row["id"], "name": row["original_name"]})
                continue
            checked_files += 1
            if sha(content) != row["sha256"]:
                blockers.append({"type": "checksum_mismatch", "fileId": row["id"], "name": row["original_name"]})
        result = {
            "tenantId": tenant["id"],
            "tenantName": tenant["name"],
            "tenantSlug": tenant["slug"],
            "exportReady": not blockers,
            "estimatedBytes": estimated_bytes,
            "limitBytes": MAX_TENANT_EXPORT,
            "blockers": blockers[:50],
            "counts": {
                "workspace": 1 if workspace else 0,
                "snapshots": len(snapshots),
                "files": len(files),
                "checkedFiles": checked_files,
                "quarantinedFilesExcluded": int(quarantined_count or 0),
                "auditEvents": int(audit_count or 0),
            },
            "excluded": [
                "Passwort-Hashes und MFA-Secrets",
                "Sessions, Cookies und CSRF-Token",
                "System- und Backup-Schluessel",
                "Quarantaene-Dateien",
            ],
        }
        audit(db, actor, "tenant_export_preflight_succeeded" if result["exportReady"] else "tenant_export_preflight_blocked", "tenant", tenant_id, {
            "estimatedBytes": estimated_bytes,
            "blockers": len(blockers),
            "counts": result["counts"],
        }, ip)
        return result


def create_tenant_export_artifact(actor, tenant_id, artifact_id, ip="system-job"):
    preflight = preflight_tenant_export(actor, tenant_id, ip=ip)
    if not preflight["exportReady"]:
        raise RuntimeError(f"tenant export preflight blocked: {len(preflight['blockers'])} blocker")
    with conn() as db:
        tenant = db.execute(
            "SELECT id,name,slug,status,created_at,updated_at,retention_until,legal_hold,lifecycle_note,archived_at "
            "FROM tenants WHERE id = ?",
            (tenant_id,),
        ).fetchone()
        workspace = db.execute(
            "SELECT state_json,updated_at,updated_by FROM tenant_workspace_state WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        snapshots = db.execute(
            "SELECT id,state_json,saved_at,saved_by,reason,bytes,sha256 FROM workspace_state_snapshots "
            "WHERE tenant_id = ? ORDER BY id DESC",
            (tenant_id,),
        ).fetchall()
        users = db.execute(
            "SELECT id,username,email,role,active,mfa_enabled,created_at,updated_at,last_login_at,platform_admin "
            "FROM users WHERE tenant_id = ? ORDER BY username",
            (tenant_id,),
        ).fetchall()
        invitations = db.execute(
            "SELECT id,email,display_name,role,status,created_at,expires_at,accepted_at,accepted_user_id,revoked_at "
            "FROM invitations WHERE tenant_id = ? ORDER BY created_at DESC",
            (tenant_id,),
        ).fetchall()
        files = db.execute(
            "SELECT f.id,f.original_name,f.stored_name,f.content_type,f.size,f.sha256,f.nonce,f.uploaded_at,"
            "f.document_id,f.version_label,f.previous_file_id,f.linked_to,f.classification,u.username AS uploaded_by_username "
            "FROM files f LEFT JOIN users u ON u.id = f.uploaded_by "
            "WHERE f.tenant_id = ? AND f.quarantined = 0 ORDER BY f.uploaded_at,f.id",
            (tenant_id,),
        ).fetchall()
        audit_rows = db.execute(
            "SELECT id,ts,username,action,target_type,target_id,detail_json,ip FROM audit_log WHERE tenant_id = ? ORDER BY id",
            (tenant_id,),
        ).fetchall()

        tenant_public = {
            "id": tenant["id"],
            "name": tenant["name"],
            "slug": tenant["slug"],
            "status": tenant["status"],
            "createdAt": tenant["created_at"],
            "updatedAt": tenant["updated_at"],
            "archivedAt": tenant["archived_at"],
            "retentionUntil": tenant["retention_until"],
            "legalHold": bool(tenant["legal_hold"]),
            "lifecycleNote": tenant["lifecycle_note"] or "",
        }
        user_rows = [{
            "id": row["id"],
            "username": row["username"],
            "email": row["email"] or "",
            "role": row["role"],
            "active": bool(row["active"]),
            "mfaEnabled": bool(row["mfa_enabled"]),
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
            "lastLoginAt": row["last_login_at"],
            "platformAdmin": bool(row["platform_admin"]),
        } for row in users]
        invitation_rows = [{
            "id": row["id"],
            "email": row["email"],
            "displayName": row["display_name"] or "",
            "role": row["role"],
            "status": row["status"],
            "createdAt": row["created_at"],
            "expiresAt": row["expires_at"],
            "acceptedAt": row["accepted_at"],
            "acceptedUserId": row["accepted_user_id"],
            "revokedAt": row["revoked_at"],
        } for row in invitations]
        audit_events = []
        for row in audit_rows:
            try:
                detail = json.loads(row["detail_json"] or "{}")
            except Exception:
                detail = {"raw": row["detail_json"] or ""}
            audit_events.append({
                "id": row["id"],
                "ts": row["ts"],
                "username": row["username"],
                "action": row["action"],
                "targetType": row["target_type"],
                "targetId": row["target_id"],
                "detail": detail,
                "ip": row["ip"],
            })

        decrypted_files = []
        export_files = []
        for row in files:
            content = decrypt(unb64(row["nonce"]), FILE_STORAGE.get(row["stored_name"]))
            if sha(content) != row["sha256"]:
                raise RuntimeError(f"checksum mismatch for file {row['id']}")
            archive_name = f"files/{row['id'][:12]}-{safe_filename(row['original_name'])}"
            decrypted_files.append((archive_name, content))
            export_files.append({
                "id": row["id"],
                "name": row["original_name"],
                "archivePath": archive_name,
                "contentType": row["content_type"],
                "size": row["size"],
                "sha256": row["sha256"],
                "uploadedAt": row["uploaded_at"],
                "uploadedBy": row["uploaded_by_username"] or "unknown",
                "documentId": row["document_id"] or "",
                "version": row["version_label"] or "",
                "previousFileId": row["previous_file_id"] or "",
                "linkedTo": row["linked_to"] or "",
                "classification": row["classification"] or "",
            })

        exported_at = now()
        manifest = {
            "format": "sfm-compliance-tenant-export-v1",
            "exportedAt": exported_at,
            "exportedBy": actor.get("username") or "system-job",
            "tenant": tenant_public,
            "counts": {
                "users": len(user_rows),
                "invitations": len(invitation_rows),
                "files": len(export_files),
                "snapshots": len(snapshots),
                "auditEvents": len(audit_events),
                "workspace": 1 if workspace else 0,
            },
            "preflight": preflight,
            "excluded": preflight["excluded"],
        }
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            archive.writestr("README.txt", (
                "SFM Compliance Mandantenexport\n\n"
                "Dieser Export wurde als Hintergrundjob erstellt.\n"
                "Er enthaelt keine Passwoerter, Sessions, MFA-Secrets, CSRF-Token, Systemschluessel oder Quarantaene-Dateien.\n"
                "Die fachliche Bewertung und Auditbereitschaft bleiben beim Berater/Admin.\n"
            ))
            archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
            archive.writestr("tenant.json", json.dumps(tenant_public, ensure_ascii=False, indent=2))
            archive.writestr("records/users.json", json.dumps(user_rows, ensure_ascii=False, indent=2))
            archive.writestr("records/invitations.json", json.dumps(invitation_rows, ensure_ascii=False, indent=2))
            archive.writestr("records/audit-log.json", json.dumps(audit_events, ensure_ascii=False, indent=2))
            archive.writestr("files/index.json", json.dumps(export_files, ensure_ascii=False, indent=2))
            if workspace:
                archive.writestr("workspace/current.json", workspace["state_json"])
            for row in snapshots:
                archive.writestr(f"workspace/snapshots/{row['id']}.json", row["state_json"])
            for archive_name, content in decrypted_files:
                archive.writestr(archive_name, content)

        content = buffer.getvalue()
        stamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"sfm-compliance-{safe_filename(tenant['slug'])}-{stamp}.zip"
        artifact_path = JOB_ARTIFACTS / f"{safe_filename(artifact_id)}.zip"
        artifact_path.write_bytes(content)
        try:
            artifact_path.chmod(0o600)
        except OSError:
            pass
        audit(db, actor, "tenant_export_artifact_created", "tenant", tenant_id, {
            "name": tenant["name"],
            "slug": tenant["slug"],
            "bytes": len(content),
            "sha256": sha(content),
            "filename": filename,
            "counts": manifest["counts"],
        }, ip)
        return {
            "tenantId": tenant_id,
            "tenantName": tenant["name"],
            "filename": filename,
            "size": len(content),
            "sha256": sha(content),
            "artifactId": artifact_id,
            "downloadUrl": f"/api/jobs/{urllib.parse.quote(artifact_id)}/artifact",
            "createdAt": exported_at,
            "counts": manifest["counts"],
        }


def run_background_job(job_id):
    started_at = now()
    with conn() as db:
        row = db.execute(
            "SELECT j.*,u.username AS created_by_username,u.role AS created_by_role,u.platform_admin AS created_by_platform_admin FROM background_jobs j "
            "LEFT JOIN users u ON u.id = j.created_by WHERE j.id = ?",
            (job_id,),
        ).fetchone()
        if not row or row["status"] not in {"queued", "retry"}:
            return False
        attempts = int(row["attempts"] or 0) + 1
        claimed = db.execute(
            "UPDATE background_jobs SET status='running',attempts=?,locked_at=?,locked_by=?,updated_at=?,last_error=NULL WHERE id=? AND status IN ('queued','retry')",
            (attempts, started_at, BACKGROUND_JOB_WORKER_ID, started_at, job_id),
        )
        if claimed.rowcount != 1:
            return False
        job = dict(row)
        job["attempts"] = attempts

    actor = job_actor(job)
    try:
        if job["job_type"] in {"intune_preview", "intune_sync"}:
            result = intune_service().run(actor, automatic=job["job_type"] == "intune_sync")
        elif job["job_type"] == "operations_alert_refresh":
            refreshed_at = run_operational_monitor(actor=actor, ip="job-worker", schedule_next=False)
            if not refreshed_at:
                raise RuntimeError("operations monitor did not complete")
            result = {"refreshedAt": refreshed_at}
        elif job["job_type"] == "backup_create":
            result = {"backup": create_encrypted_backup(actor, ip="job-worker")}
        elif job["job_type"] == "quarantine_rescan":
            payload = json.loads(job["payload_json"] or "{}")
            file_id = metadata_value(payload.get("fileId"), 200)
            if not file_id:
                raise ValueError("missing quarantined file id")
            result = {"rescan": rescan_quarantined_file(actor, file_id, ip="job-worker")}
        elif job["job_type"] == "tenant_export_preflight":
            payload = json.loads(job["payload_json"] or "{}")
            tenant_id = metadata_value(payload.get("tenantId") or job["tenant_id"], 200)
            if not tenant_id:
                raise ValueError("missing tenant id")
            result = {"exportPreflight": preflight_tenant_export(actor, tenant_id, ip="job-worker")}
        elif job["job_type"] == "tenant_export_create":
            payload = json.loads(job["payload_json"] or "{}")
            tenant_id = metadata_value(payload.get("tenantId") or job["tenant_id"], 200)
            if not tenant_id:
                raise ValueError("missing tenant id")
            result = {"tenantExport": create_tenant_export_artifact(actor, tenant_id, job_id, ip="job-worker")}
        else:
            raise ValueError("unsupported background job type")
        finished_at = now()
        with conn() as db:
            db.execute(
                "UPDATE background_jobs SET status='succeeded',result_json=?,updated_at=?,finished_at=?,locked_at=NULL,locked_by=NULL,last_error=NULL WHERE id=?",
                (json.dumps(result, ensure_ascii=False, sort_keys=True), finished_at, finished_at, job_id),
            )
            audit(db, actor, "background_job_succeeded", "background_job", job_id, {
                "jobType": job["job_type"],
                "attempts": job["attempts"],
            }, "job-worker")
        return True
    except Exception as exc:
        error_text = metadata_value(str(exc), 500) or "background job failed"
        if job["job_type"] in {"intune_preview", "intune_sync"} and not isinstance(exc, IntuneError):
            error_text = "Intune-Verarbeitung fehlgeschlagen. Serverkonfiguration pruefen."
        final_failure = int(job["attempts"] or 0) >= int(job["max_attempts"] or BACKGROUND_JOB_MAX_ATTEMPTS)
        if isinstance(exc, IntuneError) and not exc.retry_after:
            final_failure = True
        next_attempt = None if final_failure else now() + min(3600, 30 * (2 ** max(0, int(job["attempts"] or 1) - 1)))
        if isinstance(exc, IntuneError) and exc.retry_after and not final_failure:
            next_attempt = max(next_attempt, now() + exc.retry_after)
        status = "failed" if final_failure else "retry"
        with conn() as db:
            db.execute(
                "UPDATE background_jobs SET status=?,next_run_at=?,updated_at=?,finished_at=?,locked_at=NULL,locked_by=NULL,last_error=? WHERE id=?",
                (status, next_attempt, now(), now() if final_failure else None, error_text, job_id),
            )
            audit(db, actor, "background_job_failed" if final_failure else "background_job_retry", "background_job", job_id, {
                "jobType": job["job_type"],
                "attempts": job["attempts"],
                "nextRunAt": next_attempt,
                "error": error_text,
            }, "job-worker")
        return False


def run_background_job_queue():
    if not BACKGROUND_JOB_WORKER_ENABLED:
        return 0
    intune_service().queue_due(enqueue_background_job)
    timestamp = now()
    with conn() as db:
        db.execute(
            "UPDATE background_jobs SET status='retry',next_run_at=?,locked_at=NULL,locked_by=NULL,updated_at=? "
            "WHERE status='running' AND COALESCE(locked_at,created_at) < ?",
            (timestamp, timestamp, timestamp - 900),
        )
        rows = db.execute(
            "SELECT id FROM background_jobs WHERE status IN ('queued','retry') AND COALESCE(next_run_at,0) <= ? "
            "ORDER BY priority DESC, created_at LIMIT 5",
            (timestamp,),
        ).fetchall()
    processed = 0
    for row in rows:
        run_background_job(row["id"])
        processed += 1
    return processed


def background_job_loop():
    while not BACKGROUND_JOB_STOP.wait(BACKGROUND_JOB_WORKER_SECONDS):
        run_background_job_queue()


def start_background_job_worker():
    if not BACKGROUND_JOB_WORKER_ENABLED:
        return None
    run_background_job_queue()
    thread = threading.Thread(target=background_job_loop, name="sfm-background-jobs", daemon=True)
    thread.start()
    return thread


def maintenance_status_payload(db):
    current = now()
    artifact_count = 0
    artifact_bytes = 0
    for artifact in JOB_ARTIFACTS.glob("*.zip"):
        if artifact.is_file():
            artifact_count += 1
            artifact_bytes += artifact.stat().st_size
    completed_job_count = int(db.execute(
        "SELECT COUNT(*) FROM background_jobs WHERE status IN ('succeeded','failed','cancelled')"
    ).fetchone()[0] or 0)
    return {
        "actions": [
            {
                "key": "cleanup-expired-sessions",
                "label": "Abgelaufene Sessions bereinigen",
                "description": "Entfernt ausschließlich bereits abgelaufene Sitzungen. Aktive Anmeldungen bleiben erhalten.",
                "affected": int(db.execute("SELECT COUNT(*) FROM sessions WHERE expires_at <= ?", (current,)).fetchone()[0] or 0),
            },
            {
                "key": "expire-stale-invitations",
                "label": "Abgelaufene Einladungen aktualisieren",
                "description": "Markiert ausschließlich abgelaufene offene Einladungen als abgelaufen. Es werden keine Einladungsdaten gelöscht.",
                "affected": int(db.execute(
                    "SELECT COUNT(*) FROM invitations WHERE status = 'pending' AND expires_at <= ?",
                    (current,),
                ).fetchone()[0] or 0),
            },
            {
                "key": "cleanup-job-artifacts",
                "label": "Job-Artefakte prüfen",
                "description": "Zeigt exportierte Job-Artefakte und abgeschlossene Jobs. Bereinigung erfolgt kontrolliert im Backup-&-Recovery-Bereich.",
                "affected": artifact_count + completed_job_count,
                "artifactBytes": artifact_bytes,
            },
        ]
    }


def mfa_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_code(secret, for_time=None, step=30):
    padded = secret.replace(" ", "").upper()
    padded += "=" * (-len(padded) % 8)
    key = base64.b32decode(padded)
    counter = int((for_time or time.time()) // step)
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify_totp(secret, code, window=1):
    cleaned = re.sub(r"\s+", "", str(code or ""))
    if not re.fullmatch(r"\d{6}", cleaned):
        return False
    current = time.time()
    return any(hmac.compare_digest(totp_code(secret, current + offset * 30), cleaned) for offset in range(-window, window + 1))


def otpauth_uri(username, secret):
    label = urllib.parse.quote(f"{APP_NAME}:{username}")
    issuer = urllib.parse.quote(APP_NAME)
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def parse_multipart(body, content_type):
    match = re.search(r"boundary=([^;]+)", content_type or "")
    if not match:
        raise ValueError("missing multipart boundary")
    boundary = match.group(1).strip().strip('"').encode()
    files = []
    fields = {}
    for raw in body.split(b"--" + boundary)[1:]:
        if raw.startswith(b"--"):
            break
        part = raw[2:] if raw.startswith(b"\r\n") else raw
        if part.endswith(b"\r\n"):
            part = part[:-2]
        if not part:
            continue
        head, _, content = part.partition(b"\r\n\r\n")
        headers = {}
        for line in head.decode("latin1").split("\r\n"):
            key, _, value = line.partition(":")
            headers[key.lower().strip()] = value.strip()
        disposition = headers.get("content-disposition", "")
        name_match = re.search(r'name="([^"]*)"', disposition)
        field_name = name_match.group(1) if name_match else ""
        file_match = re.search(r'filename="([^"]*)"', disposition)
        if file_match:
            files.append({
                "filename": safe_filename(file_match.group(1)),
                "content_type": headers.get("content-type", "application/octet-stream"),
                "content": content,
            })
        elif field_name:
            value = content.decode("utf-8", errors="replace")
            if field_name in fields:
                if not isinstance(fields[field_name], list):
                    fields[field_name] = [fields[field_name]]
                fields[field_name].append(value)
            else:
                fields[field_name] = value
    return {"files": files, "fields": fields}


def metadata_value(value, max_length=240):
    text = str(value or "").strip()
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    return text[:max_length]


def metadata_list(fields, name):
    raw = fields.get(name, "")
    if isinstance(raw, list):
        return [metadata_value(item) for item in raw]
    raw = str(raw or "").strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [metadata_value(item) for item in parsed]
    except Exception:
        pass
    return [metadata_value(raw)]


def metadata_at(values, index, default=""):
    if index < len(values) and values[index]:
        return values[index]
    return default


def live_event_type(action):
    action = str(action or "")
    if action in {
        "state_saved",
        "state_submission_saved",
        "state_restored",
        "asset_created",
        "asset_updated",
        "asset_deleted",
        "intune_assets_synced",
        "risk_created",
        "risk_updated",
        "risk_deleted",
        "supplier_created",
        "supplier_updated",
        "supplier_deleted",
        "policy_created",
        "policy_updated",
        "policy_deleted",
        "incident_created",
        "incident_updated",
        "incident_deleted",
        "contract_created",
        "contract_updated",
        "contract_deleted",
        "task_created",
        "task_updated",
        "task_deleted",
        "legal_created",
        "legal_updated",
        "legal_deleted",
        "soa_updated",
        "audit_finding_created",
        "audit_finding_updated",
        "audit_finding_deleted",
        "management_review_updated",
        "internal_audit_plan_updated",
    }:
        return "workspace.updated"
    if action.startswith("file_") and action not in {"file_downloaded"}:
        return "evidence.updated"
    if action.startswith(("invitation_", "user_", "mfa_", "password_")):
        return "team.updated"
    if action.startswith("notification_"):
        return "notifications.updated"
    if action.startswith(("background_job_", "operational_alert_", "maintenance_", "backup_", "restore_drill_")):
        return "operations.updated"
    if action.startswith("tenant_"):
        return "tenant.updated"
    return None


def record_live_event(db, user, action, target_type=None, target_id=None, detail=None, timestamp=None):
    tenant_id = user.get("tenant_id") if user else None
    event_type = live_event_type(action)
    if not tenant_id or not event_type:
        return
    revision_row = db.execute(
        "SELECT revision FROM tenant_workspace_state WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchone()
    workspace_revision = revision_row["revision"] if revision_row else None
    detail_revision = (detail or {}).get("revision")
    if isinstance(detail_revision, int) and not isinstance(detail_revision, bool):
        workspace_revision = detail_revision
    db.execute(
        "INSERT INTO tenant_events (tenant_id,event_type,action,entity_type,entity_id,actor_user_id,actor_username,created_at,workspace_revision) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (
            tenant_id,
            event_type,
            action,
            target_type,
            str(target_id or ""),
            user.get("id"),
            user.get("username"),
            timestamp or now(),
            workspace_revision,
        ),
    )


def audit(db, user, action, target_type=None, target_id=None, detail=None, ip=None):
    timestamp = now()
    tenant_id = user.get("tenant_id") if user else None
    user_id = user["id"] if user else None
    username = user["username"] if user else None
    detail_json = json.dumps(detail or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if DATABASE.dialect == "postgres":
        # Keep each tenant hash chain linear when requests write concurrently.
        db.execute("LOCK TABLE audit_log IN SHARE ROW EXCLUSIVE MODE")
    if tenant_id is None:
        previous = db.execute(
            "SELECT event_hash FROM audit_log WHERE tenant_id IS NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()
    else:
        previous = db.execute(
            "SELECT event_hash FROM audit_log WHERE tenant_id = ? ORDER BY id DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
    previous_hash = (previous["event_hash"] if previous else "") or ""
    event_hash = audit_event_hash(
        timestamp,
        tenant_id,
        user_id,
        username,
        action,
        target_type,
        target_id,
        detail_json,
        ip,
        previous_hash,
    )
    db.execute(
        "INSERT INTO audit_log (ts,tenant_id,user_id,username,action,target_type,target_id,detail_json,ip,previous_hash,event_hash) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (timestamp, tenant_id, user_id, username, action, target_type, target_id, detail_json, ip, previous_hash, event_hash),
    )
    record_live_event(db, user, action, target_type, target_id, detail, timestamp)


def audit_event_hash(timestamp, tenant_id, user_id, username, action, target_type, target_id, detail_json, ip, previous_hash):
    payload = {
        "ts": timestamp,
        "tenantId": tenant_id,
        "userId": user_id,
        "username": username,
        "action": action,
        "targetType": target_type,
        "targetId": target_id,
        "detailJson": detail_json or "{}",
        "ip": ip,
        "previousHash": previous_hash or "",
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha(canonical.encode("utf-8"))


def backfill_audit_hash_chain(db):
    rows = db.execute(
        "SELECT id,ts,tenant_id,user_id,username,action,target_type,target_id,detail_json,ip,previous_hash,event_hash "
        "FROM audit_log ORDER BY id ASC"
    ).fetchall()
    heads = {}
    for row in rows:
        tenant_key = row["tenant_id"]
        if row["event_hash"]:
            heads[tenant_key] = row["event_hash"]
            continue
        previous_hash = heads.get(tenant_key, "")
        event_hash = audit_event_hash(
            row["ts"], row["tenant_id"], row["user_id"], row["username"], row["action"],
            row["target_type"], row["target_id"], row["detail_json"] or "{}", row["ip"], previous_hash,
        )
        db.execute(
            "UPDATE audit_log SET previous_hash = ?, event_hash = ? WHERE id = ?",
            (previous_hash, event_hash, row["id"]),
        )
        heads[tenant_key] = event_hash


def verify_audit_hash_chain(db, tenant_id=None, all_tenants=False):
    if all_tenants:
        rows = db.execute(
            "SELECT id,ts,tenant_id,user_id,username,action,target_type,target_id,detail_json,ip,previous_hash,event_hash "
            "FROM audit_log ORDER BY tenant_id ASC, id ASC"
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT id,ts,tenant_id,user_id,username,action,target_type,target_id,detail_json,ip,previous_hash,event_hash "
            "FROM audit_log WHERE tenant_id = ? ORDER BY id ASC",
            (tenant_id,),
        ).fetchall()

    grouped = {}
    for row in rows:
        grouped.setdefault(row["tenant_id"] or "system", []).append(row)

    chains = []
    for chain_tenant, chain_rows in grouped.items():
        previous_hash = (chain_rows[0]["previous_hash"] or "") if chain_rows else ""
        invalid = []
        for row in chain_rows:
            stored_previous = row["previous_hash"] or ""
            expected_hash = audit_event_hash(
                row["ts"], row["tenant_id"], row["user_id"], row["username"], row["action"],
                row["target_type"], row["target_id"], row["detail_json"] or "{}", row["ip"], stored_previous,
            )
            reasons = []
            if stored_previous != previous_hash:
                reasons.append("previous_hash_mismatch")
            if not row["event_hash"] or row["event_hash"] != expected_hash:
                reasons.append("event_hash_mismatch")
            if reasons and len(invalid) < 25:
                invalid.append({"id": row["id"], "reasons": reasons})
            previous_hash = row["event_hash"] or ""
        chains.append({
            "tenantId": chain_tenant,
            "valid": not invalid,
            "events": len(chain_rows),
            "anchorHash": (chain_rows[0]["previous_hash"] or "") if chain_rows else "",
            "headHash": (chain_rows[-1]["event_hash"] or "") if chain_rows else "",
            "invalidEvents": invalid,
        })

    return {
        "valid": all(chain["valid"] for chain in chains),
        "checkedEvents": sum(chain["events"] for chain in chains),
        "chains": chains,
        "verifiedAt": now(),
    }


def role_permissions(role, platform_admin=False):
    permissions = set(ROLE_PERMISSIONS.get(role, set()))
    if platform_admin:
        for values in ROLE_PERMISSIONS.values():
            permissions.update(values)
        permissions.update(PLATFORM_ADMIN_PERMISSIONS)
    return sorted(permissions)


def role_list():
    ordered = [role for role in ROLE_ORDER if role in READ_ROLES]
    return ordered + sorted(READ_ROLES.difference(ordered))


def has_permission(user, permission):
    if not user:
        return False
    return permission in role_permissions(user.get("role"), bool(user.get("platform_admin", 0)))


def mfa_required_for_user(user):
    if not user or MFA_ENFORCEMENT != "write":
        return False
    return bool(user.get("platform_admin", 0)) or user.get("role") in MFA_REQUIRED_ROLES


def mfa_write_allowed(user):
    return not mfa_required_for_user(user) or bool(user.get("mfa_enabled", 0))


def access_policy_public(user=None):
    required = mfa_required_for_user(user)
    return {
        "mfaEnforcement": MFA_ENFORCEMENT,
        "mfaRequiredRoles": sorted(MFA_REQUIRED_ROLES),
        "platformAdminMfaRequired": MFA_ENFORCEMENT == "write",
        "loginProtection": {
            "persistent": True,
            "accountMaxAttempts": LOGIN_ACCOUNT_MAX_ATTEMPTS,
            "ipMaxAttempts": LOGIN_IP_MAX_ATTEMPTS,
            "attemptWindowSeconds": LOGIN_ATTEMPT_WINDOW_SECONDS,
            "lockSeconds": LOGIN_LOCK_SECONDS,
        },
        "accountRecovery": {
            "enabled": ACCOUNT_RECOVERY_ENABLED,
            "deliveryConfigured": account_recovery_delivery_configured(),
            "tokenSeconds": ACCOUNT_RECOVERY_TOKEN_SECONDS,
        },
        "passwordPolicy": password_policy_public(),
        "currentUser": {
            "required": required,
            "compliant": not required or bool(user and user.get("mfa_enabled", 0)),
            "passwordChangeRequired": bool(user and user.get("password_change_required", 0)),
            "writeAllowed": mfa_write_allowed(user) and not bool(user and user.get("password_change_required", 0)),
        } if user else None,
        "technicalPolicyOnly": True,
    }


def user_public(user):
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "roleLabel": ROLE_DETAILS.get(user["role"], {}).get("label", user["role"]),
        "permissions": role_permissions(user["role"], bool(user.get("platform_admin", 0))),
        "active": bool(user.get("active", 1)),
        "mfaEnabled": bool(user.get("mfa_enabled", 0)),
        "mfaRequired": mfa_required_for_user(user),
        "passwordChangeRequired": bool(user.get("password_change_required", 0)),
        "writeAllowed": mfa_write_allowed(user) and not bool(user.get("password_change_required", 0)),
        "ssoLinked": bool(user.get("sso_linked", 0)),
        "platformAdmin": bool(user.get("platform_admin", 0)),
        "tenant": {
            "id": user.get("tenant_id", DEFAULT_TENANT_ID),
            "name": user.get("tenant_name", DEFAULT_TENANT_NAME),
            "slug": user.get("tenant_slug", "internal"),
            "status": user.get("tenant_status", "active"),
        },
    }


def create_session(db, user, ip, action="login"):
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    db.execute(
        "INSERT INTO sessions (token_hash,user_id,tenant_id,csrf_token,expires_at,created_at,ip) VALUES (?,?,?,?,?,?,?)",
        (sha(token.encode()), user["id"], user["tenant_id"], csrf, now() + SESSION_SECONDS, now(), ip),
    )
    db.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), user["id"]))
    audit(db, user, action, "user", str(user["id"]), {}, ip)
    return token, csrf


def sso_username(email, tenant_slug, db):
    local = re.sub(r"[^A-Za-z0-9._-]+", ".", email.split("@", 1)[0]).strip("._-") or "user"
    tenant_part = re.sub(r"[^A-Za-z0-9_-]+", "-", tenant_slug).strip("-") or "tenant"
    base = f"{local}.{tenant_part}"[:56].strip("._-")
    candidate = base
    counter = 1
    while db.execute("SELECT 1 FROM users WHERE username = ?", (candidate,)).fetchone():
        counter += 1
        candidate = f"{base[:56-len(str(counter))]}.{counter}"
    return candidate


def invitation_public(row):
    data = dict(row)
    status = data["status"]
    if status == "pending" and row["expires_at"] < now():
        status = "expired"
    return {
        "id": row["id"],
        "email": row["email"],
        "displayName": row["display_name"] or "",
        "role": row["role"],
        "roleLabel": ROLE_DETAILS.get(row["role"], {}).get("label", row["role"]),
        "status": status,
        "tenantId": row["tenant_id"],
        "tenantName": row["tenant_name"],
        "createdAt": row["created_at"],
        "expiresAt": row["expires_at"],
        "acceptedAt": row["accepted_at"],
        "revokedAt": row["revoked_at"],
        "acceptedUserId": row["accepted_user_id"],
        "invitedBy": row["invited_by_username"] or "",
        "deliveryStatus": data.get("delivery_status") or "manual",
        "deliveryAttempts": int(data.get("delivery_attempts") or 0),
        "lastSentAt": data.get("last_sent_at"),
        "deliveredAt": data.get("delivered_at"),
        "deliveryError": "Zustellung fehlgeschlagen" if data.get("delivery_status") == "failed" else "",
    }


class App(BaseHTTPRequestHandler):
    server_version = "SFMCompliance/0.1"

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if os.environ.get("ISMS_HSTS") == "1" or os.environ.get("ISMS_PUBLIC_URL", "").startswith("https://"):
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        )
        super().end_headers()

    def log_message(self, fmt, *args):
        return

    def body(self, max_bytes=MAX_JSON):
        length = int(self.headers.get("Content-Length") or 0)
        if length > max_bytes:
            raise ValueError("request too large")
        return self.rfile.read(length)

    def json_body(self):
        raw = self.body(MAX_JSON)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def send_json(self, payload, status=200, extra_headers=None, head_only=False):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if not head_only:
            self.wfile.write(data)

    def send_error_json(self, status, message, head_only=False):
        self.send_json({"error": message}, status=status, head_only=head_only)

    def send_password_policy_error(self, error):
        code, message = error
        self.send_json({
            "error": message,
            "code": code,
            "passwordPolicy": password_policy_public(),
        }, status=400)

    def send_redirect(self, location, cookie=None):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def current_user(self):
        token = read_cookie(self.headers.get("Cookie"))
        if not token:
            return None
        token_hash = sha(token.encode())
        with conn() as db:
            row = db.execute(
                "SELECT s.csrf_token, s.expires_at, u.id, u.username, u.role, u.active, u.mfa_enabled, u.password_change_required, "
                "CASE WHEN u.platform_admin = 1 THEN COALESCE(NULLIF(s.tenant_id, ''), u.tenant_id) ELSE u.tenant_id END AS tenant_id, "
                "u.tenant_id AS home_tenant_id, u.platform_admin, t.name AS tenant_name, t.slug AS tenant_slug, t.status AS tenant_status, "
                "CASE WHEN EXISTS(SELECT 1 FROM oidc_identities oi WHERE oi.user_id = u.id) THEN 1 ELSE 0 END AS sso_linked "
                "FROM sessions s JOIN users u ON u.id = s.user_id "
                "JOIN tenants t ON t.id = CASE WHEN u.platform_admin = 1 THEN COALESCE(NULLIF(s.tenant_id, ''), u.tenant_id) ELSE u.tenant_id END "
                "WHERE s.token_hash = ? AND u.active = 1 AND t.status = 'active'",
                (token_hash,),
            ).fetchone()
            if not row or row["expires_at"] < now():
                if row:
                    db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
                return None
            return dict(row)

    def require_user(self, write=False, permission=None):
        user = self.current_user()
        if not user:
            self.send_error_json(401, "not authenticated")
            return None
        if permission:
            if not has_permission(user, permission):
                self.send_error_json(403, f"permission required: {permission}")
                return None
            if permission in MUTATING_PERMISSIONS and self.headers.get("X-CSRF-Token") != user["csrf_token"]:
                self.send_error_json(403, "invalid csrf token")
                return None
            if permission in MUTATING_PERMISSIONS and user.get("password_change_required"):
                self.send_json({
                    "error": "password change required before modifying customer data",
                    "code": "password_change_required",
                    "passwordChangeRequired": True,
                    "accountPath": "/#account",
                }, status=403)
                return None
            if permission in MUTATING_PERMISSIONS and not mfa_write_allowed(user):
                self.send_json({
                    "error": "mfa enrollment required for privileged changes",
                    "code": "mfa_enrollment_required",
                    "mfaEnrollmentRequired": True,
                    "accountPath": "/#account",
                }, status=403)
                return None
            return user
        allowed = WRITE_ROLES if write else READ_ROLES
        if user["role"] not in allowed:
            self.send_error_json(403, "not allowed")
            return None
        if write and self.headers.get("X-CSRF-Token") != user["csrf_token"]:
            self.send_error_json(403, "invalid csrf token")
            return None
        if write and user.get("password_change_required"):
            self.send_json({
                "error": "password change required before modifying customer data",
                "code": "password_change_required",
                "passwordChangeRequired": True,
                "accountPath": "/#account",
            }, status=403)
            return None
        if write and not mfa_write_allowed(user):
            self.send_json({
                "error": "mfa enrollment required for privileged changes",
                "code": "mfa_enrollment_required",
                "mfaEnrollmentRequired": True,
                "accountPath": "/#account",
            }, status=403)
            return None
        return user

    def require_authenticated_write(self):
        user = self.current_user()
        if not user:
            self.send_error_json(401, "not authenticated")
            return None
        if self.headers.get("X-CSRF-Token") != user["csrf_token"]:
            self.send_error_json(403, "invalid csrf token")
            return None
        return user

    def require_admin(self, write=False):
        user = self.require_user(write=write)
        if not user:
            return None
        if user["role"] != "admin":
            self.send_error_json(403, "admin role required")
            return None
        return user

    def require_platform_admin(self, write=False):
        user = self.require_admin(write=write)
        if not user:
            return None
        if not user.get("platform_admin"):
            self.send_error_json(403, "platform admin required")
            return None
        return user

    def public_base_url(self):
        configured = os.environ.get("ISMS_PUBLIC_URL", "").strip().rstrip("/")
        if configured:
            return configured
        host = self.headers.get("Host") or "127.0.0.1:5173"
        scheme = "https" if os.environ.get("ISMS_COOKIE_SECURE") == "1" else "http"
        return f"{scheme}://{host}"

    def invitation_accept_url(self, token):
        return f"{self.public_base_url()}/#invite={urllib.parse.quote(token)}"

    def password_recovery_url(self, token):
        return f"{self.public_base_url()}/#recover={urllib.parse.quote(token)}"

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/health":
            self.send_json({"ok": True, "service": f"{APP_NAME} Backend", "database": DATABASE.dialect, "storage": FILE_STORAGE.backend, "sso": bool(OIDC_PROVIDERS), "malwareScanning": MALWARE_SCANNER.mode, "jobWorker": BACKGROUND_JOB_WORKER_ENABLED})
        elif path == "/api/events":
            self.handle_event_stream()
        elif path == "/api/auth/sso/providers":
            self.handle_oidc_providers()
        elif path == "/api/auth/sso/start":
            self.handle_oidc_start()
        elif path == "/api/auth/sso/callback":
            self.handle_oidc_callback()
        elif path == "/api/auth/recovery":
            self.handle_password_recovery_info()
        elif path == "/api/session":
            self.handle_session()
        elif path == "/api/access-policy":
            self.handle_access_policy()
        elif path == "/api/sessions/me":
            self.handle_list_my_sessions()
        elif path == "/api/state":
            self.handle_get_state()
        elif path == "/api/state/meta":
            self.handle_get_state_meta()
        elif path == "/api/audit-package/status":
            self.handle_audit_package_status()
        elif path == "/api/audit-package/export":
            self.handle_export_audit_package()
        elif path == "/api/integrations/intune":
            self.handle_intune("status")
        elif path == "/api/assets":
            self.handle_list_assets()
        elif path == "/api/risks":
            self.handle_list_risks()
        elif path == "/api/suppliers":
            self.handle_list_suppliers()
        elif path == "/api/policies":
            self.handle_list_policies()
        elif path == "/api/incidents":
            self.handle_list_incidents()
        elif path == "/api/contracts":
            self.handle_list_contracts()
        elif path == "/api/tasks":
            self.handle_list_tasks()
        elif path == "/api/legal":
            self.handle_list_legal()
        elif path == "/api/soa":
            self.handle_list_soa()
        elif path == "/api/audit-findings":
            self.handle_list_audit_findings()
        elif path == "/api/management-review":
            self.handle_get_management_review()
        elif path == "/api/internal-audit-plan":
            self.handle_get_internal_audit_plan()
        elif path == "/api/state/snapshots":
            self.handle_list_state_snapshots()
        elif path == "/api/files":
            self.handle_list_files()
        elif path == "/api/files/quarantine":
            self.handle_list_quarantine()
        elif path.startswith("/api/files/") and path.endswith("/download"):
            self.handle_download_file(path.split("/")[3])
        elif path == "/api/audit-log":
            self.handle_audit_log()
        elif path == "/api/audit-log/integrity":
            self.handle_audit_log_integrity()
        elif path == "/api/audit-log/export":
            self.handle_audit_log_export()
        elif path == "/api/security/status":
            self.handle_security_status()
        elif path == "/api/operations/alerts":
            self.handle_operational_alerts()
        elif path == "/api/notifications/state":
            self.handle_notification_states()
        elif path == "/api/notifications/deliveries":
            self.handle_notification_deliveries()
        elif path == "/api/maintenance/status":
            self.handle_maintenance_status()
        elif path == "/api/jobs":
            self.handle_list_background_jobs()
        elif path.startswith("/api/jobs/") and path.endswith("/artifact"):
            self.handle_download_job_artifact(path.split("/")[3])
        elif path == "/api/users":
            self.handle_list_users()
        elif path == "/api/invitations":
            self.handle_list_invitations()
        elif path == "/api/invitations/accept":
            self.handle_get_invitation_accept()
        elif path == "/api/tenants/overview":
            self.handle_tenant_overview()
        elif path == "/api/tenants/lifecycle":
            self.handle_tenant_lifecycle()
        elif path == "/api/tenants":
            self.handle_list_tenants()
        elif path == "/api/backups":
            self.handle_list_backups()
        elif path.startswith("/api/backups/") and path.endswith("/download"):
            self.handle_download_backup(path.split("/")[3])
        else:
            self.serve_static(path)

    def handle_event_stream(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        supplied_cursor = (query.get("after") or [self.headers.get("Last-Event-ID", "")])[0]
        try:
            cursor = max(0, int(supplied_cursor)) if str(supplied_cursor).strip() else None
        except (TypeError, ValueError):
            self.send_error_json(400, "invalid event cursor")
            return
        once = str((query.get("once") or [""])[0]).strip().lower() in {"1", "true", "yes"}
        with conn() as db:
            if cursor is None:
                latest = db.execute(
                    "SELECT MAX(id) AS id FROM tenant_events WHERE tenant_id = ?",
                    (user["tenant_id"],),
                ).fetchone()
                cursor = int((latest["id"] if latest else 0) or 0)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        def emit(payload, event_id=None):
            lines = ["event: sfm-update"]
            if event_id is not None:
                lines.append(f"id: {event_id}")
            lines.append(f"data: {json.dumps(payload, ensure_ascii=False, separators=(',', ':'))}")
            lines.append("")
            self.wfile.write(("\n".join(lines) + "\n").encode("utf-8"))
            self.wfile.flush()

        try:
            emit({
                "eventType": "connected",
                "cursor": cursor,
                "tenantId": user["tenant_id"],
                "createdAt": now(),
            }, cursor)
            if once:
                with conn() as db:
                    rows = db.execute(
                        "SELECT id,event_type,action,entity_type,entity_id,actor_username,created_at,workspace_revision "
                        "FROM tenant_events WHERE tenant_id = ? AND id > ? ORDER BY id ASC LIMIT 100",
                        (user["tenant_id"], cursor),
                    ).fetchall()
                for row in rows:
                    emit(self.live_event_payload(row), row["id"])
                return

            stream_seconds = env_int("ISMS_EVENT_STREAM_SECONDS", 55, 15, 300)
            heartbeat_seconds = env_int("ISMS_EVENT_HEARTBEAT_SECONDS", 15, 5, 60)
            deadline = time.monotonic() + stream_seconds
            last_heartbeat = time.monotonic()
            while time.monotonic() < deadline:
                with conn() as db:
                    rows = db.execute(
                        "SELECT id,event_type,action,entity_type,entity_id,actor_username,created_at,workspace_revision "
                        "FROM tenant_events WHERE tenant_id = ? AND id > ? ORDER BY id ASC LIMIT 100",
                        (user["tenant_id"], cursor),
                    ).fetchall()
                for row in rows:
                    cursor = int(row["id"])
                    emit(self.live_event_payload(row), cursor)
                if time.monotonic() - last_heartbeat >= heartbeat_seconds:
                    self.wfile.write(f": heartbeat {now()}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    last_heartbeat = time.monotonic()
                time.sleep(1)
            emit({"eventType": "reconnect", "cursor": cursor, "createdAt": now()}, cursor)
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            return
        finally:
            self.close_connection = True

    @staticmethod
    def live_event_payload(row):
        return {
            "eventType": row["event_type"],
            "action": row["action"],
            "entityType": row["entity_type"] or "",
            "entityId": row["entity_id"] or "",
            "actor": row["actor_username"] or "System",
            "createdAt": row["created_at"],
            "workspaceRevision": row["workspace_revision"],
        }

    def do_HEAD(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/health":
            self.send_json({"ok": True, "service": f"{APP_NAME} Backend", "database": DATABASE.dialect, "storage": FILE_STORAGE.backend, "sso": bool(OIDC_PROVIDERS), "malwareScanning": MALWARE_SCANNER.mode, "jobWorker": BACKGROUND_JOB_WORKER_ENABLED}, head_only=True)
        else:
            self.serve_static(path, head_only=True)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/auth/login":
            self.handle_login()
        elif path == "/api/auth/recovery/request":
            self.handle_password_recovery_request()
        elif path == "/api/auth/recovery/confirm":
            self.handle_password_recovery_confirm()
        elif path == "/api/auth/logout":
            self.handle_logout()
        elif path == "/api/sessions/revoke":
            self.handle_revoke_my_session()
        elif path == "/api/sessions/revoke-others":
            self.handle_revoke_other_sessions()
        elif path == "/api/session/tenant":
            self.handle_switch_tenant()
        elif path == "/api/state/snapshots":
            self.handle_create_state_snapshot()
        elif path == "/api/state/restore":
            self.handle_restore_state_snapshot()
        elif path in {"/api/integrations/intune/preview", "/api/integrations/intune/apply", "/api/integrations/intune/schedule", "/api/integrations/intune/configure", "/api/integrations/intune/disconnect"}:
            self.handle_intune(path.rsplit("/", 1)[-1])
        elif path == "/api/audit-package/approve":
            self.handle_approve_audit_package()
        elif path == "/api/assets":
            self.handle_create_asset()
        elif path == "/api/risks":
            self.handle_create_risk()
        elif path == "/api/suppliers":
            self.handle_create_supplier()
        elif path == "/api/policies":
            self.handle_create_policy()
        elif path == "/api/incidents":
            self.handle_create_incident()
        elif path == "/api/contracts":
            self.handle_create_contract()
        elif path == "/api/tasks":
            self.handle_create_task()
        elif path == "/api/legal":
            self.handle_create_legal_entry()
        elif path == "/api/audit-findings":
            self.handle_create_audit_finding()
        elif path == "/api/files":
            self.handle_upload()
        elif path.startswith("/api/files/") and path.endswith("/rescan-job"):
            self.handle_queue_quarantined_file_rescan(path.split("/")[3])
        elif path.startswith("/api/files/") and path.endswith("/rescan"):
            self.handle_rescan_quarantined_file(path.split("/")[3])
        elif path.startswith("/api/files/") and path.endswith("/quarantine/delete"):
            self.handle_delete_quarantined_file(path.split("/")[3])
        elif path == "/api/users":
            self.handle_create_user()
        elif path.startswith("/api/users/") and path.endswith("/sessions/revoke"):
            self.handle_revoke_user_sessions(path.split("/")[3])
        elif path.startswith("/api/users/") and path.endswith("/unlock"):
            self.handle_unlock_user(path.split("/")[3])
        elif path == "/api/invitations":
            self.handle_create_invitation()
        elif path == "/api/invitations/accept":
            self.handle_accept_invitation()
        elif path.startswith("/api/invitations/") and path.endswith("/revoke"):
            self.handle_revoke_invitation(path.split("/")[3])
        elif path.startswith("/api/invitations/") and path.endswith("/resend"):
            self.handle_resend_invitation(path.split("/")[3])
        elif path == "/api/tenants":
            self.handle_create_tenant()
        elif path.startswith("/api/tenants/") and path.endswith("/export"):
            self.handle_export_tenant(path.split("/")[3])
        elif path.startswith("/api/tenants/") and path.endswith("/export-job"):
            self.handle_queue_tenant_export_preflight(path.split("/")[3])
        elif path.startswith("/api/tenants/") and path.endswith("/export-artifact-job"):
            self.handle_queue_tenant_export_artifact(path.split("/")[3])
        elif path.startswith("/api/tenants/") and path.endswith("/purge"):
            self.handle_purge_tenant(path.split("/")[3])
        elif path == "/api/users/me/password":
            self.handle_change_password()
        elif path == "/api/mfa/setup":
            self.handle_mfa_setup()
        elif path == "/api/mfa/enable":
            self.handle_mfa_enable()
        elif path == "/api/mfa/disable":
            self.handle_mfa_disable()
        elif path == "/api/backups":
            self.handle_create_backup()
        elif path == "/api/restore-drills":
            self.handle_record_restore_drill()
        elif path == "/api/operations/alerts/refresh":
            self.handle_refresh_operational_alerts()
        elif path.startswith("/api/operations/alerts/") and path.endswith("/acknowledge"):
            self.handle_acknowledge_operational_alert(path.split("/")[4])
        elif path == "/api/notifications/state":
            self.handle_update_notification_states()
        elif path == "/api/notifications/deliveries":
            self.handle_create_notification_delivery()
        elif path.startswith("/api/notifications/deliveries/") and path.endswith("/retry"):
            self.handle_retry_notification_delivery(path.split("/")[4])
        elif path.startswith("/api/maintenance/actions/"):
            self.handle_maintenance_action(path.split("/")[4])
        elif path == "/api/maintenance/retention":
            self.handle_retention()
        elif path == "/api/jobs":
            self.handle_create_background_job()
        elif path.startswith("/api/jobs/") and path.endswith("/retry"):
            self.handle_retry_background_job(path.split("/")[3])
        elif path.startswith("/api/jobs/") and path.endswith("/cancel"):
            self.handle_cancel_background_job(path.split("/")[3])
        else:
            self.send_error_json(404, "not found")

    def do_PUT(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/state":
            self.handle_put_state()
        elif path == "/api/state/submission":
            self.handle_submit_state()
        elif path.startswith("/api/users/"):
            self.handle_update_user(path.split("/")[3])
        elif path.startswith("/api/tenants/"):
            self.handle_update_tenant(path.split("/")[3])
        else:
            self.send_error_json(404, "not found")

    def do_PATCH(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/assets/"):
            self.handle_update_asset(urllib.parse.unquote(path[len("/api/assets/"):]))
        elif path.startswith("/api/risks/"):
            self.handle_update_risk(urllib.parse.unquote(path[len("/api/risks/"):]))
        elif path.startswith("/api/suppliers/"):
            self.handle_update_supplier(urllib.parse.unquote(path[len("/api/suppliers/"):]))
        elif path.startswith("/api/policies/"):
            self.handle_update_policy(urllib.parse.unquote(path[len("/api/policies/"):]))
        elif path.startswith("/api/incidents/"):
            self.handle_update_incident(urllib.parse.unquote(path[len("/api/incidents/"):]))
        elif path.startswith("/api/contracts/"):
            self.handle_update_contract(urllib.parse.unquote(path[len("/api/contracts/"):]))
        elif path.startswith("/api/tasks/"):
            self.handle_update_task(urllib.parse.unquote(path[len("/api/tasks/"):]))
        elif path.startswith("/api/legal/"):
            self.handle_update_legal_entry(urllib.parse.unquote(path[len("/api/legal/"):]))
        elif path.startswith("/api/soa/"):
            self.handle_update_soa_control(urllib.parse.unquote(path[len("/api/soa/"):]))
        elif path.startswith("/api/audit-findings/"):
            self.handle_update_audit_finding(urllib.parse.unquote(path[len("/api/audit-findings/"):]))
        elif path == "/api/management-review":
            self.handle_update_management_review()
        elif path == "/api/internal-audit-plan":
            self.handle_update_internal_audit_plan()
        else:
            self.send_error_json(404, "not found")

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/assets/"):
            self.handle_delete_asset(urllib.parse.unquote(path[len("/api/assets/"):]))
        elif path.startswith("/api/risks/"):
            self.handle_delete_risk(urllib.parse.unquote(path[len("/api/risks/"):]))
        elif path.startswith("/api/suppliers/"):
            self.handle_delete_supplier(urllib.parse.unquote(path[len("/api/suppliers/"):]))
        elif path.startswith("/api/policies/"):
            self.handle_delete_policy(urllib.parse.unquote(path[len("/api/policies/"):]))
        elif path.startswith("/api/incidents/"):
            self.handle_delete_incident(urllib.parse.unquote(path[len("/api/incidents/"):]))
        elif path.startswith("/api/contracts/"):
            self.handle_delete_contract(urllib.parse.unquote(path[len("/api/contracts/"):]))
        elif path.startswith("/api/tasks/"):
            self.handle_delete_task(urllib.parse.unquote(path[len("/api/tasks/"):]))
        elif path.startswith("/api/legal/"):
            self.handle_delete_legal_entry(urllib.parse.unquote(path[len("/api/legal/"):]))
        elif path.startswith("/api/audit-findings/"):
            self.handle_delete_audit_finding(urllib.parse.unquote(path[len("/api/audit-findings/"):]))
        else:
            self.send_error_json(404, "not found")

    def serve_static(self, path, head_only=False):
        if path in ("", "/"):
            path = "/index.html"
        decoded = urllib.parse.unquote(path).lstrip("/")
        target = (STATIC_BASE / decoded).resolve()
        intune_config = Path(os.environ.get("ISMS_INTUNE_CONFIG_FILE") or DATA / "intune-config.json").resolve()
        if (not is_within(STATIC_BASE, target) or is_within(DATA, target)
                or target == intune_config or target.suffix.lower() not in STATIC_EXT or not target.is_file()):
            self.send_error_json(404, "not found", head_only=head_only)
            return
        content = target.read_bytes()
        etag = f'"{sha(content)[:24]}"'
        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache" if target.name == "index.html" else "public, max-age=300, must-revalidate")
            self.end_headers()
            return
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if target.suffix.lower() == ".md":
            content_type = "text/markdown; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("ETag", etag)
        self.send_header("Cache-Control", "no-cache" if target.name == "index.html" else "public, max-age=300, must-revalidate")
        self.end_headers()
        if not head_only:
            self.wfile.write(content)

    def handle_session(self):
        user = self.current_user()
        if not user:
            self.send_json({"authenticated": False, "passwordPolicy": password_policy_public()})
            return
        self.send_json({"authenticated": True, "user": user_public(user), "csrfToken": user["csrf_token"], "passwordPolicy": password_policy_public()})

    def handle_access_policy(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        self.send_json({"accessPolicy": access_policy_public(user)})

    def oidc_callback_url(self):
        return f"{self.public_base_url()}/api/auth/sso/callback"

    def handle_oidc_providers(self):
        providers = []
        if OIDC_PROVIDERS:
            with conn() as db:
                for provider in OIDC_PROVIDERS.values():
                    if provider["tenant_id"]:
                        tenant = db.execute(
                            "SELECT id,name,status FROM tenants WHERE id = ?",
                            (provider["tenant_id"],),
                        ).fetchone()
                    else:
                        tenant = db.execute(
                            "SELECT id,name,status FROM tenants WHERE slug = ?",
                            (provider["tenant_slug"],),
                        ).fetchone()
                    if tenant and tenant["status"] == "active":
                        providers.append(public_provider(provider, tenant["name"]))
        self.send_json({"providers": providers})

    def handle_oidc_start(self):
        ip = self.client_address[0]
        if rate_limited(f"oidc:{ip}", limit=20, window=60):
            self.send_error_json(429, "too many login attempts")
            return
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        provider_id = str((query.get("provider") or [""])[0]).strip()
        provider = OIDC_PROVIDERS.get(provider_id)
        if not provider:
            self.send_error_json(404, "SSO provider not found")
            return
        redirect_after = str((query.get("next") or ["#dashboard"])[0]).strip()
        if not re.fullmatch(r"#[A-Za-z0-9_-]{1,80}", redirect_after):
            redirect_after = "#dashboard"
        values = new_login_values()
        try:
            login_url = authorization_url(
                provider,
                self.oidc_callback_url(),
                values["state"],
                values["nonce"],
                values["challenge"],
            )
        except OIDCError:
            self.send_error_json(503, "SSO provider is currently unavailable")
            return
        with conn() as db:
            tenant_filter = ("id", provider["tenant_id"]) if provider["tenant_id"] else ("slug", provider["tenant_slug"])
            tenant = db.execute(
                f"SELECT id,status FROM tenants WHERE {tenant_filter[0]} = ?",
                (tenant_filter[1],),
            ).fetchone()
            if not tenant or tenant["status"] != "active":
                self.send_error_json(403, "customer workspace is not active")
                return
            db.execute("DELETE FROM oidc_login_states WHERE expires_at <= ?", (now(),))
            db.execute(
                "INSERT INTO oidc_login_states (state_hash,provider_id,code_verifier,nonce,redirect_after,created_at,expires_at,ip) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (sha(values["state"].encode()), provider_id, values["verifier"], values["nonce"], redirect_after, now(), now() + OIDC_STATE_SECONDS, ip),
            )
            audit(db, None, "sso_login_started", "oidc_provider", provider_id, {"tenantId": tenant["id"]}, ip)
        self.send_redirect(login_url)

    def handle_oidc_callback(self):
        ip = self.client_address[0]
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        state = str((query.get("state") or [""])[0]).strip()
        code = str((query.get("code") or [""])[0]).strip()
        if query.get("error") or not state or not code:
            self.send_error_json(400, "SSO login was not completed")
            return
        with conn() as db:
            login_state = db.execute(
                "SELECT * FROM oidc_login_states WHERE state_hash = ?",
                (sha(state.encode()),),
            ).fetchone()
            if login_state:
                db.execute("DELETE FROM oidc_login_states WHERE state_hash = ?", (sha(state.encode()),))
        if not login_state or login_state["expires_at"] < now():
            self.send_error_json(400, "SSO login state is invalid or expired")
            return
        if login_state["ip"] and not secrets.compare_digest(str(login_state["ip"]), str(ip)):
            self.send_error_json(400, "SSO login state does not match this session")
            return
        provider = OIDC_PROVIDERS.get(login_state["provider_id"])
        if not provider:
            self.send_error_json(400, "SSO provider is no longer configured")
            return
        try:
            identity = exchange_code(
                provider,
                self.oidc_callback_url(),
                code,
                login_state["code_verifier"],
                login_state["nonce"],
            )
        except OIDCError:
            with conn() as db:
                audit(db, None, "sso_login_failed", "oidc_provider", provider["id"], {}, ip)
            self.send_error_json(401, "SSO identity could not be verified")
            return

        try:
            with conn() as db:
                tenant_filter = ("id", provider["tenant_id"]) if provider["tenant_id"] else ("slug", provider["tenant_slug"])
                tenant = db.execute(
                    f"SELECT id,name,slug,status FROM tenants WHERE {tenant_filter[0]} = ?",
                    (tenant_filter[1],),
                ).fetchone()
                if not tenant or tenant["status"] != "active":
                    self.send_error_json(403, "customer workspace is not active")
                    return
                user_row = db.execute(
                    "SELECT u.id,u.username,u.role,u.active,u.mfa_enabled,u.tenant_id,u.platform_admin,"
                    "t.name AS tenant_name,t.slug AS tenant_slug,t.status AS tenant_status,1 AS sso_linked "
                    "FROM oidc_identities oi JOIN users u ON u.id = oi.user_id JOIN tenants t ON t.id = u.tenant_id "
                    "WHERE oi.provider_id = ? AND oi.subject = ? AND u.tenant_id = ?",
                    (provider["id"], identity["subject"], tenant["id"]),
                ).fetchone()
                invitation = None
                if not user_row:
                    user_row = db.execute(
                        "SELECT u.id,u.username,u.role,u.active,u.mfa_enabled,u.tenant_id,u.platform_admin,"
                        "t.name AS tenant_name,t.slug AS tenant_slug,t.status AS tenant_status,0 AS sso_linked "
                        "FROM users u JOIN tenants t ON t.id = u.tenant_id "
                        "WHERE u.tenant_id = ? AND LOWER(u.email) = ?",
                        (tenant["id"], identity["email"]),
                    ).fetchone()
                if not user_row:
                    invitation = db.execute(
                        "SELECT * FROM invitations WHERE tenant_id = ? AND LOWER(email) = ? "
                        "AND status = 'pending' AND expires_at > ? ORDER BY created_at DESC",
                        (tenant["id"], identity["email"], now()),
                    ).fetchone()
                    if not invitation:
                        audit(db, None, "sso_login_not_preapproved", "oidc_provider", provider["id"], {"tenantId": tenant["id"]}, ip)
                        self.send_error_json(403, "SSO account is not invited to this customer workspace")
                        return
                    role = invitation["role"] if invitation["role"] in TENANT_INVITE_ROLES else "customer"
                    username = sso_username(identity["email"], tenant["slug"], db)
                    db.execute(
                        "INSERT INTO users (username,password_hash,role,created_at,active,updated_at,email,tenant_id,platform_admin) "
                        "VALUES (?,?,?,?,1,?,?,?,0)",
                        (username, password_hash(secrets.token_urlsafe(48)), role, now(), now(), identity["email"], tenant["id"]),
                    )
                    user_row = db.execute(
                        "SELECT u.id,u.username,u.role,u.active,u.mfa_enabled,u.tenant_id,u.platform_admin,"
                        "t.name AS tenant_name,t.slug AS tenant_slug,t.status AS tenant_status,0 AS sso_linked "
                        "FROM users u JOIN tenants t ON t.id = u.tenant_id WHERE u.username = ?",
                        (username,),
                    ).fetchone()
                if not user_row["active"]:
                    self.send_error_json(403, "user inactive")
                    return
                db.execute(
                    "INSERT INTO oidc_identities (provider_id,subject,user_id,email,created_at,last_login_at) VALUES (?,?,?,?,?,?) "
                    "ON CONFLICT(provider_id,subject) DO UPDATE SET email = excluded.email, last_login_at = excluded.last_login_at",
                    (provider["id"], identity["subject"], user_row["id"], identity["email"], now(), now()),
                )
                db.execute("UPDATE users SET email = ?, updated_at = ? WHERE id = ?", (identity["email"], now(), user_row["id"]))
                if invitation:
                    db.execute(
                        "UPDATE invitations SET status = 'accepted', accepted_at = ?, accepted_user_id = ? WHERE id = ?",
                        (now(), user_row["id"], invitation["id"]),
                    )
                user = dict(user_row)
                user["sso_linked"] = 1
                token, csrf = create_session(db, user, ip, action="sso_login")
                audit(db, user, "sso_identity_linked", "oidc_provider", provider["id"], {
                    "newUser": bool(invitation),
                    "tenantId": tenant["id"],
                }, ip)
        except DATABASE.integrity_errors:
            self.send_error_json(409, "SSO identity is already linked to another account")
            return
        destination = f"{self.public_base_url()}/{login_state['redirect_after'] or '#dashboard'}"
        self.send_redirect(destination, cookie_value(token))

    def handle_login(self):
        ip = self.client_address[0]
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        response_payload = None
        response_status = 200
        response_headers = None
        user = None
        token = ""
        csrf = ""
        with conn() as db:
            limit_status = login_limit_status(db, username, ip)
            if limit_status["blocked"]:
                audit(db, None, "login_blocked_rate_limit", "user", "", {
                    "blockedScopes": limit_status["scopes"],
                    "retryAfter": limit_status["retryAfter"],
                }, ip)
                response_payload = {
                    "error": "login temporarily unavailable",
                    "code": "login_temporarily_locked",
                    "retryAfter": limit_status["retryAfter"],
                }
                response_status = 429
                response_headers = {"Retry-After": str(limit_status["retryAfter"])}
            else:
                row = db.execute(
                    "SELECT u.id, u.username, u.password_hash, u.role, u.active, u.mfa_secret, u.mfa_enabled, u.password_change_required, "
                    "u.tenant_id, u.platform_admin, t.name AS tenant_name, t.slug AS tenant_slug, t.status AS tenant_status "
                    "FROM users u JOIN tenants t ON t.id = u.tenant_id WHERE u.username = ?",
                    (username,),
                ).fetchone()
                if not row or not password_ok(password, row["password_hash"]):
                    failure = record_login_failure(db, username, ip)
                    audit(db, dict(row) if row else None, "login_failed", "user", username if row else "", {
                        "blocked": failure["blocked"],
                        "blockedScopes": failure["scopes"],
                    }, ip)
                    if failure["blocked"]:
                        response_payload = {
                            "error": "login temporarily unavailable",
                            "code": "login_temporarily_locked",
                            "retryAfter": failure["retryAfter"],
                        }
                        response_status = 429
                        response_headers = {"Retry-After": str(failure["retryAfter"])}
                    else:
                        response_payload = {"error": "invalid credentials"}
                        response_status = 401
                elif not row["active"]:
                    audit(db, dict(row), "login_blocked_inactive", "user", str(row["id"]), {}, ip)
                    response_payload = {"error": "user inactive"}
                    response_status = 403
                elif row["tenant_status"] != "active":
                    audit(db, dict(row), "login_blocked_tenant_inactive", "user", str(row["id"]), {"tenantId": row["tenant_id"]}, ip)
                    response_payload = {"error": "tenant inactive"}
                    response_status = 403
                else:
                    if row["mfa_enabled"]:
                        code = str(payload.get("totp") or "")
                        if not code:
                            audit(db, dict(row), "login_mfa_required", "user", str(row["id"]), {}, ip)
                            response_payload = {"error": "mfa_required", "mfaRequired": True}
                            response_status = 401
                        elif not row["mfa_secret"] or not verify_totp(row["mfa_secret"], code):
                            failure = record_login_failure(db, username, ip)
                            audit(db, dict(row), "login_mfa_failed", "user", str(row["id"]), {
                                "blocked": failure["blocked"],
                                "blockedScopes": failure["scopes"],
                            }, ip)
                            if failure["blocked"]:
                                response_payload = {
                                    "error": "login temporarily unavailable",
                                    "code": "login_temporarily_locked",
                                    "retryAfter": failure["retryAfter"],
                                }
                                response_status = 429
                                response_headers = {"Retry-After": str(failure["retryAfter"])}
                            else:
                                response_payload = {"error": "invalid mfa code"}
                                response_status = 401
                    if response_payload is None:
                        user = dict(row)
                        clear_login_failures(db, username, ip)
                        db.execute("UPDATE users SET updated_at = ? WHERE id = ?", (now(), user["id"]))
                        token, csrf = create_session(db, user, ip)

        # Authentication state must be committed before the browser receives a result.
        if response_payload is not None:
            self.send_json(response_payload, status=response_status, extra_headers=response_headers)
            return
        self.send_json(
            {"authenticated": True, "user": user_public(user), "csrfToken": csrf, "passwordPolicy": password_policy_public()},
            extra_headers={"Set-Cookie": cookie_value(token)},
        )

    def handle_password_recovery_request(self):
        ip = self.client_address[0]
        generic_response = {
            "ok": True,
            "message": "If a recoverable account matches, a one-time link will be sent.",
        }
        if rate_limited(f"recovery-request:{ip}", limit=5, window=15 * 60):
            self.send_json(generic_response, status=202)
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        identifier = str(payload.get("identifier") or "").strip().lower()
        if not identifier or len(identifier) > 240 or not account_recovery_delivery_configured():
            self.send_json(generic_response, status=202)
            return
        requested_at = now()
        deliveries = []
        with conn() as db:
            rows = db.execute(
                "SELECT u.id,u.username,u.email,u.tenant_id FROM users u JOIN tenants t ON t.id = u.tenant_id "
                "WHERE u.active = 1 AND t.status = 'active' AND (LOWER(u.username) = ? OR LOWER(u.email) = ?) LIMIT 5",
                (identifier, identifier),
            ).fetchall()
            for row in rows:
                destination = str(row["email"] or "").strip().lower()
                if not valid_email(destination):
                    continue
                token = secrets.token_urlsafe(40)
                reset_id = uuid.uuid4().hex
                expires_at = requested_at + ACCOUNT_RECOVERY_TOKEN_SECONDS
                db.execute(
                    "UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
                    (requested_at, row["id"]),
                )
                db.execute(
                    "INSERT INTO password_reset_tokens (id,token_hash,user_id,requested_at,expires_at,requested_ip_hash) VALUES (?,?,?,?,?,?)",
                    (
                        reset_id,
                        sha(token.encode()),
                        row["id"],
                        requested_at,
                        expires_at,
                        persistent_login_scope_key("recovery-ip", ip),
                    ),
                )
                audit(db, None, "password_recovery_requested", "user", str(row["id"]), {
                    "resetId": reset_id,
                    "tenantId": row["tenant_id"],
                    "expiresAt": expires_at,
                }, ip)
                deliveries.append((reset_id, row["id"], destination, self.password_recovery_url(token)))
        for reset_id, user_id, destination, recovery_url in deliveries:
            threading.Thread(
                target=deliver_account_recovery,
                args=(reset_id, user_id, destination, recovery_url, ip),
                name=f"password-recovery-{reset_id[:8]}",
                daemon=True,
            ).start()
        self.send_json(generic_response, status=202)

    def handle_password_recovery_info(self):
        if not ACCOUNT_RECOVERY_ENABLED:
            self.send_error_json(404, "recovery link invalid or expired")
            return
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        token = str((query.get("token") or [""])[0]).strip()
        if not token or len(token) > 240:
            self.send_error_json(404, "recovery link invalid or expired")
            return
        with conn() as db:
            row = db.execute(
                "SELECT r.expires_at,u.username,u.email FROM password_reset_tokens r "
                "JOIN users u ON u.id = r.user_id JOIN tenants t ON t.id = u.tenant_id "
                "WHERE r.token_hash = ? AND r.used_at IS NULL AND r.expires_at > ? "
                "AND u.active = 1 AND t.status = 'active'",
                (sha(token.encode()), now()),
            ).fetchone()
        if not row:
            self.send_error_json(404, "recovery link invalid or expired")
            return
        account_hint = masked_email(row["email"]) if row["email"] else f"{str(row['username'])[:1]}***"
        self.send_json({"valid": True, "expiresAt": row["expires_at"], "accountHint": account_hint, "passwordPolicy": password_policy_public()})

    def handle_password_recovery_confirm(self):
        ip = self.client_address[0]
        if not ACCOUNT_RECOVERY_ENABLED:
            self.send_error_json(404, "recovery link invalid or expired")
            return
        if rate_limited(f"recovery-confirm:{ip}", limit=10, window=15 * 60):
            self.send_error_json(429, "too many recovery attempts")
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        token = str(payload.get("token") or "").strip()
        new_password = str(payload.get("newPassword") or "")
        if not token or len(token) > 240:
            self.send_error_json(404, "recovery link invalid or expired")
            return
        completed_at = now()
        with conn() as db:
            row = db.execute(
                "SELECT r.id,r.user_id,u.username,u.email,u.tenant_id FROM password_reset_tokens r "
                "JOIN users u ON u.id = r.user_id JOIN tenants t ON t.id = u.tenant_id "
                "WHERE r.token_hash = ? AND r.used_at IS NULL AND r.expires_at > ? "
                "AND u.active = 1 AND t.status = 'active'",
                (sha(token.encode()), completed_at),
            ).fetchone()
            if not row:
                self.send_error_json(404, "recovery link invalid or expired")
                return
            policy_error = update_user_password(
                db, row["user_id"], new_password, row["username"], row["email"],
                changed_by=None, reason="account_recovery", require_change=False,
            )
            if policy_error:
                self.send_password_policy_error(policy_error)
                return
            db.execute(
                "UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
                (completed_at, row["user_id"]),
            )
            revoked = db.execute("SELECT COUNT(*) FROM sessions WHERE user_id = ?", (row["user_id"],)).fetchone()[0]
            db.execute("DELETE FROM sessions WHERE user_id = ?", (row["user_id"],))
            clear_login_failures(db, row["username"])
            audit(db, None, "password_recovery_completed", "user", str(row["user_id"]), {
                "resetId": row["id"],
                "tenantId": row["tenant_id"],
                "sessionsRevoked": revoked,
                "mfaPreserved": True,
            }, ip)
        self.send_json({"ok": True, "sessionsRevoked": revoked, "mfaPreserved": True})

    def handle_logout(self):
        user = self.require_authenticated_write()
        if not user:
            return
        token = read_cookie(self.headers.get("Cookie"))
        with conn() as db:
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (sha(token.encode()),))
            audit(db, user, "logout", "user", str(user["id"]), {}, self.client_address[0])
        self.send_json({"ok": True}, extra_headers={"Set-Cookie": cookie_value("", 0)})

    def handle_list_my_sessions(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        token = read_cookie(self.headers.get("Cookie"))
        current_hash = sha(token.encode()) if token else ""
        with conn() as db:
            rows = db.execute(
                "SELECT s.token_hash, s.tenant_id, s.expires_at, s.created_at, s.ip, t.name AS tenant_name "
                "FROM sessions s LEFT JOIN tenants t ON t.id = s.tenant_id "
                "WHERE s.user_id = ? ORDER BY s.created_at DESC",
                (user["id"],),
            ).fetchall()
        current_ts = now()
        self.send_json({
            "sessions": [
                {
                    "id": row["token_hash"][:16],
                    "current": row["token_hash"] == current_hash,
                    "tenantId": row["tenant_id"],
                    "tenantName": row["tenant_name"] or row["tenant_id"] or "",
                    "createdAt": row["created_at"],
                    "expiresAt": row["expires_at"],
                    "ip": row["ip"] or "",
                    "status": "active" if row["expires_at"] > current_ts else "expired",
                }
                for row in rows
            ]
        })

    def handle_revoke_my_session(self):
        user = self.require_authenticated_write()
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        session_id = str(payload.get("sessionId") or "").strip()
        if len(session_id) < 8 or not re.fullmatch(r"[a-f0-9]+", session_id):
            self.send_error_json(400, "invalid session id")
            return
        token = read_cookie(self.headers.get("Cookie"))
        current_hash = sha(token.encode()) if token else ""
        with conn() as db:
            rows = db.execute(
                "SELECT token_hash FROM sessions WHERE user_id = ? AND token_hash LIKE ?",
                (user["id"], f"{session_id}%"),
            ).fetchall()
            if not rows:
                self.send_error_json(404, "session not found")
                return
            if len(rows) > 1:
                self.send_error_json(409, "session id ambiguous")
                return
            target_hash = rows[0]["token_hash"]
            if target_hash == current_hash:
                self.send_error_json(400, "current session must be ended via logout")
                return
            db.execute("DELETE FROM sessions WHERE token_hash = ? AND user_id = ?", (target_hash, user["id"]))
            audit(db, user, "session_revoked", "session", session_id, {"current": False}, self.client_address[0])
        self.send_json({"ok": True, "revoked": 1})

    def handle_revoke_other_sessions(self):
        user = self.require_authenticated_write()
        if not user:
            return
        token = read_cookie(self.headers.get("Cookie"))
        current_hash = sha(token.encode()) if token else ""
        with conn() as db:
            before = db.execute(
                "SELECT COUNT(*) FROM sessions WHERE user_id = ? AND token_hash <> ?",
                (user["id"], current_hash),
            ).fetchone()[0]
            db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?", (user["id"], current_hash))
            audit(db, user, "other_sessions_revoked", "user", str(user["id"]), {"revoked": before}, self.client_address[0])
        self.send_json({"ok": True, "revoked": before})

    def handle_switch_tenant(self):
        user = self.require_platform_admin(write=True)
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        tenant_id = str(payload.get("tenantId") or "").strip()
        if not tenant_id:
            self.send_error_json(400, "tenant id required")
            return
        token = read_cookie(self.headers.get("Cookie"))
        if not token:
            self.send_error_json(401, "not authenticated")
            return
        token_hash = sha(token.encode())
        with conn() as db:
            tenant = db.execute(
                "SELECT id, name, slug, status FROM tenants WHERE id = ?",
                (tenant_id,),
            ).fetchone()
            if not tenant:
                self.send_error_json(404, "tenant not found")
                return
            if tenant["status"] != "active":
                self.send_error_json(409, "tenant is not active")
                return
            db.execute("UPDATE sessions SET tenant_id = ? WHERE token_hash = ?", (tenant_id, token_hash))
            audit(db, user, "tenant_context_switched", "tenant", tenant_id, {
                "fromTenantId": user.get("tenant_id"),
                "fromTenantName": user.get("tenant_name"),
                "toTenantId": tenant_id,
                "toTenantName": tenant["name"],
                "toTenantSlug": tenant["slug"],
            }, self.client_address[0])
        switched_user = self.current_user()
        if not switched_user:
            self.send_error_json(401, "session expired")
            return
        self.send_json({"ok": True, "user": user_public(switched_user), "csrfToken": switched_user["csrf_token"]})

    def handle_get_state(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT w.state_json, w.updated_at, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({"state": None, "updatedAt": None, "updatedBy": None, "revision": None})
            return
        try:
            state = json.loads(row["state_json"])
        except json.JSONDecodeError:
            state = None
        validation = workspace_state_validation_report(state, row["state_json"])
        self.send_json({
            "state": state,
            "updatedAt": row["updated_at"],
            "updatedBy": row["updated_by_username"],
            "revision": row["revision"],
            "validation": validation,
        })

    def handle_get_state_meta(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT w.updated_at, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({"exists": False, "revision": None, "updatedAt": None, "updatedBy": None})
            return
        self.send_json({
            "exists": True,
            "revision": row["revision"],
            "updatedAt": row["updated_at"],
            "updatedBy": row["updated_by_username"],
        })

    def handle_audit_package_status(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT state_json,revision,updated_at FROM tenant_workspace_state WHERE tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({
                "error": "workspace_not_initialized",
                "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
            }, status=409)
            return
        try:
            state = json.loads(row["state_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            self.send_error_json(500, "stored workspace state is invalid")
            return
        status = audit_package_status(state, int(row["revision"] or 1))
        status["updatedAt"] = row["updated_at"]
        self.send_json({"auditPackage": status})

    def handle_approve_audit_package(self):
        user = self.require_user(permission="reviewDocument")
        if not user:
            return
        if user.get("role") not in {"admin", "consultant"}:
            self.send_error_json(403, "audit package approval requires admin or consultant role")
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        expected_revision = payload.get("expectedRevision")
        expected_fingerprint = str(payload.get("fingerprint") or "").strip()
        if expected_revision is not None and (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 1
        ):
            self.send_error_json(400, "expectedRevision must be a positive integer or null")
            return

        approved_at = now()
        with conn() as db:
            DATABASE.begin_workspace_write(db)
            row = db.execute(
                "SELECT state_json,revision,updated_at,updated_by FROM tenant_workspace_state WHERE tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            if not row:
                self.send_json({
                    "error": "workspace_not_initialized",
                    "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                }, status=409)
                return
            current_revision = int(row["revision"] or 1)
            if expected_revision is not None and expected_revision != current_revision:
                self.send_json({
                    "error": "workspace_conflict",
                    "message": "Workspace wurde zwischenzeitlich geändert.",
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                }, status=409)
                return
            try:
                state = json.loads(row["state_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                self.send_error_json(500, "stored workspace state is invalid")
                return
            current_status = audit_package_status(state, current_revision)
            if expected_fingerprint and expected_fingerprint != current_status["fingerprint"]:
                self.send_json({
                    "error": "audit_package_changed",
                    "message": "Das Auditpaket wurde seit der Prüfung geändert. Bitte erneut prüfen.",
                    "auditPackage": current_status,
                }, status=409)
                return
            if not current_status["formalGateClear"]:
                audit(db, user, "audit_package_approval_blocked", "audit_package", user["tenant_id"], {
                    "fingerprint": current_status["fingerprint"],
                    "blockerCount": current_status["blockerCount"],
                    "revision": current_revision,
                }, self.client_address[0])
                self.send_json({
                    "error": "audit_package_blocked",
                    "message": "Auditpaket ist vorbereitet, aber noch nicht durch den Berater freigegeben.",
                    "auditPackage": current_status,
                }, status=409)
                return
            proposed_state = json.loads(json.dumps(state, ensure_ascii=False))
            package = proposed_state.get("auditPackage")
            if not isinstance(package, dict):
                package = {}
                proposed_state["auditPackage"] = package
            approvals = package.get("approvals")
            if not isinstance(approvals, list):
                approvals = []
            approval = {
                "id": f"audit-package-approval-{uuid.uuid4().hex}",
                "status": "beraterfreigegeben",
                "fingerprint": current_status["fingerprint"],
                "approvedAt": approved_at,
                "approvedBy": user["username"],
                "approvedByRole": user["role"],
                "workspaceRevision": current_revision,
                "comment": str(payload.get("comment") or "").strip()[:2000],
            }
            package["approvals"] = [approval] + [
                item for item in approvals
                if isinstance(item, dict) and item.get("fingerprint") != approval["fingerprint"]
            ][:49]
            package["status"] = "beraterfreigegeben"
            package["updatedAt"] = approved_at
            package["updatedBy"] = user["username"]
            state_json = json.dumps(proposed_state, ensure_ascii=False, separators=(",", ":"))
            validation = workspace_state_validation_report(proposed_state, state_json)
            if not validation["valid"]:
                self.send_json({"error": "workspace state is incomplete", "validation": validation}, status=400)
                return
            snapshot_id = insert_state_snapshot(
                db,
                user["tenant_id"],
                row["state_json"],
                row["updated_by"],
                "before_audit_package_approval",
            )
            new_revision = current_revision + 1
            db.execute(
                "UPDATE tenant_workspace_state SET state_json = ?,updated_at = ?,updated_by = ?,revision = ? WHERE tenant_id = ?",
                (state_json, approved_at, user["id"], new_revision, user["tenant_id"]),
            )
            audit(db, user, "audit_package_approved", "audit_package", user["tenant_id"], {
                "approvalId": approval["id"],
                "fingerprint": approval["fingerprint"],
                "previousRevision": current_revision,
                "revision": new_revision,
                "snapshotId": snapshot_id,
            }, self.client_address[0])

        result = audit_package_status(proposed_state, new_revision)
        self.send_json({"ok": True, "auditPackage": result, "approval": approval})

    def handle_export_audit_package(self):
        user = self.require_user(permission="downloadFile")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT state_json,revision,updated_at FROM tenant_workspace_state WHERE tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            tenant = db.execute(
                "SELECT id,name,slug FROM tenants WHERE id = ?",
                (user["tenant_id"],),
            ).fetchone()
            file_rows = db.execute(
                "SELECT id,original_name,stored_name,content_type,size,sha256,nonce,uploaded_at,document_id,"
                "version_label,linked_to,classification FROM files "
                "WHERE tenant_id = ? AND quarantined = 0 ORDER BY uploaded_at,id",
                (user["tenant_id"],),
            ).fetchall()
            if not row or not tenant:
                self.send_json({
                    "error": "workspace_not_initialized",
                    "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                }, status=409)
                return
            try:
                state = json.loads(row["state_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                self.send_error_json(500, "stored workspace state is invalid")
                return
            package_status = audit_package_status(state, int(row["revision"] or 1))
            if not package_status["exportReady"]:
                self.send_json({
                    "error": "audit_package_not_approved",
                    "message": "Auditpaket ist vorbereitet, aber noch nicht durch den Berater freigegeben.",
                    "auditPackage": package_status,
                }, status=409)
                return

            estimated_bytes = len(row["state_json"].encode("utf-8")) + sum(int(item["size"] or 0) for item in file_rows)
            if estimated_bytes > MAX_TENANT_EXPORT:
                self.send_json({
                    "error": "audit package exceeds configured size limit",
                    "estimatedBytes": estimated_bytes,
                    "limitBytes": MAX_TENANT_EXPORT,
                }, status=413)
                return

            exported_files = []
            decrypted_files = []
            for item in file_rows:
                try:
                    content = decrypt(unb64(item["nonce"]), FILE_STORAGE.get(item["stored_name"]))
                except Exception:
                    self.send_json({
                        "error": "audit package blocked because a file failed integrity verification",
                        "fileId": item["id"],
                        "name": item["original_name"],
                    }, status=409)
                    return
                if sha(content) != item["sha256"]:
                    self.send_json({
                        "error": "audit package blocked because a file checksum does not match",
                        "fileId": item["id"],
                        "name": item["original_name"],
                    }, status=409)
                    return
                archive_path = f"evidence/{str(item['id'])[:12]}-{safe_filename(item['original_name'])}"
                decrypted_files.append((archive_path, content))
                exported_files.append({
                    "id": item["id"],
                    "name": item["original_name"],
                    "archivePath": archive_path,
                    "contentType": item["content_type"],
                    "size": item["size"],
                    "sha256": item["sha256"],
                    "uploadedAt": item["uploaded_at"],
                    "documentId": item["document_id"] or "",
                    "version": item["version_label"] or "",
                    "linkedTo": item["linked_to"] or "",
                    "classification": item["classification"] or "",
                })

            exported_at = now()
            public_state = audit_package_public_value(audit_package_material_state(state))
            manifest = {
                "format": "sfm-compliance-audit-package-v1",
                "tenant": {"id": tenant["id"], "name": tenant["name"], "slug": tenant["slug"]},
                "exportedAt": exported_at,
                "exportedBy": user["username"],
                "fingerprint": package_status["fingerprint"],
                "workspaceRevision": package_status["workspaceRevision"],
                "advisorApproval": package_status["approval"],
                "formalGate": {
                    "clear": package_status["formalGateClear"],
                    "criteria": package_status["criteria"],
                },
                "files": exported_files,
                "notice": "Technisch vorbereitet und durch Berater/Admin freigegeben. Keine automatische Aussage zu ISO-Konformitaet, NIS-2-Erfuellung oder Auditbereitschaft.",
            }
            buffer = io.BytesIO()
            try:
                with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                    archive.writestr("README.txt", (
                        "SFM Compliance Auditpaket\n\n"
                        "Das Paket wurde technisch zusammengestellt und explizit durch Berater/Admin freigegeben.\n"
                        "Es ist keine automatische Aussage zu ISO-Konformitaet, NIS-2-Erfuellung oder Auditbereitschaft.\n"
                    ))
                    archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
                    archive.writestr("workspace/registers.json", json.dumps(public_state, ensure_ascii=False, indent=2))
                    archive.writestr("evidence/index.json", json.dumps(exported_files, ensure_ascii=False, indent=2))
                    for archive_path, content in decrypted_files:
                        archive.writestr(archive_path, content)
            except Exception:
                self.send_error_json(500, "audit package could not be created")
                return
            content = buffer.getvalue()
            audit(db, user, "audit_package_exported", "audit_package", user["tenant_id"], {
                "fingerprint": package_status["fingerprint"],
                "workspaceRevision": package_status["workspaceRevision"],
                "files": len(exported_files),
                "bytes": len(content),
            }, self.client_address[0])

        stamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"sfm-audit-package-{safe_filename(tenant['slug'])}-{stamp}.zip"
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def handle_intune(self, action):
        user = self.require_user(permission="readWorkspace" if action == "status" else "admin")
        if not user:
            return
        service = intune_service()
        try:
            if action == "status":
                result = service.status(user["tenant_id"])
                result["workerEnabled"] = BACKGROUND_JOB_WORKER_ENABLED
                result["canManage"] = user["role"] == "admin"
                result["setupTransportAllowed"] = setup_transport_allowed(self.public_base_url(), self.client_address[0])
            else:
                payload = self.json_body()
                if not isinstance(payload, dict):
                    raise IntuneError("JSON-Objekt erwartet.")
                if action in {"configure", "disconnect"}:
                    if not setup_transport_allowed(self.public_base_url(), self.client_address[0]):
                        raise IntuneError("App-Zugang nur ueber HTTPS oder auf localhost einrichten.", 403)
                    with conn() as db:
                        DATABASE.begin_workspace_write(db)
                        service.configure(db, user, payload, remove=action == "disconnect")
                    result = {"saved": action == "configure"}
                elif action == "apply":
                    preview_id = payload.get("previewId")
                    if not isinstance(preview_id, str) or not preview_id:
                        raise IntuneError("previewId ist erforderlich.")
                    result = service.apply(user, preview_id=preview_id)
                elif action == "preview":
                    if not BACKGROUND_JOB_WORKER_ENABLED:
                        raise IntuneError("Hintergrunddienst ist deaktiviert.", 409)
                    with conn() as db:
                        DATABASE.begin_workspace_write(db)
                        job_id = service.enqueue(db, user, enqueue_background_job)
                    result = {"jobId": job_id}
                else:
                    if not isinstance(payload.get("enabled"), bool):
                        raise IntuneError("enabled muss ein Wahrheitswert sein.")
                    if payload["enabled"] and not BACKGROUND_JOB_WORKER_ENABLED:
                        raise IntuneError("Hintergrunddienst ist deaktiviert.", 409)
                    with conn() as db:
                        DATABASE.begin_workspace_write(db)
                        service.schedule(db, user, payload["enabled"])
                    result = {"enabled": payload["enabled"]}
            self.send_json(result, status=202 if action == "preview" else 200)
        except IntuneError as exc:
            self.send_error_json(exc.status, str(exc))
        except (ValueError, TypeError):
            self.send_error_json(400, "Intune-Anfrage oder gespeicherte Vorschau ungueltig.")

    def handle_list_assets(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT w.state_json, w.updated_at, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({"assets": [], "updatedAt": None, "updatedBy": None, "revision": None})
            return
        try:
            state = json.loads(row["state_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            self.send_error_json(500, "stored workspace state is invalid")
            return
        assets = state.get("assets")
        if not isinstance(assets, list):
            self.send_error_json(500, "stored asset register is invalid")
            return
        self.send_json({
            "assets": assets,
            "updatedAt": row["updated_at"],
            "updatedBy": row["updated_by_username"],
            "revision": row["revision"],
        })

    def handle_create_asset(self):
        self.handle_asset_mutation("create")

    def handle_update_asset(self, asset_id):
        self.handle_asset_mutation("update", asset_id)

    def handle_delete_asset(self, asset_id):
        self.handle_asset_mutation("delete", asset_id)

    def handle_list_risks(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT w.state_json, w.updated_at, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({"risks": [], "updatedAt": None, "updatedBy": None, "revision": None})
            return
        try:
            state = json.loads(row["state_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            self.send_error_json(500, "stored workspace state is invalid")
            return
        risks = state.get("risks")
        if not isinstance(risks, list):
            self.send_error_json(500, "stored risk register is invalid")
            return
        self.send_json({
            "risks": risks,
            "updatedAt": row["updated_at"],
            "updatedBy": row["updated_by_username"],
            "revision": row["revision"],
        })

    def handle_create_risk(self):
        self.handle_risk_mutation("create")

    def handle_update_risk(self, risk_id):
        self.handle_risk_mutation("update", risk_id)

    def handle_delete_risk(self, risk_id):
        self.handle_risk_mutation("delete", risk_id)

    def handle_list_suppliers(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT w.state_json, w.updated_at, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({"suppliers": [], "updatedAt": None, "updatedBy": None, "revision": None})
            return
        try:
            state = json.loads(row["state_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            self.send_error_json(500, "stored workspace state is invalid")
            return
        suppliers = state.get("suppliers")
        if not isinstance(suppliers, list):
            self.send_error_json(500, "stored supplier register is invalid")
            return
        self.send_json({
            "suppliers": suppliers,
            "updatedAt": row["updated_at"],
            "updatedBy": row["updated_by_username"],
            "revision": row["revision"],
        })

    def handle_create_supplier(self):
        self.handle_supplier_mutation("create")

    def handle_update_supplier(self, supplier_id):
        self.handle_supplier_mutation("update", supplier_id)

    def handle_delete_supplier(self, supplier_id):
        self.handle_supplier_mutation("delete", supplier_id)

    def handle_list_policies(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT w.state_json, w.updated_at, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({"policies": [], "updatedAt": None, "updatedBy": None, "revision": None})
            return
        try:
            state = json.loads(row["state_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            self.send_error_json(500, "stored workspace state is invalid")
            return
        policies = state.get("policies")
        if not isinstance(policies, list):
            self.send_error_json(500, "stored policy register is invalid")
            return
        self.send_json({
            "policies": policies,
            "updatedAt": row["updated_at"],
            "updatedBy": row["updated_by_username"],
            "revision": row["revision"],
        })

    def handle_create_policy(self):
        self.handle_policy_mutation("create")

    def handle_update_policy(self, policy_id):
        self.handle_policy_mutation("update", policy_id)

    def handle_delete_policy(self, policy_id):
        self.handle_policy_mutation("delete", policy_id)

    def handle_list_incidents(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT w.state_json, w.updated_at, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({"incidents": [], "updatedAt": None, "updatedBy": None, "revision": None})
            return
        try:
            state = json.loads(row["state_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            self.send_error_json(500, "stored workspace state is invalid")
            return
        incidents = state.get("incidents")
        if not isinstance(incidents, list):
            self.send_error_json(500, "stored incident register is invalid")
            return
        self.send_json({
            "incidents": incidents,
            "updatedAt": row["updated_at"],
            "updatedBy": row["updated_by_username"],
            "revision": row["revision"],
        })

    def handle_create_incident(self):
        self.handle_incident_mutation("create")

    def handle_update_incident(self, incident_id):
        self.handle_incident_mutation("update", incident_id)

    def handle_delete_incident(self, incident_id):
        self.handle_incident_mutation("delete", incident_id)

    def handle_list_contracts(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT w.state_json, w.updated_at, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({"contracts": [], "updatedAt": None, "updatedBy": None, "revision": None})
            return
        try:
            state = json.loads(row["state_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            self.send_error_json(500, "stored workspace state is invalid")
            return
        contracts = state.get("contracts")
        if not isinstance(contracts, list):
            self.send_error_json(500, "stored contract register is invalid")
            return
        self.send_json({
            "contracts": contracts,
            "updatedAt": row["updated_at"],
            "updatedBy": row["updated_by_username"],
            "revision": row["revision"],
        })

    def handle_create_contract(self):
        self.handle_contract_mutation("create")

    def handle_update_contract(self, contract_id):
        self.handle_contract_mutation("update", contract_id)

    def handle_delete_contract(self, contract_id):
        self.handle_contract_mutation("delete", contract_id)

    def handle_list_tasks(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT w.state_json, w.updated_at, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({"tasks": [], "updatedAt": None, "updatedBy": None, "revision": None})
            return
        try:
            state = json.loads(row["state_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            self.send_error_json(500, "stored workspace state is invalid")
            return
        tasks = state.get("tasks")
        if not isinstance(tasks, list):
            self.send_error_json(500, "stored task register is invalid")
            return
        self.send_json({
            "tasks": tasks,
            "updatedAt": row["updated_at"],
            "updatedBy": row["updated_by_username"],
            "revision": row["revision"],
        })

    def handle_create_task(self):
        self.handle_task_mutation("create")

    def handle_update_task(self, task_id):
        self.handle_task_mutation("update", task_id)

    def handle_delete_task(self, task_id):
        self.handle_task_mutation("delete", task_id)

    def handle_list_legal(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT w.state_json, w.updated_at, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({"legal": [], "updatedAt": None, "updatedBy": None, "revision": None})
            return
        try:
            state = json.loads(row["state_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            self.send_error_json(500, "stored workspace state is invalid")
            return
        legal_entries = state.get("legal")
        if not isinstance(legal_entries, list):
            self.send_error_json(500, "stored legal register is invalid")
            return
        self.send_json({
            "legal": legal_entries,
            "updatedAt": row["updated_at"],
            "updatedBy": row["updated_by_username"],
            "revision": row["revision"],
        })

    def handle_create_legal_entry(self):
        self.handle_legal_mutation("create")

    def handle_update_legal_entry(self, legal_id):
        self.handle_legal_mutation("update", legal_id)

    def handle_delete_legal_entry(self, legal_id):
        self.handle_legal_mutation("delete", legal_id)

    def handle_list_soa(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT w.state_json, w.updated_at, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({"soa": [], "updatedAt": None, "updatedBy": None, "revision": None})
            return
        try:
            state = json.loads(row["state_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            self.send_error_json(500, "stored workspace state is invalid")
            return
        records = state.get("soa", [])
        if not isinstance(records, list):
            self.send_error_json(500, "stored SoA register is invalid")
            return
        self.send_json({
            "soa": records,
            "updatedAt": row["updated_at"],
            "updatedBy": row["updated_by_username"],
            "revision": row["revision"],
        })

    def handle_update_soa_control(self, control_id):
        self.handle_soa_mutation(control_id)

    def handle_list_audit_findings(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT w.state_json, w.updated_at, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({"auditFindings": [], "updatedAt": None, "updatedBy": None, "revision": None})
            return
        try:
            state = json.loads(row["state_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            self.send_error_json(500, "stored workspace state is invalid")
            return
        findings = state.get("auditFindings", [])
        if not isinstance(findings, list):
            self.send_error_json(500, "stored audit finding register is invalid")
            return
        self.send_json({
            "auditFindings": findings,
            "updatedAt": row["updated_at"],
            "updatedBy": row["updated_by_username"],
            "revision": row["revision"],
        })

    def handle_create_audit_finding(self):
        self.handle_audit_finding_mutation("create")

    def handle_update_audit_finding(self, finding_id):
        self.handle_audit_finding_mutation("update", finding_id)

    def handle_delete_audit_finding(self, finding_id):
        self.handle_audit_finding_mutation("delete", finding_id)

    def handle_get_management_review(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT w.state_json, w.updated_at, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({"managementReview": {}, "updatedAt": None, "updatedBy": None, "revision": None})
            return
        try:
            state = json.loads(row["state_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            self.send_error_json(500, "stored workspace state is invalid")
            return
        review = state.get("managementReview", {})
        if not isinstance(review, dict):
            self.send_error_json(500, "stored management review is invalid")
            return
        self.send_json({
            "managementReview": review,
            "updatedAt": row["updated_at"],
            "updatedBy": row["updated_by_username"],
            "revision": row["revision"],
        })

    def handle_update_management_review(self):
        user, submission_only = self.require_asset_mutation_user(delete=False)
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        if "expectedRevision" not in payload:
            self.send_error_json(400, "expectedRevision is required")
            return
        expected_revision = payload.get("expectedRevision")
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            self.send_error_json(400, "expectedRevision must be a non-negative integer")
            return
        changes = payload.get("changes")
        if not isinstance(changes, dict) or not changes:
            self.send_error_json(400, "changes must be a non-empty object")
            return
        changes = json.loads(json.dumps(changes, ensure_ascii=False))

        mutable_fields = {
            "title", "reviewPeriod", "meetingDate", "nextReview", "chair", "participants", "status",
            "reviewStatus", "summary", "decisions", "resources", "improvements", "customerComment",
            "consultantInternalComment", "consultantDecision", "auditRelevant", "reviewAssignee", "reviewDue",
        }
        protected_server_fields = {
            "id", "workflowHistory", "serverUpdatedAt", "serverUpdatedBy", "submittedAt", "submittedBy",
            "approvedAt", "approvedBy", "rejectedAt", "rejectedBy",
        }
        for field in protected_server_fields:
            changes.pop(field, None)
        if not changes:
            self.send_error_json(400, "changes contain no mutable management review fields")
            return
        unknown_fields = sorted(set(changes) - mutable_fields)
        if unknown_fields:
            self.send_json({
                "error": "unsupported_management_review_fields",
                "message": "Unsupported management review fields were supplied.",
                "fields": unknown_fields,
            }, status=400)
            return

        allowed_statuses = {
            "offen", "vorbereitet", "vom_kunden_eingereicht", "in_beraterpruefung", "nacharbeit_noetig",
            "freigegeben", "abgelehnt", "auditrelevant", "spaeter_pruefen",
        }
        for field in ("status", "reviewStatus"):
            value = str(changes.get(field) or "").strip()
            if value and value not in allowed_statuses:
                self.send_error_json(400, f"invalid management review {field}")
                return
        for field, value in changes.items():
            if field == "auditRelevant":
                if not isinstance(value, bool):
                    self.send_error_json(400, "auditRelevant must be a boolean")
                    return
                continue
            if not isinstance(value, str):
                self.send_error_json(400, f"{field} must be a string")
                return
            if len(value) > 20000:
                self.send_error_json(400, f"{field} is too long")
                return

        requested_status = normalized_submission_status(changes.get("status"))
        requested_review_status = normalized_submission_status(changes.get("reviewStatus"))
        requested_protected_decision = requested_status in CUSTOMER_FORBIDDEN_STATUS_VALUES \
            or requested_review_status in CUSTOMER_FORBIDDEN_STATUS_VALUES \
            or any(field in changes for field in ("consultantInternalComment", "consultantDecision", "auditRelevant"))
        saved_at = now()
        saved_date = time.strftime("%Y-%m-%d", time.localtime(saved_at))
        saved_iso = datetime.fromtimestamp(saved_at, tz=timezone.utc).isoformat()
        submission_report = None
        submission_changes = []
        snapshot_id = None
        customer_task = None

        with conn() as db:
            DATABASE.begin_workspace_write(db)
            previous = db.execute(
                "SELECT w.state_json, w.updated_at, w.updated_by, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            if not previous:
                self.send_json({
                    "error": "workspace_not_initialized",
                    "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                }, status=409)
                return
            current_revision = int(previous["revision"] or 1)
            if expected_revision != current_revision:
                audit(db, user, "management_review_update_conflict", "management_review", "management-review", {
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, self.client_address[0])
                self.send_json({
                    "error": "workspace_conflict",
                    "message": "Workspace wurde zwischenzeitlich geändert.",
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, status=409)
                return
            try:
                previous_state = json.loads(previous["state_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                self.send_error_json(500, "stored workspace state is invalid")
                return
            current_review = previous_state.get("managementReview", {})
            if not isinstance(current_review, dict):
                self.send_error_json(500, "stored management review is invalid")
                return
            proposed_state = json.loads(json.dumps(previous_state, ensure_ascii=False))
            response_review = {
                "id": "management-review",
                "title": "Managementbewertung",
                "status": "offen",
                "reviewStatus": "offen",
                "auditRelevant": not submission_only,
                **current_review,
                **changes,
            }
            if submission_only:
                response_review["status"] = "vom_kunden_eingereicht"
                response_review["reviewStatus"] = "vom_kunden_eingereicht"
                response_review["submittedAt"] = saved_at
                response_review["submittedBy"] = user["username"]
            else:
                decision_status = str(response_review.get("reviewStatus") or response_review.get("status") or "offen")
                if decision_status == "freigegeben":
                    response_review["approvedAt"] = saved_at
                    response_review["approvedBy"] = user["username"]
                    response_review.pop("rejectedAt", None)
                    response_review.pop("rejectedBy", None)
                elif decision_status == "abgelehnt":
                    response_review["rejectedAt"] = saved_at
                    response_review["rejectedBy"] = user["username"]
                    response_review.pop("approvedAt", None)
                    response_review.pop("approvedBy", None)
            proposed_state["managementReview"] = response_review
            changed_fields = sorted(
                key for key in set(current_review) | set(response_review)
                if canonical_workspace_value(current_review.get(key)) != canonical_workspace_value(response_review.get(key))
            )
            if not changed_fields:
                self.send_json({
                    "ok": True,
                    "managementReview": response_review,
                    "updatedAt": previous["updated_at"],
                    "updatedBy": previous["updated_by_username"],
                    "revision": current_revision,
                    "unchanged": True,
                })
                return

            if not submission_only:
                tasks = proposed_state.get("tasks", [])
                if not isinstance(tasks, list):
                    self.send_error_json(500, "stored task register is invalid")
                    return
                task_index = next(
                    (
                        index for index, task in enumerate(tasks)
                        if isinstance(task, dict)
                        and task.get("reviewItemKey") == "managementReview:management-review"
                        and task.get("workflowType") == "review-rework"
                        and task.get("status") != "Erledigt"
                    ),
                    None,
                )
                review_status = str(response_review.get("reviewStatus") or response_review.get("status") or "offen")
                if review_status in {"nacharbeit_noetig", "abgelehnt"}:
                    missing = str(response_review.get("customerComment") or "Managementbewertung fachlich ergänzen.").strip()
                    task = {
                        "id": tasks[task_index].get("id") if task_index is not None else workspace_item_id("task"),
                        "title": f"Nacharbeit: {response_review.get('title') or 'Managementbewertung'}",
                        "module": "Managementbewertung",
                        "owner": str(response_review.get("chair") or "Kunde / Projektteam"),
                        "due": today_iso(14),
                        "status": "Offen",
                        "workflowType": "review-rework",
                        "source": "Berater-Rückgabe",
                        "reviewReturnStatus": review_status,
                        "reviewItemKey": "managementReview:management-review",
                        "linkedTo": "Managementbewertung / Auditpaket",
                        "reworkMissing": missing,
                        "reworkWhy": "Die Managementbewertung ist fachlich noch nicht freigegeben.",
                        "reworkAction": "Bitte ergänze die angeforderten Inhalte und reiche die Managementbewertung erneut ein.",
                        "reworkReference": str(response_review.get("title") or "Managementbewertung"),
                        "note": (
                            f"Was fehlt? {missing}\n"
                            "Warum reicht es noch nicht? Die Managementbewertung ist fachlich noch nicht freigegeben.\n"
                            "Was ist zu tun? Inhalte ergänzen und erneut zur Beraterprüfung einreichen.\n"
                            f"Bezug: {response_review.get('title') or 'Managementbewertung'}"
                        ),
                    }
                    if task_index is None:
                        tasks.insert(0, task)
                    else:
                        tasks[task_index] = task
                    customer_task = task
                elif review_status == "freigegeben" and task_index is not None:
                    tasks[task_index]["status"] = "Erledigt"
                    tasks[task_index]["note"] = "Managementbewertung durch Berater/Admin freigegeben."
                    customer_task = tasks[task_index]

            if submission_only:
                submission_report = customer_submission_policy_report(previous_state, proposed_state)
                if requested_protected_decision:
                    submission_report["violations"].append({
                        "path": "managementReview.reviewStatus",
                        "reason": "management_review_decision_requires_advisor",
                    })
                    submission_report["allowed"] = False
                if not submission_report["allowed"]:
                    audit(db, user, "management_review_update_rejected", "management_review", "management-review", {
                        "violations": submission_report["violations"],
                        "revision": current_revision,
                    }, self.client_address[0])
                    self.send_json({
                        "error": "submission_policy_violation",
                        "message": "Diese Managementbewertungs-Entscheidung benötigt Berater- oder Adminrechte.",
                        "submission": submission_report,
                    }, status=403)
                    return

            response_review["serverUpdatedAt"] = saved_at
            response_review["serverUpdatedBy"] = user["username"]
            workflow_entry = {
                "date": saved_date,
                "dateTime": saved_iso,
                "action": "Managementbewertung eingereicht" if submission_only else "Managementbewertung aktualisiert",
                "by": user["username"],
                "note": "Änderung über die Managementbewertungs-API gespeichert.",
                "status": str(response_review.get("reviewStatus") or "offen"),
                "changes": changed_fields,
                "snapshot": {
                    "title": str(response_review.get("title") or ""),
                    "reviewPeriod": str(response_review.get("reviewPeriod") or ""),
                    "meetingDate": str(response_review.get("meetingDate") or ""),
                    "chair": str(response_review.get("chair") or ""),
                    "status": str(response_review.get("status") or ""),
                    "reviewStatus": str(response_review.get("reviewStatus") or ""),
                },
            }
            existing_workflow = response_review.get("workflowHistory")
            if not isinstance(existing_workflow, list):
                existing_workflow = []
            response_review["workflowHistory"] = [workflow_entry, *existing_workflow][:40]

            try:
                state_json = json.dumps(proposed_state, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                self.send_error_json(400, "management review contains unsupported values")
                return
            validation = workspace_state_validation_report(proposed_state, state_json)
            if len(state_json.encode("utf-8")) > MAX_JSON:
                self.send_json({"error": "state too large", "validation": validation}, status=413)
                return
            if not validation["valid"]:
                self.send_json({"error": "workspace state is incomplete", "validation": validation}, status=400)
                return

            snapshot_id = insert_state_snapshot(
                db,
                user["tenant_id"],
                previous["state_json"],
                previous["updated_by"],
                "before_management_review_update",
            )
            new_revision = current_revision + 1
            db.execute(
                "UPDATE tenant_workspace_state SET state_json = ?, updated_at = ?, updated_by = ?, revision = ? WHERE tenant_id = ?",
                (state_json, saved_at, user["id"], new_revision, user["tenant_id"]),
            )
            audit(db, user, "management_review_updated", "management_review", "management-review", {
                "changedFields": changed_fields,
                "snapshotId": snapshot_id,
                "previousRevision": current_revision,
                "revision": new_revision,
                "submission": submission_report,
            }, self.client_address[0])

        self.send_json({
            "ok": True,
            "managementReview": response_review,
            "updatedAt": saved_at,
            "updatedBy": user["username"],
            "revision": new_revision,
            "snapshotId": snapshot_id,
            "submission": submission_report,
            "customerTask": customer_task,
        })

    def handle_get_internal_audit_plan(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            row = db.execute(
                "SELECT w.state_json, w.updated_at, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
        if not row:
            self.send_json({"internalAuditPlan": {}, "updatedAt": None, "updatedBy": None, "revision": None})
            return
        try:
            state = json.loads(row["state_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            self.send_error_json(500, "stored workspace state is invalid")
            return
        plan = state.get("internalAuditPlan", {})
        if not isinstance(plan, dict):
            self.send_error_json(500, "stored internal audit plan is invalid")
            return
        self.send_json({
            "internalAuditPlan": plan,
            "updatedAt": row["updated_at"],
            "updatedBy": row["updated_by_username"],
            "revision": row["revision"],
        })

    def handle_update_internal_audit_plan(self):
        user, submission_only = self.require_asset_mutation_user(delete=False)
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        expected_revision = payload.get("expectedRevision")
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            self.send_error_json(400, "expectedRevision must be a non-negative integer")
            return
        changes = payload.get("changes")
        if not isinstance(changes, dict) or not changes:
            self.send_error_json(400, "changes must be a non-empty object")
            return
        changes = json.loads(json.dumps(changes, ensure_ascii=False))

        mutable_fields = {
            "title", "auditPeriod", "plannedDate", "reportDue", "leadAuditor", "participants",
            "scope", "objectives", "criteria", "interviewPlan", "samplingPlan", "notes",
            "customerComment", "consultantInternalComment", "consultantDecision", "status",
            "reviewStatus", "auditRelevant", "reviewAssignee", "reviewDue",
        }
        protected_server_fields = {
            "id", "workflowHistory", "serverUpdatedAt", "serverUpdatedBy", "submittedAt", "submittedBy",
            "approvedAt", "approvedBy", "rejectedAt", "rejectedBy",
        }
        for field in protected_server_fields:
            changes.pop(field, None)
        if not changes:
            self.send_error_json(400, "changes contain no mutable internal audit plan fields")
            return
        unknown_fields = sorted(set(changes) - mutable_fields)
        if unknown_fields:
            self.send_json({
                "error": "unsupported_internal_audit_plan_fields",
                "message": "Unsupported internal audit plan fields were supplied.",
                "fields": unknown_fields,
            }, status=400)
            return

        allowed_statuses = {
            "offen", "vorbereitet", "vom_kunden_eingereicht", "in_beraterpruefung", "nacharbeit_noetig",
            "freigegeben", "abgelehnt", "auditrelevant", "spaeter_pruefen",
        }
        for field in ("status", "reviewStatus"):
            value = str(changes.get(field) or "").strip()
            if value and value not in allowed_statuses:
                self.send_error_json(400, f"invalid internal audit plan {field}")
                return
        for field, value in changes.items():
            if field == "auditRelevant":
                if not isinstance(value, bool):
                    self.send_error_json(400, "auditRelevant must be a boolean")
                    return
                continue
            if not isinstance(value, str):
                self.send_error_json(400, f"{field} must be a string")
                return
            if len(value) > 20000:
                self.send_error_json(400, f"{field} is too long")
                return

        requested_status = normalized_submission_status(changes.get("status"))
        requested_review_status = normalized_submission_status(changes.get("reviewStatus"))
        requested_protected_decision = requested_status in CUSTOMER_FORBIDDEN_STATUS_VALUES \
            or requested_review_status in CUSTOMER_FORBIDDEN_STATUS_VALUES \
            or any(field in changes for field in ("consultantInternalComment", "consultantDecision", "auditRelevant"))
        saved_at = now()
        saved_date = time.strftime("%Y-%m-%d", time.localtime(saved_at))
        saved_iso = datetime.fromtimestamp(saved_at, tz=timezone.utc).isoformat()
        submission_report = None
        snapshot_id = None
        customer_task = None

        with conn() as db:
            DATABASE.begin_workspace_write(db)
            previous = db.execute(
                "SELECT w.state_json, w.updated_at, w.updated_by, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            if not previous:
                self.send_json({
                    "error": "workspace_not_initialized",
                    "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                }, status=409)
                return
            current_revision = int(previous["revision"] or 1)
            if expected_revision != current_revision:
                audit(db, user, "internal_audit_plan_update_conflict", "internal_audit_plan", "internal-audit-plan", {
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, self.client_address[0])
                self.send_json({
                    "error": "workspace_conflict",
                    "message": "Workspace wurde zwischenzeitlich geändert.",
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, status=409)
                return
            try:
                previous_state = json.loads(previous["state_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                self.send_error_json(500, "stored workspace state is invalid")
                return
            current_plan = previous_state.get("internalAuditPlan", {})
            if not isinstance(current_plan, dict):
                self.send_error_json(500, "stored internal audit plan is invalid")
                return
            proposed_state = json.loads(json.dumps(previous_state, ensure_ascii=False))
            response_plan = {
                "id": "internal-audit-plan",
                "title": "Interne Auditplanung Informationssicherheit",
                "status": "offen",
                "reviewStatus": "offen",
                "auditRelevant": not submission_only,
                **current_plan,
                **changes,
            }
            if submission_only:
                response_plan["status"] = "vom_kunden_eingereicht"
                response_plan["reviewStatus"] = "vom_kunden_eingereicht"
                response_plan["submittedAt"] = saved_at
                response_plan["submittedBy"] = user["username"]
            else:
                decision_status = str(response_plan.get("reviewStatus") or response_plan.get("status") or "offen")
                if decision_status == "freigegeben":
                    response_plan["approvedAt"] = saved_at
                    response_plan["approvedBy"] = user["username"]
                    response_plan.pop("rejectedAt", None)
                    response_plan.pop("rejectedBy", None)
                elif decision_status == "abgelehnt":
                    response_plan["rejectedAt"] = saved_at
                    response_plan["rejectedBy"] = user["username"]
                    response_plan.pop("approvedAt", None)
                    response_plan.pop("approvedBy", None)
            proposed_state["internalAuditPlan"] = response_plan
            changed_fields = sorted(
                key for key in set(current_plan) | set(response_plan)
                if canonical_workspace_value(current_plan.get(key)) != canonical_workspace_value(response_plan.get(key))
            )
            if not changed_fields:
                self.send_json({
                    "ok": True,
                    "internalAuditPlan": response_plan,
                    "updatedAt": previous["updated_at"],
                    "updatedBy": previous["updated_by_username"],
                    "revision": current_revision,
                    "unchanged": True,
                })
                return

            if not submission_only:
                tasks = proposed_state.get("tasks", [])
                if not isinstance(tasks, list):
                    self.send_error_json(500, "stored task register is invalid")
                    return
                task_index = next((
                    index for index, task in enumerate(tasks)
                    if isinstance(task, dict)
                    and task.get("reviewItemKey") == "internalAuditPlan:internal-audit-plan"
                    and task.get("workflowType") == "review-rework"
                    and task.get("status") != "Erledigt"
                ), None)
                review_status = str(response_plan.get("reviewStatus") or response_plan.get("status") or "offen")
                if review_status in {"nacharbeit_noetig", "abgelehnt"}:
                    missing = str(response_plan.get("customerComment") or "Auditplanung fachlich ergänzen.").strip()
                    task = {
                        "id": tasks[task_index].get("id") if task_index is not None else workspace_item_id("task"),
                        "title": f"Nacharbeit: {response_plan.get('title') or 'Interne Auditplanung'}",
                        "module": "Interne Auditplanung",
                        "owner": str(response_plan.get("participants") or "Kunde / Projektteam"),
                        "due": today_iso(14),
                        "status": "Offen",
                        "workflowType": "review-rework",
                        "source": "Berater-Rückgabe",
                        "reviewReturnStatus": review_status,
                        "reviewItemKey": "internalAuditPlan:internal-audit-plan",
                        "linkedTo": "Interne Auditplanung / Auditpaket",
                        "reworkMissing": missing,
                        "reworkWhy": "Die interne Auditplanung ist fachlich noch nicht freigegeben.",
                        "reworkAction": "Bitte ergänze die angeforderten Inhalte und reiche die Auditplanung erneut ein.",
                        "reworkReference": str(response_plan.get("title") or "Interne Auditplanung"),
                        "note": (
                            f"Was fehlt? {missing}\n"
                            "Warum reicht es noch nicht? Die interne Auditplanung ist fachlich noch nicht freigegeben.\n"
                            "Was ist zu tun? Inhalte ergänzen und erneut zur Beraterprüfung einreichen.\n"
                            f"Bezug: {response_plan.get('title') or 'Interne Auditplanung'}"
                        ),
                    }
                    if task_index is None:
                        tasks.insert(0, task)
                    else:
                        tasks[task_index] = task
                    customer_task = task
                elif review_status == "freigegeben" and task_index is not None:
                    tasks[task_index]["status"] = "Erledigt"
                    tasks[task_index]["note"] = "Interne Auditplanung durch Berater/Admin freigegeben."
                    customer_task = tasks[task_index]

            if submission_only:
                submission_report = customer_submission_policy_report(previous_state, proposed_state)
                if requested_protected_decision:
                    submission_report["violations"].append({
                        "path": "internalAuditPlan.reviewStatus",
                        "reason": "internal_audit_plan_decision_requires_advisor",
                    })
                    submission_report["allowed"] = False
                if not submission_report["allowed"]:
                    audit(db, user, "internal_audit_plan_update_rejected", "internal_audit_plan", "internal-audit-plan", {
                        "violations": submission_report["violations"],
                        "revision": current_revision,
                    }, self.client_address[0])
                    self.send_json({
                        "error": "submission_policy_violation",
                        "message": "Diese Auditplan-Entscheidung benötigt Berater- oder Adminrechte.",
                        "submission": submission_report,
                    }, status=403)
                    return

            response_plan["serverUpdatedAt"] = saved_at
            response_plan["serverUpdatedBy"] = user["username"]
            workflow_entry = {
                "date": saved_date,
                "dateTime": saved_iso,
                "action": "Auditplanung eingereicht" if submission_only else "Auditplanung aktualisiert",
                "by": user["username"],
                "note": "Änderung über die Auditplan-API gespeichert.",
                "status": str(response_plan.get("reviewStatus") or "offen"),
                "changes": changed_fields,
                "snapshot": {
                    "title": str(response_plan.get("title") or ""),
                    "auditPeriod": str(response_plan.get("auditPeriod") or ""),
                    "plannedDate": str(response_plan.get("plannedDate") or ""),
                    "leadAuditor": str(response_plan.get("leadAuditor") or ""),
                    "status": str(response_plan.get("status") or ""),
                    "reviewStatus": str(response_plan.get("reviewStatus") or ""),
                },
            }
            existing_workflow = response_plan.get("workflowHistory")
            if not isinstance(existing_workflow, list):
                existing_workflow = []
            response_plan["workflowHistory"] = [workflow_entry, *existing_workflow][:40]

            try:
                state_json = json.dumps(proposed_state, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                self.send_error_json(400, "internal audit plan contains unsupported values")
                return
            validation = workspace_state_validation_report(proposed_state, state_json)
            if len(state_json.encode("utf-8")) > MAX_JSON:
                self.send_json({"error": "state too large", "validation": validation}, status=413)
                return
            if not validation["valid"]:
                self.send_json({"error": "workspace state is incomplete", "validation": validation}, status=400)
                return

            snapshot_id = insert_state_snapshot(
                db,
                user["tenant_id"],
                previous["state_json"],
                previous["updated_by"],
                "before_internal_audit_plan_update",
            )
            new_revision = current_revision + 1
            db.execute(
                "UPDATE tenant_workspace_state SET state_json = ?, updated_at = ?, updated_by = ?, revision = ? WHERE tenant_id = ?",
                (state_json, saved_at, user["id"], new_revision, user["tenant_id"]),
            )
            audit(db, user, "internal_audit_plan_updated", "internal_audit_plan", "internal-audit-plan", {
                "changedFields": changed_fields,
                "snapshotId": snapshot_id,
                "previousRevision": current_revision,
                "revision": new_revision,
                "submission": submission_report,
            }, self.client_address[0])

        self.send_json({
            "ok": True,
            "internalAuditPlan": response_plan,
            "updatedAt": saved_at,
            "updatedBy": user["username"],
            "revision": new_revision,
            "snapshotId": snapshot_id,
            "submission": submission_report,
            "customerTask": customer_task,
        })

    def require_asset_mutation_user(self, delete=False):
        session_user = self.current_user()
        if not session_user:
            self.send_error_json(401, "not authenticated")
            return None, None
        if has_permission(session_user, "saveWorkspace"):
            return self.require_user(permission="saveWorkspace"), False
        if not delete and has_permission(session_user, "submitWorkspace"):
            return self.require_user(permission="submitWorkspace"), True
        required = "saveWorkspace" if delete else "saveWorkspace or submitWorkspace"
        self.send_error_json(403, f"permission required: {required}")
        return None, None

    def handle_asset_mutation(self, operation, asset_id=None):
        user, submission_only = self.require_asset_mutation_user(delete=operation == "delete")
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        if "expectedRevision" not in payload:
            self.send_error_json(400, "expectedRevision is required")
            return
        expected_revision = payload.get("expectedRevision")
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            self.send_error_json(400, "expectedRevision must be a non-negative integer")
            return

        requested_asset = None
        changes = None
        if operation == "create":
            requested_asset = payload.get("asset")
            if not isinstance(requested_asset, dict):
                self.send_error_json(400, "asset must be an object")
                return
            requested_asset = json.loads(json.dumps(requested_asset, ensure_ascii=False))
            requested_asset["id"] = str(requested_asset.get("id") or uuid.uuid4()).strip()
            asset_id = requested_asset["id"]
        elif operation == "update":
            changes = payload.get("changes")
            if not isinstance(changes, dict) or not changes:
                self.send_error_json(400, "changes must be a non-empty object")
                return
            changes = json.loads(json.dumps(changes, ensure_ascii=False))
            if "id" in changes and str(changes.get("id") or "").strip() != str(asset_id or "").strip():
                self.send_error_json(400, "asset id cannot be changed")
                return
            changes.pop("id", None)

        asset_id = str(asset_id or "").strip()
        if not asset_id or len(asset_id) > 200 or "/" in asset_id or "\\" in asset_id:
            self.send_error_json(400, "invalid asset id")
            return

        saved_at = now()
        response_asset = None
        submission_report = None
        changed_fields = []
        snapshot_id = None
        with conn() as db:
            DATABASE.begin_workspace_write(db)
            previous = db.execute(
                "SELECT w.state_json, w.updated_at, w.updated_by, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            if not previous:
                self.send_json({
                    "error": "workspace_not_initialized",
                    "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                }, status=409)
                return
            current_revision = int(previous["revision"] or 1)
            if expected_revision != current_revision:
                audit(db, user, f"asset_{operation}_conflict", "asset", asset_id, {
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, self.client_address[0])
                self.send_json({
                    "error": "workspace_conflict",
                    "message": "Workspace wurde zwischenzeitlich geändert.",
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, status=409)
                return
            try:
                previous_state = json.loads(previous["state_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                self.send_error_json(500, "stored workspace state is invalid")
                return
            assets = previous_state.get("assets")
            if not isinstance(assets, list):
                self.send_error_json(500, "stored asset register is invalid")
                return
            proposed_state = json.loads(json.dumps(previous_state, ensure_ascii=False))
            proposed_assets = proposed_state["assets"]
            asset_index = next(
                (index for index, item in enumerate(proposed_assets) if str((item or {}).get("id") or "") == asset_id),
                None,
            )

            if operation == "create":
                if asset_index is not None:
                    self.send_json({"error": "asset_conflict", "message": "Asset-ID ist bereits vorhanden."}, status=409)
                    return
                if submission_only:
                    requested_asset.setdefault("reviewStatus", "vom_kunden_eingereicht")
                    requested_asset.setdefault("submittedAt", saved_at)
                    requested_asset.setdefault("submittedBy", user["username"])
                    requested_asset.setdefault("reviewUpdatedAt", saved_at)
                proposed_assets.insert(0, requested_asset)
                response_asset = requested_asset
                changed_fields = sorted(requested_asset.keys())
            elif operation == "update":
                if asset_index is None:
                    self.send_error_json(404, "asset not found")
                    return
                current_asset = proposed_assets[asset_index]
                if not isinstance(current_asset, dict):
                    self.send_error_json(500, "stored asset record is invalid")
                    return
                response_asset = {**current_asset, **changes, "id": asset_id}
                if submission_only:
                    response_asset["reviewStatus"] = "vom_kunden_eingereicht"
                    response_asset["submittedAt"] = saved_at
                    response_asset["submittedBy"] = user["username"]
                    response_asset["reviewUpdatedAt"] = saved_at
                proposed_assets[asset_index] = response_asset
                changed_fields = sorted(
                    key for key in set(current_asset) | set(response_asset)
                    if canonical_workspace_value(current_asset.get(key)) != canonical_workspace_value(response_asset.get(key))
                )
                if not changed_fields:
                    self.send_json({
                        "ok": True,
                        "asset": response_asset,
                        "updatedAt": previous["updated_at"],
                        "updatedBy": previous["updated_by_username"],
                        "revision": current_revision,
                        "unchanged": True,
                    })
                    return
            else:
                if asset_index is None:
                    self.send_error_json(404, "asset not found")
                    return
                response_asset = proposed_assets.pop(asset_index)
                changed_fields = sorted(response_asset.keys()) if isinstance(response_asset, dict) else []

            if operation != "delete":
                title = str(response_asset.get("name") or response_asset.get("title") or "").strip()
                if not title:
                    self.send_error_json(400, "asset name or title is required")
                    return
                if len(title) > 500:
                    self.send_error_json(400, "asset name or title is too long")
                    return

            submission_changes = []
            if submission_only:
                submission_report = customer_submission_policy_report(previous_state, proposed_state)
                submission_report, submission_changes = contributor_submission_policy_report(
                    db,
                    user,
                    previous_state,
                    proposed_state,
                    submission_report,
                )
                if not submission_report["allowed"]:
                    audit(db, user, f"asset_{operation}_rejected", "asset", asset_id, {
                        "violations": submission_report["violations"],
                        "revision": current_revision,
                    }, self.client_address[0])
                    self.send_json({
                        "error": "submission_policy_violation",
                        "message": "Diese Änderung benötigt Berater- oder Adminrechte.",
                        "submission": submission_report,
                    }, status=403)
                    return

            try:
                state_json = json.dumps(proposed_state, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                self.send_error_json(400, "asset contains unsupported values")
                return
            validation = workspace_state_validation_report(proposed_state, state_json)
            if len(state_json.encode("utf-8")) > MAX_JSON:
                self.send_json({"error": "state too large", "validation": validation}, status=413)
                return
            if not validation["valid"]:
                self.send_json({"error": "workspace state is incomplete", "validation": validation}, status=400)
                return

            snapshot_id = insert_state_snapshot(
                db,
                user["tenant_id"],
                previous["state_json"],
                previous["updated_by"],
                f"before_asset_{operation}",
            )
            new_revision = current_revision + 1
            db.execute(
                "UPDATE tenant_workspace_state SET state_json = ?, updated_at = ?, updated_by = ?, revision = ? WHERE tenant_id = ?",
                (state_json, saved_at, user["id"], new_revision, user["tenant_id"]),
            )
            if submission_only:
                persist_submission_record_ownership(db, user, submission_changes, saved_at)
            else:
                prune_workspace_record_ownership(db, user["tenant_id"], proposed_state)
            audit(db, user, f"asset_{operation}d" if operation != "delete" else "asset_deleted", "asset", asset_id, {
                "changedFields": changed_fields,
                "snapshotId": snapshot_id,
                "previousRevision": current_revision,
                "revision": new_revision,
                "submission": submission_report,
            }, self.client_address[0])

        response = {
            "ok": True,
            "updatedAt": saved_at,
            "updatedBy": user["username"],
            "revision": new_revision,
            "submission": submission_report,
        }
        if operation == "delete":
            response["deletedId"] = asset_id
        else:
            response["asset"] = response_asset
        self.send_json(response, status=201 if operation == "create" else 200)

    def handle_risk_mutation(self, operation, risk_id=None):
        user, submission_only = self.require_asset_mutation_user(delete=operation == "delete")
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        if "expectedRevision" not in payload:
            self.send_error_json(400, "expectedRevision is required")
            return
        expected_revision = payload.get("expectedRevision")
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            self.send_error_json(400, "expectedRevision must be a non-negative integer")
            return

        requested_risk = None
        changes = None
        if operation == "create":
            requested_risk = payload.get("risk")
            if not isinstance(requested_risk, dict):
                self.send_error_json(400, "risk must be an object")
                return
            requested_risk = json.loads(json.dumps(requested_risk, ensure_ascii=False))
            requested_risk["id"] = str(requested_risk.get("id") or uuid.uuid4()).strip()
            risk_id = requested_risk["id"]
        elif operation == "update":
            changes = payload.get("changes")
            if not isinstance(changes, dict) or not changes:
                self.send_error_json(400, "changes must be a non-empty object")
                return
            changes = json.loads(json.dumps(changes, ensure_ascii=False))
            if "id" in changes and str(changes.get("id") or "").strip() != str(risk_id or "").strip():
                self.send_error_json(400, "risk id cannot be changed")
                return
            changes.pop("id", None)

        risk_id = str(risk_id or "").strip()
        if not risk_id or len(risk_id) > 200 or "/" in risk_id or "\\" in risk_id:
            self.send_error_json(400, "invalid risk id")
            return

        saved_at = now()
        response_risk = None
        submission_report = None
        changed_fields = []
        snapshot_id = None
        with conn() as db:
            DATABASE.begin_workspace_write(db)
            previous = db.execute(
                "SELECT w.state_json, w.updated_at, w.updated_by, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            if not previous:
                self.send_json({
                    "error": "workspace_not_initialized",
                    "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                }, status=409)
                return
            current_revision = int(previous["revision"] or 1)
            if expected_revision != current_revision:
                audit(db, user, f"risk_{operation}_conflict", "risk", risk_id, {
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, self.client_address[0])
                self.send_json({
                    "error": "workspace_conflict",
                    "message": "Workspace wurde zwischenzeitlich geändert.",
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, status=409)
                return
            try:
                previous_state = json.loads(previous["state_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                self.send_error_json(500, "stored workspace state is invalid")
                return
            risks = previous_state.get("risks")
            if not isinstance(risks, list):
                self.send_error_json(500, "stored risk register is invalid")
                return
            proposed_state = json.loads(json.dumps(previous_state, ensure_ascii=False))
            proposed_risks = proposed_state["risks"]
            risk_index = next(
                (index for index, item in enumerate(proposed_risks) if str((item or {}).get("id") or "") == risk_id),
                None,
            )

            if operation == "create":
                if risk_index is not None:
                    self.send_json({"error": "risk_conflict", "message": "Risiko-ID ist bereits vorhanden."}, status=409)
                    return
                if submission_only:
                    requested_risk["reviewStatus"] = "vom_kunden_eingereicht"
                    requested_risk["submittedAt"] = saved_at
                    requested_risk["submittedBy"] = user["username"]
                    requested_risk["reviewUpdatedAt"] = saved_at
                proposed_risks.insert(0, requested_risk)
                response_risk = requested_risk
                changed_fields = sorted(requested_risk.keys())
            elif operation == "update":
                if risk_index is None:
                    self.send_error_json(404, "risk not found")
                    return
                current_risk = proposed_risks[risk_index]
                if not isinstance(current_risk, dict):
                    self.send_error_json(500, "stored risk record is invalid")
                    return
                response_risk = {**current_risk, **changes, "id": risk_id}
                if submission_only:
                    response_risk["reviewStatus"] = "vom_kunden_eingereicht"
                    response_risk["submittedAt"] = saved_at
                    response_risk["submittedBy"] = user["username"]
                    response_risk["reviewUpdatedAt"] = saved_at
                proposed_risks[risk_index] = response_risk
                changed_fields = sorted(
                    key for key in set(current_risk) | set(response_risk)
                    if canonical_workspace_value(current_risk.get(key)) != canonical_workspace_value(response_risk.get(key))
                )
                if not changed_fields:
                    self.send_json({
                        "ok": True,
                        "risk": response_risk,
                        "updatedAt": previous["updated_at"],
                        "updatedBy": previous["updated_by_username"],
                        "revision": current_revision,
                        "unchanged": True,
                    })
                    return
            else:
                if risk_index is None:
                    self.send_error_json(404, "risk not found")
                    return
                response_risk = proposed_risks.pop(risk_index)
                changed_fields = sorted(response_risk.keys()) if isinstance(response_risk, dict) else []

            if operation != "delete":
                scenario = str(response_risk.get("scenario") or "").strip()
                if not scenario:
                    self.send_error_json(400, "risk scenario is required")
                    return
                if len(scenario) > 4000:
                    self.send_error_json(400, "risk scenario is too long")
                    return
                for score_field in ("likelihood", "impact", "residualLikelihood", "residualImpact"):
                    score_value = response_risk.get(score_field)
                    if score_value in (None, ""):
                        continue
                    try:
                        normalized_score = int(score_value)
                    except (TypeError, ValueError):
                        self.send_error_json(400, f"{score_field} must be between 1 and 5")
                        return
                    if normalized_score < 1 or normalized_score > 5:
                        self.send_error_json(400, f"{score_field} must be between 1 and 5")
                        return

            submission_changes = []
            if submission_only:
                submission_report = customer_submission_policy_report(previous_state, proposed_state)
                submission_report, submission_changes = contributor_submission_policy_report(
                    db,
                    user,
                    previous_state,
                    proposed_state,
                    submission_report,
                )
                if operation != "delete" and normalized_submission_status(response_risk.get("status")) in {
                    "akzeptiert", "erledigt", "geschlossen"
                }:
                    submission_report["violations"].append({
                        "path": f"risks.id:{risk_id}.status",
                        "reason": "risk_decision_requires_advisor",
                    })
                    submission_report["allowed"] = False
                if not submission_report["allowed"]:
                    audit(db, user, f"risk_{operation}_rejected", "risk", risk_id, {
                        "violations": submission_report["violations"],
                        "revision": current_revision,
                    }, self.client_address[0])
                    self.send_json({
                        "error": "submission_policy_violation",
                        "message": "Diese Änderung benötigt Berater- oder Adminrechte.",
                        "submission": submission_report,
                    }, status=403)
                    return

            try:
                state_json = json.dumps(proposed_state, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                self.send_error_json(400, "risk contains unsupported values")
                return
            validation = workspace_state_validation_report(proposed_state, state_json)
            if len(state_json.encode("utf-8")) > MAX_JSON:
                self.send_json({"error": "state too large", "validation": validation}, status=413)
                return
            if not validation["valid"]:
                self.send_json({"error": "workspace state is incomplete", "validation": validation}, status=400)
                return

            snapshot_id = insert_state_snapshot(
                db,
                user["tenant_id"],
                previous["state_json"],
                previous["updated_by"],
                f"before_risk_{operation}",
            )
            new_revision = current_revision + 1
            db.execute(
                "UPDATE tenant_workspace_state SET state_json = ?, updated_at = ?, updated_by = ?, revision = ? WHERE tenant_id = ?",
                (state_json, saved_at, user["id"], new_revision, user["tenant_id"]),
            )
            if submission_only:
                persist_submission_record_ownership(db, user, submission_changes, saved_at)
            else:
                prune_workspace_record_ownership(db, user["tenant_id"], proposed_state)
            audit(db, user, f"risk_{operation}d" if operation != "delete" else "risk_deleted", "risk", risk_id, {
                "changedFields": changed_fields,
                "snapshotId": snapshot_id,
                "previousRevision": current_revision,
                "revision": new_revision,
                "submission": submission_report,
            }, self.client_address[0])

        response = {
            "ok": True,
            "updatedAt": saved_at,
            "updatedBy": user["username"],
            "revision": new_revision,
            "submission": submission_report,
        }
        if operation == "delete":
            response["deletedId"] = risk_id
        else:
            response["risk"] = response_risk
        self.send_json(response, status=201 if operation == "create" else 200)

    def handle_supplier_mutation(self, operation, supplier_id=None):
        user, submission_only = self.require_asset_mutation_user(delete=operation == "delete")
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        if "expectedRevision" not in payload:
            self.send_error_json(400, "expectedRevision is required")
            return
        expected_revision = payload.get("expectedRevision")
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            self.send_error_json(400, "expectedRevision must be a non-negative integer")
            return

        requested_supplier = None
        changes = None
        if operation == "create":
            requested_supplier = payload.get("supplier")
            if not isinstance(requested_supplier, dict):
                self.send_error_json(400, "supplier must be an object")
                return
            requested_supplier = json.loads(json.dumps(requested_supplier, ensure_ascii=False))
            requested_supplier["id"] = str(requested_supplier.get("id") or uuid.uuid4()).strip()
            supplier_id = requested_supplier["id"]
        elif operation == "update":
            changes = payload.get("changes")
            if not isinstance(changes, dict) or not changes:
                self.send_error_json(400, "changes must be a non-empty object")
                return
            changes = json.loads(json.dumps(changes, ensure_ascii=False))
            if "id" in changes and str(changes.get("id") or "").strip() != str(supplier_id or "").strip():
                self.send_error_json(400, "supplier id cannot be changed")
                return
            changes.pop("id", None)

        supplier_id = str(supplier_id or "").strip()
        if not supplier_id or len(supplier_id) > 200 or "/" in supplier_id or "\\" in supplier_id:
            self.send_error_json(400, "invalid supplier id")
            return

        saved_at = now()
        response_supplier = None
        submission_report = None
        changed_fields = []
        snapshot_id = None
        with conn() as db:
            DATABASE.begin_workspace_write(db)
            previous = db.execute(
                "SELECT w.state_json, w.updated_at, w.updated_by, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            if not previous:
                self.send_json({
                    "error": "workspace_not_initialized",
                    "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                }, status=409)
                return
            current_revision = int(previous["revision"] or 1)
            if expected_revision != current_revision:
                audit(db, user, f"supplier_{operation}_conflict", "supplier", supplier_id, {
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, self.client_address[0])
                self.send_json({
                    "error": "workspace_conflict",
                    "message": "Workspace wurde zwischenzeitlich geändert.",
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, status=409)
                return
            try:
                previous_state = json.loads(previous["state_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                self.send_error_json(500, "stored workspace state is invalid")
                return
            suppliers = previous_state.get("suppliers")
            if not isinstance(suppliers, list):
                self.send_error_json(500, "stored supplier register is invalid")
                return
            proposed_state = json.loads(json.dumps(previous_state, ensure_ascii=False))
            proposed_suppliers = proposed_state["suppliers"]
            supplier_index = next(
                (index for index, item in enumerate(proposed_suppliers) if str((item or {}).get("id") or "") == supplier_id),
                None,
            )

            if operation == "create":
                if supplier_index is not None:
                    self.send_json({"error": "supplier_conflict", "message": "Lieferanten-ID ist bereits vorhanden."}, status=409)
                    return
                if submission_only:
                    requested_supplier["reviewStatus"] = "vom_kunden_eingereicht"
                    requested_supplier["submittedAt"] = saved_at
                    requested_supplier["submittedBy"] = user["username"]
                    requested_supplier["reviewUpdatedAt"] = saved_at
                proposed_suppliers.insert(0, requested_supplier)
                response_supplier = requested_supplier
                changed_fields = sorted(requested_supplier.keys())
            elif operation == "update":
                if supplier_index is None:
                    self.send_error_json(404, "supplier not found")
                    return
                current_supplier = proposed_suppliers[supplier_index]
                if not isinstance(current_supplier, dict):
                    self.send_error_json(500, "stored supplier record is invalid")
                    return
                response_supplier = {**current_supplier, **changes, "id": supplier_id}
                if submission_only:
                    response_supplier["reviewStatus"] = "vom_kunden_eingereicht"
                    response_supplier["submittedAt"] = saved_at
                    response_supplier["submittedBy"] = user["username"]
                    response_supplier["reviewUpdatedAt"] = saved_at
                proposed_suppliers[supplier_index] = response_supplier
                changed_fields = sorted(
                    key for key in set(current_supplier) | set(response_supplier)
                    if canonical_workspace_value(current_supplier.get(key)) != canonical_workspace_value(response_supplier.get(key))
                )
                if not changed_fields:
                    self.send_json({
                        "ok": True,
                        "supplier": response_supplier,
                        "updatedAt": previous["updated_at"],
                        "updatedBy": previous["updated_by_username"],
                        "revision": current_revision,
                        "unchanged": True,
                    })
                    return
            else:
                if supplier_index is None:
                    self.send_error_json(404, "supplier not found")
                    return
                response_supplier = proposed_suppliers.pop(supplier_index)
                changed_fields = sorted(response_supplier.keys()) if isinstance(response_supplier, dict) else []

            if operation != "delete":
                name = str(response_supplier.get("name") or response_supplier.get("title") or "").strip()
                if not name:
                    self.send_error_json(400, "supplier name or title is required")
                    return
                if len(name) > 500:
                    self.send_error_json(400, "supplier name or title is too long")
                    return
                for text_field in ("service", "owner", "dataAccess", "evidence"):
                    if len(str(response_supplier.get(text_field) or "")) > 4000:
                        self.send_error_json(400, f"{text_field} is too long")
                        return

            submission_changes = []
            if submission_only:
                submission_report = customer_submission_policy_report(previous_state, proposed_state)
                submission_report, submission_changes = contributor_submission_policy_report(
                    db,
                    user,
                    previous_state,
                    proposed_state,
                    submission_report,
                )
                if operation != "delete":
                    for status_field in ("review", "contractStatus"):
                        if normalized_submission_status(response_supplier.get(status_field)) in {
                            "freigegeben", "abgelehnt", "auditrelevant"
                        }:
                            submission_report["violations"].append({
                                "path": f"suppliers.id:{supplier_id}.{status_field}",
                                "reason": "supplier_review_requires_advisor",
                            })
                            submission_report["allowed"] = False
                if not submission_report["allowed"]:
                    audit(db, user, f"supplier_{operation}_rejected", "supplier", supplier_id, {
                        "violations": submission_report["violations"],
                        "revision": current_revision,
                    }, self.client_address[0])
                    self.send_json({
                        "error": "submission_policy_violation",
                        "message": "Diese Änderung benötigt Berater- oder Adminrechte.",
                        "submission": submission_report,
                    }, status=403)
                    return

            try:
                state_json = json.dumps(proposed_state, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                self.send_error_json(400, "supplier contains unsupported values")
                return
            validation = workspace_state_validation_report(proposed_state, state_json)
            if len(state_json.encode("utf-8")) > MAX_JSON:
                self.send_json({"error": "state too large", "validation": validation}, status=413)
                return
            if not validation["valid"]:
                self.send_json({"error": "workspace state is incomplete", "validation": validation}, status=400)
                return

            snapshot_id = insert_state_snapshot(
                db,
                user["tenant_id"],
                previous["state_json"],
                previous["updated_by"],
                f"before_supplier_{operation}",
            )
            new_revision = current_revision + 1
            db.execute(
                "UPDATE tenant_workspace_state SET state_json = ?, updated_at = ?, updated_by = ?, revision = ? WHERE tenant_id = ?",
                (state_json, saved_at, user["id"], new_revision, user["tenant_id"]),
            )
            if submission_only:
                persist_submission_record_ownership(db, user, submission_changes, saved_at)
            else:
                prune_workspace_record_ownership(db, user["tenant_id"], proposed_state)
            audit(db, user, f"supplier_{operation}d" if operation != "delete" else "supplier_deleted", "supplier", supplier_id, {
                "changedFields": changed_fields,
                "snapshotId": snapshot_id,
                "previousRevision": current_revision,
                "revision": new_revision,
                "submission": submission_report,
            }, self.client_address[0])

        response = {
            "ok": True,
            "updatedAt": saved_at,
            "updatedBy": user["username"],
            "revision": new_revision,
            "submission": submission_report,
        }
        if operation == "delete":
            response["deletedId"] = supplier_id
        else:
            response["supplier"] = response_supplier
        self.send_json(response, status=201 if operation == "create" else 200)

    def handle_policy_mutation(self, operation, policy_id=None):
        user, submission_only = self.require_asset_mutation_user(delete=operation == "delete")
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        if "expectedRevision" not in payload:
            self.send_error_json(400, "expectedRevision is required")
            return
        expected_revision = payload.get("expectedRevision")
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            self.send_error_json(400, "expectedRevision must be a non-negative integer")
            return

        requested_policy = None
        changes = None
        if operation == "create":
            requested_policy = payload.get("policy")
            if not isinstance(requested_policy, dict):
                self.send_error_json(400, "policy must be an object")
                return
            requested_policy = json.loads(json.dumps(requested_policy, ensure_ascii=False))
            requested_policy["id"] = str(requested_policy.get("id") or uuid.uuid4()).strip()
            policy_id = requested_policy["id"]
            requested_policy.pop("workflowHistory", None)
            requested_policy.pop("versionHistory", None)
        elif operation == "update":
            changes = payload.get("changes")
            if not isinstance(changes, dict) or not changes:
                self.send_error_json(400, "changes must be a non-empty object")
                return
            changes = json.loads(json.dumps(changes, ensure_ascii=False))
            if "id" in changes and str(changes.get("id") or "").strip() != str(policy_id or "").strip():
                self.send_error_json(400, "policy id cannot be changed")
                return
            for protected_field in ("id", "workflowHistory", "versionHistory", "serverUpdatedAt", "serverUpdatedBy"):
                changes.pop(protected_field, None)
            if not changes:
                self.send_error_json(400, "changes contain no mutable policy fields")
                return

        policy_id = str(policy_id or "").strip()
        if not policy_id or len(policy_id) > 200 or "/" in policy_id or "\\" in policy_id:
            self.send_error_json(400, "invalid policy id")
            return

        saved_at = now()
        saved_date = time.strftime("%Y-%m-%d", time.localtime(saved_at))
        saved_iso = datetime.fromtimestamp(saved_at, tz=timezone.utc).isoformat()
        response_policy = None
        previous_policy = None
        submission_report = None
        changed_fields = []
        snapshot_id = None
        with conn() as db:
            DATABASE.begin_workspace_write(db)
            previous = db.execute(
                "SELECT w.state_json, w.updated_at, w.updated_by, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            if not previous:
                self.send_json({
                    "error": "workspace_not_initialized",
                    "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                }, status=409)
                return
            current_revision = int(previous["revision"] or 1)
            if expected_revision != current_revision:
                audit(db, user, f"policy_{operation}_conflict", "policy", policy_id, {
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, self.client_address[0])
                self.send_json({
                    "error": "workspace_conflict",
                    "message": "Workspace wurde zwischenzeitlich geändert.",
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, status=409)
                return
            try:
                previous_state = json.loads(previous["state_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                self.send_error_json(500, "stored workspace state is invalid")
                return
            policies = previous_state.get("policies")
            if not isinstance(policies, list):
                self.send_error_json(500, "stored policy register is invalid")
                return
            proposed_state = json.loads(json.dumps(previous_state, ensure_ascii=False))
            proposed_policies = proposed_state["policies"]
            policy_index = next(
                (index for index, item in enumerate(proposed_policies) if str((item or {}).get("id") or "") == policy_id),
                None,
            )

            if operation == "create":
                if policy_index is not None:
                    self.send_json({"error": "policy_conflict", "message": "Policy-ID ist bereits vorhanden."}, status=409)
                    return
                requested_policy.setdefault("version", "0.1")
                requested_policy.setdefault("status", "Entwurf")
                requested_policy.setdefault("added", saved_date)
                if submission_only:
                    requested_policy["reviewStatus"] = "vom_kunden_eingereicht"
                    requested_policy["submittedAt"] = saved_at
                    requested_policy["submittedBy"] = user["username"]
                    requested_policy["reviewUpdatedAt"] = saved_at
                proposed_policies.insert(0, requested_policy)
                response_policy = requested_policy
                changed_fields = sorted(requested_policy.keys())
            elif operation == "update":
                if policy_index is None:
                    self.send_error_json(404, "policy not found")
                    return
                current_policy = proposed_policies[policy_index]
                if not isinstance(current_policy, dict):
                    self.send_error_json(500, "stored policy record is invalid")
                    return
                previous_policy = json.loads(json.dumps(current_policy, ensure_ascii=False))
                response_policy = {**current_policy, **changes, "id": policy_id}
                if submission_only:
                    response_policy["reviewStatus"] = "vom_kunden_eingereicht"
                    response_policy["submittedAt"] = saved_at
                    response_policy["submittedBy"] = user["username"]
                    response_policy["reviewUpdatedAt"] = saved_at
                proposed_policies[policy_index] = response_policy
                changed_fields = sorted(
                    key for key in set(current_policy) | set(response_policy)
                    if key not in {"workflowHistory", "versionHistory", "serverUpdatedAt", "serverUpdatedBy"}
                    and canonical_workspace_value(current_policy.get(key)) != canonical_workspace_value(response_policy.get(key))
                )
                if not changed_fields:
                    self.send_json({
                        "ok": True,
                        "policy": response_policy,
                        "updatedAt": previous["updated_at"],
                        "updatedBy": previous["updated_by_username"],
                        "revision": current_revision,
                        "unchanged": True,
                    })
                    return
            else:
                if policy_index is None:
                    self.send_error_json(404, "policy not found")
                    return
                response_policy = proposed_policies.pop(policy_index)
                previous_policy = response_policy if isinstance(response_policy, dict) else None
                changed_fields = sorted(response_policy.keys()) if isinstance(response_policy, dict) else []

            if operation != "delete":
                title = str(response_policy.get("title") or "").strip()
                if not title:
                    self.send_error_json(400, "policy title is required")
                    return
                if len(title) > 500:
                    self.send_error_json(400, "policy title is too long")
                    return
                for text_field in ("owner", "linkedTo", "scope", "note", "customerComment", "consultantInternalComment"):
                    if len(str(response_policy.get(text_field) or "")) > 12000:
                        self.send_error_json(400, f"{text_field} is too long")
                        return

            submission_changes = []
            if submission_only:
                submission_report = customer_submission_policy_report(previous_state, proposed_state)
                submission_report, submission_changes = contributor_submission_policy_report(
                    db,
                    user,
                    previous_state,
                    proposed_state,
                    submission_report,
                )
                if operation != "delete" and normalized_submission_status(response_policy.get("status")) in {
                    "freigegeben", "veröffentlicht", "veroffentlicht", "published", "abgelehnt", "auditrelevant", "archiviert"
                }:
                    submission_report["violations"].append({
                        "path": f"policies.id:{policy_id}.status",
                        "reason": "policy_approval_requires_advisor",
                    })
                    submission_report["allowed"] = False
                if not submission_report["allowed"]:
                    audit(db, user, f"policy_{operation}_rejected", "policy", policy_id, {
                        "violations": submission_report["violations"],
                        "revision": current_revision,
                    }, self.client_address[0])
                    self.send_json({
                        "error": "submission_policy_violation",
                        "message": "Diese Änderung benötigt Berater- oder Adminrechte.",
                        "submission": submission_report,
                    }, status=403)
                    return

            if operation != "delete":
                response_policy["serverUpdatedAt"] = saved_at
                response_policy["serverUpdatedBy"] = user["username"]
                action_label = "Policy angelegt" if operation == "create" else "Policy aktualisiert"
                old_record = previous_policy or {}
                version_changes = [
                    {
                        "field": field,
                        "label": field,
                        "before": old_record.get(field),
                        "after": response_policy.get(field),
                    }
                    for field in changed_fields
                    if field not in {"workflowHistory", "versionHistory"}
                ]
                version_entry = {
                    "id": str(uuid.uuid4()),
                    "date": saved_date,
                    "dateTime": saved_iso,
                    "by": user["username"],
                    "action": action_label,
                    "version": str(response_policy.get("version") or "0.1"),
                    "previousVersion": str(old_record.get("version") or ""),
                    "status": str(response_policy.get("status") or "Entwurf"),
                    "previousStatus": str(old_record.get("status") or ""),
                    "approval": str(response_policy.get("approval") or ""),
                    "review": str(response_policy.get("review") or ""),
                    "linkedTo": str(response_policy.get("linkedTo") or ""),
                    "note": str(response_policy.get("note") or ""),
                    "snapshot": {
                        "title": str(response_policy.get("title") or ""),
                        "owner": str(response_policy.get("owner") or ""),
                        "priority": str(response_policy.get("priority") or ""),
                        "scope": str(response_policy.get("scope") or ""),
                        "group": str(response_policy.get("group") or ""),
                        "source": str(response_policy.get("source") or ""),
                    },
                    "changes": version_changes,
                }
                existing_versions = response_policy.get("versionHistory")
                if not isinstance(existing_versions, list):
                    existing_versions = []
                response_policy["versionHistory"] = [version_entry, *existing_versions][:40]
                workflow_entry = {
                    "date": saved_date,
                    "dateTime": saved_iso,
                    "action": action_label,
                    "by": user["username"],
                    "note": "Änderung über die Policy API gespeichert.",
                }
                existing_workflow = response_policy.get("workflowHistory")
                if not isinstance(existing_workflow, list):
                    existing_workflow = []
                response_policy["workflowHistory"] = [workflow_entry, *existing_workflow][:40]

            try:
                state_json = json.dumps(proposed_state, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                self.send_error_json(400, "policy contains unsupported values")
                return
            validation = workspace_state_validation_report(proposed_state, state_json)
            if len(state_json.encode("utf-8")) > MAX_JSON:
                self.send_json({"error": "state too large", "validation": validation}, status=413)
                return
            if not validation["valid"]:
                self.send_json({"error": "workspace state is incomplete", "validation": validation}, status=400)
                return

            snapshot_id = insert_state_snapshot(
                db,
                user["tenant_id"],
                previous["state_json"],
                previous["updated_by"],
                f"before_policy_{operation}",
            )
            new_revision = current_revision + 1
            db.execute(
                "UPDATE tenant_workspace_state SET state_json = ?, updated_at = ?, updated_by = ?, revision = ? WHERE tenant_id = ?",
                (state_json, saved_at, user["id"], new_revision, user["tenant_id"]),
            )
            if submission_only:
                persist_submission_record_ownership(db, user, submission_changes, saved_at)
            else:
                prune_workspace_record_ownership(db, user["tenant_id"], proposed_state)
            audit(db, user, f"policy_{operation}d" if operation != "delete" else "policy_deleted", "policy", policy_id, {
                "changedFields": changed_fields,
                "snapshotId": snapshot_id,
                "previousRevision": current_revision,
                "revision": new_revision,
                "submission": submission_report,
            }, self.client_address[0])

        response = {
            "ok": True,
            "updatedAt": saved_at,
            "updatedBy": user["username"],
            "revision": new_revision,
            "snapshotId": snapshot_id,
            "submission": submission_report,
        }
        if operation == "delete":
            response["deletedId"] = policy_id
        else:
            response["policy"] = response_policy
        self.send_json(response, status=201 if operation == "create" else 200)

    def handle_incident_mutation(self, operation, incident_id=None):
        user, submission_only = self.require_asset_mutation_user(delete=operation == "delete")
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        if "expectedRevision" not in payload:
            self.send_error_json(400, "expectedRevision is required")
            return
        expected_revision = payload.get("expectedRevision")
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            self.send_error_json(400, "expectedRevision must be a non-negative integer")
            return

        requested_incident = None
        changes = None
        if operation == "create":
            requested_incident = payload.get("incident")
            if not isinstance(requested_incident, dict):
                self.send_error_json(400, "incident must be an object")
                return
            requested_incident = json.loads(json.dumps(requested_incident, ensure_ascii=False))
            requested_incident["id"] = str(requested_incident.get("id") or uuid.uuid4()).strip()
            incident_id = requested_incident["id"]
            for protected_field in ("workflowHistory", "serverUpdatedAt", "serverUpdatedBy"):
                requested_incident.pop(protected_field, None)
        elif operation == "update":
            changes = payload.get("changes")
            if not isinstance(changes, dict) or not changes:
                self.send_error_json(400, "changes must be a non-empty object")
                return
            changes = json.loads(json.dumps(changes, ensure_ascii=False))
            if "id" in changes and str(changes.get("id") or "").strip() != str(incident_id or "").strip():
                self.send_error_json(400, "incident id cannot be changed")
                return
            for protected_field in ("id", "workflowHistory", "serverUpdatedAt", "serverUpdatedBy"):
                changes.pop(protected_field, None)
            if not changes:
                self.send_error_json(400, "changes contain no mutable incident fields")
                return

        incident_id = str(incident_id or "").strip()
        if not incident_id or len(incident_id) > 200 or "/" in incident_id or "\\" in incident_id:
            self.send_error_json(400, "invalid incident id")
            return

        saved_at = now()
        saved_date = time.strftime("%Y-%m-%d", time.localtime(saved_at))
        saved_iso = datetime.fromtimestamp(saved_at, tz=timezone.utc).isoformat()
        response_incident = None
        previous_incident = None
        submission_report = None
        changed_fields = []
        snapshot_id = None
        with conn() as db:
            DATABASE.begin_workspace_write(db)
            previous = db.execute(
                "SELECT w.state_json, w.updated_at, w.updated_by, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            if not previous:
                self.send_json({
                    "error": "workspace_not_initialized",
                    "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                }, status=409)
                return
            current_revision = int(previous["revision"] or 1)
            if expected_revision != current_revision:
                audit(db, user, f"incident_{operation}_conflict", "incident", incident_id, {
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, self.client_address[0])
                self.send_json({
                    "error": "workspace_conflict",
                    "message": "Workspace wurde zwischenzeitlich geändert.",
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, status=409)
                return
            try:
                previous_state = json.loads(previous["state_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                self.send_error_json(500, "stored workspace state is invalid")
                return
            incidents = previous_state.get("incidents")
            if not isinstance(incidents, list):
                self.send_error_json(500, "stored incident register is invalid")
                return
            proposed_state = json.loads(json.dumps(previous_state, ensure_ascii=False))
            proposed_incidents = proposed_state["incidents"]
            incident_index = next(
                (index for index, item in enumerate(proposed_incidents) if str((item or {}).get("id") or "") == incident_id),
                None,
            )

            if operation == "create":
                if incident_index is not None:
                    self.send_json({"error": "incident_conflict", "message": "Incident-ID ist bereits vorhanden."}, status=409)
                    return
                requested_incident.setdefault("status", "Offen")
                requested_incident.setdefault("added", saved_date)
                if submission_only:
                    requested_incident["reviewStatus"] = "vom_kunden_eingereicht"
                    requested_incident["submittedAt"] = saved_at
                    requested_incident["submittedBy"] = user["username"]
                    requested_incident["reviewUpdatedAt"] = saved_at
                proposed_incidents.insert(0, requested_incident)
                response_incident = requested_incident
                changed_fields = sorted(requested_incident.keys())
            elif operation == "update":
                if incident_index is None:
                    self.send_error_json(404, "incident not found")
                    return
                current_incident = proposed_incidents[incident_index]
                if not isinstance(current_incident, dict):
                    self.send_error_json(500, "stored incident record is invalid")
                    return
                previous_incident = json.loads(json.dumps(current_incident, ensure_ascii=False))
                response_incident = {**current_incident, **changes, "id": incident_id}
                if submission_only:
                    response_incident["reviewStatus"] = "vom_kunden_eingereicht"
                    response_incident["submittedAt"] = saved_at
                    response_incident["submittedBy"] = user["username"]
                    response_incident["reviewUpdatedAt"] = saved_at
                proposed_incidents[incident_index] = response_incident
                changed_fields = sorted(
                    key for key in set(current_incident) | set(response_incident)
                    if key not in {"workflowHistory", "serverUpdatedAt", "serverUpdatedBy"}
                    and canonical_workspace_value(current_incident.get(key)) != canonical_workspace_value(response_incident.get(key))
                )
                if not changed_fields:
                    self.send_json({
                        "ok": True,
                        "incident": response_incident,
                        "updatedAt": previous["updated_at"],
                        "updatedBy": previous["updated_by_username"],
                        "revision": current_revision,
                        "unchanged": True,
                    })
                    return
            else:
                if incident_index is None:
                    self.send_error_json(404, "incident not found")
                    return
                response_incident = proposed_incidents.pop(incident_index)
                previous_incident = response_incident if isinstance(response_incident, dict) else None
                changed_fields = sorted(response_incident.keys()) if isinstance(response_incident, dict) else []

            if operation != "delete":
                title = str(response_incident.get("title") or "").strip()
                if not title:
                    self.send_error_json(400, "incident title is required")
                    return
                if len(title) > 500:
                    self.send_error_json(400, "incident title is too long")
                    return
                for text_field in (
                    "owner", "note", "evidence", "framework", "severity",
                    "customerComment", "consultantInternalComment",
                ):
                    if len(str(response_incident.get(text_field) or "")) > 12000:
                        self.send_error_json(400, f"{text_field} is too long")
                        return

            submission_changes = []
            if submission_only:
                submission_report = customer_submission_policy_report(previous_state, proposed_state)
                submission_report, submission_changes = contributor_submission_policy_report(
                    db,
                    user,
                    previous_state,
                    proposed_state,
                    submission_report,
                )
                protected_statuses = {
                    "geschlossen", "erledigt", "freigegeben", "abgelehnt",
                    "auditrelevant", "archiviert", "meldepflichtig", "nicht meldepflichtig",
                }
                if operation != "delete" and normalized_submission_status(response_incident.get("status")) in protected_statuses:
                    submission_report["violations"].append({
                        "path": f"incidents.id:{incident_id}.status",
                        "reason": "incident_closure_requires_advisor",
                    })
                    submission_report["allowed"] = False
                if not submission_report["allowed"]:
                    audit(db, user, f"incident_{operation}_rejected", "incident", incident_id, {
                        "violations": submission_report["violations"],
                        "revision": current_revision,
                    }, self.client_address[0])
                    self.send_json({
                        "error": "submission_policy_violation",
                        "message": "Diese Incident-Entscheidung benötigt Berater- oder Adminrechte.",
                        "submission": submission_report,
                    }, status=403)
                    return

            if operation != "delete":
                response_incident["serverUpdatedAt"] = saved_at
                response_incident["serverUpdatedBy"] = user["username"]
                action_label = "Incident angelegt" if operation == "create" else "Incident aktualisiert"
                workflow_entry = {
                    "date": saved_date,
                    "dateTime": saved_iso,
                    "action": action_label,
                    "by": user["username"],
                    "note": "Änderung über die Incident API gespeichert.",
                    "status": str(response_incident.get("status") or "Offen"),
                    "severity": str(response_incident.get("severity") or ""),
                    "changes": changed_fields,
                    "snapshot": {
                        "title": str(response_incident.get("title") or ""),
                        "owner": str(response_incident.get("owner") or ""),
                        "framework": str(response_incident.get("framework") or ""),
                        "due": str(response_incident.get("due") or ""),
                    },
                }
                existing_workflow = response_incident.get("workflowHistory")
                if not isinstance(existing_workflow, list):
                    existing_workflow = []
                response_incident["workflowHistory"] = [workflow_entry, *existing_workflow][:40]

            try:
                state_json = json.dumps(proposed_state, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                self.send_error_json(400, "incident contains unsupported values")
                return
            validation = workspace_state_validation_report(proposed_state, state_json)
            if len(state_json.encode("utf-8")) > MAX_JSON:
                self.send_json({"error": "state too large", "validation": validation}, status=413)
                return
            if not validation["valid"]:
                self.send_json({"error": "workspace state is incomplete", "validation": validation}, status=400)
                return

            snapshot_id = insert_state_snapshot(
                db,
                user["tenant_id"],
                previous["state_json"],
                previous["updated_by"],
                f"before_incident_{operation}",
            )
            new_revision = current_revision + 1
            db.execute(
                "UPDATE tenant_workspace_state SET state_json = ?, updated_at = ?, updated_by = ?, revision = ? WHERE tenant_id = ?",
                (state_json, saved_at, user["id"], new_revision, user["tenant_id"]),
            )
            if submission_only:
                persist_submission_record_ownership(db, user, submission_changes, saved_at)
            else:
                prune_workspace_record_ownership(db, user["tenant_id"], proposed_state)
            audit(db, user, f"incident_{operation}d" if operation != "delete" else "incident_deleted", "incident", incident_id, {
                "changedFields": changed_fields,
                "snapshotId": snapshot_id,
                "previousRevision": current_revision,
                "revision": new_revision,
                "submission": submission_report,
            }, self.client_address[0])

        response = {
            "ok": True,
            "updatedAt": saved_at,
            "updatedBy": user["username"],
            "revision": new_revision,
            "snapshotId": snapshot_id,
            "submission": submission_report,
        }
        if operation == "delete":
            response["deletedId"] = incident_id
        else:
            response["incident"] = response_incident
        self.send_json(response, status=201 if operation == "create" else 200)

    def handle_contract_mutation(self, operation, contract_id=None):
        user, submission_only = self.require_asset_mutation_user(delete=operation == "delete")
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        if "expectedRevision" not in payload:
            self.send_error_json(400, "expectedRevision is required")
            return
        expected_revision = payload.get("expectedRevision")
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            self.send_error_json(400, "expectedRevision must be a non-negative integer")
            return

        requested_contract = None
        changes = None
        if operation == "create":
            requested_contract = payload.get("contract")
            if not isinstance(requested_contract, dict):
                self.send_error_json(400, "contract must be an object")
                return
            requested_contract = json.loads(json.dumps(requested_contract, ensure_ascii=False))
            requested_contract["id"] = str(requested_contract.get("id") or uuid.uuid4()).strip()
            contract_id = requested_contract["id"]
            for protected_field in ("workflowHistory", "serverUpdatedAt", "serverUpdatedBy"):
                requested_contract.pop(protected_field, None)
        elif operation == "update":
            changes = payload.get("changes")
            if not isinstance(changes, dict) or not changes:
                self.send_error_json(400, "changes must be a non-empty object")
                return
            changes = json.loads(json.dumps(changes, ensure_ascii=False))
            if "id" in changes and str(changes.get("id") or "").strip() != str(contract_id or "").strip():
                self.send_error_json(400, "contract id cannot be changed")
                return
            for protected_field in ("id", "workflowHistory", "serverUpdatedAt", "serverUpdatedBy"):
                changes.pop(protected_field, None)
            if not changes:
                self.send_error_json(400, "changes contain no mutable contract fields")
                return

        contract_id = str(contract_id or "").strip()
        if not contract_id or len(contract_id) > 200 or "/" in contract_id or "\\" in contract_id:
            self.send_error_json(400, "invalid contract id")
            return

        saved_at = now()
        saved_date = time.strftime("%Y-%m-%d", time.localtime(saved_at))
        saved_iso = datetime.fromtimestamp(saved_at, tz=timezone.utc).isoformat()
        response_contract = None
        submission_report = None
        changed_fields = []
        snapshot_id = None
        with conn() as db:
            DATABASE.begin_workspace_write(db)
            previous = db.execute(
                "SELECT w.state_json, w.updated_at, w.updated_by, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            if not previous:
                self.send_json({
                    "error": "workspace_not_initialized",
                    "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                }, status=409)
                return
            current_revision = int(previous["revision"] or 1)
            if expected_revision != current_revision:
                audit(db, user, f"contract_{operation}_conflict", "contract", contract_id, {
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, self.client_address[0])
                self.send_json({
                    "error": "workspace_conflict",
                    "message": "Workspace wurde zwischenzeitlich geändert.",
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, status=409)
                return
            try:
                previous_state = json.loads(previous["state_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                self.send_error_json(500, "stored workspace state is invalid")
                return
            contracts = previous_state.get("contracts")
            if not isinstance(contracts, list):
                self.send_error_json(500, "stored contract register is invalid")
                return
            proposed_state = json.loads(json.dumps(previous_state, ensure_ascii=False))
            proposed_contracts = proposed_state["contracts"]
            contract_index = next(
                (index for index, item in enumerate(proposed_contracts) if str((item or {}).get("id") or "") == contract_id),
                None,
            )

            if operation == "create":
                if contract_index is not None:
                    self.send_json({"error": "contract_conflict", "message": "Vertrags-ID ist bereits vorhanden."}, status=409)
                    return
                requested_contract.setdefault("status", "Prüfen")
                requested_contract.setdefault("added", saved_date)
                if submission_only:
                    requested_contract["reviewStatus"] = "vom_kunden_eingereicht"
                    requested_contract["submittedAt"] = saved_at
                    requested_contract["submittedBy"] = user["username"]
                    requested_contract["reviewUpdatedAt"] = saved_at
                proposed_contracts.insert(0, requested_contract)
                response_contract = requested_contract
                changed_fields = sorted(requested_contract.keys())
            elif operation == "update":
                if contract_index is None:
                    self.send_error_json(404, "contract not found")
                    return
                current_contract = proposed_contracts[contract_index]
                if not isinstance(current_contract, dict):
                    self.send_error_json(500, "stored contract record is invalid")
                    return
                response_contract = {**current_contract, **changes, "id": contract_id}
                if submission_only:
                    response_contract["reviewStatus"] = "vom_kunden_eingereicht"
                    response_contract["submittedAt"] = saved_at
                    response_contract["submittedBy"] = user["username"]
                    response_contract["reviewUpdatedAt"] = saved_at
                proposed_contracts[contract_index] = response_contract
                changed_fields = sorted(
                    key for key in set(current_contract) | set(response_contract)
                    if key not in {"workflowHistory", "serverUpdatedAt", "serverUpdatedBy"}
                    and canonical_workspace_value(current_contract.get(key)) != canonical_workspace_value(response_contract.get(key))
                )
                if not changed_fields:
                    self.send_json({
                        "ok": True,
                        "contract": response_contract,
                        "updatedAt": previous["updated_at"],
                        "updatedBy": previous["updated_by_username"],
                        "revision": current_revision,
                        "unchanged": True,
                    })
                    return
            else:
                if contract_index is None:
                    self.send_error_json(404, "contract not found")
                    return
                response_contract = proposed_contracts.pop(contract_index)
                changed_fields = sorted(response_contract.keys()) if isinstance(response_contract, dict) else []

            if operation != "delete":
                title = str(response_contract.get("title") or "").strip()
                if not title:
                    self.send_error_json(400, "contract title is required")
                    return
                if len(title) > 500:
                    self.send_error_json(400, "contract title is too long")
                    return
                for text_field in (
                    "vendor", "owner", "linkedTo", "evidence", "framework", "note",
                    "customerComment", "consultantInternalComment",
                ):
                    if len(str(response_contract.get(text_field) or "")) > 12000:
                        self.send_error_json(400, f"{text_field} is too long")
                        return

            submission_changes = []
            if submission_only:
                submission_report = customer_submission_policy_report(previous_state, proposed_state)
                submission_report, submission_changes = contributor_submission_policy_report(
                    db,
                    user,
                    previous_state,
                    proposed_state,
                    submission_report,
                )
                protected_statuses = {
                    "geprüft", "freigegeben", "abgelehnt", "auditrelevant",
                    "archiviert", "gekündigt", "abgeschlossen",
                }
                if operation != "delete" and normalized_submission_status(response_contract.get("status")) in protected_statuses:
                    submission_report["violations"].append({
                        "path": f"contracts.id:{contract_id}.status",
                        "reason": "contract_approval_requires_advisor",
                    })
                    submission_report["allowed"] = False
                if not submission_report["allowed"]:
                    audit(db, user, f"contract_{operation}_rejected", "contract", contract_id, {
                        "violations": submission_report["violations"],
                        "revision": current_revision,
                    }, self.client_address[0])
                    self.send_json({
                        "error": "submission_policy_violation",
                        "message": "Diese Vertragsentscheidung benötigt Berater- oder Adminrechte.",
                        "submission": submission_report,
                    }, status=403)
                    return

            if operation != "delete":
                response_contract["serverUpdatedAt"] = saved_at
                response_contract["serverUpdatedBy"] = user["username"]
                workflow_entry = {
                    "date": saved_date,
                    "dateTime": saved_iso,
                    "action": "Vertrag angelegt" if operation == "create" else "Vertrag aktualisiert",
                    "by": user["username"],
                    "note": "Änderung über die Contract API gespeichert.",
                    "status": str(response_contract.get("status") or "Prüfen"),
                    "changes": changed_fields,
                    "snapshot": {
                        "title": str(response_contract.get("title") or ""),
                        "vendor": str(response_contract.get("vendor") or ""),
                        "owner": str(response_contract.get("owner") or ""),
                        "framework": str(response_contract.get("framework") or ""),
                        "review": str(response_contract.get("review") or ""),
                    },
                }
                existing_workflow = response_contract.get("workflowHistory")
                if not isinstance(existing_workflow, list):
                    existing_workflow = []
                response_contract["workflowHistory"] = [workflow_entry, *existing_workflow][:40]

            try:
                state_json = json.dumps(proposed_state, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                self.send_error_json(400, "contract contains unsupported values")
                return
            validation = workspace_state_validation_report(proposed_state, state_json)
            if len(state_json.encode("utf-8")) > MAX_JSON:
                self.send_json({"error": "state too large", "validation": validation}, status=413)
                return
            if not validation["valid"]:
                self.send_json({"error": "workspace state is incomplete", "validation": validation}, status=400)
                return

            snapshot_id = insert_state_snapshot(
                db,
                user["tenant_id"],
                previous["state_json"],
                previous["updated_by"],
                f"before_contract_{operation}",
            )
            new_revision = current_revision + 1
            db.execute(
                "UPDATE tenant_workspace_state SET state_json = ?, updated_at = ?, updated_by = ?, revision = ? WHERE tenant_id = ?",
                (state_json, saved_at, user["id"], new_revision, user["tenant_id"]),
            )
            if submission_only:
                persist_submission_record_ownership(db, user, submission_changes, saved_at)
            else:
                prune_workspace_record_ownership(db, user["tenant_id"], proposed_state)
            audit(db, user, f"contract_{operation}d" if operation != "delete" else "contract_deleted", "contract", contract_id, {
                "changedFields": changed_fields,
                "snapshotId": snapshot_id,
                "previousRevision": current_revision,
                "revision": new_revision,
                "submission": submission_report,
            }, self.client_address[0])

        response = {
            "ok": True,
            "updatedAt": saved_at,
            "updatedBy": user["username"],
            "revision": new_revision,
            "snapshotId": snapshot_id,
            "submission": submission_report,
        }
        if operation == "delete":
            response["deletedId"] = contract_id
        else:
            response["contract"] = response_contract
        self.send_json(response, status=201 if operation == "create" else 200)

    def handle_task_mutation(self, operation, task_id=None):
        user, submission_only = self.require_asset_mutation_user(delete=operation == "delete")
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        if "expectedRevision" not in payload:
            self.send_error_json(400, "expectedRevision is required")
            return
        expected_revision = payload.get("expectedRevision")
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            self.send_error_json(400, "expectedRevision must be a non-negative integer")
            return

        requested_task = None
        changes = None
        if operation == "create":
            requested_task = payload.get("task")
            if not isinstance(requested_task, dict):
                self.send_error_json(400, "task must be an object")
                return
            requested_task = json.loads(json.dumps(requested_task, ensure_ascii=False))
            requested_task["id"] = str(requested_task.get("id") or uuid.uuid4()).strip()
            task_id = requested_task["id"]
            for protected_field in ("workflowHistory", "serverUpdatedAt", "serverUpdatedBy"):
                requested_task.pop(protected_field, None)
        elif operation == "update":
            changes = payload.get("changes")
            if not isinstance(changes, dict) or not changes:
                self.send_error_json(400, "changes must be a non-empty object")
                return
            changes = json.loads(json.dumps(changes, ensure_ascii=False))
            if "id" in changes and str(changes.get("id") or "").strip() != str(task_id or "").strip():
                self.send_error_json(400, "task id cannot be changed")
                return
            for protected_field in ("id", "workflowHistory", "serverUpdatedAt", "serverUpdatedBy"):
                changes.pop(protected_field, None)
            if not changes:
                self.send_error_json(400, "changes contain no mutable task fields")
                return

        task_id = str(task_id or "").strip()
        if not task_id or len(task_id) > 200 or "/" in task_id or "\\" in task_id:
            self.send_error_json(400, "invalid task id")
            return
        requested_review_status = normalized_submission_status(
            (requested_task if operation == "create" else (changes or {})).get("reviewStatus")
        )
        requested_protected_review = requested_review_status in {"freigegeben", "abgelehnt", "auditrelevant"}

        saved_at = now()
        saved_date = time.strftime("%Y-%m-%d", time.localtime(saved_at))
        saved_iso = datetime.fromtimestamp(saved_at, tz=timezone.utc).isoformat()
        response_task = None
        submission_report = None
        changed_fields = []
        snapshot_id = None
        with conn() as db:
            DATABASE.begin_workspace_write(db)
            previous = db.execute(
                "SELECT w.state_json, w.updated_at, w.updated_by, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            if not previous:
                self.send_json({
                    "error": "workspace_not_initialized",
                    "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                }, status=409)
                return
            current_revision = int(previous["revision"] or 1)
            if expected_revision != current_revision:
                audit(db, user, f"task_{operation}_conflict", "task", task_id, {
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, self.client_address[0])
                self.send_json({
                    "error": "workspace_conflict",
                    "message": "Workspace wurde zwischenzeitlich geändert.",
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, status=409)
                return
            try:
                previous_state = json.loads(previous["state_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                self.send_error_json(500, "stored workspace state is invalid")
                return
            tasks = previous_state.get("tasks")
            if not isinstance(tasks, list):
                self.send_error_json(500, "stored task register is invalid")
                return
            proposed_state = json.loads(json.dumps(previous_state, ensure_ascii=False))
            proposed_tasks = proposed_state["tasks"]
            task_index = next(
                (index for index, item in enumerate(proposed_tasks) if str((item or {}).get("id") or "") == task_id),
                None,
            )

            if operation == "create":
                if task_index is not None:
                    self.send_json({"error": "task_conflict", "message": "Aufgaben-ID ist bereits vorhanden."}, status=409)
                    return
                requested_task.setdefault("status", "Offen")
                requested_task.setdefault("added", saved_date)
                if submission_only:
                    requested_task["reviewStatus"] = "vom_kunden_eingereicht"
                    requested_task["submittedAt"] = saved_at
                    requested_task["submittedBy"] = user["username"]
                    requested_task["reviewUpdatedAt"] = saved_at
                proposed_tasks.insert(0, requested_task)
                response_task = requested_task
                changed_fields = sorted(requested_task.keys())
            elif operation == "update":
                if task_index is None:
                    self.send_error_json(404, "task not found")
                    return
                current_task = proposed_tasks[task_index]
                if not isinstance(current_task, dict):
                    self.send_error_json(500, "stored task record is invalid")
                    return
                response_task = {**current_task, **changes, "id": task_id}
                if submission_only:
                    response_task["reviewStatus"] = "vom_kunden_eingereicht"
                    response_task["submittedAt"] = saved_at
                    response_task["submittedBy"] = user["username"]
                    response_task["reviewUpdatedAt"] = saved_at
                proposed_tasks[task_index] = response_task
                changed_fields = sorted(
                    key for key in set(current_task) | set(response_task)
                    if key not in {"workflowHistory", "serverUpdatedAt", "serverUpdatedBy"}
                    and canonical_workspace_value(current_task.get(key)) != canonical_workspace_value(response_task.get(key))
                )
                if not changed_fields and not (submission_only and requested_protected_review):
                    self.send_json({
                        "ok": True,
                        "task": response_task,
                        "updatedAt": previous["updated_at"],
                        "updatedBy": previous["updated_by_username"],
                        "revision": current_revision,
                        "unchanged": True,
                    })
                    return
            else:
                if task_index is None:
                    self.send_error_json(404, "task not found")
                    return
                response_task = proposed_tasks.pop(task_index)
                changed_fields = sorted(response_task.keys()) if isinstance(response_task, dict) else []

            if operation != "delete":
                title = str(response_task.get("title") or "").strip()
                if not title:
                    self.send_error_json(400, "task title is required")
                    return
                if len(title) > 500:
                    self.send_error_json(400, "task title is too long")
                    return
                for text_field in (
                    "module", "owner", "note", "result", "evidence", "linkedTo", "source",
                    "customerComment", "consultantInternalComment", "reworkReason", "reworkMissing",
                    "reworkWhy", "reworkAction", "reworkReference",
                ):
                    if len(str(response_task.get(text_field) or "")) > 12000:
                        self.send_error_json(400, f"{text_field} is too long")
                        return

            submission_changes = []
            if submission_only:
                submission_report = customer_submission_policy_report(previous_state, proposed_state)
                submission_report, submission_changes = contributor_submission_policy_report(
                    db,
                    user,
                    previous_state,
                    proposed_state,
                    submission_report,
                )
                protected_statuses = {
                    "erledigt", "geschlossen", "freigegeben", "abgelehnt",
                    "auditrelevant", "archiviert",
                }
                protected_review_statuses = {"freigegeben", "abgelehnt", "auditrelevant"}
                if operation != "delete" and (
                    normalized_submission_status(response_task.get("status")) in protected_statuses
                    or normalized_submission_status(response_task.get("reviewStatus")) in protected_review_statuses
                    or requested_review_status in protected_review_statuses
                ):
                    submission_report["violations"].append({
                        "path": f"tasks.id:{task_id}.status",
                        "reason": "task_completion_requires_advisor",
                    })
                    submission_report["allowed"] = False
                if not submission_report["allowed"]:
                    audit(db, user, f"task_{operation}_rejected", "task", task_id, {
                        "violations": submission_report["violations"],
                        "revision": current_revision,
                    }, self.client_address[0])
                    self.send_json({
                        "error": "submission_policy_violation",
                        "message": "Diese Aufgabenentscheidung benötigt Berater- oder Adminrechte.",
                        "submission": submission_report,
                    }, status=403)
                    return

            if operation != "delete":
                response_task["serverUpdatedAt"] = saved_at
                response_task["serverUpdatedBy"] = user["username"]
                workflow_entry = {
                    "date": saved_date,
                    "dateTime": saved_iso,
                    "action": "Aufgabe angelegt" if operation == "create" else "Aufgabe aktualisiert",
                    "by": user["username"],
                    "note": "Änderung über die Task API gespeichert.",
                    "status": str(response_task.get("status") or "Offen"),
                    "changes": changed_fields,
                    "snapshot": {
                        "title": str(response_task.get("title") or ""),
                        "module": str(response_task.get("module") or ""),
                        "owner": str(response_task.get("owner") or ""),
                        "due": str(response_task.get("due") or ""),
                        "evidence": str(response_task.get("evidence") or response_task.get("result") or ""),
                    },
                }
                existing_workflow = response_task.get("workflowHistory")
                if not isinstance(existing_workflow, list):
                    existing_workflow = []
                response_task["workflowHistory"] = [workflow_entry, *existing_workflow][:40]

            try:
                state_json = json.dumps(proposed_state, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                self.send_error_json(400, "task contains unsupported values")
                return
            validation = workspace_state_validation_report(proposed_state, state_json)
            if len(state_json.encode("utf-8")) > MAX_JSON:
                self.send_json({"error": "state too large", "validation": validation}, status=413)
                return
            if not validation["valid"]:
                self.send_json({"error": "workspace state is incomplete", "validation": validation}, status=400)
                return

            snapshot_id = insert_state_snapshot(
                db,
                user["tenant_id"],
                previous["state_json"],
                previous["updated_by"],
                f"before_task_{operation}",
            )
            new_revision = current_revision + 1
            db.execute(
                "UPDATE tenant_workspace_state SET state_json = ?, updated_at = ?, updated_by = ?, revision = ? WHERE tenant_id = ?",
                (state_json, saved_at, user["id"], new_revision, user["tenant_id"]),
            )
            if submission_only:
                persist_submission_record_ownership(db, user, submission_changes, saved_at)
            else:
                prune_workspace_record_ownership(db, user["tenant_id"], proposed_state)
            audit(db, user, f"task_{operation}d" if operation != "delete" else "task_deleted", "task", task_id, {
                "changedFields": changed_fields,
                "snapshotId": snapshot_id,
                "previousRevision": current_revision,
                "revision": new_revision,
                "submission": submission_report,
            }, self.client_address[0])

        response = {
            "ok": True,
            "updatedAt": saved_at,
            "updatedBy": user["username"],
            "revision": new_revision,
            "snapshotId": snapshot_id,
            "submission": submission_report,
        }
        if operation == "delete":
            response["deletedId"] = task_id
        else:
            response["task"] = response_task
        self.send_json(response, status=201 if operation == "create" else 200)

    def handle_legal_mutation(self, operation, legal_id=None):
        user, submission_only = self.require_asset_mutation_user(delete=operation == "delete")
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        if "expectedRevision" not in payload:
            self.send_error_json(400, "expectedRevision is required")
            return
        expected_revision = payload.get("expectedRevision")
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            self.send_error_json(400, "expectedRevision must be a non-negative integer")
            return

        requested_entry = None
        changes = None
        if operation == "create":
            requested_entry = payload.get("legalEntry")
            if not isinstance(requested_entry, dict):
                self.send_error_json(400, "legalEntry must be an object")
                return
            requested_entry = json.loads(json.dumps(requested_entry, ensure_ascii=False))
            requested_entry["id"] = str(requested_entry.get("id") or uuid.uuid4()).strip()
            legal_id = requested_entry["id"]
            for protected_field in ("workflowHistory", "serverUpdatedAt", "serverUpdatedBy"):
                requested_entry.pop(protected_field, None)
        elif operation == "update":
            changes = payload.get("changes")
            if not isinstance(changes, dict) or not changes:
                self.send_error_json(400, "changes must be a non-empty object")
                return
            changes = json.loads(json.dumps(changes, ensure_ascii=False))
            if "id" in changes and str(changes.get("id") or "").strip() != str(legal_id or "").strip():
                self.send_error_json(400, "legal entry id cannot be changed")
                return
            for protected_field in ("id", "workflowHistory", "serverUpdatedAt", "serverUpdatedBy"):
                changes.pop(protected_field, None)
            if not changes:
                self.send_error_json(400, "changes contain no mutable legal fields")
                return

        legal_id = str(legal_id or "").strip()
        if not legal_id or len(legal_id) > 200 or "/" in legal_id or "\\" in legal_id:
            self.send_error_json(400, "invalid legal entry id")
            return
        request_values = requested_entry if operation == "create" else (changes or {})
        requested_review_status = normalized_submission_status(request_values.get("reviewStatus"))
        requested_status = normalized_submission_status(request_values.get("status"))
        protected_review_statuses = {"freigegeben", "abgelehnt", "auditrelevant"}
        protected_legal_statuses = {"anwendbar", "nichtanwendbar", "umgesetzt", "geschlossen", "archiviert"}
        requested_protected_decision = (
            requested_review_status in protected_review_statuses
            or requested_status in protected_legal_statuses
        )

        saved_at = now()
        saved_date = time.strftime("%Y-%m-%d", time.localtime(saved_at))
        saved_iso = datetime.fromtimestamp(saved_at, tz=timezone.utc).isoformat()
        response_entry = None
        submission_report = None
        changed_fields = []
        snapshot_id = None
        with conn() as db:
            DATABASE.begin_workspace_write(db)
            previous = db.execute(
                "SELECT w.state_json, w.updated_at, w.updated_by, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            if not previous:
                self.send_json({
                    "error": "workspace_not_initialized",
                    "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                }, status=409)
                return
            current_revision = int(previous["revision"] or 1)
            if expected_revision != current_revision:
                audit(db, user, f"legal_{operation}_conflict", "legal", legal_id, {
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, self.client_address[0])
                self.send_json({
                    "error": "workspace_conflict",
                    "message": "Workspace wurde zwischenzeitlich geändert.",
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, status=409)
                return
            try:
                previous_state = json.loads(previous["state_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                self.send_error_json(500, "stored workspace state is invalid")
                return
            legal_entries = previous_state.get("legal")
            if not isinstance(legal_entries, list):
                self.send_error_json(500, "stored legal register is invalid")
                return
            proposed_state = json.loads(json.dumps(previous_state, ensure_ascii=False))
            proposed_entries = proposed_state["legal"]
            entry_index = next(
                (index for index, item in enumerate(proposed_entries) if str((item or {}).get("id") or "") == legal_id),
                None,
            )

            if operation == "create":
                if entry_index is not None:
                    self.send_json({"error": "legal_conflict", "message": "Rechtsregister-ID ist bereits vorhanden."}, status=409)
                    return
                requested_entry.setdefault("status", "Prüfen")
                requested_entry.setdefault("framework", "NIS-2")
                requested_entry.setdefault("added", saved_date)
                if submission_only:
                    requested_entry["reviewStatus"] = "vom_kunden_eingereicht"
                    requested_entry["submittedAt"] = saved_at
                    requested_entry["submittedBy"] = user["username"]
                    requested_entry["reviewUpdatedAt"] = saved_at
                proposed_entries.insert(0, requested_entry)
                response_entry = requested_entry
                changed_fields = sorted(requested_entry.keys())
            elif operation == "update":
                if entry_index is None:
                    self.send_error_json(404, "legal entry not found")
                    return
                current_entry = proposed_entries[entry_index]
                if not isinstance(current_entry, dict):
                    self.send_error_json(500, "stored legal record is invalid")
                    return
                response_entry = {**current_entry, **changes, "id": legal_id}
                if submission_only:
                    response_entry["reviewStatus"] = "vom_kunden_eingereicht"
                    response_entry["submittedAt"] = saved_at
                    response_entry["submittedBy"] = user["username"]
                    response_entry["reviewUpdatedAt"] = saved_at
                proposed_entries[entry_index] = response_entry
                changed_fields = sorted(
                    key for key in set(current_entry) | set(response_entry)
                    if key not in {"workflowHistory", "serverUpdatedAt", "serverUpdatedBy"}
                    and canonical_workspace_value(current_entry.get(key)) != canonical_workspace_value(response_entry.get(key))
                )
                if not changed_fields and not (submission_only and requested_protected_decision):
                    self.send_json({
                        "ok": True,
                        "legalEntry": response_entry,
                        "updatedAt": previous["updated_at"],
                        "updatedBy": previous["updated_by_username"],
                        "revision": current_revision,
                        "unchanged": True,
                    })
                    return
            else:
                if entry_index is None:
                    self.send_error_json(404, "legal entry not found")
                    return
                response_entry = proposed_entries.pop(entry_index)
                changed_fields = sorted(response_entry.keys()) if isinstance(response_entry, dict) else []

            if operation != "delete":
                requirement = str(response_entry.get("requirement") or "").strip()
                if not requirement:
                    self.send_error_json(400, "legal requirement is required")
                    return
                if len(requirement) > 1000:
                    self.send_error_json(400, "legal requirement is too long")
                    return
                for text_field in (
                    "source", "framework", "owner", "status", "evidence", "note",
                    "customerComment", "consultantInternalComment", "reworkReason", "reworkMissing",
                    "reworkWhy", "reworkAction", "reworkReference",
                ):
                    if len(str(response_entry.get(text_field) or "")) > 12000:
                        self.send_error_json(400, f"{text_field} is too long")
                        return

            submission_changes = []
            if submission_only:
                submission_report = customer_submission_policy_report(previous_state, proposed_state)
                submission_report, submission_changes = contributor_submission_policy_report(
                    db,
                    user,
                    previous_state,
                    proposed_state,
                    submission_report,
                )
                if operation != "delete" and (
                    normalized_submission_status(response_entry.get("status")) in protected_legal_statuses
                    or normalized_submission_status(response_entry.get("reviewStatus")) in protected_review_statuses
                    or requested_protected_decision
                ):
                    submission_report["violations"].append({
                        "path": f"legal.id:{legal_id}.status",
                        "reason": "legal_decision_requires_advisor",
                    })
                    submission_report["allowed"] = False
                if not submission_report["allowed"]:
                    audit(db, user, f"legal_{operation}_rejected", "legal", legal_id, {
                        "violations": submission_report["violations"],
                        "revision": current_revision,
                    }, self.client_address[0])
                    self.send_json({
                        "error": "submission_policy_violation",
                        "message": "Diese Rechtsregister-Entscheidung benötigt Berater- oder Adminrechte.",
                        "submission": submission_report,
                    }, status=403)
                    return

            if operation != "delete":
                response_entry["serverUpdatedAt"] = saved_at
                response_entry["serverUpdatedBy"] = user["username"]
                workflow_entry = {
                    "date": saved_date,
                    "dateTime": saved_iso,
                    "action": "Rechtsanforderung angelegt" if operation == "create" else "Rechtsanforderung aktualisiert",
                    "by": user["username"],
                    "note": "Änderung über die Rechtsregister-API gespeichert.",
                    "status": str(response_entry.get("status") or "Prüfen"),
                    "changes": changed_fields,
                    "snapshot": {
                        "requirement": str(response_entry.get("requirement") or ""),
                        "source": str(response_entry.get("source") or ""),
                        "framework": str(response_entry.get("framework") or ""),
                        "owner": str(response_entry.get("owner") or ""),
                        "due": str(response_entry.get("due") or ""),
                        "evidence": str(response_entry.get("evidence") or ""),
                    },
                }
                existing_workflow = response_entry.get("workflowHistory")
                if not isinstance(existing_workflow, list):
                    existing_workflow = []
                response_entry["workflowHistory"] = [workflow_entry, *existing_workflow][:40]

            try:
                state_json = json.dumps(proposed_state, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                self.send_error_json(400, "legal entry contains unsupported values")
                return
            validation = workspace_state_validation_report(proposed_state, state_json)
            if len(state_json.encode("utf-8")) > MAX_JSON:
                self.send_json({"error": "state too large", "validation": validation}, status=413)
                return
            if not validation["valid"]:
                self.send_json({"error": "workspace state is incomplete", "validation": validation}, status=400)
                return

            snapshot_id = insert_state_snapshot(
                db,
                user["tenant_id"],
                previous["state_json"],
                previous["updated_by"],
                f"before_legal_{operation}",
            )
            new_revision = current_revision + 1
            db.execute(
                "UPDATE tenant_workspace_state SET state_json = ?, updated_at = ?, updated_by = ?, revision = ? WHERE tenant_id = ?",
                (state_json, saved_at, user["id"], new_revision, user["tenant_id"]),
            )
            if submission_only:
                persist_submission_record_ownership(db, user, submission_changes, saved_at)
            else:
                prune_workspace_record_ownership(db, user["tenant_id"], proposed_state)
            audit(db, user, f"legal_{operation}d" if operation != "delete" else "legal_deleted", "legal", legal_id, {
                "changedFields": changed_fields,
                "snapshotId": snapshot_id,
                "previousRevision": current_revision,
                "revision": new_revision,
                "submission": submission_report,
            }, self.client_address[0])

        response = {
            "ok": True,
            "updatedAt": saved_at,
            "updatedBy": user["username"],
            "revision": new_revision,
            "snapshotId": snapshot_id,
            "submission": submission_report,
        }
        if operation == "delete":
            response["deletedId"] = legal_id
        else:
            response["legalEntry"] = response_entry
        self.send_json(response, status=201 if operation == "create" else 200)

    def handle_soa_mutation(self, control_id):
        user, submission_only = self.require_asset_mutation_user(delete=False)
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        if "expectedRevision" not in payload:
            self.send_error_json(400, "expectedRevision is required")
            return
        expected_revision = payload.get("expectedRevision")
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            self.send_error_json(400, "expectedRevision must be a non-negative integer")
            return
        changes = payload.get("changes")
        if not isinstance(changes, dict) or not changes:
            self.send_error_json(400, "changes must be a non-empty object")
            return
        changes = json.loads(json.dumps(changes, ensure_ascii=False))

        control_id = str(control_id or "").strip()
        if not re.fullmatch(r"A\.[5-8]\.\d{1,2}", control_id):
            self.send_error_json(400, "invalid SoA control id")
            return
        if "controlId" in changes and str(changes.get("controlId") or "").strip() != control_id:
            self.send_error_json(400, "SoA control id cannot be changed")
            return
        protected_server_fields = {
            "id", "controlId", "workflowHistory", "serverUpdatedAt", "serverUpdatedBy",
            "submittedAt", "submittedBy", "approvedAt", "approvedBy", "rejectedAt", "rejectedBy",
        }
        for field in protected_server_fields:
            changes.pop(field, None)
        mutable_fields = {
            "applicability", "implementation", "owner", "justification", "evidence", "risk", "review", "notes",
            "reviewStatus", "reviewAssignee", "reviewUpdatedAt", "customerComment", "consultantInternalComment",
            "consultantDecision", "auditRelevant", "auditRelevance", "reworkReason", "reworkMissing",
            "reworkWhy", "reworkAction", "reworkReference",
        }
        unknown_fields = sorted(set(changes) - mutable_fields)
        if unknown_fields:
            self.send_json({
                "error": "unsupported_soa_fields",
                "message": "Unsupported SoA fields were supplied.",
                "fields": unknown_fields,
            }, status=400)
            return
        if not changes:
            self.send_error_json(400, "changes contain no mutable SoA fields")
            return

        requested_review_status = normalized_submission_status(changes.get("reviewStatus"))
        protected_review_statuses = {"freigegeben", "abgelehnt", "auditrelevant"}
        requested_protected_decision = requested_review_status in protected_review_statuses
        allowed_applicability = {"Zu prüfen", "Anwendbar", "Nicht anwendbar", "Teilweise anwendbar"}
        allowed_implementation = {"Offen", "Geplant", "In Umsetzung", "Umgesetzt", "Nicht erforderlich"}
        if "applicability" in changes and changes["applicability"] not in allowed_applicability:
            self.send_error_json(400, "invalid SoA applicability")
            return
        if "implementation" in changes and changes["implementation"] not in allowed_implementation:
            self.send_error_json(400, "invalid SoA implementation status")
            return

        saved_at = now()
        saved_date = time.strftime("%Y-%m-%d", time.localtime(saved_at))
        saved_iso = datetime.fromtimestamp(saved_at, tz=timezone.utc).isoformat()
        response_record = None
        submission_report = None
        submission_changes = []
        changed_fields = []
        snapshot_id = None
        record_created = False
        with conn() as db:
            DATABASE.begin_workspace_write(db)
            previous = db.execute(
                "SELECT w.state_json, w.updated_at, w.updated_by, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            if not previous:
                self.send_json({
                    "error": "workspace_not_initialized",
                    "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                }, status=409)
                return
            current_revision = int(previous["revision"] or 1)
            if expected_revision != current_revision:
                audit(db, user, "soa_update_conflict", "soa", control_id, {
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, self.client_address[0])
                self.send_json({
                    "error": "workspace_conflict",
                    "message": "Workspace wurde zwischenzeitlich geändert.",
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, status=409)
                return
            try:
                previous_state = json.loads(previous["state_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                self.send_error_json(500, "stored workspace state is invalid")
                return
            records = previous_state.get("soa", [])
            if not isinstance(records, list):
                self.send_error_json(500, "stored SoA register is invalid")
                return
            proposed_state = json.loads(json.dumps(previous_state, ensure_ascii=False))
            proposed_records = proposed_state.setdefault("soa", [])
            record_index = next(
                (index for index, item in enumerate(proposed_records) if str((item or {}).get("controlId") or "") == control_id),
                None,
            )
            if record_index is None:
                proposed_records.append({
                    "id": str(uuid.uuid4()),
                    "controlId": control_id,
                    "applicability": "Zu prüfen",
                    "implementation": "Offen",
                    "owner": "ISB",
                    "justification": "",
                    "evidence": "",
                    "risk": "",
                    "review": "",
                    "notes": "",
                })
                record_index = len(proposed_records) - 1
                record_created = True
            current_record = proposed_records[record_index]
            if not isinstance(current_record, dict):
                self.send_error_json(500, "stored SoA record is invalid")
                return
            response_record = {**current_record, **changes, "controlId": control_id}
            if submission_only:
                response_record["reviewStatus"] = "vom_kunden_eingereicht"
                response_record["submittedAt"] = saved_at
                response_record["submittedBy"] = user["username"]
                response_record["reviewUpdatedAt"] = saved_at
            proposed_records[record_index] = response_record
            changed_fields = sorted(
                key for key in set(current_record) | set(response_record)
                if key not in {"workflowHistory", "serverUpdatedAt", "serverUpdatedBy"}
                and canonical_workspace_value(current_record.get(key)) != canonical_workspace_value(response_record.get(key))
            )
            if not changed_fields and not (submission_only and requested_protected_decision):
                self.send_json({
                    "ok": True,
                    "soaControl": response_record,
                    "updatedAt": previous["updated_at"],
                    "updatedBy": previous["updated_by_username"],
                    "revision": current_revision,
                    "unchanged": True,
                })
                return

            for text_field in (
                "owner", "justification", "evidence", "risk", "review", "notes", "customerComment",
                "consultantInternalComment", "reworkReason", "reworkMissing", "reworkWhy", "reworkAction",
                "reworkReference", "reviewAssignee",
            ):
                if len(str(response_record.get(text_field) or "")) > 12000:
                    self.send_error_json(400, f"{text_field} is too long")
                    return

            if submission_only:
                submission_report = customer_submission_policy_report(previous_state, proposed_state)
                submission_report, submission_changes = contributor_submission_policy_report(
                    db,
                    user,
                    previous_state,
                    proposed_state,
                    submission_report,
                )
                if requested_protected_decision:
                    submission_report["violations"].append({
                        "path": f"soa.controlId:{control_id}.reviewStatus",
                        "reason": "soa_decision_requires_advisor",
                    })
                    submission_report["allowed"] = False
                if not submission_report["allowed"]:
                    audit(db, user, "soa_update_rejected", "soa", control_id, {
                        "violations": submission_report["violations"],
                        "revision": current_revision,
                    }, self.client_address[0])
                    self.send_json({
                        "error": "submission_policy_violation",
                        "message": "Diese SoA-Freigabe benötigt Berater- oder Adminrechte.",
                        "submission": submission_report,
                    }, status=403)
                    return

            response_record["serverUpdatedAt"] = saved_at
            response_record["serverUpdatedBy"] = user["username"]
            workflow_entry = {
                "date": saved_date,
                "dateTime": saved_iso,
                "action": "SoA-Control angelegt" if record_created else "SoA-Control aktualisiert",
                "by": user["username"],
                "note": "Änderung über die SoA-Control-API gespeichert.",
                "status": str(response_record.get("reviewStatus") or "offen"),
                "changes": changed_fields,
                "snapshot": {
                    "applicability": str(response_record.get("applicability") or ""),
                    "implementation": str(response_record.get("implementation") or ""),
                    "owner": str(response_record.get("owner") or ""),
                    "justification": str(response_record.get("justification") or ""),
                    "evidence": str(response_record.get("evidence") or ""),
                    "risk": str(response_record.get("risk") or ""),
                    "review": str(response_record.get("review") or ""),
                },
            }
            existing_workflow = response_record.get("workflowHistory")
            if not isinstance(existing_workflow, list):
                existing_workflow = []
            response_record["workflowHistory"] = [workflow_entry, *existing_workflow][:40]

            try:
                state_json = json.dumps(proposed_state, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                self.send_error_json(400, "SoA control contains unsupported values")
                return
            validation = workspace_state_validation_report(proposed_state, state_json)
            if len(state_json.encode("utf-8")) > MAX_JSON:
                self.send_json({"error": "state too large", "validation": validation}, status=413)
                return
            if not validation["valid"]:
                self.send_json({"error": "workspace state is incomplete", "validation": validation}, status=400)
                return

            snapshot_id = insert_state_snapshot(
                db,
                user["tenant_id"],
                previous["state_json"],
                previous["updated_by"],
                "before_soa_update",
            )
            new_revision = current_revision + 1
            db.execute(
                "UPDATE tenant_workspace_state SET state_json = ?, updated_at = ?, updated_by = ?, revision = ? WHERE tenant_id = ?",
                (state_json, saved_at, user["id"], new_revision, user["tenant_id"]),
            )
            if submission_only:
                persist_submission_record_ownership(db, user, submission_changes, saved_at)
            else:
                prune_workspace_record_ownership(db, user["tenant_id"], proposed_state)
            audit(db, user, "soa_updated", "soa", control_id, {
                "changedFields": changed_fields,
                "snapshotId": snapshot_id,
                "previousRevision": current_revision,
                "revision": new_revision,
                "submission": submission_report,
            }, self.client_address[0])

        self.send_json({
            "ok": True,
            "soaControl": response_record,
            "updatedAt": saved_at,
            "updatedBy": user["username"],
            "revision": new_revision,
            "snapshotId": snapshot_id,
            "submission": submission_report,
        })

    def handle_audit_finding_mutation(self, operation, finding_id=None):
        user, submission_only = self.require_asset_mutation_user(delete=operation == "delete")
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        if "expectedRevision" not in payload:
            self.send_error_json(400, "expectedRevision is required")
            return
        expected_revision = payload.get("expectedRevision")
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            self.send_error_json(400, "expectedRevision must be a non-negative integer")
            return

        requested_finding = None
        changes = None
        if operation == "create":
            requested_finding = payload.get("auditFinding")
            if not isinstance(requested_finding, dict):
                self.send_error_json(400, "auditFinding must be an object")
                return
            requested_finding = json.loads(json.dumps(requested_finding, ensure_ascii=False))
            requested_finding["id"] = str(requested_finding.get("id") or workspace_item_id("finding")).strip()
            finding_id = requested_finding["id"]
            for protected_field in ("workflowHistory", "serverUpdatedAt", "serverUpdatedBy"):
                requested_finding.pop(protected_field, None)
        elif operation == "update":
            changes = payload.get("changes")
            if not isinstance(changes, dict) or not changes:
                self.send_error_json(400, "changes must be a non-empty object")
                return
            changes = json.loads(json.dumps(changes, ensure_ascii=False))
            if "id" in changes and str(changes.get("id") or "").strip() != str(finding_id or "").strip():
                self.send_error_json(400, "audit finding id cannot be changed")
                return
            for protected_field in (
                "id", "workflowHistory", "serverUpdatedAt", "serverUpdatedBy",
                "submittedAt", "submittedBy", "approvedAt", "approvedBy", "rejectedAt", "rejectedBy",
            ):
                changes.pop(protected_field, None)
            if not changes:
                self.send_error_json(400, "changes contain no mutable audit finding fields")
                return

        finding_id = str(finding_id or "").strip()
        if not finding_id or len(finding_id) > 200 or "/" in finding_id or "\\" in finding_id:
            self.send_error_json(400, "invalid audit finding id")
            return

        mutable_fields = {
            "title", "type", "severity", "status", "owner", "due", "mapping", "evidence", "note", "sourceView",
            "sourceRow", "reviewStatus", "reviewAssignee", "customerComment", "consultantInternalComment",
            "consultantDecision", "auditRelevant", "auditRelevance", "reworkReason", "reworkMissing", "reworkWhy",
            "reworkAction", "reworkReference", "sourceFindingId", "nonconformity", "immediateCorrection",
            "rootCause", "correctiveAction", "effectivenessCriteria", "effectivenessEvidence",
            "effectivenessAssessment", "completionDate",
        }
        candidate = requested_finding if operation == "create" else changes if operation == "update" else {}
        unknown_fields = sorted(set(candidate) - mutable_fields - {"id"})
        if unknown_fields:
            self.send_json({
                "error": "unsupported_audit_finding_fields",
                "message": "Unsupported audit finding fields were supplied.",
                "fields": unknown_fields,
            }, status=400)
            return

        allowed_severities = {"Hinweis", "Niedrig", "Mittel", "Hoch", "Kritisch"}
        allowed_statuses = {"offen", "in_pruefung", "nacharbeit_noetig", "geschlossen", "freigegeben", "abgelehnt", "auditrelevant"}
        if operation != "delete" and candidate.get("severity") not in (None, "") and candidate.get("severity") not in allowed_severities:
            self.send_error_json(400, "invalid audit finding severity")
            return
        if operation != "delete" and candidate.get("status") not in (None, "") and candidate.get("status") not in allowed_statuses:
            self.send_error_json(400, "invalid audit finding status")
            return

        requested_status = normalized_submission_status(candidate.get("status"))
        requested_review_status = normalized_submission_status(candidate.get("reviewStatus"))
        protected_statuses = {"geschlossen", "freigegeben", "abgelehnt", "auditrelevant"}
        requested_protected_decision = requested_status in protected_statuses or requested_review_status in protected_statuses
        saved_at = now()
        saved_date = time.strftime("%Y-%m-%d", time.localtime(saved_at))
        saved_iso = datetime.fromtimestamp(saved_at, tz=timezone.utc).isoformat()
        response_finding = None
        submission_report = None
        submission_changes = []
        changed_fields = []
        snapshot_id = None
        customer_task = None

        with conn() as db:
            DATABASE.begin_workspace_write(db)
            previous = db.execute(
                "SELECT w.state_json, w.updated_at, w.updated_by, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            if not previous:
                self.send_json({
                    "error": "workspace_not_initialized",
                    "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                }, status=409)
                return
            current_revision = int(previous["revision"] or 1)
            if expected_revision != current_revision:
                audit(db, user, f"audit_finding_{operation}_conflict", "audit_finding", finding_id, {
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, self.client_address[0])
                self.send_json({
                    "error": "workspace_conflict",
                    "message": "Workspace wurde zwischenzeitlich geändert.",
                    "expectedRevision": expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"],
                    "currentUpdatedBy": previous["updated_by_username"],
                }, status=409)
                return
            try:
                previous_state = json.loads(previous["state_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                self.send_error_json(500, "stored workspace state is invalid")
                return
            findings = previous_state.get("auditFindings", [])
            if not isinstance(findings, list):
                self.send_error_json(500, "stored audit finding register is invalid")
                return
            proposed_state = json.loads(json.dumps(previous_state, ensure_ascii=False))
            proposed_state.setdefault("auditFindings", [])
            proposed_findings = proposed_state["auditFindings"]
            finding_index = next(
                (index for index, item in enumerate(proposed_findings) if str((item or {}).get("id") or "") == finding_id),
                None,
            )

            if operation == "create":
                if finding_index is not None:
                    self.send_json({"error": "audit_finding_conflict", "message": "Finding-ID ist bereits vorhanden."}, status=409)
                    return
                requested_finding.setdefault("status", "offen")
                requested_finding.setdefault("severity", "Mittel")
                requested_finding.setdefault("added", saved_date)
                if submission_only:
                    requested_finding["reviewStatus"] = "vom_kunden_eingereicht"
                    requested_finding["submittedAt"] = saved_at
                    requested_finding["submittedBy"] = user["username"]
                response_finding = requested_finding
                proposed_findings.insert(0, response_finding)
                changed_fields = sorted(response_finding.keys())
            elif operation == "update":
                if finding_index is None:
                    self.send_error_json(404, "audit finding not found")
                    return
                current_finding = proposed_findings[finding_index]
                if not isinstance(current_finding, dict):
                    self.send_error_json(500, "stored audit finding record is invalid")
                    return
                response_finding = {**current_finding, **changes, "id": finding_id}
                if submission_only:
                    response_finding["reviewStatus"] = "vom_kunden_eingereicht"
                    response_finding["submittedAt"] = saved_at
                    response_finding["submittedBy"] = user["username"]
                proposed_findings[finding_index] = response_finding
                changed_fields = sorted(
                    key for key in set(current_finding) | set(response_finding)
                    if canonical_workspace_value(current_finding.get(key)) != canonical_workspace_value(response_finding.get(key))
                )
                if not changed_fields:
                    self.send_json({
                        "ok": True,
                        "auditFinding": response_finding,
                        "updatedAt": previous["updated_at"],
                        "updatedBy": previous["updated_by_username"],
                        "revision": current_revision,
                        "unchanged": True,
                    })
                    return
            else:
                if finding_index is None:
                    self.send_error_json(404, "audit finding not found")
                    return
                response_finding = proposed_findings.pop(finding_index)
                changed_fields = sorted(response_finding.keys()) if isinstance(response_finding, dict) else []

            if operation != "delete":
                title = str(response_finding.get("title") or "").strip()
                if not title:
                    self.send_error_json(400, "audit finding title is required")
                    return
                if len(title) > 1000:
                    self.send_error_json(400, "audit finding title is too long")
                    return
                for text_field in mutable_fields:
                    if len(str(response_finding.get(text_field) or "")) > 12000:
                        self.send_error_json(400, f"{text_field} is too long")
                        return

            if submission_only:
                submission_report = customer_submission_policy_report(previous_state, proposed_state)
                submission_report, submission_changes = contributor_submission_policy_report(
                    db,
                    user,
                    previous_state,
                    proposed_state,
                    submission_report,
                )
                if operation != "delete" and requested_protected_decision:
                    submission_report["violations"].append({
                        "path": f"auditFindings.id:{finding_id}.status",
                        "reason": "audit_finding_decision_requires_advisor",
                    })
                    submission_report["allowed"] = False
                if not submission_report["allowed"]:
                    audit(db, user, f"audit_finding_{operation}_rejected", "audit_finding", finding_id, {
                        "violations": submission_report["violations"],
                        "revision": current_revision,
                    }, self.client_address[0])
                    self.send_json({
                        "error": "submission_policy_violation",
                        "message": "Diese Finding-Entscheidung benötigt Berater- oder Adminrechte.",
                        "submission": submission_report,
                    }, status=403)
                    return

            if operation != "delete" and str(response_finding.get("type") or "").strip().upper() == "CAPA":
                decision_status = str(
                    response_finding.get("reviewStatus") or response_finding.get("status") or "offen"
                ).strip().lower()
                if not submission_only and decision_status == "freigegeben":
                    response_finding["effectivenessVerifiedAt"] = saved_at
                    response_finding["effectivenessVerifiedBy"] = user["username"]
                    changed_fields = sorted(set(changed_fields) | {
                        "effectivenessVerifiedAt", "effectivenessVerifiedBy",
                    })
                elif decision_status != "freigegeben":
                    removed_verification = {
                        field for field in ("effectivenessVerifiedAt", "effectivenessVerifiedBy")
                        if field in response_finding
                    }
                    response_finding.pop("effectivenessVerifiedAt", None)
                    response_finding.pop("effectivenessVerifiedBy", None)
                    changed_fields = sorted(set(changed_fields) | removed_verification)

                if not submission_only:
                    tasks = proposed_state.get("tasks", [])
                    if not isinstance(tasks, list):
                        self.send_error_json(500, "stored task register is invalid")
                        return
                    review_item_key = f"auditFinding:{finding_id}"
                    task_index = next((
                        index for index, task in enumerate(tasks)
                        if isinstance(task, dict)
                        and task.get("reviewItemKey") == review_item_key
                        and task.get("workflowType") == "review-rework"
                        and task.get("status") != "Erledigt"
                    ), None)
                    if decision_status in {"nacharbeit_noetig", "abgelehnt"}:
                        missing = str(
                            response_finding.get("customerComment")
                            or "Korrekturmaßnahme oder Wirksamkeitsnachweis fachlich ergänzen."
                        ).strip()
                        task = {
                            "id": tasks[task_index].get("id") if task_index is not None else workspace_item_id("task"),
                            "title": f"Nacharbeit CAPA: {response_finding.get('title') or 'Korrekturmaßnahme'}",
                            "module": "Maßnahmen & CAPA",
                            "owner": str(response_finding.get("owner") or "Kunde / Projektteam"),
                            "due": str(response_finding.get("due") or today_iso(14)),
                            "status": "Offen",
                            "workflowType": "review-rework",
                            "source": "Berater-Rückgabe",
                            "reviewReturnStatus": decision_status,
                            "reviewItemKey": review_item_key,
                            "linkedTo": str(response_finding.get("mapping") or "Audit-Finding / CAPA"),
                            "reworkMissing": missing,
                            "reworkWhy": "Die Korrekturmaßnahme oder ihre Wirksamkeit ist fachlich noch nicht freigegeben.",
                            "reworkAction": "Bitte ergänze die angeforderten Angaben und reiche die CAPA erneut ein.",
                            "reworkReference": str(response_finding.get("title") or "Korrekturmaßnahme"),
                            "note": (
                                f"Was fehlt? {missing}\n"
                                "Warum reicht es noch nicht? Die CAPA ist fachlich noch nicht freigegeben.\n"
                                "Was ist zu tun? Angaben oder Nachweise ergänzen und erneut einreichen.\n"
                                f"Bezug: {response_finding.get('title') or 'Korrekturmaßnahme'}"
                            ),
                        }
                        if task_index is None:
                            tasks.insert(0, task)
                        else:
                            tasks[task_index] = task
                        customer_task = task
                    elif decision_status == "freigegeben" and task_index is not None:
                        tasks[task_index]["status"] = "Erledigt"
                        tasks[task_index]["note"] = "CAPA und Wirksamkeitsprüfung durch Berater/Admin freigegeben."
                        customer_task = tasks[task_index]

            if operation != "delete":
                response_finding["serverUpdatedAt"] = saved_at
                response_finding["serverUpdatedBy"] = user["username"]
                workflow_entry = {
                    "date": saved_date,
                    "dateTime": saved_iso,
                    "action": "Audit-Finding angelegt" if operation == "create" else "Audit-Finding aktualisiert",
                    "by": user["username"],
                    "note": "Änderung über die Audit-Finding-API gespeichert.",
                    "status": str(response_finding.get("status") or "offen"),
                    "changes": changed_fields,
                    "snapshot": {
                        "title": str(response_finding.get("title") or ""),
                        "severity": str(response_finding.get("severity") or ""),
                        "status": str(response_finding.get("status") or ""),
                        "owner": str(response_finding.get("owner") or ""),
                        "due": str(response_finding.get("due") or ""),
                        "mapping": str(response_finding.get("mapping") or ""),
                    },
                }
                existing_workflow = response_finding.get("workflowHistory")
                if not isinstance(existing_workflow, list):
                    existing_workflow = []
                response_finding["workflowHistory"] = [workflow_entry, *existing_workflow][:40]

            try:
                state_json = json.dumps(proposed_state, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                self.send_error_json(400, "audit finding contains unsupported values")
                return
            validation = workspace_state_validation_report(proposed_state, state_json)
            if len(state_json.encode("utf-8")) > MAX_JSON:
                self.send_json({"error": "state too large", "validation": validation}, status=413)
                return
            if not validation["valid"]:
                self.send_json({"error": "workspace state is incomplete", "validation": validation}, status=400)
                return

            snapshot_id = insert_state_snapshot(
                db,
                user["tenant_id"],
                previous["state_json"],
                previous["updated_by"],
                f"before_audit_finding_{operation}",
            )
            new_revision = current_revision + 1
            db.execute(
                "UPDATE tenant_workspace_state SET state_json = ?, updated_at = ?, updated_by = ?, revision = ? WHERE tenant_id = ?",
                (state_json, saved_at, user["id"], new_revision, user["tenant_id"]),
            )
            if submission_only:
                persist_submission_record_ownership(db, user, submission_changes, saved_at)
            else:
                prune_workspace_record_ownership(db, user["tenant_id"], proposed_state)
            event_action = f"audit_finding_{'deleted' if operation == 'delete' else operation + 'd'}"
            audit(db, user, event_action, "audit_finding", finding_id, {
                "changedFields": changed_fields,
                "snapshotId": snapshot_id,
                "previousRevision": current_revision,
                "revision": new_revision,
                "submission": submission_report,
            }, self.client_address[0])

        response = {
            "ok": True,
            "updatedAt": saved_at,
            "updatedBy": user["username"],
            "revision": new_revision,
            "snapshotId": snapshot_id,
            "submission": submission_report,
        }
        if operation == "delete":
            response["deletedId"] = finding_id
        else:
            response["auditFinding"] = response_finding
        response["customerTask"] = customer_task
        self.send_json(response, status=201 if operation == "create" else 200)

    def handle_put_state(self):
        user = self.require_user(permission="saveWorkspace")
        if not user:
            return
        self.handle_workspace_state_write(user, submission_only=False)

    def handle_submit_state(self):
        user = self.require_user(permission="submitWorkspace")
        if not user:
            return
        self.handle_workspace_state_write(user, submission_only=True)

    def handle_workspace_state_write(self, user, submission_only=False):
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        state = payload.get("state")
        if not isinstance(state, dict):
            self.send_error_json(400, "state must be an object")
            return
        has_expected_revision = "expectedRevision" in payload
        expected_revision = payload.get("expectedRevision")
        if expected_revision is not None and (not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0):
            self.send_error_json(400, "expectedRevision must be a non-negative integer or null")
            return
        state_json = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
        validation = workspace_state_validation_report(state, state_json)
        if len(state_json.encode("utf-8")) > MAX_JSON:
            self.send_json({"error": "state too large", "validation": validation}, status=413)
            return
        if not validation["valid"]:
            self.send_json({"error": "workspace state is incomplete", "validation": validation}, status=400)
            return
        saved_at = now()
        with conn() as db:
            DATABASE.begin_workspace_write(db)
            previous = db.execute(
                "SELECT w.state_json, w.updated_at, w.updated_by, w.revision, u.username AS updated_by_username "
                "FROM tenant_workspace_state w LEFT JOIN users u ON u.id = w.updated_by "
                "WHERE w.tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            current_revision = int(previous["revision"] or 1) if previous else 0
            normalized_expected_revision = 0 if expected_revision is None else expected_revision
            if has_expected_revision and normalized_expected_revision != current_revision:
                conflict_action = "state_submission_conflict" if submission_only else "state_save_conflict"
                audit(db, user, conflict_action, "workspace", user["tenant_id"], {
                    "expectedRevision": normalized_expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"] if previous else None,
                    "currentUpdatedBy": previous["updated_by_username"] if previous else None,
                }, self.client_address[0])
                self.send_json({
                    "error": "workspace_conflict",
                    "message": "Workspace wurde zwischenzeitlich geändert.",
                    "expectedRevision": normalized_expected_revision,
                    "currentRevision": current_revision,
                    "currentUpdatedAt": previous["updated_at"] if previous else None,
                    "currentUpdatedBy": previous["updated_by_username"] if previous else None,
                }, status=409)
                return

            submission_report = None
            submission_changes = []
            if submission_only:
                if not previous:
                    self.send_json({
                        "error": "workspace_not_initialized",
                        "message": "Der Workspace muss zuerst durch Berater/Admin angelegt werden.",
                    }, status=409)
                    return
                try:
                    previous_state = json.loads(previous["state_json"])
                except (TypeError, ValueError, json.JSONDecodeError):
                    self.send_error_json(500, "stored workspace state is invalid")
                    return
                submission_report = customer_submission_policy_report(previous_state, state)
                submission_report, submission_changes = contributor_submission_policy_report(
                    db,
                    user,
                    previous_state,
                    state,
                    submission_report,
                )
                if not submission_report["allowed"]:
                    audit(db, user, "state_submission_rejected", "workspace", user["tenant_id"], {
                        "changedSections": submission_report["changedSections"],
                        "violations": submission_report["violations"],
                        "revision": current_revision,
                    }, self.client_address[0])
                    self.send_json({
                        "error": "submission_policy_violation",
                        "message": "Diese Änderung benötigt Berater- oder Adminrechte.",
                        "submission": submission_report,
                    }, status=403)
                    return
            snapshot_id = None
            if previous and previous["state_json"] != state_json:
                snapshot_id = insert_state_snapshot(
                    db,
                    user["tenant_id"],
                    previous["state_json"],
                    previous["updated_by"],
                    "before_customer_submission" if submission_only else "before_state_save",
                )
            new_revision = current_revision + 1
            db.execute(
                "INSERT INTO tenant_workspace_state (tenant_id,state_json,updated_at,updated_by,revision) VALUES (?,?,?,?,?) "
                "ON CONFLICT(tenant_id) DO UPDATE SET state_json=excluded.state_json, updated_at=excluded.updated_at, updated_by=excluded.updated_by, revision=excluded.revision",
                (user["tenant_id"], state_json, saved_at, user["id"], new_revision),
            )
            if submission_only:
                persist_submission_record_ownership(db, user, submission_changes, saved_at)
            else:
                prune_workspace_record_ownership(db, user["tenant_id"], state)
            audit_action = "state_submission_saved" if submission_only else "state_saved"
            audit(db, user, audit_action, "workspace", user["tenant_id"], {
                "bytes": len(state_json),
                "previousBytes": len(previous["state_json"]) if previous else 0,
                "snapshotId": snapshot_id,
                "previousRevision": current_revision,
                "revision": new_revision,
                "validation": {
                    "format": validation["format"],
                    "warnings": len(validation["warnings"]),
                    "unknownTopLevelKeys": len(validation["unknownTopLevelKeys"]),
                    "snapshotRecommended": validation["snapshotRecommended"],
                },
                "submission": submission_report,
            }, self.client_address[0])
        self.send_json({
            "ok": True,
            "updatedAt": saved_at,
            "updatedBy": user["username"],
            "revision": new_revision,
            "validation": validation,
            "submission": submission_report,
        })

    def handle_list_state_snapshots(self):
        user = self.require_admin()
        if not user:
            return
        with conn() as db:
            rows = db.execute(
                "SELECT s.id, s.tenant_id, s.saved_at, s.saved_by, s.reason, s.bytes, s.sha256, s.state_json, u.username "
                "FROM workspace_state_snapshots s LEFT JOIN users u ON u.id = s.saved_by "
                "WHERE s.tenant_id = ? ORDER BY s.id DESC LIMIT 30",
                (user["tenant_id"],),
            ).fetchall()
        snapshots = []
        for row in rows:
            state = None
            try:
                state = json.loads(row["state_json"])
                checksum_valid = hmac.compare_digest(sha(row["state_json"].encode("utf-8")), row["sha256"])
                validation = workspace_state_validation_report(state, row["state_json"])
                restorable = checksum_valid and validation["valid"]
            except Exception:
                checksum_valid = False
                restorable = False
                validation = workspace_state_validation_report(None)
            snapshots.append({
                "id": row["id"],
                "tenantId": row["tenant_id"],
                "savedAt": row["saved_at"],
                "savedBy": row["username"] or "System",
                "reason": row["reason"],
                "bytes": row["bytes"],
                "sha256": row["sha256"],
                "checksumValid": checksum_valid,
                "restorable": restorable,
                "validation": validation,
                "summary": {
                    "documents": len(workspace_list(state, "documents")),
                    "policies": len(workspace_list(state, "policies")),
                    "risks": len(workspace_list(state, "risks")),
                    "tasks": len(workspace_list(state, "tasks")),
                },
            })
        self.send_json({"snapshots": snapshots})

    def handle_create_state_snapshot(self):
        user = self.require_admin(write=True)
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        reason = re.sub(r"\s+", " ", str(payload.get("reason") or "manual_snapshot").strip())[:160]
        with conn() as db:
            current = db.execute(
                "SELECT state_json FROM tenant_workspace_state WHERE tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            if not current:
                self.send_error_json(404, "workspace not found")
                return
            try:
                current_state = json.loads(current["state_json"])
            except json.JSONDecodeError:
                self.send_error_json(409, "workspace is not readable")
                return
            validation = workspace_state_validation_report(current_state, current["state_json"])
            if not validation["valid"]:
                self.send_json({"error": "workspace is incomplete", "validation": validation}, status=409)
                return
            snapshot_id = insert_state_snapshot(
                db,
                user["tenant_id"],
                current["state_json"],
                user["id"],
                reason or "manual_snapshot",
            )
            checksum = sha(current["state_json"].encode("utf-8"))
            audit(db, user, "state_snapshot_created", "workspace", user["tenant_id"], {
                "snapshotId": snapshot_id,
                "reason": reason or "manual_snapshot",
                "bytes": len(current["state_json"].encode("utf-8")),
                "sha256": checksum,
                "validation": {
                    "format": validation["format"],
                    "warnings": len(validation["warnings"]),
                    "unknownTopLevelKeys": len(validation["unknownTopLevelKeys"]),
                },
            }, self.client_address[0])
        self.send_json({
            "ok": True,
            "snapshot": {
                "id": snapshot_id,
                "savedAt": now(),
                "savedBy": user["username"],
                "reason": reason or "manual_snapshot",
                "bytes": len(current["state_json"].encode("utf-8")),
                "sha256": checksum,
                "checksumValid": True,
                "restorable": True,
                "validation": validation,
            },
        })

    def handle_restore_state_snapshot(self):
        user = self.require_user(permission="restoreWorkspace")
        if not user:
            return
        try:
            payload = self.json_body()
            snapshot_id = int(payload.get("snapshotId"))
        except Exception:
            self.send_error_json(400, "invalid snapshot id")
            return
        with conn() as db:
            DATABASE.begin_workspace_write(db)
            snapshot = db.execute(
                "SELECT id, state_json, bytes FROM workspace_state_snapshots WHERE id = ? AND tenant_id = ?",
                (snapshot_id, user["tenant_id"]),
            ).fetchone()
            if not snapshot:
                self.send_error_json(404, "snapshot not found")
                return
            try:
                restored_state = json.loads(snapshot["state_json"])
            except json.JSONDecodeError:
                self.send_error_json(409, "snapshot is not readable")
                return
            validation = workspace_state_validation_report(restored_state, snapshot["state_json"])
            if not validation["valid"]:
                self.send_json({"error": "snapshot is incomplete", "validation": validation}, status=409)
                return
            current = db.execute(
                "SELECT state_json, updated_by, revision FROM tenant_workspace_state WHERE tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()
            current_revision = int(current["revision"] or 1) if current else 0
            new_revision = current_revision + 1
            before_restore_snapshot_id = None
            if current and current["state_json"] != snapshot["state_json"]:
                before_restore_snapshot_id = insert_state_snapshot(
                    db,
                    user["tenant_id"],
                    current["state_json"],
                    current["updated_by"],
                    "before_state_restore",
                )
            restored_at = now()
            db.execute(
                "INSERT INTO tenant_workspace_state (tenant_id,state_json,updated_at,updated_by,revision) VALUES (?,?,?,?,?) "
                "ON CONFLICT(tenant_id) DO UPDATE SET state_json=excluded.state_json, updated_at=excluded.updated_at, updated_by=excluded.updated_by, revision=excluded.revision",
                (user["tenant_id"], snapshot["state_json"], restored_at, user["id"], new_revision),
            )
            audit(db, user, "state_restored", "workspace", user["tenant_id"], {
                "snapshotId": snapshot_id,
                "beforeRestoreSnapshotId": before_restore_snapshot_id,
                "bytes": snapshot["bytes"],
                "previousRevision": current_revision,
                "revision": new_revision,
                "validation": {
                    "format": validation["format"],
                    "warnings": len(validation["warnings"]),
                    "unknownTopLevelKeys": len(validation["unknownTopLevelKeys"]),
                },
            }, self.client_address[0])
        self.send_json({
            "ok": True,
            "state": restored_state,
            "updatedAt": restored_at,
            "updatedBy": user["username"],
            "revision": new_revision,
            "validation": validation,
        })

    def handle_upload(self):
        user = self.require_user(permission="uploadFile")
        if not user:
            return
        content_type = self.headers.get("Content-Type", "")
        try:
            parsed = parse_multipart(self.body(MAX_UPLOAD), content_type)
            files = parsed["files"]
            fields = parsed["fields"]
        except ValueError as exc:
            self.send_error_json(400, str(exc))
            return
        if not files:
            self.send_error_json(400, "no files provided")
            return
        document_ids = metadata_list(fields, "documentIds")
        version_labels = metadata_list(fields, "versionLabels")
        previous_file_ids = metadata_list(fields, "previousFileIds")
        linked_to_values = metadata_list(fields, "linkedToValues")
        classification_values = metadata_list(fields, "classificationValues")
        common_document_id = metadata_value(fields.get("documentId"), 160)
        common_version_label = metadata_value(fields.get("versionLabel"), 80)
        common_previous_file_id = metadata_value(fields.get("previousFileId"), 160)
        common_linked_to = metadata_value(fields.get("linkedTo"), 240)
        common_classification = metadata_value(fields.get("classification"), 80)
        if (common_previous_file_id or any(previous_file_ids)) and not has_permission(user, "versionFile"):
            self.send_error_json(403, "permission required: versionFile")
            return
        for item in files:
            ext = Path(item["filename"]).suffix.lower()
            if ext not in UPLOAD_EXT:
                self.send_error_json(400, f"file type not allowed: {ext or 'without extension'}")
                return
        scan_results = [MALWARE_SCANNER.scan(item["content"]) for item in files]
        blocked_indices = [
            index for index, result in enumerate(scan_results)
            if result.status == "infected" or (result.status == "error" and MALWARE_SCANNER.required)
        ]

        def persist_file(db, index, quarantined=False):
            item = files[index]
            result = scan_results[index]
            name = item["filename"]
            content = item["content"]
            file_id = str(uuid.uuid4())
            document_id = metadata_at(document_ids, index, common_document_id)
            version_label = metadata_at(version_labels, index, common_version_label)
            previous_file_id = metadata_at(previous_file_ids, index, common_previous_file_id)
            linked_to = metadata_at(linked_to_values, index, common_linked_to)
            classification = metadata_at(classification_values, index, common_classification)
            nonce, encrypted = encrypt(content)
            stored_name = f"{file_id}.bin"
            FILE_STORAGE.put(stored_name, encrypted)
            stored_objects.append(stored_name)
            scanned_at = now() if result.status != "unscanned" else None
            meta = {
                "id": file_id,
                "name": name,
                "contentType": item["content_type"],
                "size": len(content),
                "sha256": sha(content),
                "added": now(),
                "uploadedBy": user["username"],
                "documentId": document_id,
                "version": version_label,
                "previousFileId": previous_file_id,
                "linkedTo": linked_to,
                "classification": classification,
                "scanStatus": result.status,
                "scanEngine": result.engine,
                "scannedAt": scanned_at,
                "quarantined": bool(quarantined),
            }
            db.execute(
                "INSERT INTO files (id,tenant_id,original_name,stored_name,content_type,size,sha256,nonce,uploaded_by,uploaded_at,document_id,version_label,previous_file_id,linked_to,classification,scan_status,scan_engine,scan_signature,scan_detail,scanned_at,quarantined) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    file_id, user["tenant_id"], name, stored_name, item["content_type"], len(content), meta["sha256"],
                    b64(nonce), user["id"], meta["added"], document_id, version_label, previous_file_id, linked_to,
                    classification, result.status, result.engine, result.signature, result.detail, scanned_at, 1 if quarantined else 0,
                ),
            )
            audit(db, user, "file_quarantined" if quarantined else "file_uploaded", "file", file_id, {
                "name": name,
                "size": len(content),
                "documentId": document_id,
                "version": version_label,
                "previousFileId": previous_file_id,
                "scanStatus": result.status,
                "scanEngine": result.engine,
                "quarantined": bool(quarantined),
            }, self.client_address[0])
            return meta

        saved = []
        stored_objects = []
        try:
            with conn() as db:
                if blocked_indices:
                    saved = [persist_file(db, index, quarantined=True) for index in blocked_indices]
                else:
                    saved = [persist_file(db, index, quarantined=False) for index in range(len(files))]
        except StorageError as exc:
            for stored_name in stored_objects:
                try:
                    FILE_STORAGE.delete(stored_name)
                except StorageError:
                    pass
            self.send_error_json(503, f"file storage unavailable: {exc}")
            return
        except Exception:
            for stored_name in stored_objects:
                try:
                    FILE_STORAGE.delete(stored_name)
                except StorageError:
                    pass
            raise
        if blocked_indices:
            infected = any(scan_results[index].status == "infected" for index in blocked_indices)
            self.send_json({
                "error": "upload quarantined because a security check failed" if infected else "upload quarantined because the required security scan was unavailable",
                "quarantined": [{"id": item["id"], "name": item["name"], "scanStatus": item["scanStatus"]} for item in saved],
            }, status=422 if infected else 503)
            return
        self.send_json({"files": saved}, status=201)

    def handle_list_files(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            rows = db.execute(
                "SELECT f.id, f.original_name, f.content_type, f.size, f.sha256, f.uploaded_at, f.document_id, f.version_label, f.previous_file_id, f.linked_to, f.classification, f.scan_status, f.scan_engine, f.scanned_at, u.username "
                "FROM files f LEFT JOIN users u ON u.id = f.uploaded_by WHERE f.tenant_id = ? AND f.quarantined = 0 ORDER BY f.uploaded_at DESC",
                (user["tenant_id"],),
            ).fetchall()
        self.send_json({
            "files": [
                {
                    "id": row["id"],
                    "name": row["original_name"],
                    "contentType": row["content_type"],
                    "size": row["size"],
                    "sha256": row["sha256"],
                    "added": row["uploaded_at"],
                    "uploadedBy": row["username"] or "unknown",
                    "documentId": row["document_id"] or "",
                    "version": row["version_label"] or "",
                    "previousFileId": row["previous_file_id"] or "",
                    "linkedTo": row["linked_to"] or "",
                    "classification": row["classification"] or "",
                    "scanStatus": row["scan_status"] or "unscanned",
                    "scanEngine": row["scan_engine"] or "",
                    "scannedAt": row["scanned_at"],
                }
                for row in rows
            ]
        })

    def handle_list_quarantine(self):
        user = self.require_admin()
        if not user:
            return
        with conn() as db:
            if user.get("platform_admin"):
                rows = db.execute(
                    "SELECT f.id,f.tenant_id,f.original_name,f.content_type,f.size,f.sha256,f.uploaded_at,f.scan_status,f.scan_engine,f.scan_signature,f.scan_detail,f.scanned_at,u.username,t.name AS tenant_name "
                    "FROM files f LEFT JOIN users u ON u.id = f.uploaded_by JOIN tenants t ON t.id = f.tenant_id "
                    "WHERE f.quarantined = 1 ORDER BY f.uploaded_at DESC LIMIT 200"
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT f.id,f.tenant_id,f.original_name,f.content_type,f.size,f.sha256,f.uploaded_at,f.scan_status,f.scan_engine,f.scan_signature,f.scan_detail,f.scanned_at,u.username,t.name AS tenant_name "
                    "FROM files f LEFT JOIN users u ON u.id = f.uploaded_by JOIN tenants t ON t.id = f.tenant_id "
                    "WHERE f.quarantined = 1 AND f.tenant_id = ? ORDER BY f.uploaded_at DESC LIMIT 100",
                    (user["tenant_id"],),
                ).fetchall()
        self.send_json({
            "scanner": MALWARE_SCANNER.health(),
            "files": [{
                "id": row["id"],
                "tenantId": row["tenant_id"],
                "tenantName": row["tenant_name"],
                "name": row["original_name"],
                "contentType": row["content_type"],
                "size": row["size"],
                "sha256": row["sha256"],
                "uploadedAt": row["uploaded_at"],
                "uploadedBy": row["username"] or "unknown",
                "scanStatus": row["scan_status"],
                "scanEngine": row["scan_engine"] or "",
                "signature": row["scan_signature"] or "",
                "detail": row["scan_detail"] or "",
                "scannedAt": row["scanned_at"],
            } for row in rows],
        })

    def handle_rescan_quarantined_file(self, file_id):
        user = self.require_admin(write=True)
        if not user:
            return
        try:
            result = rescan_quarantined_file(user, urllib.parse.unquote(file_id), ip=self.client_address[0])
        except FileNotFoundError:
            self.send_error_json(404, "quarantined file not found")
            return
        except RuntimeError:
            self.send_error_json(500, "quarantined file could not be decrypted")
            return
        self.send_json({"ok": True, "released": result["released"], "scanStatus": result["scanStatus"]})

    def handle_queue_quarantined_file_rescan(self, file_id):
        user = self.require_admin(write=True)
        if not user:
            return
        file_id = urllib.parse.unquote(file_id)
        with conn() as db:
            tenant_clause = "" if user.get("platform_admin") else " AND tenant_id = ?"
            params = (file_id,) if user.get("platform_admin") else (file_id, user["tenant_id"])
            row = db.execute(
                f"SELECT id,original_name,tenant_id FROM files WHERE id = ? AND quarantined = 1{tenant_clause}",
                params,
            ).fetchone()
            if not row:
                self.send_error_json(404, "quarantined file not found")
                return
            job_id = enqueue_background_job(
                db,
                "quarantine_rescan",
                user,
                payload={"fileId": file_id, "tenantId": row["tenant_id"], "name": row["original_name"]},
                priority=90,
            )
            result = background_jobs_payload(db) if user.get("platform_admin") else {"queuedId": job_id}
        result["queuedId"] = job_id
        self.send_json(result, status=202)

    def handle_delete_quarantined_file(self, file_id):
        user = self.require_admin(write=True)
        if not user:
            return
        with conn() as db:
            tenant_clause = "" if user.get("platform_admin") else " AND tenant_id = ?"
            params = (file_id,) if user.get("platform_admin") else (file_id, user["tenant_id"])
            row = db.execute(
                f"SELECT id,tenant_id,stored_name,original_name,scan_status FROM files WHERE id = ? AND quarantined = 1{tenant_clause}",
                params,
            ).fetchone()
            if not row:
                self.send_error_json(404, "quarantined file not found")
                return
            db.execute("DELETE FROM files WHERE id = ?", (file_id,))
            audit(db, user, "file_quarantine_deleted", "file", file_id, {
                "name": row["original_name"],
                "tenantId": row["tenant_id"],
                "scanStatus": row["scan_status"],
            }, self.client_address[0])
        try:
            FILE_STORAGE.delete(row["stored_name"])
        except StorageError:
            self.send_error_json(503, "quarantine metadata deleted but encrypted object cleanup failed")
            return
        self.send_json({"ok": True})

    def handle_download_file(self, file_id):
        user = self.require_user(permission="downloadFile")
        if not user:
            return
        with conn() as db:
            row = db.execute("SELECT * FROM files WHERE id = ? AND tenant_id = ?", (file_id, user["tenant_id"])).fetchone()
            if not row:
                self.send_error_json(404, "file not found")
                return
            if row["quarantined"]:
                self.send_error_json(423, "file is quarantined and cannot be downloaded")
                return
            try:
                content = decrypt(unb64(row["nonce"]), FILE_STORAGE.get(row["stored_name"]))
            except Exception:
                self.send_error_json(500, "file could not be decrypted")
                return
            audit(db, user, "file_downloaded", "file", file_id, {"name": row["original_name"]}, self.client_address[0])
        disposition = f"attachment; filename=\"{safe_filename(row['original_name'])}\""
        self.send_response(200)
        self.send_header("Content-Type", row["content_type"])
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Content-Disposition", disposition)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def handle_list_tenants(self):
        user = self.require_user()
        if not user:
            return
        with conn() as db:
            if user.get("platform_admin"):
                rows = db.execute(
                    "SELECT id, name, slug, status, created_at, updated_at FROM tenants ORDER BY name"
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT id, name, slug, status, created_at, updated_at FROM tenants WHERE id = ?",
                    (user["tenant_id"],),
                ).fetchall()
        self.send_json({
            "tenants": [
                {
                    "id": row["id"],
                    "name": row["name"],
                    "slug": row["slug"],
                    "status": row["status"],
                    "createdAt": row["created_at"],
                    "updatedAt": row["updated_at"],
                }
                for row in rows
            ]
        })

    def handle_tenant_overview(self):
        user = self.require_admin()
        if not user:
            return
        with conn() as db:
            if user.get("platform_admin"):
                tenant_rows = db.execute(
                    "SELECT t.id, t.name, t.slug, t.status, t.created_at, t.updated_at, "
                    "s.state_json, s.updated_at AS state_updated_at "
                    "FROM tenants t LEFT JOIN tenant_workspace_state s ON s.tenant_id = t.id "
                    "ORDER BY t.name"
                ).fetchall()
            else:
                tenant_rows = db.execute(
                    "SELECT t.id, t.name, t.slug, t.status, t.created_at, t.updated_at, "
                    "s.state_json, s.updated_at AS state_updated_at "
                    "FROM tenants t LEFT JOIN tenant_workspace_state s ON s.tenant_id = t.id "
                    "WHERE t.id = ? ORDER BY t.name",
                    (user["tenant_id"],),
                ).fetchall()

            overviews = []
            for row in tenant_rows:
                tenant_id = row["id"]
                try:
                    state = json.loads(row["state_json"] or "{}")
                except Exception:
                    state = {}
                metrics = workspace_overview_metrics(state)
                user_stats = db.execute(
                    "SELECT COUNT(*) AS users, "
                    "SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) AS active_users, "
                    "SUM(CASE WHEN active = 1 AND mfa_enabled = 1 THEN 1 ELSE 0 END) AS mfa_users, "
                    "SUM(CASE WHEN active = 1 AND role = 'admin' THEN 1 ELSE 0 END) AS admin_users, "
                    "SUM(CASE WHEN active = 1 AND role IN ('admin','consultant','manager') THEN 1 ELSE 0 END) AS privileged_users, "
                    "SUM(CASE WHEN active = 1 AND role IN ('admin','consultant','manager') AND mfa_enabled = 1 THEN 1 ELSE 0 END) AS privileged_mfa_users, "
                    "MAX(last_login_at) AS last_login_at "
                    "FROM users WHERE tenant_id = ?",
                    (tenant_id,),
                ).fetchone()
                file_stats = db.execute(
                    "SELECT COUNT(*) AS files, MAX(uploaded_at) AS last_file_at FROM files WHERE tenant_id = ? AND quarantined = 0",
                    (tenant_id,),
                ).fetchone()
                invitation_stats = db.execute(
                    "SELECT COUNT(*) AS pending_invitations, "
                    "SUM(CASE WHEN created_at < ? THEN 1 ELSE 0 END) AS stale_invitations "
                    "FROM invitations WHERE tenant_id = ? AND status = 'pending' AND expires_at > ?",
                    (now() - 7 * 86400, tenant_id, now()),
                ).fetchone()
                session_stats = db.execute(
                    "SELECT "
                    "SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END) AS active_sessions, "
                    "SUM(CASE WHEN expires_at <= ? THEN 1 ELSE 0 END) AS expired_sessions "
                    "FROM sessions WHERE tenant_id = ?",
                    (now(), now(), tenant_id),
                ).fetchone()
                snapshot_stats = db.execute(
                    "SELECT COUNT(*) AS snapshots, MAX(saved_at) AS last_snapshot_at FROM workspace_state_snapshots WHERE tenant_id = ?",
                    (tenant_id,),
                ).fetchone()
                audit_stats = db.execute(
                    "SELECT MAX(ts) AS last_audit_at FROM audit_log WHERE tenant_id = ?",
                    (tenant_id,),
                ).fetchone()
                last_activity = max(
                    row["state_updated_at"] or 0,
                    user_stats["last_login_at"] or 0,
                    file_stats["last_file_at"] or 0,
                    audit_stats["last_audit_at"] or 0,
                ) or None
                recommendations = tenant_recommendations(
                    metrics,
                    active_users=user_stats["active_users"] or 0,
                    mfa_users=user_stats["mfa_users"] or 0,
                    files=file_stats["files"] or 0,
                    last_activity_at=last_activity,
                )
                security = tenant_security_checks(
                    metrics,
                    active_users=user_stats["active_users"] or 0,
                    admin_users=user_stats["admin_users"] or 0,
                    privileged_users=user_stats["privileged_users"] or 0,
                    privileged_mfa_users=user_stats["privileged_mfa_users"] or 0,
                    files=file_stats["files"] or 0,
                    pending_invitations=invitation_stats["pending_invitations"] or 0,
                    stale_invitations=invitation_stats["stale_invitations"] or 0,
                    active_sessions=session_stats["active_sessions"] or 0,
                    expired_sessions=session_stats["expired_sessions"] or 0,
                    snapshots=snapshot_stats["snapshots"] or 0,
                    last_snapshot_at=snapshot_stats["last_snapshot_at"],
                    last_activity_at=last_activity,
                    state_updated_at=row["state_updated_at"],
                )
                overviews.append({
                    "id": tenant_id,
                    "name": row["name"],
                    "slug": row["slug"],
                    "status": row["status"],
                    "createdAt": row["created_at"],
                    "updatedAt": row["updated_at"],
                    "stateUpdatedAt": row["state_updated_at"],
                    "lastLoginAt": user_stats["last_login_at"],
                    "lastFileAt": file_stats["last_file_at"],
                    "lastAuditAt": audit_stats["last_audit_at"],
                    "lastActivityAt": last_activity,
                    "users": user_stats["users"] or 0,
                    "activeUsers": user_stats["active_users"] or 0,
                    "mfaUsers": user_stats["mfa_users"] or 0,
                    "adminUsers": user_stats["admin_users"] or 0,
                    "privilegedUsers": user_stats["privileged_users"] or 0,
                    "privilegedMfaUsers": user_stats["privileged_mfa_users"] or 0,
                    "files": file_stats["files"] or 0,
                    "pendingInvitations": invitation_stats["pending_invitations"] or 0,
                    "staleInvitations": invitation_stats["stale_invitations"] or 0,
                    "activeSessions": session_stats["active_sessions"] or 0,
                    "expiredSessions": session_stats["expired_sessions"] or 0,
                    "snapshots": snapshot_stats["snapshots"] or 0,
                    "lastSnapshotAt": snapshot_stats["last_snapshot_at"],
                    "securityChecks": security["checks"],
                    "securityProblemCount": security["problemCount"],
                    "securityBlockerCount": security["blockerCount"],
                    "securityStatus": security["status"],
                    "securityLabel": security["label"],
                    "recommendations": recommendations,
                    **metrics,
                })
        self.send_json({"tenants": overviews, "activeTenantId": user["tenant_id"]})

    def handle_tenant_lifecycle(self):
        user = self.require_platform_admin()
        if not user:
            return
        with conn() as db:
            rows = db.execute(
                "SELECT id,name,slug,status,created_at,updated_at,retention_until,legal_hold,lifecycle_note,archived_at "
                "FROM tenants ORDER BY name"
            ).fetchall()
            tenants = [tenant_lifecycle_summary(db, row, user) for row in rows]
        self.send_json({
            "tenants": tenants,
            "summary": {
                "active": sum(1 for row in tenants if row["status"] == "active"),
                "paused": sum(1 for row in tenants if row["status"] == "paused"),
                "archived": sum(1 for row in tenants if row["status"] == "archived"),
                "legalHolds": sum(1 for row in tenants if row["legalHold"]),
                "purgeEligible": sum(1 for row in tenants if row["purgeEligible"]),
            },
        })

    def handle_export_tenant(self, tenant_id):
        user = self.require_admin(write=True)
        if not user:
            return
        if not user.get("platform_admin") and tenant_id != user.get("tenant_id"):
            self.send_error_json(403, "tenant export is limited to the active tenant")
            return

        with conn() as db:
            tenant = db.execute(
                "SELECT id,name,slug,status,created_at,updated_at,retention_until,legal_hold,lifecycle_note,archived_at "
                "FROM tenants WHERE id = ?",
                (tenant_id,),
            ).fetchone()
            if not tenant:
                self.send_error_json(404, "tenant not found")
                return

            workspace = db.execute(
                "SELECT state_json,updated_at,updated_by FROM tenant_workspace_state WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
            snapshots = db.execute(
                "SELECT id,state_json,saved_at,saved_by,reason,bytes,sha256 FROM workspace_state_snapshots "
                "WHERE tenant_id = ? ORDER BY id DESC",
                (tenant_id,),
            ).fetchall()
            users = db.execute(
                "SELECT id,username,email,role,active,mfa_enabled,created_at,updated_at,last_login_at,platform_admin "
                "FROM users WHERE tenant_id = ? ORDER BY username",
                (tenant_id,),
            ).fetchall()
            oidc_identities = db.execute(
                "SELECT oi.provider_id,oi.subject,oi.user_id,oi.email,oi.created_at,oi.last_login_at "
                "FROM oidc_identities oi JOIN users u ON u.id = oi.user_id "
                "WHERE u.tenant_id = ? ORDER BY oi.provider_id,oi.user_id",
                (tenant_id,),
            ).fetchall()
            invitations = db.execute(
                "SELECT i.id,i.email,i.display_name,i.role,i.status,i.created_at,i.expires_at,i.accepted_at,"
                "i.accepted_user_id,i.revoked_at,u.username AS invited_by_username "
                "FROM invitations i LEFT JOIN users u ON u.id = i.invited_by "
                "WHERE i.tenant_id = ? ORDER BY i.created_at DESC",
                (tenant_id,),
            ).fetchall()
            files = db.execute(
                "SELECT f.id,f.original_name,f.stored_name,f.content_type,f.size,f.sha256,f.nonce,f.uploaded_at,"
                "f.document_id,f.version_label,f.previous_file_id,f.linked_to,f.classification,u.username AS uploaded_by_username "
                "FROM files f LEFT JOIN users u ON u.id = f.uploaded_by "
                "WHERE f.tenant_id = ? AND f.quarantined = 0 ORDER BY f.uploaded_at,f.id",
                (tenant_id,),
            ).fetchall()
            audit_rows = db.execute(
                "SELECT id,ts,username,action,target_type,target_id,detail_json,ip "
                "FROM audit_log WHERE tenant_id = ? ORDER BY id",
                (tenant_id,),
            ).fetchall()
            notification_rows = db.execute(
                "SELECT user_id,notification_id,read_at,dismissed_at,escalated_at,updated_at "
                "FROM notification_states WHERE tenant_id = ? ORDER BY user_id,updated_at DESC",
                (tenant_id,),
            ).fetchall()
            notification_delivery_rows = db.execute(
                "SELECT d.id,d.notification_id,d.channel,d.destination_label,d.payload_json,d.status,d.attempt_count,"
                "d.next_attempt_at,d.created_at,d.last_attempt_at,d.sent_at,d.last_error,d.response_code,"
                "u.username AS created_by_username FROM notification_deliveries d LEFT JOIN users u ON u.id=d.created_by "
                "WHERE d.tenant_id = ? ORDER BY d.created_at,d.id",
                (tenant_id,),
            ).fetchall()

            estimated_bytes = sum(int(row["size"] or 0) for row in files)
            estimated_bytes += len(workspace["state_json"].encode("utf-8")) if workspace else 0
            estimated_bytes += sum(len(row["state_json"].encode("utf-8")) for row in snapshots)
            estimated_bytes += sum(len(row["payload_json"].encode("utf-8")) for row in notification_delivery_rows)
            if estimated_bytes > MAX_TENANT_EXPORT:
                self.send_json({
                    "error": "tenant export exceeds configured size limit",
                    "estimatedBytes": estimated_bytes,
                    "limitBytes": MAX_TENANT_EXPORT,
                }, status=413)
                return

            export_files = []
            decrypted_files = []
            for row in files:
                try:
                    blob_exists = FILE_STORAGE.exists(row["stored_name"])
                except StorageError:
                    blob_exists = False
                if not blob_exists:
                    self.send_json({
                        "error": "tenant export blocked because a file blob is missing",
                        "fileId": row["id"],
                        "name": row["original_name"],
                    }, status=409)
                    return
                try:
                    content = decrypt(unb64(row["nonce"]), FILE_STORAGE.get(row["stored_name"]))
                except Exception:
                    self.send_json({
                        "error": "tenant export blocked because a file failed integrity verification",
                        "fileId": row["id"],
                        "name": row["original_name"],
                    }, status=409)
                    return
                if sha(content) != row["sha256"]:
                    self.send_json({
                        "error": "tenant export blocked because a file checksum does not match",
                        "fileId": row["id"],
                        "name": row["original_name"],
                    }, status=409)
                    return
                archive_name = f"files/{row['id'][:12]}-{safe_filename(row['original_name'])}"
                decrypted_files.append((archive_name, content))
                export_files.append({
                    "id": row["id"],
                    "name": row["original_name"],
                    "archivePath": archive_name,
                    "contentType": row["content_type"],
                    "size": row["size"],
                    "sha256": row["sha256"],
                    "uploadedAt": row["uploaded_at"],
                    "uploadedBy": row["uploaded_by_username"] or "unknown",
                    "documentId": row["document_id"] or "",
                    "version": row["version_label"] or "",
                    "previousFileId": row["previous_file_id"] or "",
                    "linkedTo": row["linked_to"] or "",
                    "classification": row["classification"] or "",
                })

            exported_at = now()
            tenant_public = {
                "id": tenant["id"],
                "name": tenant["name"],
                "slug": tenant["slug"],
                "status": tenant["status"],
                "createdAt": tenant["created_at"],
                "updatedAt": tenant["updated_at"],
                "archivedAt": tenant["archived_at"],
                "retentionUntil": tenant["retention_until"],
                "legalHold": bool(tenant["legal_hold"]),
                "lifecycleNote": tenant["lifecycle_note"] or "",
            }
            user_rows = [{
                "id": row["id"],
                "username": row["username"],
                "email": row["email"] or "",
                "role": row["role"],
                "active": bool(row["active"]),
                "mfaEnabled": bool(row["mfa_enabled"]),
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
                "lastLoginAt": row["last_login_at"],
                "platformAdmin": bool(row["platform_admin"]),
            } for row in users]
            oidc_identity_rows = [{
                "providerId": row["provider_id"],
                "subject": row["subject"],
                "userId": row["user_id"],
                "email": row["email"] or "",
                "createdAt": row["created_at"],
                "lastLoginAt": row["last_login_at"],
            } for row in oidc_identities]
            invitation_rows = [{
                "id": row["id"],
                "email": row["email"],
                "displayName": row["display_name"] or "",
                "role": row["role"],
                "status": row["status"],
                "createdAt": row["created_at"],
                "expiresAt": row["expires_at"],
                "acceptedAt": row["accepted_at"],
                "acceptedUserId": row["accepted_user_id"],
                "revokedAt": row["revoked_at"],
                "invitedBy": row["invited_by_username"] or "",
            } for row in invitations]
            notification_state_rows = [{
                "userId": row["user_id"],
                "notificationId": row["notification_id"],
                "readAt": row["read_at"],
                "dismissedAt": row["dismissed_at"],
                "escalatedAt": row["escalated_at"],
                "updatedAt": row["updated_at"],
            } for row in notification_rows]
            notification_delivery_export_rows = []
            for row in notification_delivery_rows:
                try:
                    delivery_payload = json.loads(row["payload_json"] or "{}")
                except Exception:
                    delivery_payload = {"invalidPayload": True}
                notification_delivery_export_rows.append({
                    "id": row["id"],
                    "notificationId": row["notification_id"],
                    "channel": row["channel"],
                    "destinationLabel": row["destination_label"],
                    "payload": delivery_payload,
                    "status": row["status"],
                    "attemptCount": row["attempt_count"],
                    "nextAttemptAt": row["next_attempt_at"],
                    "createdAt": row["created_at"],
                    "createdBy": row["created_by_username"] or "",
                    "lastAttemptAt": row["last_attempt_at"],
                    "sentAt": row["sent_at"],
                    "lastError": row["last_error"] or "",
                    "responseCode": row["response_code"],
                })
            audit_events = []
            for row in audit_rows:
                try:
                    detail = json.loads(row["detail_json"] or "{}")
                except Exception:
                    detail = {"raw": row["detail_json"] or ""}
                audit_events.append({
                    "id": row["id"],
                    "ts": row["ts"],
                    "username": row["username"],
                    "action": row["action"],
                    "targetType": row["target_type"],
                    "targetId": row["target_id"],
                    "detail": detail,
                    "ip": row["ip"],
                })
            snapshot_index = [{
                "id": row["id"],
                "archivePath": f"workspace/snapshots/{row['id']}.json",
                "savedAt": row["saved_at"],
                "savedBy": row["saved_by"],
                "reason": row["reason"],
                "bytes": row["bytes"],
                "sha256": row["sha256"],
            } for row in snapshots]
            manifest = {
                "format": "sfm-compliance-tenant-export-v1",
                "exportedAt": exported_at,
                "exportedBy": user["username"],
                "tenant": tenant_public,
                "counts": {
                    "users": len(user_rows),
                    "ssoIdentities": len(oidc_identity_rows),
                    "invitations": len(invitation_rows),
                    "files": len(export_files),
                    "snapshots": len(snapshot_index),
                    "auditEvents": len(audit_events),
                    "notificationStates": len(notification_state_rows),
                    "notificationDeliveries": len(notification_delivery_export_rows),
                    "workspace": 1 if workspace else 0,
                },
                "included": [
                    "Aktueller Workspace und Register",
                    "Workspace-Snapshots",
                    "Nachweisdateien mit Metadaten und SHA-256",
                    "Benutzer ohne Passwoerter oder MFA-Secrets",
                    "Einladungsstatus ohne Einladungstoken",
                    "Persoenliche Benachrichtigungszustaende",
                    "Kontrollierte Benachrichtigungs-Zustellhistorie",
                    "Mandantenbezogener Audit Trail",
                ],
                "excluded": [
                    "Passwort-Hashes und MFA-Secrets",
                    "Sessions, Cookies und CSRF-Token",
                    "System- und Backup-Schluessel",
                    "Globale System-Backups",
                ],
            }

            buffer = io.BytesIO()
            try:
                with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                    archive.writestr("README.txt", (
                        "SFM Compliance Mandantenexport\n\n"
                        "Der Export enthaelt den Kundenraum und seine Nachweise zum angegebenen Exportzeitpunkt.\n"
                        "Er enthaelt keine Passwoerter, Sessions, MFA-Secrets, CSRF-Token oder Systemschluessel.\n"
                        "Die fachliche Bewertung und Auditbereitschaft bleiben beim Berater/Admin.\n"
                    ))
                    archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
                    archive.writestr("tenant.json", json.dumps(tenant_public, ensure_ascii=False, indent=2))
                    archive.writestr("records/users.json", json.dumps(user_rows, ensure_ascii=False, indent=2))
                    archive.writestr("records/sso-identities.json", json.dumps(oidc_identity_rows, ensure_ascii=False, indent=2))
                    archive.writestr("records/invitations.json", json.dumps(invitation_rows, ensure_ascii=False, indent=2))
                    archive.writestr("records/notification-states.json", json.dumps(notification_state_rows, ensure_ascii=False, indent=2))
                    archive.writestr("records/notification-deliveries.json", json.dumps(notification_delivery_export_rows, ensure_ascii=False, indent=2))
                    archive.writestr("records/audit-log.json", json.dumps(audit_events, ensure_ascii=False, indent=2))
                    archive.writestr("files/index.json", json.dumps(export_files, ensure_ascii=False, indent=2))
                    archive.writestr("workspace/snapshots/index.json", json.dumps(snapshot_index, ensure_ascii=False, indent=2))
                    if workspace:
                        archive.writestr("workspace/current.json", workspace["state_json"])
                    for row in snapshots:
                        archive.writestr(f"workspace/snapshots/{row['id']}.json", row["state_json"])
                    for archive_name, content in decrypted_files:
                        archive.writestr(archive_name, content)
            except Exception:
                self.send_error_json(500, "tenant export could not be created")
                return

            content = buffer.getvalue()
            target_user = dict(user)
            target_user["tenant_id"] = tenant_id
            audit(db, target_user, "tenant_exported", "tenant", tenant_id, {
                "name": tenant["name"],
                "slug": tenant["slug"],
                "bytes": len(content),
                "counts": manifest["counts"],
                "format": manifest["format"],
            }, self.client_address[0])

        stamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"sfm-compliance-{safe_filename(tenant['slug'])}-{stamp}.zip"
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def handle_queue_tenant_export_preflight(self, tenant_id):
        user = self.require_admin(write=True)
        if not user:
            return
        tenant_id = urllib.parse.unquote(tenant_id)
        if not user.get("platform_admin") and tenant_id != user.get("tenant_id"):
            self.send_error_json(403, "tenant export is limited to the active tenant")
            return
        with conn() as db:
            tenant = db.execute(
                "SELECT id,name FROM tenants WHERE id = ?",
                (tenant_id,),
            ).fetchone()
            if not tenant:
                self.send_error_json(404, "tenant not found")
                return
            job_id = enqueue_background_job(
                db,
                "tenant_export_preflight",
                user,
                payload={"tenantId": tenant_id, "tenantName": tenant["name"]},
                priority=70,
            )
            result = background_jobs_payload(db) if user.get("platform_admin") else {"queuedId": job_id}
        result["queuedId"] = job_id
        self.send_json(result, status=202)

    def handle_queue_tenant_export_artifact(self, tenant_id):
        user = self.require_admin(write=True)
        if not user:
            return
        tenant_id = urllib.parse.unquote(tenant_id)
        if not user.get("platform_admin") and tenant_id != user.get("tenant_id"):
            self.send_error_json(403, "tenant export is limited to the active tenant")
            return
        with conn() as db:
            tenant = db.execute(
                "SELECT id,name FROM tenants WHERE id = ?",
                (tenant_id,),
            ).fetchone()
            if not tenant:
                self.send_error_json(404, "tenant not found")
                return
            job_id = enqueue_background_job(
                db,
                "tenant_export_create",
                user,
                payload={"tenantId": tenant_id, "tenantName": tenant["name"]},
                priority=75,
                max_attempts=1,
            )
            result = background_jobs_payload(db) if user.get("platform_admin") else {"queuedId": job_id}
        result["queuedId"] = job_id
        self.send_json(result, status=202)

    def handle_purge_tenant(self, tenant_id):
        user = self.require_platform_admin(write=True)
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        confirm_slug = str(payload.get("confirmSlug") or "").strip()
        with conn() as db:
            tenant = db.execute(
                "SELECT id,name,slug,status,created_at,updated_at,retention_until,legal_hold,lifecycle_note,archived_at "
                "FROM tenants WHERE id = ?",
                (tenant_id,),
            ).fetchone()
            if not tenant:
                self.send_error_json(404, "tenant not found")
                return
            lifecycle = tenant_lifecycle_summary(db, tenant, user)
            if confirm_slug != tenant["slug"]:
                self.send_error_json(400, "exact tenant slug confirmation required")
                return
            if not lifecycle["purgeEligible"]:
                self.send_json({"error": "tenant purge blocked", "blockers": lifecycle["purgeBlockers"]}, status=409)
                return
            file_rows = db.execute("SELECT stored_name FROM files WHERE tenant_id = ?", (tenant_id,)).fetchall()
            counts = lifecycle["counts"]
            db.execute("DELETE FROM sessions WHERE tenant_id = ?", (tenant_id,))
            db.execute("DELETE FROM invitations WHERE tenant_id = ?", (tenant_id,))
            db.execute("DELETE FROM workspace_state_snapshots WHERE tenant_id = ?", (tenant_id,))
            db.execute("DELETE FROM tenant_workspace_state WHERE tenant_id = ?", (tenant_id,))
            db.execute("DELETE FROM files WHERE tenant_id = ?", (tenant_id,))
            db.execute("DELETE FROM notification_states WHERE tenant_id = ?", (tenant_id,))
            db.execute("DELETE FROM notification_deliveries WHERE tenant_id = ?", (tenant_id,))
            db.execute("DELETE FROM oidc_identities WHERE user_id IN (SELECT id FROM users WHERE tenant_id = ?)", (tenant_id,))
            db.execute("DELETE FROM password_history WHERE user_id IN (SELECT id FROM users WHERE tenant_id = ?)", (tenant_id,))
            db.execute("DELETE FROM users WHERE tenant_id = ?", (tenant_id,))
            db.execute("DELETE FROM audit_log WHERE tenant_id = ?", (tenant_id,))
            db.execute("DELETE FROM tenants WHERE id = ?", (tenant_id,))
            audit(db, user, "tenant_purged", "tenant", tenant_id, {
                "name": tenant["name"],
                "slug": tenant["slug"],
                "counts": counts,
                "fileBytes": lifecycle["fileBytes"],
                "confirmedBySlug": True,
            }, self.client_address[0])
        deleted_blobs = 0
        for row in file_rows:
            try:
                if FILE_STORAGE.delete(row["stored_name"]):
                    deleted_blobs += 1
            except StorageError:
                pass
        self.send_json({"ok": True, "tenantId": tenant_id, "deletedBlobs": deleted_blobs, "counts": counts})

    def handle_create_tenant(self):
        user = self.require_platform_admin(write=True)
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        name = str(payload.get("name") or "").strip()
        slug = tenant_slug(payload.get("slug") or name)
        admin_username = str(payload.get("adminUsername") or "").strip()
        admin_password = str(payload.get("adminPassword") or "")
        if len(name) < 2:
            self.send_error_json(400, "tenant name required")
            return
        if admin_password and not admin_username:
            self.send_error_json(400, "admin username required when admin password is set")
            return
        if admin_username:
            if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", admin_username):
                self.send_error_json(400, "admin username must be 3-64 characters and use letters, numbers, dot, dash or underscore")
                return
            policy_error = password_policy_error(admin_password, admin_username)
            if policy_error:
                self.send_password_policy_error(policy_error)
                return
        tenant_id = str(uuid.uuid4())
        starter_state = create_starter_workspace_state(name, admin_username)
        starter_summary = starter_workspace_summary(starter_state)
        starter_json = json.dumps(starter_state, ensure_ascii=False, separators=(",", ":"))
        try:
            with conn() as db:
                db.execute(
                    "INSERT INTO tenants (id,name,slug,status,created_at,updated_at) VALUES (?,?,?,?,?,?)",
                    (tenant_id, name, slug, "active", now(), now()),
                )
                db.execute(
                    "INSERT INTO tenant_workspace_state (tenant_id,state_json,updated_at,updated_by) VALUES (?,?,?,?)",
                    (tenant_id, starter_json, now(), user["id"]),
                )
                admin_created = False
                if admin_username:
                    db.execute(
                        "INSERT INTO users (username,password_hash,role,created_at,active,updated_at,tenant_id,platform_admin,password_change_required) VALUES (?,?,?,?,1,?,?,0,1)",
                        (admin_username, password_hash(admin_password), "admin", now(), now(), tenant_id),
                    )
                    admin_created = True
                audit(db, user, "tenant_created", "tenant", tenant_id, {
                    "name": name,
                    "slug": slug,
                    "adminCreated": admin_created,
                    "starterSummary": starter_summary,
                }, self.client_address[0])
        except DATABASE.integrity_errors:
            self.send_error_json(409, "tenant slug or admin username already exists")
            return
        self.send_json({
            "ok": True,
            "tenant": {
                "id": tenant_id,
                "name": name,
                "slug": slug,
                "status": "active",
                "adminCreated": bool(admin_username),
                "adminUsername": admin_username if admin_created else "",
                "createdAt": now(),
                "starterSummary": starter_summary,
            },
        }, status=201)

    def handle_update_tenant(self, tenant_id):
        user = self.require_platform_admin(write=True)
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        name = payload.get("name")
        status = payload.get("status")
        legal_hold = payload.get("legalHold") if "legalHold" in payload else None
        retention_input = payload.get("retentionUntil") if "retentionUntil" in payload else None
        lifecycle_note = payload.get("lifecycleNote") if "lifecycleNote" in payload else None
        updates = []
        params = []
        detail = {}
        if name is not None:
            name = str(name).strip()
            if len(name) < 2:
                self.send_error_json(400, "tenant name required")
                return
            updates.append("name = ?")
            params.append(name)
            detail["name"] = name
        if status is not None:
            status = str(status).strip()
            if status not in {"active", "paused", "archived"}:
                self.send_error_json(400, "invalid tenant status")
                return
            if tenant_id == DEFAULT_TENANT_ID and status != "active":
                self.send_error_json(400, "default tenant must remain active")
                return
            if tenant_id == user.get("tenant_id") and status != "active":
                self.send_error_json(409, "switch to another tenant before pausing or archiving this tenant")
                return
            updates.append("status = ?")
            params.append(status)
            detail["status"] = status
            if status == "archived":
                updates.append("archived_at = COALESCE(archived_at, ?)")
                params.append(now())
            elif status == "active":
                updates.append("archived_at = NULL")
        if legal_hold is not None:
            legal_hold = bool(legal_hold)
            updates.append("legal_hold = ?")
            params.append(1 if legal_hold else 0)
            detail["legalHold"] = legal_hold
        if retention_input is not None:
            retention_text = str(retention_input or "").strip()
            retention_until = parse_iso_date_epoch(retention_text)
            if retention_text and retention_until is None:
                self.send_error_json(400, "retentionUntil must use YYYY-MM-DD")
                return
            updates.append("retention_until = ?")
            params.append(retention_until)
            detail["retentionUntil"] = retention_text
        if lifecycle_note is not None:
            lifecycle_note = re.sub(r"\s+", " ", str(lifecycle_note or "").strip())[:500]
            updates.append("lifecycle_note = ?")
            params.append(lifecycle_note)
            detail["lifecycleNote"] = lifecycle_note
        if not updates:
            self.send_json({"ok": True})
            return
        updates.append("updated_at = ?")
        params.extend([now(), tenant_id])
        with conn() as db:
            row = db.execute("SELECT id,status FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
            if not row:
                self.send_error_json(404, "tenant not found")
                return
            db.execute(f"UPDATE tenants SET {', '.join(updates)} WHERE id = ?", params)
            if status and status != "active":
                db.execute("DELETE FROM sessions WHERE tenant_id = ?", (tenant_id,))
            audit(db, user, "tenant_updated", "tenant", tenant_id, detail, self.client_address[0])
        self.send_json({"ok": True})

    def handle_security_status(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            tenant_filter = "" if user.get("platform_admin") else "WHERE tenant_id = ?"
            tenant_params = () if user.get("platform_admin") else (user["tenant_id"],)
            tenant_count = db.execute("SELECT COUNT(*) FROM tenants").fetchone()[0] if user.get("platform_admin") else 1
            counts = {
                "tenants": tenant_count,
                "users": db.execute(f"SELECT COUNT(*) FROM users {tenant_filter}", tenant_params).fetchone()[0],
                "activeUsers": db.execute(f"SELECT COUNT(*) FROM users {tenant_filter + (' AND active = 1' if tenant_filter else 'WHERE active = 1')}", tenant_params).fetchone()[0],
                "mfaUsers": db.execute(f"SELECT COUNT(*) FROM users {tenant_filter + (' AND active = 1 AND mfa_enabled = 1' if tenant_filter else 'WHERE active = 1 AND mfa_enabled = 1')}", tenant_params).fetchone()[0],
                "files": db.execute("SELECT COUNT(*) FROM files WHERE tenant_id = ? AND quarantined = 0", (user["tenant_id"],)).fetchone()[0],
                "quarantinedFiles": db.execute("SELECT COUNT(*) FROM files WHERE tenant_id = ? AND quarantined = 1", (user["tenant_id"],)).fetchone()[0],
                "auditEvents": db.execute(f"SELECT COUNT(*) FROM audit_log {tenant_filter}", tenant_params).fetchone()[0],
                "backups": len(list(BACKUPS.glob("*.ismsbak"))),
                "workspaceSnapshots": db.execute(
                    f"SELECT COUNT(*) FROM workspace_state_snapshots {tenant_filter}",
                    tenant_params,
                ).fetchone()[0],
            }
            workspace_rows = db.execute(
                f"SELECT COUNT(*) FROM tenant_workspace_state {tenant_filter}",
                tenant_params,
            ).fetchone()[0]
            current_tenant_files = db.execute(
                "SELECT COUNT(*) FROM files WHERE tenant_id = ? AND quarantined = 0",
                (user["tenant_id"],),
            ).fetchone()[0]
            current_tenant_snapshots = db.execute(
                "SELECT COUNT(*) FROM workspace_state_snapshots WHERE tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()[0]
            current_tenant_audit = db.execute(
                "SELECT COUNT(*) FROM audit_log WHERE tenant_id = ?",
                (user["tenant_id"],),
            ).fetchone()[0]
            orphan_counts = {}
            if user.get("platform_admin"):
                orphan_counts = {
                    "users": db.execute("SELECT COUNT(*) FROM users WHERE tenant_id IS NULL OR tenant_id = ''").fetchone()[0],
                    "sessions": db.execute("SELECT COUNT(*) FROM sessions WHERE tenant_id IS NULL OR tenant_id = ''").fetchone()[0],
                    "files": db.execute("SELECT COUNT(*) FROM files WHERE tenant_id IS NULL OR tenant_id = ''").fetchone()[0],
                    "auditLog": db.execute("SELECT COUNT(*) FROM audit_log WHERE tenant_id IS NULL OR tenant_id = ''").fetchone()[0],
                    "snapshots": db.execute("SELECT COUNT(*) FROM workspace_state_snapshots WHERE tenant_id IS NULL OR tenant_id = ''").fetchone()[0],
                }
            missing_workspace_rows = max(tenant_count - workspace_rows, 0) if user.get("platform_admin") else 0 if workspace_rows else 1
            orphan_total = sum(orphan_counts.values()) if orphan_counts else 0
            tenant_isolation_checks = [
                {
                    "name": "Aktiver Mandantenkontext",
                    "status": "active" if user.get("tenant_id") else "warning",
                    "detail": f"{user.get('tenant_name') or 'Mandant'} ({user.get('tenant_slug') or user.get('tenant_id')})",
                },
                {
                    "name": "Workspace pro Mandant",
                    "status": "active" if missing_workspace_rows == 0 else "warning",
                    "detail": f"{workspace_rows} Workspace-Datensatz/Datenraum; {missing_workspace_rows} Mandant(en) ohne Workspace-Datensatz",
                },
                {
                    "name": "Dateien mandantengebunden",
                    "status": "active",
                    "detail": f"{current_tenant_files} Datei(en) im aktiven Mandanten; Downloads werden per tenant_id gefiltert",
                },
                {
                    "name": "Snapshots mandantengebunden",
                    "status": "active",
                    "detail": f"{current_tenant_snapshots} Snapshot(s) im aktiven Mandanten; Restore wird per tenant_id gefiltert",
                },
                {
                    "name": "Audit-Log mandantengebunden",
                    "status": "active",
                    "detail": f"{current_tenant_audit} Event(s) im aktiven Mandanten; Nicht-Platform-Admins sehen nur eigene Mandantendaten",
                },
            ]
            if user.get("platform_admin"):
                tenant_isolation_checks.append({
                    "name": "Orphan-Daten ohne Mandant",
                    "status": "active" if orphan_total == 0 else "warning",
                    "detail": f"{orphan_total} Datensatz/Daten ohne tenant_id (User {orphan_counts['users']}, Sessions {orphan_counts['sessions']}, Dateien {orphan_counts['files']}, Audit {orphan_counts['auditLog']}, Snapshots {orphan_counts['snapshots']})",
                })
            isolation_problem_count = sum(1 for check in tenant_isolation_checks if check["status"] != "active")
            tenant_isolation_status = "active" if isolation_problem_count == 0 else "warning"
            role_matrix = {role: role_permissions(role) for role in role_list()}
            role_boundary_checks = [
                {
                    "name": "Kunden koennen nicht final freigeben",
                    "status": "active" if "submitWorkspace" in role_matrix.get("customer", []) and not {"saveWorkspace", "reviewDocument", "admin"}.intersection(role_matrix.get("customer", [])) else "warning",
                    "detail": "customer darf begrenzte Arbeitsstaende und Nachweise einreichen, aber keine Review-/Freigabeentscheidung setzen",
                },
                {
                    "name": "Mitwirkende koennen nicht reviewen",
                    "status": "active" if "submitWorkspace" in role_matrix.get("contributor", []) and not {"saveWorkspace", "reviewDocument", "admin"}.intersection(role_matrix.get("contributor", [])) else "warning",
                    "detail": "contributor darf begrenzt beitragen und versionieren, aber keine fachliche Freigabe setzen",
                },
                {
                    "name": "Auditoren sind lesend",
                    "status": "active" if not {"saveWorkspace", "submitWorkspace", "uploadFile", "reviewDocument", "admin"}.intersection(role_matrix.get("auditor", [])) else "warning",
                    "detail": "auditor darf Workspace und Dateien einsehen/herunterladen, aber nicht veraendern",
                },
                {
                    "name": "Viewer sind lesend",
                    "status": "active" if not {"saveWorkspace", "submitWorkspace", "uploadFile", "versionFile", "reviewDocument", "admin"}.intersection(role_matrix.get("viewer", [])) else "warning",
                    "detail": "viewer darf Workspace und Dateien einsehen/herunterladen, aber nicht veraendern",
                },
                {
                    "name": "Admin-Funktionen nur Admin",
                    "status": "active" if all(("admin" in permissions) == (role == "admin") for role, permissions in role_matrix.items()) else "warning",
                    "detail": "Benutzer-, Mandanten- und Betriebsverwaltung ist an admin gebunden",
                },
                {
                    "name": "Review-Rollen begrenzt",
                    "status": "active" if all(("reviewDocument" in permissions) == (role in {"admin", "consultant", "manager"}) for role, permissions in role_matrix.items()) else "warning",
                    "detail": "Freigabe, Ablehnung und Auditrelevanz sind auf admin, consultant und manager begrenzt",
                },
            ]
            role_boundary_problem_count = sum(1 for check in role_boundary_checks if check["status"] != "active")
            role_boundary_status = "active" if role_boundary_problem_count == 0 else "warning"
            privileged_where = "(u.role IN ('admin','consultant','manager') OR u.platform_admin = 1) AND u.active = 1"
            if user.get("platform_admin"):
                privileged_rows = db.execute(
                    f"SELECT u.username, u.role, u.mfa_enabled, u.platform_admin, t.name AS tenant_name "
                    f"FROM users u JOIN tenants t ON t.id = u.tenant_id WHERE {privileged_where} ORDER BY t.name, u.username"
                ).fetchall()
            else:
                privileged_rows = db.execute(
                    f"SELECT u.username, u.role, u.mfa_enabled, u.platform_admin, t.name AS tenant_name "
                    f"FROM users u JOIN tenants t ON t.id = u.tenant_id WHERE u.tenant_id = ? AND {privileged_where} ORDER BY u.username",
                    (user["tenant_id"],),
                ).fetchall()
            privileged_total = len(privileged_rows)
            privileged_mfa = sum(1 for row in privileged_rows if row["mfa_enabled"])
            privileged_missing_mfa = [row for row in privileged_rows if not row["mfa_enabled"]]
            current_user_mfa_status = "active" if user.get("mfa_enabled") else "warning"
            mfa_policy_active = MFA_ENFORCEMENT == "write"
            mfa_problem_count = len(privileged_missing_mfa) + (0 if mfa_policy_active else 1)
            mfa_readiness_status = "active" if mfa_problem_count == 0 else "warning"
            can_see_user_details = has_permission(user, "admin")
            mfa_readiness_checks = [
                {
                    "name": "MFA-Schreibschutz",
                    "status": "active" if mfa_policy_active else "warning",
                    "detail": (
                        f"Privilegierte Schreibzugriffe verlangen MFA; Rollen: {', '.join(sorted(MFA_REQUIRED_ROLES)) or 'keine'}"
                        if mfa_policy_active
                        else "MFA-Schreibschutz ist nicht aktiviert; ISMS_MFA_ENFORCEMENT=write setzen"
                    ),
                },
                {
                    "name": "Privilegierte Konten mit MFA",
                    "status": mfa_readiness_status,
                    "detail": f"{privileged_mfa} von {privileged_total} privilegierten aktiven Konten haben MFA aktiviert",
                },
                {
                    "name": "Eigener Zugang",
                    "status": current_user_mfa_status,
                    "detail": "MFA ist fuer deinen aktuellen Login aktiviert" if user.get("mfa_enabled") else "MFA ist fuer deinen aktuellen Login noch nicht aktiviert",
                },
                {
                    "name": "MFA/TOTP-Funktion",
                    "status": "active",
                    "detail": "TOTP-Setup, Aktivierung und Deaktivierung sind pro Benutzer vorhanden und auditierbar",
                },
            ]
            file_filter = "" if user.get("platform_admin") else "WHERE tenant_id = ?"
            file_params = () if user.get("platform_admin") else (user["tenant_id"],)
            file_rows = db.execute(f"SELECT id, tenant_id, stored_name FROM files {file_filter}", file_params).fetchall()
            all_file_rows = db.execute("SELECT stored_name FROM files").fetchall() if user.get("platform_admin") else []
            storage_health = FILE_STORAGE.health()
            try:
                missing_blob_count = sum(1 for row in file_rows if not FILE_STORAGE.exists(row["stored_name"]))
                physical_blobs = set(FILE_STORAGE.list_names(suffix=".bin")) if user.get("platform_admin") else set()
            except StorageError:
                missing_blob_count = len(file_rows)
                physical_blobs = set()
            db_blobs = {row["stored_name"] for row in all_file_rows} if user.get("platform_admin") else set()
            orphan_blob_count = len(physical_blobs.difference(db_blobs)) if user.get("platform_admin") else 0
            orphan_file_metadata = db.execute("SELECT COUNT(*) FROM files WHERE tenant_id IS NULL OR tenant_id = ''").fetchone()[0] if user.get("platform_admin") else 0
            file_key_configured = bool(os.environ.get("ISMS_FILE_KEY")) or FILE_KEY.exists()
            scanner_health = MALWARE_SCANNER.health()
            quarantine_count = db.execute(
                "SELECT COUNT(*) FROM files WHERE quarantined = 1" if user.get("platform_admin") else "SELECT COUNT(*) FROM files WHERE tenant_id = ? AND quarantined = 1",
                () if user.get("platform_admin") else (user["tenant_id"],),
            ).fetchone()[0]
            file_storage_checks = [
                {
                    "name": "Objektspeicher",
                    "status": "active" if storage_health["ready"] else "warning",
                    "detail": f"Backend {FILE_STORAGE.backend}: {storage_health['detail']}",
                },
                {
                    "name": "Dateiverschluesselung",
                    "status": "active" if file_key_configured else "warning",
                    "detail": "Dateischluessel ist vorhanden oder per ISMS_FILE_KEY gesetzt" if file_key_configured else "Dateischluessel fehlt; Uploads koennen nicht sicher abgelegt werden",
                },
                {
                    "name": "Datei-Metadaten mandantengebunden",
                    "status": "active" if orphan_file_metadata == 0 else "warning",
                    "detail": f"{orphan_file_metadata} Datei-Metadatensatz/Daten ohne tenant_id",
                },
                {
                    "name": "Datenbank zu Dateiablage",
                    "status": "active" if missing_blob_count == 0 else "warning",
                    "detail": f"{missing_blob_count} Datei-Metadatensatz/Daten ohne passende verschluesselte Datei",
                },
                {
                    "name": "Verwaiste Dateiablage",
                    "status": "active" if orphan_blob_count == 0 else "warning",
                    "detail": f"{orphan_blob_count} verschluesselte Blob-Datei(en) ohne Datenbankeintrag" if user.get("platform_admin") else "Nur Platform-Admins pruefen globale verwaiste Blob-Dateien",
                },
                {
                    "name": "Dateityp-Whitelist",
                    "status": "active",
                    "detail": f"{len(UPLOAD_EXT)} erlaubte Dateiendungen; Uploads werden vor Speicherung geprueft",
                },
                {
                    "name": "Malware-Scanner",
                    "status": "active" if scanner_health["ready"] and scanner_health["mode"] != "disabled" else "warning",
                    "detail": scanner_health["detail"],
                },
                {
                    "name": "Datei-Quarantäne",
                    "status": "active" if quarantine_count == 0 else "warning",
                    "detail": f"{quarantine_count} isolierte Datei(en) warten auf administrative Bearbeitung",
                },
            ]
            file_storage_problem_count = sum(1 for check in file_storage_checks if check["status"] != "active")
            file_storage_status = "active" if file_storage_problem_count == 0 else "warning"
            backup_files = sorted(BACKUPS.glob("*.ismsbak"), key=lambda item: item.stat().st_mtime, reverse=True)
            latest_backup = backup_files[0] if backup_files else None
            latest_backup_at = int(latest_backup.stat().st_mtime) if latest_backup else None
            latest_backup_age_days = int((time.time() - latest_backup_at) // 86400) if latest_backup_at else None
            backup_dir_ready = BACKUPS.exists() and os.access(BACKUPS, os.W_OK)
            backup_created_filter = "" if user.get("platform_admin") else "AND tenant_id = ?"
            backup_created_params = () if user.get("platform_admin") else (user["tenant_id"],)
            last_backup_created_at = db.execute(
                f"SELECT MAX(ts) FROM audit_log WHERE action = 'backup_created' {backup_created_filter}",
                backup_created_params,
            ).fetchone()[0]
            last_restore_at = db.execute(
                f"SELECT MAX(ts) FROM audit_log WHERE action IN ('state_restored','restore_drill_verified') {backup_created_filter}",
                backup_created_params,
            ).fetchone()[0]
            backup_recovery_checks = [
                {
                    "name": "Backup-Verzeichnis",
                    "status": "active" if backup_dir_ready else "warning",
                    "detail": f"{BACKUPS} ist {'beschreibbar' if backup_dir_ready else 'nicht beschreibbar'}",
                },
                {
                    "name": "System-Backup vorhanden",
                    "status": "active" if latest_backup and latest_backup_age_days is not None and latest_backup_age_days <= 30 else "warning",
                    "detail": (
                        f"Letztes Backup {latest_backup.name}, vor {latest_backup_age_days} Tag(en)"
                        if latest_backup and latest_backup_age_days is not None
                        else "Noch kein verschluesseltes System-Backup vorhanden"
                    ),
                },
                {
                    "name": "Backup-Schluessel verfuegbar",
                    "status": "active" if file_key_configured else "warning",
                    "detail": "Wiederherstellung kann denselben Dateischluessel verwenden" if file_key_configured else "Dateischluessel fehlt; Backup-Restore waere nicht moeglich",
                },
                {
                    "name": "Workspace-Snapshots vorhanden",
                    "status": "active" if current_tenant_snapshots > 0 else "warning",
                    "detail": f"{current_tenant_snapshots} Snapshot(s) im aktuellen Mandanten",
                },
                {
                    "name": "Backup-Erstellung protokolliert",
                    "status": "active" if last_backup_created_at else "warning",
                    "detail": f"Letztes Backup-Event: {last_backup_created_at}" if last_backup_created_at else "Noch kein backup_created Audit-Event vorhanden",
                },
                {
                    "name": "Restore-Drill protokolliert",
                    "status": "active" if last_restore_at else "warning",
                    "detail": f"Letztes Restore-Event: {last_restore_at}" if last_restore_at else "Noch kein technischer Restore oder verifizierter Restore-Drill protokolliert",
                },
            ]
            backup_recovery_problem_count = sum(1 for check in backup_recovery_checks if check["status"] != "active")
            backup_recovery_status = "active" if backup_recovery_problem_count == 0 else "warning"
            current_ts = now()
            data_dir_ready = DATA.exists() and os.access(DATA, os.W_OK)
            db_ready = DATABASE.storage_ready()
            db_bytes = DB.stat().st_size if DATABASE.dialect == "sqlite" and DB.exists() else 0
            try:
                upload_bytes = FILE_STORAGE.total_bytes()
            except StorageError:
                upload_bytes = 0
            backup_bytes = sum(path.stat().st_size for path in BACKUPS.glob("*.ismsbak")) if BACKUPS.exists() else 0
            try:
                quick_check_result = DATABASE.integrity_check(db)
            except Exception as exc:
                quick_check_result = str(exc)
            quick_check_ok = quick_check_result == "ok"
            session_tenant_filter = "" if user.get("platform_admin") else "AND tenant_id = ?"
            session_params = (current_ts,) if user.get("platform_admin") else (current_ts, user["tenant_id"])
            active_session_count = db.execute(
                f"SELECT COUNT(*) FROM sessions WHERE expires_at > ? {session_tenant_filter}",
                session_params,
            ).fetchone()[0]
            expired_session_count = db.execute(
                f"SELECT COUNT(*) FROM sessions WHERE expires_at <= ? {session_tenant_filter}",
                session_params,
            ).fetchone()[0]
            last_audit_at = db.execute(
                f"SELECT MAX(ts) FROM audit_log {tenant_filter}",
                tenant_params,
            ).fetchone()[0]
            last_workspace_update_at = db.execute(
                f"SELECT MAX(updated_at) FROM tenant_workspace_state {tenant_filter}",
                tenant_params,
            ).fetchone()[0]
            last_activity_age_days = int((current_ts - last_audit_at) // 86400) if last_audit_at else None
            background_job_counts = db.execute(
                "SELECT "
                "SUM(CASE WHEN status IN ('queued','retry') THEN 1 ELSE 0 END) AS pending, "
                "SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running, "
                "SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed, "
                "SUM(CASE WHEN status = 'running' AND COALESCE(locked_at,updated_at,created_at) < ? THEN 1 ELSE 0 END) AS stale, "
                "SUM(CASE WHEN status = 'succeeded' THEN 1 ELSE 0 END) AS succeeded "
                "FROM background_jobs",
                (current_ts - 900,),
            ).fetchone()
            background_jobs_pending = int(background_job_counts["pending"] or 0)
            background_jobs_running = int(background_job_counts["running"] or 0)
            background_jobs_failed = int(background_job_counts["failed"] or 0)
            background_jobs_stale = int(background_job_counts["stale"] or 0)
            background_jobs_succeeded = int(background_job_counts["succeeded"] or 0)
            background_job_artifacts = 0
            background_job_artifact_bytes = 0
            if JOB_ARTIFACTS.exists():
                for artifact_path in JOB_ARTIFACTS.glob("*.zip"):
                    if artifact_path.is_file():
                        background_job_artifacts += 1
                        background_job_artifact_bytes += artifact_path.stat().st_size
            background_job_problem_count = background_jobs_failed + background_jobs_stale
            background_job_status = "active" if background_job_problem_count == 0 else "warning"
            system_diagnostic_checks = [
                {
                    "name": "Backend erreichbar",
                    "status": "active",
                    "detail": "Security-/Betriebsstatus wurde vom Backend erfolgreich geliefert",
                },
                {
                    "name": "Datenverzeichnis",
                    "status": "active" if data_dir_ready else "warning",
                    "detail": f"{DATA} ist {'beschreibbar' if data_dir_ready else 'nicht beschreibbar'}",
                },
                {
                    "name": f"{DATABASE.dialect.title()}-Datenbank",
                    "status": "active" if db_ready and quick_check_ok else "warning",
                    "detail": f"{db_bytes} Byte; check={quick_check_result}" if DATABASE.dialect == "sqlite" else f"Verbindung und Abfrage: {quick_check_result}",
                },
                {
                    "name": "Sessions",
                    "status": "active" if expired_session_count == 0 else "warning",
                    "detail": f"{active_session_count} aktive Session(s), {expired_session_count} abgelaufene Session(s)",
                },
                {
                    "name": "Letzte Aktivität",
                    "status": "active" if last_activity_age_days is not None and last_activity_age_days <= 14 else "warning",
                    "detail": f"Letztes Audit-Event vor {last_activity_age_days} Tag(en)" if last_activity_age_days is not None else "Noch kein Audit-Event vorhanden",
                },
                {
                    "name": "Workspace-Aktualisierung",
                    "status": "active" if last_workspace_update_at else "warning",
                    "detail": f"Letzter Workspace-Sync: {last_workspace_update_at}" if last_workspace_update_at else "Noch kein Workspace-Sync protokolliert",
                },
                {
                    "name": "Speicherbelegung",
                    "status": "active" if storage_health["ready"] else "warning",
                    "detail": f"Uploads {upload_bytes} Byte ({FILE_STORAGE.backend}), Backups {backup_bytes} Byte",
                },
                {
                    "name": "Hintergrundjobs",
                    "status": background_job_status,
                    "detail": f"{background_jobs_pending} wartend, {background_jobs_running} laufend, {background_jobs_failed} fehlgeschlagen, {background_jobs_stale} festhängend",
                },
                {
                    "name": "Export-Artefakte",
                    "status": "active" if background_job_artifact_bytes <= 500 * 1024 * 1024 else "warning",
                    "detail": f"{background_job_artifacts} Job-Artefakt(e), {background_job_artifact_bytes} Byte",
                },
                {
                    "name": "Konfigurationslimits",
                    "status": "active",
                    "detail": f"Session {SESSION_SECONDS}s, JSON {MAX_JSON} Byte, Upload {MAX_UPLOAD} Byte",
                },
            ]
            system_diagnostic_problem_count = sum(1 for check in system_diagnostic_checks if check["status"] != "active")
            system_diagnostic_status = "active" if system_diagnostic_problem_count == 0 else "warning"
        self.send_json({
            "backend": True,
            "user": user_public(user),
            "counts": counts,
            "roles": role_list(),
            "roleDetails": {role: ROLE_DETAILS.get(role, {}) for role in role_list()},
            "permissions": role_permissions(user["role"], bool(user.get("platform_admin", 0))),
            "roleMatrix": role_matrix,
            "tenantIsolation": {
                "status": tenant_isolation_status,
                "problemCount": isolation_problem_count,
                "checks": tenant_isolation_checks,
            },
            "roleBoundary": {
                "status": role_boundary_status,
                "problemCount": role_boundary_problem_count,
                "checks": role_boundary_checks,
            },
            "mfaReadiness": {
                "status": mfa_readiness_status,
                "problemCount": mfa_problem_count,
                "accessPolicy": access_policy_public(user),
                "privilegedUsers": privileged_total,
                "protectedPrivilegedUsers": privileged_mfa,
                "missingPrivilegedUsers": [
                    {
                        "username": row["username"],
                        "role": row["role"],
                        "tenantName": row["tenant_name"],
                        "platformAdmin": bool(row["platform_admin"]),
                    }
                    for row in privileged_missing_mfa[:12]
                ] if can_see_user_details else [],
                "checks": mfa_readiness_checks,
            },
            "fileStorage": {
                "status": file_storage_status,
                "problemCount": file_storage_problem_count,
                "files": len(file_rows),
                "missingBlobs": missing_blob_count,
                "orphanBlobs": orphan_blob_count,
                "checks": file_storage_checks,
            },
            "backupRecovery": {
                "status": backup_recovery_status,
                "problemCount": backup_recovery_problem_count,
                "backupCount": len(backup_files),
                "snapshotCount": current_tenant_snapshots,
                "latestBackupName": latest_backup.name if latest_backup else "",
                "latestBackupAt": latest_backup_at,
                "latestBackupAgeDays": latest_backup_age_days,
                "lastRestoreAt": last_restore_at,
                "checks": backup_recovery_checks,
            },
            "systemDiagnostics": {
                "status": system_diagnostic_status,
                "problemCount": system_diagnostic_problem_count,
                "databaseBytes": db_bytes,
                "uploadBytes": upload_bytes,
                "backupBytes": backup_bytes,
                "activeSessions": active_session_count,
                "expiredSessions": expired_session_count,
                "lastAuditAt": last_audit_at,
                "lastWorkspaceUpdateAt": last_workspace_update_at,
                "checks": system_diagnostic_checks,
            },
            "backgroundJobs": {
                "status": background_job_status,
                "problemCount": background_job_problem_count,
                "pending": background_jobs_pending,
                "running": background_jobs_running,
                "failed": background_jobs_failed,
                "stale": background_jobs_stale,
                "succeeded": background_jobs_succeeded,
                "artifactCount": background_job_artifacts,
                "artifactBytes": background_job_artifact_bytes,
                "checks": [
                    {
                        "name": "Job-Queue",
                        "status": "active" if background_jobs_failed == 0 else "warning",
                        "detail": f"{background_jobs_pending} wartend, {background_jobs_succeeded} erfolgreich, {background_jobs_failed} fehlgeschlagen",
                    },
                    {
                        "name": "Festhängende Jobs",
                        "status": "active" if background_jobs_stale == 0 else "warning",
                        "detail": f"{background_jobs_stale} Job(s) laenger als 15 Minuten im Status 'running'",
                    },
                    {
                        "name": "Export-Artefakte",
                        "status": "active" if background_job_artifact_bytes <= 500 * 1024 * 1024 else "warning",
                        "detail": f"{background_job_artifacts} herunterladbare ZIP-Artefakt(e), {background_job_artifact_bytes} Byte",
                    },
                ],
            },
            "controls": [
                {"name": "Authentication", "status": "active", "detail": "Session-Cookie mit HttpOnly und SameSite=Lax"},
                {"name": "Role Based Access", "status": "active", "detail": "Granulare Rollenrechte für Lesen, Speichern, Upload, Versionierung, Download, Review und Admin"},
                {"name": "Tenant Isolation", "status": tenant_isolation_status, "detail": "Workspace, Dateien, Snapshots und Audit-Log sind an den aktiven Mandantenkontext gebunden"},
                {"name": "Role Boundary Tests", "status": role_boundary_status, "detail": "Kunden-, Mitwirkenden-, Auditor- und Viewer-Rollen werden gegen kritische Freigabe-/Schreibrechte geprüft"},
                {"name": "CSRF Protection", "status": "active", "detail": "Schreibende Requests benötigen X-CSRF-Token"},
                {"name": "System Diagnostics", "status": system_diagnostic_status, "detail": "Backend, Datenbank, Sessions, Speicher und letzte Aktivität werden als Betriebsmonitor geprüft"},
                {"name": "Privileged MFA", "status": mfa_readiness_status, "detail": "Privilegierte Konten werden auf aktivierte MFA geprueft"},
                {"name": "Encrypted File Storage", "status": file_storage_status, "detail": "Upload-Inhalte werden verschluesselt abgelegt und gegen Datenbank-Metadaten geprueft"},
                {"name": "Audit Log", "status": "active", "detail": "Sicherheitsrelevante Aktionen werden protokolliert"},
                {"name": "Backups", "status": backup_recovery_status, "detail": "Backup-Verzeichnis, Schluessel, Backup-Alter, Snapshots und Restore-Drill werden geprueft"},
                {"name": "Background Jobs", "status": background_job_status, "detail": "Asynchrone Export-, Backup-, Scan- und Betriebsjobs werden auf Fehler und Stillstand geprueft"},
                {"name": "Workspace Snapshots", "status": "active", "detail": "Vor jeder State-Überschreibung wird eine Wiederherstellungsversion gesichert"},
            ],
        })

    def handle_operational_alerts(self):
        user = self.require_platform_admin()
        if not user:
            return
        with conn() as db:
            self.send_json(operational_alerts_payload(db))

    def handle_refresh_operational_alerts(self):
        user = self.require_platform_admin(write=True)
        if not user:
            return
        refreshed_at = run_operational_monitor(actor=user, ip=self.client_address[0], schedule_next=False)
        with conn() as db:
            payload = operational_alerts_payload(db, refreshed_at)
        self.send_json(payload)

    def handle_acknowledge_operational_alert(self, alert_key):
        user = self.require_platform_admin(write=True)
        if not user:
            return
        key = urllib.parse.unquote(alert_key)
        with conn() as db:
            row = db.execute(
                "SELECT alert_key,status,severity,title FROM operational_alerts WHERE alert_key = ?",
                (key,),
            ).fetchone()
            if not row:
                self.send_error_json(404, "operational alert not found")
                return
            if row["status"] == "resolved":
                self.send_error_json(409, "resolved operational alert cannot be acknowledged")
                return
            db.execute(
                "UPDATE operational_alerts SET status='acknowledged',acknowledged_at=?,acknowledged_by=? WHERE alert_key=?",
                (now(), user["id"], key),
            )
            audit(db, user, "operational_alert_acknowledged", "operational_alert", key, {
                "severity": row["severity"],
                "title": row["title"],
            }, self.client_address[0])
            payload = operational_alerts_payload(db)
        self.send_json(payload)

    def handle_notification_states(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        with conn() as db:
            self.send_json(notification_states_payload(db, user))

    def handle_update_notification_states(self):
        user = self.require_authenticated_write()
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        action = str(payload.get("action") or "").strip().lower()
        if action not in {"read", "unread", "dismiss", "restore", "escalate"}:
            self.send_error_json(400, "unsupported notification action")
            return
        raw_ids = payload.get("notificationIds")
        if not isinstance(raw_ids, list):
            raw_ids = [payload.get("notificationId")]
        notification_ids = []
        for raw_id in raw_ids[:1000]:
            notification_id = str(raw_id or "").strip()
            if not notification_id or len(notification_id) > 300 or re.search(r"[\x00-\x1f\x7f]", notification_id):
                continue
            if notification_id not in notification_ids:
                notification_ids.append(notification_id)
        if not notification_ids:
            self.send_error_json(400, "notification id required")
            return

        timestamp = now()
        with conn() as db:
            changed_ids = []
            for notification_id in notification_ids:
                row = db.execute(
                    "SELECT read_at,dismissed_at,escalated_at FROM notification_states "
                    "WHERE tenant_id = ? AND user_id = ? AND notification_id = ?",
                    (user["tenant_id"], user["id"], notification_id),
                ).fetchone()
                read_at = row["read_at"] if row else None
                dismissed_at = row["dismissed_at"] if row else None
                escalated_at = row["escalated_at"] if row else None
                before = (read_at, dismissed_at, escalated_at)
                if action == "read":
                    read_at = read_at or timestamp
                elif action == "unread":
                    read_at = None
                elif action == "dismiss":
                    read_at = read_at or timestamp
                    dismissed_at = dismissed_at or timestamp
                elif action == "restore":
                    dismissed_at = None
                elif action == "escalate":
                    read_at = read_at or timestamp
                    escalated_at = escalated_at or timestamp
                if before == (read_at, dismissed_at, escalated_at):
                    continue
                db.execute(
                    "INSERT INTO notification_states "
                    "(tenant_id,user_id,notification_id,read_at,dismissed_at,escalated_at,updated_at) "
                    "VALUES (?,?,?,?,?,?,?) "
                    "ON CONFLICT(tenant_id,user_id,notification_id) DO UPDATE SET "
                    "read_at=excluded.read_at,dismissed_at=excluded.dismissed_at,"
                    "escalated_at=excluded.escalated_at,updated_at=excluded.updated_at",
                    (
                        user["tenant_id"], user["id"], notification_id, read_at,
                        dismissed_at, escalated_at, timestamp,
                    ),
                )
                changed_ids.append(notification_id)
            db.execute(
                "DELETE FROM notification_states WHERE tenant_id = ? AND user_id = ? AND notification_id NOT IN ("
                "SELECT notification_id FROM notification_states WHERE tenant_id = ? AND user_id = ? "
                "ORDER BY updated_at DESC LIMIT 2000"
                ")",
                (user["tenant_id"], user["id"], user["tenant_id"], user["id"]),
            )
            if changed_ids:
                audit_action = {
                    "read": "notification_marked_read",
                    "unread": "notification_marked_unread",
                    "dismiss": "notification_dismissed",
                    "restore": "notification_restored",
                    "escalate": "notification_escalated",
                }[action]
                audit(db, user, audit_action, "notification_state", str(user["id"]), {
                    "count": len(changed_ids),
                    "notificationIds": changed_ids[:20],
                }, self.client_address[0])
            result = notification_states_payload(db, user)
            result["changed"] = len(changed_ids)
        self.send_json(result)

    def handle_notification_deliveries(self):
        user = self.require_user(permission="readWorkspace")
        if not user:
            return
        if not has_permission(user, "reviewDocument"):
            self.send_error_json(403, "permission required: reviewDocument")
            return
        with conn() as db:
            self.send_json(notification_deliveries_payload(db, user))

    def handle_create_notification_delivery(self):
        user = self.require_user(permission="reviewDocument")
        if not user:
            return
        if not NOTIFICATION_DELIVERY_ENABLED:
            self.send_error_json(409, "notification delivery is disabled")
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        channel = str(payload.get("channel") or "").strip().lower()
        channel_config = notification_delivery_channel_config(channel)
        if channel not in {"webhook", "smtp"} or not channel_config["configured"]:
            self.send_error_json(409, "notification delivery channel is not configured")
            return
        notification_id = metadata_value(payload.get("notificationId"), 300)
        if not notification_id:
            self.send_error_json(400, "notification id required")
            return
        notification = clean_delivery_notification(payload.get("notification"))
        notification["id"] = notification["id"] or notification_id
        delivery_id = str(uuid.uuid4())
        queued_at = now()
        delivery_payload = {
            "event": "sfm.notification",
            "deliveryId": delivery_id,
            "queuedAt": queued_at,
            "tenant": {
                "id": user["tenant_id"],
                "name": user.get("tenant_name") or "",
                "slug": user.get("tenant_slug") or "",
            },
            "actor": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            },
            "notification": notification,
            "notice": "Diese Zustellung ist ein Hinweis und keine fachliche Freigabe.",
        }
        with conn() as db:
            existing = db.execute(
                "SELECT id FROM notification_deliveries WHERE tenant_id=? AND notification_id=? AND channel=? "
                "AND status IN ('queued','retry','delivering') ORDER BY created_at DESC LIMIT 1",
                (user["tenant_id"], notification_id, channel),
            ).fetchone()
            if existing:
                result = notification_deliveries_payload(db, user)
                result["queuedId"] = existing["id"]
                result["reused"] = True
                self.send_json(result)
                return
            db.execute(
                "INSERT INTO notification_deliveries "
                "(id,tenant_id,notification_id,channel,destination_label,payload_json,status,attempt_count,next_attempt_at,created_at,created_by) "
                "VALUES (?,?,?,?,?,?,'queued',0,?,?,?)",
                (
                    delivery_id, user["tenant_id"], notification_id, channel,
                    channel_config["destinationLabel"], json.dumps(delivery_payload, ensure_ascii=False),
                    queued_at, queued_at, user["id"],
                ),
            )
            audit(db, user, "notification_delivery_queued", "notification_delivery", delivery_id, {
                "notificationId": notification_id,
                "channel": channel,
                "destinationLabel": channel_config["destinationLabel"],
                "title": notification["title"],
            }, self.client_address[0])
            result = notification_deliveries_payload(db, user)
            result["queuedId"] = delivery_id
            result["reused"] = False
        self.send_json(result, status=201)

    def handle_retry_notification_delivery(self, delivery_id):
        user = self.require_user(permission="reviewDocument")
        if not user:
            return
        if not NOTIFICATION_DELIVERY_ENABLED:
            self.send_error_json(409, "notification delivery is disabled")
            return
        delivery_id = metadata_value(urllib.parse.unquote(delivery_id), 100)
        with conn() as db:
            row = db.execute(
                "SELECT id,notification_id,channel,status FROM notification_deliveries WHERE id=? AND tenant_id=?",
                (delivery_id, user["tenant_id"]),
            ).fetchone()
            if not row:
                self.send_error_json(404, "notification delivery not found")
                return
            if row["status"] == "sent":
                self.send_error_json(409, "sent notification delivery cannot be retried")
                return
            if not notification_delivery_channel_config(row["channel"])["configured"]:
                self.send_error_json(409, "notification delivery channel is not configured")
                return
            db.execute(
                "UPDATE notification_deliveries SET status='queued',attempt_count=0,next_attempt_at=?,last_error=NULL,response_code=NULL "
                "WHERE id=?",
                (now(), delivery_id),
            )
            audit(db, user, "notification_delivery_retry_requested", "notification_delivery", delivery_id, {
                "notificationId": row["notification_id"],
                "channel": row["channel"],
                "previousStatus": row["status"],
            }, self.client_address[0])
            result = notification_deliveries_payload(db, user)
            result["queuedId"] = delivery_id
        self.send_json(result)

    def handle_maintenance_status(self):
        user = self.require_platform_admin()
        if not user:
            return
        with conn() as db:
            self.send_json(maintenance_status_payload(db))

    def handle_maintenance_action(self, action_key):
        user = self.require_platform_admin(write=True)
        if not user:
            return
        action = urllib.parse.unquote(action_key)
        with conn() as db:
            if action == "cleanup-expired-sessions":
                cursor = db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now(),))
                affected = max(0, int(cursor.rowcount or 0))
                detail = {
                    "action": action,
                    "affected": affected,
                    "scope": "expired sessions only",
                    "activeSessionsPreserved": True,
                }
            elif action == "expire-stale-invitations":
                cursor = db.execute(
                    "UPDATE invitations SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?",
                    (now(),),
                )
                affected = max(0, int(cursor.rowcount or 0))
                detail = {
                    "action": action,
                    "affected": affected,
                    "scope": "expired pending invitations only",
                    "recordsDeleted": False,
                }
            elif action == "cleanup-job-artifacts":
                artifact_count = 0
                artifact_bytes = 0
                for artifact in JOB_ARTIFACTS.glob("*.zip"):
                    if artifact.is_file():
                        artifact_count += 1
                        artifact_bytes += artifact.stat().st_size
                completed_jobs = int(db.execute(
                    "SELECT COUNT(*) FROM background_jobs WHERE status IN ('succeeded','failed','cancelled')"
                ).fetchone()[0] or 0)
                affected = artifact_count + completed_jobs
                detail = {
                    "action": action,
                    "affected": affected,
                    "scope": "review only",
                    "recordsDeleted": False,
                    "artifactCount": artifact_count,
                    "artifactBytes": artifact_bytes,
                    "completedJobs": completed_jobs,
                    "note": "Job-Artefakte werden kontrolliert ueber Retention oder den Hintergrundjobs-Bereich geprueft.",
                }
            else:
                self.send_error_json(404, "maintenance action not found")
                return
            audit(db, user, "maintenance_action_executed", "maintenance", action, detail, self.client_address[0])
            refreshed_at = sync_operational_alerts(db, actor=user, ip=self.client_address[0])
            mark_operations_runtime_success(refreshed_at, schedule_next=False)
            payload = operational_alerts_payload(db, refreshed_at)
        self.send_json({"ok": True, "action": action, "affected": affected, "operations": payload})

    def handle_list_background_jobs(self):
        user = self.require_platform_admin()
        if not user:
            return
        with conn() as db:
            self.send_json(background_jobs_payload(db))

    def handle_create_background_job(self):
        user = self.require_platform_admin(write=True)
        if not user:
            return
        payload = self.json_body()
        job_type = metadata_value(payload.get("jobType"), 120)
        if job_type not in BACKGROUND_JOB_TYPES or job_type in {"intune_preview", "intune_sync"}:
            self.send_error_json(400, "unsupported background job type")
            return
        try:
            priority = int(payload.get("priority") or 50)
        except (TypeError, ValueError):
            priority = 50
        with conn() as db:
            job_id = enqueue_background_job(db, job_type, user, payload=payload.get("payload") or {}, priority=priority)
            result = background_jobs_payload(db)
        result["queuedId"] = job_id
        self.send_json(result, status=201)

    def handle_retry_background_job(self, job_id):
        user = self.require_platform_admin(write=True)
        if not user:
            return
        job_id = urllib.parse.unquote(job_id)
        with conn() as db:
            row = db.execute(
                "SELECT id,status,job_type FROM background_jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
            if not row:
                self.send_error_json(404, "background job not found")
                return
            if row["status"] not in {"failed", "cancelled"}:
                self.send_error_json(409, "only failed or cancelled jobs can be retried")
                return
            timestamp = now()
            db.execute(
                "UPDATE background_jobs SET status='queued',attempts=0,next_run_at=?,locked_at=NULL,locked_by=NULL,updated_at=?,finished_at=NULL,last_error=NULL WHERE id=?",
                (timestamp, timestamp, job_id),
            )
            audit(db, user, "background_job_retry_requested", "background_job", job_id, {
                "jobType": row["job_type"],
                "previousStatus": row["status"],
            }, self.client_address[0])
            result = background_jobs_payload(db)
        result["queuedId"] = job_id
        self.send_json(result)

    def handle_cancel_background_job(self, job_id):
        user = self.require_platform_admin(write=True)
        if not user:
            return
        job_id = urllib.parse.unquote(job_id)
        with conn() as db:
            row = db.execute(
                "SELECT id,status,job_type FROM background_jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
            if not row:
                self.send_error_json(404, "background job not found")
                return
            if row["status"] not in {"queued", "retry"}:
                self.send_error_json(409, "only queued or retry jobs can be cancelled")
                return
            timestamp = now()
            db.execute(
                "UPDATE background_jobs SET status='cancelled',updated_at=?,finished_at=?,locked_at=NULL,locked_by=NULL,last_error=NULL WHERE id=?",
                (timestamp, timestamp, job_id),
            )
            audit(db, user, "background_job_cancelled", "background_job", job_id, {
                "jobType": row["job_type"],
                "previousStatus": row["status"],
            }, self.client_address[0])
            result = background_jobs_payload(db)
        self.send_json(result)

    def handle_download_job_artifact(self, job_id):
        user = self.require_admin()
        if not user:
            return
        job_id = urllib.parse.unquote(job_id)
        with conn() as db:
            row = db.execute(
                "SELECT id,tenant_id,job_type,status,result_json,created_by FROM background_jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
            if not row:
                self.send_error_json(404, "background job not found")
                return
            if row["job_type"] != "tenant_export_create" or row["status"] != "succeeded":
                self.send_error_json(409, "job artifact is not ready")
                return
            if not user.get("platform_admin") and row["tenant_id"] != user.get("tenant_id"):
                self.send_error_json(403, "job artifact is limited to the active tenant")
                return
            try:
                result = json.loads(row["result_json"] or "{}")
            except Exception:
                result = {}
            artifact = result.get("tenantExport") or {}
            filename = safe_filename(artifact.get("filename") or f"{job_id}.zip")
        artifact_path = JOB_ARTIFACTS / f"{safe_filename(job_id)}.zip"
        if not artifact_path.exists() or not is_within(JOB_ARTIFACTS, artifact_path):
            self.send_error_json(404, "job artifact file not found")
            return
        content = artifact_path.read_bytes()
        checksum = artifact.get("sha256")
        if checksum and sha(content) != checksum:
            self.send_error_json(409, "job artifact checksum mismatch")
            return
        with conn() as db:
            audit(db, user, "background_job_artifact_downloaded", "background_job", job_id, {
                "filename": filename,
                "bytes": len(content),
            }, self.client_address[0])
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def handle_list_users(self):
        user = self.require_admin()
        if not user:
            return
        with conn() as db:
            if user.get("platform_admin"):
                rows = db.execute(
                    "SELECT u.id, u.username, u.email, u.role, u.active, u.mfa_enabled, u.password_change_required, u.created_at, u.updated_at, u.last_login_at, "
                    "u.tenant_id, u.platform_admin, t.name AS tenant_name, "
                    "CASE WHEN EXISTS(SELECT 1 FROM oidc_identities oi WHERE oi.user_id = u.id) THEN 1 ELSE 0 END AS sso_linked "
                    "FROM users u JOIN tenants t ON t.id = u.tenant_id ORDER BY t.name, u.username"
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT u.id, u.username, u.email, u.role, u.active, u.mfa_enabled, u.password_change_required, u.created_at, u.updated_at, u.last_login_at, "
                    "u.tenant_id, u.platform_admin, t.name AS tenant_name, "
                    "CASE WHEN EXISTS(SELECT 1 FROM oidc_identities oi WHERE oi.user_id = u.id) THEN 1 ELSE 0 END AS sso_linked "
                    "FROM users u JOIN tenants t ON t.id = u.tenant_id WHERE u.tenant_id = ? ORDER BY u.username",
                    (user["tenant_id"],),
                ).fetchall()
            current_ts = now()
            if user.get("platform_admin"):
                session_rows = db.execute(
                    "SELECT user_id, "
                    "SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END) AS active_sessions, "
                    "SUM(CASE WHEN expires_at <= ? THEN 1 ELSE 0 END) AS expired_sessions "
                    "FROM sessions GROUP BY user_id",
                    (current_ts, current_ts),
                ).fetchall()
            else:
                session_rows = db.execute(
                    "SELECT user_id, "
                    "SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END) AS active_sessions, "
                    "SUM(CASE WHEN expires_at <= ? THEN 1 ELSE 0 END) AS expired_sessions "
                    "FROM sessions WHERE tenant_id = ? GROUP BY user_id",
                    (current_ts, current_ts, user["tenant_id"]),
                ).fetchall()
            session_counts = {
                row["user_id"]: {
                    "active": int(row["active_sessions"] or 0),
                    "expired": int(row["expired_sessions"] or 0),
                }
                for row in session_rows
            }
            login_locks = {
                row["id"]: account_login_lock(db, row["username"], current_ts)
                for row in rows
            }
        self.send_json({
            "users": [
                {
                    "id": row["id"],
                    "username": row["username"],
                    "email": row["email"] or "",
                    "role": row["role"],
                    "active": bool(row["active"]),
                    "mfaEnabled": bool(row["mfa_enabled"]),
                    "passwordChangeRequired": bool(row["password_change_required"]),
                    "ssoLinked": bool(row["sso_linked"]),
                    "platformAdmin": bool(row["platform_admin"]),
                    "tenantId": row["tenant_id"],
                    "tenantName": row["tenant_name"],
                    "createdAt": row["created_at"],
                    "updatedAt": row["updated_at"],
                    "lastLoginAt": row["last_login_at"],
                    "activeSessionCount": session_counts.get(row["id"], {}).get("active", 0),
                    "expiredSessionCount": session_counts.get(row["id"], {}).get("expired", 0),
                    "loginLocked": login_locks.get(row["id"], {}).get("locked", False),
                    "loginLockedUntil": login_locks.get(row["id"], {}).get("lockedUntil"),
                    "failedLoginAttempts": login_locks.get(row["id"], {}).get("failedAttempts", 0),
                }
                for row in rows
            ]
        })

    def handle_list_invitations(self):
        user = self.require_admin()
        if not user:
            return
        with conn() as db:
            if user.get("platform_admin"):
                rows = db.execute(
                    "SELECT i.*, t.name AS tenant_name, u.username AS invited_by_username "
                    "FROM invitations i JOIN tenants t ON t.id = i.tenant_id "
                    "LEFT JOIN users u ON u.id = i.invited_by "
                    "ORDER BY i.created_at DESC LIMIT 200"
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT i.*, t.name AS tenant_name, u.username AS invited_by_username "
                    "FROM invitations i JOIN tenants t ON t.id = i.tenant_id "
                    "LEFT JOIN users u ON u.id = i.invited_by "
                    "WHERE i.tenant_id = ? ORDER BY i.created_at DESC LIMIT 100",
                    (user["tenant_id"],),
                ).fetchall()
        self.send_json({
            "invitations": [invitation_public(row) for row in rows],
            "deliveryConfigured": invitation_delivery_configured(),
        })

    def handle_get_invitation_accept(self):
        token = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("token", [""])[0]
        if not token:
            self.send_error_json(400, "token required")
            return
        token_hash = sha(token.encode())
        with conn() as db:
            row = db.execute(
                "SELECT i.*, t.name AS tenant_name, u.username AS invited_by_username "
                "FROM invitations i JOIN tenants t ON t.id = i.tenant_id "
                "LEFT JOIN users u ON u.id = i.invited_by WHERE i.token_hash = ?",
                (token_hash,),
            ).fetchone()
            if not row:
                self.send_error_json(404, "invitation not found")
                return
            if row["status"] == "pending" and row["expires_at"] < now():
                db.execute("UPDATE invitations SET status = 'expired' WHERE id = ?", (row["id"],))
                row = dict(row)
                row["status"] = "expired"
        public = invitation_public(row)
        if public["status"] != "pending":
            self.send_error_json(410, f"invitation {public['status']}")
            return
        self.send_json({"invitation": public, "passwordPolicy": password_policy_public()})

    def handle_create_invitation(self):
        admin = self.require_admin(write=True)
        if not admin:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        email = str(payload.get("email") or "").strip().lower()
        display_name = metadata_value(payload.get("displayName") or payload.get("name") or "", 120)
        role = str(payload.get("role") or "customer").strip()
        tenant_id = str(payload.get("tenantId") or admin["tenant_id"]).strip()
        if not admin.get("platform_admin"):
            tenant_id = admin["tenant_id"]
        if not valid_email(email):
            self.send_error_json(400, "valid email required")
            return
        if not invite_role_allowed(admin, role):
            self.send_error_json(400, "role cannot be invited by this admin")
            return
        try:
            expires_days = int(payload.get("expiresDays") or 7)
        except (TypeError, ValueError):
            expires_days = 7
        expires_days = min(max(expires_days, 1), 30)
        invitation_id = str(uuid.uuid4())
        token = secrets.token_urlsafe(32)
        created_at = now()
        expires_at = created_at + expires_days * 86400
        with conn() as db:
            tenant = db.execute("SELECT id, name FROM tenants WHERE id = ? AND status = 'active'", (tenant_id,)).fetchone()
            if not tenant:
                self.send_error_json(400, "tenant not found or inactive")
                return
            existing_user = db.execute(
                "SELECT id FROM users WHERE tenant_id = ? AND LOWER(email) = ?",
                (tenant_id, email),
            ).fetchone()
            if existing_user:
                self.send_json({"error": "an account already uses this email", "code": "invitation_account_exists"}, status=409)
                return
            db.execute(
                "UPDATE invitations SET status = 'expired' WHERE tenant_id = ? AND LOWER(email) = ? "
                "AND status = 'pending' AND expires_at <= ?",
                (tenant_id, email, created_at),
            )
            pending = db.execute(
                "SELECT id FROM invitations WHERE tenant_id = ? AND LOWER(email) = ? AND status = 'pending' AND expires_at > ?",
                (tenant_id, email, created_at),
            ).fetchone()
            if pending:
                self.send_json({
                    "error": "a pending invitation already exists for this email",
                    "code": "invitation_already_pending",
                    "invitationId": pending["id"],
                }, status=409)
                return
            db.execute(
                "INSERT INTO invitations (id,token_hash,email,display_name,role,tenant_id,invited_by,status,created_at,expires_at) "
                "VALUES (?,?,?,?,?,?,?,'pending',?,?)",
                (invitation_id, sha(token.encode()), email, display_name, role, tenant_id, admin["id"], created_at, expires_at),
            )
            row = db.execute(
                "SELECT i.*, t.name AS tenant_name, u.username AS invited_by_username "
                "FROM invitations i JOIN tenants t ON t.id = i.tenant_id "
                "LEFT JOIN users u ON u.id = i.invited_by WHERE i.id = ?",
                (invitation_id,),
            ).fetchone()
            audit(db, admin, "invitation_created", "invitation", invitation_id, {
                "email": email,
                "role": role,
                "tenantId": tenant_id,
                "expiresAt": expires_at,
            }, self.client_address[0])
        accept_url = self.invitation_accept_url(token)
        deliver_invitation(
            invitation_id,
            email,
            display_name,
            tenant["name"],
            role,
            accept_url,
            expires_at,
            admin,
            self.client_address[0],
        )
        with conn() as db:
            refreshed = db.execute(
                "SELECT i.*, t.name AS tenant_name, u.username AS invited_by_username "
                "FROM invitations i JOIN tenants t ON t.id = i.tenant_id "
                "LEFT JOIN users u ON u.id = i.invited_by WHERE i.id = ?",
                (invitation_id,),
            ).fetchone()
        invitation = invitation_public(refreshed)
        invitation["acceptUrl"] = accept_url
        self.send_json({
            "ok": True,
            "invitation": invitation,
            "deliveryConfigured": invitation_delivery_configured(),
        }, status=201)

    def handle_resend_invitation(self, invitation_id):
        admin = self.require_admin(write=True)
        if not admin:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        try:
            expires_days = int(payload.get("expiresDays") or 7)
        except (TypeError, ValueError):
            expires_days = 7
        expires_days = min(max(expires_days, 1), 30)
        issued_at = now()
        expires_at = issued_at + expires_days * 86400
        token = secrets.token_urlsafe(32)
        with conn() as db:
            if admin.get("platform_admin"):
                row = db.execute(
                    "SELECT i.*,t.name AS tenant_name,u.username AS invited_by_username FROM invitations i "
                    "JOIN tenants t ON t.id = i.tenant_id LEFT JOIN users u ON u.id = i.invited_by WHERE i.id = ?",
                    (invitation_id,),
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT i.*,t.name AS tenant_name,u.username AS invited_by_username FROM invitations i "
                    "JOIN tenants t ON t.id = i.tenant_id LEFT JOIN users u ON u.id = i.invited_by "
                    "WHERE i.id = ? AND i.tenant_id = ?",
                    (invitation_id, admin["tenant_id"]),
                ).fetchone()
            if not row:
                self.send_error_json(404, "invitation not found")
                return
            if row["status"] != "pending" or row["expires_at"] <= issued_at:
                if row["status"] == "pending":
                    db.execute("UPDATE invitations SET status = 'expired' WHERE id = ?", (invitation_id,))
                self.send_error_json(409, "only a valid pending invitation can be resent")
                return
            db.execute(
                "UPDATE invitations SET token_hash = ?, expires_at = ?, delivery_status = 'manual', delivery_error = NULL WHERE id = ?",
                (sha(token.encode()), expires_at, invitation_id),
            )
            audit(db, admin, "invitation_reissued", "invitation", invitation_id, {
                "email": row["email"],
                "expiresAt": expires_at,
                "previousTokenInvalidated": True,
            }, self.client_address[0])
        accept_url = self.invitation_accept_url(token)
        delivery_status = deliver_invitation(
            invitation_id,
            row["email"],
            row["display_name"] or "",
            row["tenant_name"],
            row["role"],
            accept_url,
            expires_at,
            admin,
            self.client_address[0],
        )
        with conn() as db:
            refreshed = db.execute(
                "SELECT i.*,t.name AS tenant_name,u.username AS invited_by_username FROM invitations i "
                "JOIN tenants t ON t.id = i.tenant_id LEFT JOIN users u ON u.id = i.invited_by WHERE i.id = ?",
                (invitation_id,),
            ).fetchone()
        invitation = invitation_public(refreshed)
        invitation["acceptUrl"] = accept_url
        invitation["deliveryStatus"] = delivery_status
        self.send_json({
            "ok": True,
            "invitation": invitation,
            "deliveryConfigured": invitation_delivery_configured(),
        })

    def handle_accept_invitation(self):
        ip = self.client_address[0]
        if rate_limited(f"invite:{ip}", limit=12, window=60):
            self.send_error_json(429, "too many attempts")
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        token = str(payload.get("token") or "").strip()
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        if not token:
            self.send_error_json(400, "token required")
            return
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", username):
            self.send_error_json(400, "username must be 3-64 characters and use letters, numbers, dot, dash or underscore")
            return
        policy_error = password_policy_error(password, username)
        if policy_error:
            self.send_password_policy_error(policy_error)
            return
        token_hash = sha(token.encode())
        try:
            with conn() as db:
                invitation = db.execute(
                    "SELECT i.*, t.name AS tenant_name, t.slug AS tenant_slug, t.status AS tenant_status, u.username AS invited_by_username "
                    "FROM invitations i JOIN tenants t ON t.id = i.tenant_id "
                    "LEFT JOIN users u ON u.id = i.invited_by WHERE i.token_hash = ?",
                    (token_hash,),
                ).fetchone()
                if not invitation:
                    self.send_error_json(404, "invitation not found")
                    return
                if invitation["status"] != "pending":
                    self.send_error_json(409, f"invitation {invitation['status']}")
                    return
                if invitation["expires_at"] < now():
                    db.execute("UPDATE invitations SET status = 'expired' WHERE id = ?", (invitation["id"],))
                    self.send_error_json(410, "invitation expired")
                    return
                if invitation["tenant_status"] != "active":
                    self.send_error_json(403, "tenant inactive")
                    return
                policy_error = password_policy_error(password, username, invitation["email"])
                if policy_error:
                    self.send_password_policy_error(policy_error)
                    return
                existing_account = db.execute(
                    "SELECT id FROM users WHERE tenant_id = ? AND LOWER(email) = ?",
                    (invitation["tenant_id"], str(invitation["email"]).lower()),
                ).fetchone()
                if existing_account:
                    self.send_json({"error": "an account already exists for this invitation email", "code": "invitation_account_exists"}, status=409)
                    return
                claimed = db.execute(
                    "UPDATE invitations SET status = 'accepting' WHERE id = ? AND status = 'pending' AND expires_at >= ?",
                    (invitation["id"], now()),
                )
                if getattr(claimed, "rowcount", 0) != 1:
                    self.send_error_json(409, "invitation is already being accepted")
                    return
                db.execute(
                    "INSERT INTO users (username,password_hash,role,created_at,active,updated_at,email,tenant_id,platform_admin,password_change_required) VALUES (?,?,?,?,1,?,?,?,0,0)",
                    (username, password_hash(password), invitation["role"], now(), now(), invitation["email"], invitation["tenant_id"]),
                )
                user_row = db.execute(
                    "SELECT u.id, u.username, u.role, u.active, u.mfa_enabled, u.password_change_required, u.tenant_id, u.platform_admin, "
                    "t.name AS tenant_name, t.slug AS tenant_slug, t.status AS tenant_status "
                    "FROM users u JOIN tenants t ON t.id = u.tenant_id WHERE u.username = ?",
                    (username,),
                ).fetchone()
                db.execute(
                    "UPDATE invitations SET status = 'accepted', accepted_at = ?, accepted_user_id = ? WHERE id = ?",
                    (now(), user_row["id"], invitation["id"]),
                )
                token_session = secrets.token_urlsafe(32)
                csrf = secrets.token_urlsafe(24)
                db.execute(
                    "INSERT INTO sessions (token_hash,user_id,tenant_id,csrf_token,expires_at,created_at,ip) VALUES (?,?,?,?,?,?,?)",
                    (sha(token_session.encode()), user_row["id"], invitation["tenant_id"], csrf, now() + SESSION_SECONDS, now(), ip),
                )
                db.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), user_row["id"]))
                user = dict(user_row)
                audit(db, user, "invitation_accepted", "invitation", invitation["id"], {
                    "email": invitation["email"],
                    "role": invitation["role"],
                    "invitedBy": invitation["invited_by_username"] or "",
                }, ip)
        except DATABASE.integrity_errors:
            self.send_error_json(409, "username already exists")
            return
        self.send_json(
            {"ok": True, "authenticated": True, "user": user_public(user), "csrfToken": csrf, "passwordPolicy": password_policy_public()},
            extra_headers={"Set-Cookie": cookie_value(token_session)},
            status=201,
        )

    def handle_revoke_invitation(self, invitation_id):
        admin = self.require_admin(write=True)
        if not admin:
            return
        with conn() as db:
            if admin.get("platform_admin"):
                row = db.execute("SELECT id, tenant_id, status, email FROM invitations WHERE id = ?", (invitation_id,)).fetchone()
            else:
                row = db.execute("SELECT id, tenant_id, status, email FROM invitations WHERE id = ? AND tenant_id = ?", (invitation_id, admin["tenant_id"])).fetchone()
            if not row:
                self.send_error_json(404, "invitation not found")
                return
            if row["status"] != "pending":
                self.send_error_json(409, f"invitation {row['status']}")
                return
            db.execute(
                "UPDATE invitations SET status = 'revoked', revoked_at = ? WHERE id = ?",
                (now(), invitation_id),
            )
            audit(db, admin, "invitation_revoked", "invitation", invitation_id, {
                "email": row["email"],
                "tenantId": row["tenant_id"],
            }, self.client_address[0])
        self.send_json({"ok": True})

    def handle_create_user(self):
        admin = self.require_admin(write=True)
        if not admin:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        username = str(payload.get("username") or "").strip()
        email = str(payload.get("email") or "").strip().lower()
        password = str(payload.get("password") or "")
        role = str(payload.get("role") or "viewer").strip()
        tenant_id = str(payload.get("tenantId") or admin["tenant_id"]).strip()
        if not admin.get("platform_admin"):
            tenant_id = admin["tenant_id"]
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", username):
            self.send_error_json(400, "username must be 3-64 characters and use letters, numbers, dot, dash or underscore")
            return
        if role not in READ_ROLES:
            self.send_error_json(400, "invalid role")
            return
        if email and not valid_email(email):
            self.send_error_json(400, "valid email required")
            return
        policy_error = password_policy_error(password, username, email)
        if policy_error:
            self.send_password_policy_error(policy_error)
            return
        try:
            with conn() as db:
                tenant = db.execute("SELECT id, name FROM tenants WHERE id = ? AND status = 'active'", (tenant_id,)).fetchone()
                if not tenant:
                    self.send_error_json(400, "tenant not found or inactive")
                    return
                db.execute(
                    "INSERT INTO users (username,password_hash,role,created_at,active,updated_at,email,tenant_id,platform_admin,password_change_required) VALUES (?,?,?,?,1,?,?,?,0,1)",
                    (username, password_hash(password), role, now(), now(), email or None, tenant_id),
                )
                new_id = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
                audit(db, admin, "user_created", "user", str(new_id), {"username": username, "role": role, "tenantId": tenant_id}, self.client_address[0])
        except DATABASE.integrity_errors:
            self.send_error_json(409, "username already exists")
            return
        self.send_json({
            "ok": True,
            "user": {
                "id": new_id,
                "username": username,
                "email": email,
                "role": role,
                "roleLabel": ROLE_DETAILS.get(role, {}).get("label", role),
                "tenantId": tenant_id,
                "tenantName": tenant["name"],
                "createdAt": now(),
                "passwordChangeRequired": True,
            },
        }, status=201)

    def handle_update_user(self, user_id):
        admin = self.require_admin(write=True)
        if not admin:
            return
        try:
            target_id = int(user_id)
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid request")
            return
        role = payload.get("role")
        active = payload.get("active")
        tenant_id = payload.get("tenantId")
        email = payload.get("email")
        password = str(payload.get("password") or "")
        updates = []
        params = []
        detail = {}
        if email is not None:
            email = str(email).strip().lower()
            if email and not valid_email(email):
                self.send_error_json(400, "valid email required")
                return
            updates.append("email = ?")
            params.append(email or None)
            detail["emailUpdated"] = True
        if role is not None:
            role = str(role)
            if role not in READ_ROLES:
                self.send_error_json(400, "invalid role")
                return
            if target_id == admin["id"] and role != "admin":
                self.send_error_json(400, "cannot remove your own admin role")
                return
            updates.append("role = ?")
            params.append(role)
            detail["role"] = role
        if active is not None:
            active_value = 1 if active in (True, 1, "1", "true", "on", "active") else 0
            if target_id == admin["id"] and not active_value:
                self.send_error_json(400, "cannot deactivate your own user")
                return
            updates.append("active = ?")
            params.append(active_value)
            detail["active"] = bool(active_value)
        if tenant_id is not None:
            if not admin.get("platform_admin"):
                self.send_error_json(403, "platform admin required for tenant changes")
                return
            tenant_id = str(tenant_id).strip()
            if target_id == admin["id"] and tenant_id != admin["tenant_id"]:
                self.send_error_json(400, "cannot move your own user to another tenant")
                return
            updates.append("tenant_id = ?")
            params.append(tenant_id)
            detail["tenantId"] = tenant_id
        if not updates:
            if not password:
                self.send_json({"ok": True})
                return
        updates.append("updated_at = ?")
        params.extend([now(), target_id])
        with conn() as db:
            if tenant_id is not None:
                tenant = db.execute("SELECT id FROM tenants WHERE id = ? AND status = 'active'", (tenant_id,)).fetchone()
                if not tenant:
                    self.send_error_json(400, "tenant not found or inactive")
                    return
            if admin.get("platform_admin"):
                row = db.execute("SELECT id, username, email, tenant_id FROM users WHERE id = ?", (target_id,)).fetchone()
            else:
                row = db.execute("SELECT id, username, email, tenant_id FROM users WHERE id = ? AND tenant_id = ?", (target_id, admin["tenant_id"])).fetchone()
            if not row:
                self.send_error_json(404, "user not found")
                return
            if password:
                policy_error = update_user_password(
                    db, target_id, password, row["username"], email if email is not None else row["email"],
                    changed_by=admin["id"], reason="admin_reset", require_change=True,
                )
                if policy_error:
                    self.send_password_policy_error(policy_error)
                    return
                detail["passwordChanged"] = True
                detail["passwordChangeRequired"] = True
            if updates:
                db.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
            if password or active is not None:
                token = read_cookie(self.headers.get("Cookie"))
                current_hash = sha(token.encode()) if token else ""
                db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?", (target_id, current_hash))
            if password:
                clear_login_failures(db, row["username"])
            audit(db, admin, "user_updated", "user", str(target_id), detail, self.client_address[0])
        self.send_json({"ok": True})

    def handle_revoke_user_sessions(self, user_id):
        admin = self.require_admin(write=True)
        if not admin:
            return
        try:
            target_id = int(user_id)
        except ValueError:
            self.send_error_json(400, "invalid user id")
            return
        token = read_cookie(self.headers.get("Cookie"))
        current_hash = sha(token.encode()) if token else ""
        with conn() as db:
            if admin.get("platform_admin"):
                row = db.execute("SELECT id, username, tenant_id FROM users WHERE id = ?", (target_id,)).fetchone()
            else:
                row = db.execute(
                    "SELECT id, username, tenant_id FROM users WHERE id = ? AND tenant_id = ?",
                    (target_id, admin["tenant_id"]),
                ).fetchone()
            if not row:
                self.send_error_json(404, "user not found")
                return
            delete_params = [target_id]
            current_clause = ""
            if target_id == admin["id"] and current_hash:
                current_clause = " AND token_hash <> ?"
                delete_params.append(current_hash)
            before = db.execute(
                f"SELECT COUNT(*) FROM sessions WHERE user_id = ?{current_clause}",
                tuple(delete_params),
            ).fetchone()[0]
            db.execute(
                f"DELETE FROM sessions WHERE user_id = ?{current_clause}",
                tuple(delete_params),
            )
            audit(db, admin, "user_sessions_revoked", "user", str(target_id), {
                "username": row["username"],
                "tenantId": row["tenant_id"],
                "revoked": before,
                "keptCurrentSession": target_id == admin["id"] and bool(current_hash),
            }, self.client_address[0])
        self.send_json({"ok": True, "revoked": before})

    def handle_unlock_user(self, user_id):
        admin = self.require_admin(write=True)
        if not admin:
            return
        try:
            target_id = int(user_id)
        except ValueError:
            self.send_error_json(400, "invalid user id")
            return
        with conn() as db:
            if admin.get("platform_admin"):
                row = db.execute("SELECT id,username,tenant_id FROM users WHERE id = ?", (target_id,)).fetchone()
            else:
                row = db.execute(
                    "SELECT id,username,tenant_id FROM users WHERE id = ? AND tenant_id = ?",
                    (target_id, admin["tenant_id"]),
                ).fetchone()
            if not row:
                self.send_error_json(404, "user not found")
                return
            previous = account_login_lock(db, row["username"])
            clear_login_failures(db, row["username"])
            audit(db, admin, "user_login_unlocked", "user", str(target_id), {
                "username": row["username"],
                "tenantId": row["tenant_id"],
                "previousLockedUntil": previous["lockedUntil"],
                "previousFailedAttempts": previous["failedAttempts"],
            }, self.client_address[0])
        self.send_json({"ok": True, "wasLocked": previous["locked"]})

    def handle_change_password(self):
        user = self.require_authenticated_write()
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        current_password = str(payload.get("currentPassword") or "")
        new_password = str(payload.get("newPassword") or "")
        token = read_cookie(self.headers.get("Cookie"))
        token_hash = sha(token.encode()) if token else ""
        with conn() as db:
            row = db.execute("SELECT password_hash,username,email FROM users WHERE id = ?", (user["id"],)).fetchone()
            if not row or not password_ok(current_password, row["password_hash"]):
                self.send_error_json(401, "invalid current password")
                return
            policy_error = update_user_password(
                db, user["id"], new_password, row["username"], row["email"],
                changed_by=user["id"], reason="self_service", require_change=False,
            )
            if policy_error:
                self.send_password_policy_error(policy_error)
                return
            db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?", (user["id"], token_hash))
            clear_login_failures(db, user["username"])
            audit(db, user, "password_changed", "user", str(user["id"]), {}, self.client_address[0])
        refreshed = self.current_user()
        self.send_json({
            "ok": True,
            "user": user_public(refreshed) if refreshed else None,
            "passwordPolicy": password_policy_public(),
        })

    def handle_mfa_setup(self):
        user = self.require_authenticated_write()
        if not user:
            return
        with conn() as db:
            row = db.execute("SELECT username, mfa_secret, mfa_enabled FROM users WHERE id = ?", (user["id"],)).fetchone()
            if row["mfa_enabled"]:
                self.send_error_json(409, "mfa already enabled")
                return
            secret = row["mfa_secret"] or mfa_secret()
            db.execute("UPDATE users SET mfa_secret = ?, updated_at = ? WHERE id = ?", (secret, now(), user["id"]))
            audit(db, user, "mfa_setup_started", "user", str(user["id"]), {}, self.client_address[0])
        self.send_json({"secret": secret, "otpauthUri": otpauth_uri(row["username"], secret)})

    def handle_mfa_enable(self):
        user = self.require_authenticated_write()
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        with conn() as db:
            row = db.execute("SELECT mfa_secret FROM users WHERE id = ?", (user["id"],)).fetchone()
            if not row or not row["mfa_secret"]:
                self.send_error_json(400, "mfa setup required")
                return
            if not verify_totp(row["mfa_secret"], payload.get("code")):
                audit(db, user, "mfa_enable_failed", "user", str(user["id"]), {}, self.client_address[0])
                self.send_error_json(400, "invalid mfa code")
                return
            db.execute("UPDATE users SET mfa_enabled = 1, updated_at = ? WHERE id = ?", (now(), user["id"]))
            audit(db, user, "mfa_enabled", "user", str(user["id"]), {}, self.client_address[0])
        self.send_json({"ok": True})

    def handle_mfa_disable(self):
        user = self.require_authenticated_write()
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return
        password = str(payload.get("currentPassword") or "")
        with conn() as db:
            row = db.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
            if not row or not password_ok(password, row["password_hash"]):
                self.send_error_json(401, "invalid current password")
                return
            db.execute("UPDATE users SET mfa_secret = NULL, mfa_enabled = 0, updated_at = ? WHERE id = ?", (now(), user["id"]))
            audit(db, user, "mfa_disabled", "user", str(user["id"]), {}, self.client_address[0])
        self.send_json({"ok": True})

    def handle_create_backup(self):
        user = self.require_platform_admin(write=True)
        if not user:
            return
        try:
            backup = create_encrypted_backup(user, ip=self.client_address[0])
            self.send_json({"ok": True, "backup": backup})
        except (RuntimeError, StorageError, subprocess.SubprocessError) as error:
            self.send_error_json(503, f"backup unavailable: {error}")

    def handle_record_restore_drill(self):
        user = self.require_platform_admin(write=True)
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            self.send_error_json(400, "invalid json")
            return

        backup_name = safe_filename(metadata_value(payload.get("backupName"), 200))
        backup_path = (BACKUPS / backup_name).resolve()
        if (
            not backup_name
            or backup_path.suffix != ".ismsbak"
            or not is_within(BACKUPS, backup_path)
            or not backup_path.is_file()
        ):
            self.send_error_json(400, "verified backup not found")
            return

        required_true = ("stateMatches", "fileMetadataMatches", "auditIntegrity")
        if any(payload.get(name) is not True for name in required_true):
            self.send_error_json(400, "restore verification is incomplete")
            return

        source_database = metadata_value(payload.get("sourceDatabase"), 32).lower()
        restored_database = metadata_value(payload.get("restoredDatabase"), 32).lower()
        restored_storage = metadata_value(payload.get("restoredStorage"), 32).lower()
        if source_database not in {"sqlite", "postgres"} or restored_database not in {"sqlite", "postgres"}:
            self.send_error_json(400, "unsupported restore database")
            return
        if restored_storage not in {"local", "s3"}:
            self.send_error_json(400, "unsupported restore storage")
            return

        numeric_fields = {}
        for name in ("workspaceRevision", "files", "downloadsVerified", "auditEventsChecked"):
            value = payload.get(name)
            if isinstance(value, bool):
                self.send_error_json(400, f"invalid {name}")
                return
            try:
                value = int(value)
            except (TypeError, ValueError):
                self.send_error_json(400, f"invalid {name}")
                return
            if value < 0 or value > 10_000_000:
                self.send_error_json(400, f"invalid {name}")
                return
            numeric_fields[name] = value

        completed_at = now()
        detail = {
            "backupName": backup_name,
            "sourceDatabase": source_database,
            "restoredDatabase": restored_database,
            "restoredStorage": restored_storage,
            **numeric_fields,
            "stateMatches": True,
            "fileMetadataMatches": True,
            "auditIntegrity": True,
            "technicalVerificationOnly": True,
            "completedAt": completed_at,
        }
        with conn() as db:
            audit(
                db,
                user,
                "restore_drill_verified",
                "backup",
                backup_name,
                detail,
                self.client_address[0],
            )
        run_operational_monitor(actor=user, ip=self.client_address[0], schedule_next=False)
        self.send_json({
            "ok": True,
            "recordedAt": completed_at,
            "backupName": backup_name,
            "technicalVerificationOnly": True,
        }, status=201)

    def handle_list_backups(self):
        user = self.require_platform_admin()
        if not user:
            return
        backups = []
        for path in sorted(BACKUPS.glob("*.ismsbak"), key=lambda item: item.stat().st_mtime, reverse=True):
            stat = path.stat()
            backups.append({"name": path.name, "size": stat.st_size, "createdAt": int(stat.st_mtime)})
        self.send_json({"backups": backups})

    def handle_download_backup(self, backup_name):
        user = self.require_platform_admin()
        if not user:
            return
        name = safe_filename(urllib.parse.unquote(backup_name))
        path = (BACKUPS / name).resolve()
        if not is_within(BACKUPS, path) or path.suffix != ".ismsbak" or not path.exists():
            self.send_error_json(404, "backup not found")
            return
        content = path.read_bytes()
        with conn() as db:
            audit(db, user, "backup_downloaded", "backup", name, {"bytes": len(content)}, self.client_address[0])
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Content-Disposition", f"attachment; filename=\"{name}\"")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def handle_retention(self):
        user = self.require_platform_admin(write=True)
        if not user:
            return
        try:
            payload = self.json_body()
        except Exception:
            payload = {}
        audit_days = max(30, min(3650, int(payload.get("auditDays") or 365)))
        backup_days = max(30, min(3650, int(payload.get("backupDays") or 365)))
        job_days = max(7, min(3650, int(payload.get("jobDays") or 90)))
        audit_cutoff = now() - audit_days * 86400
        backup_cutoff = time.time() - backup_days * 86400
        job_cutoff = now() - job_days * 86400
        event_cutoff = now() - EVENT_RETENTION_DAYS * 86400
        authentication_cutoff = now() - 7 * 86400
        artifact_cutoff = time.time() - job_days * 86400
        deleted_backups = 0
        for path in BACKUPS.glob("*.ismsbak"):
            if path.stat().st_mtime < backup_cutoff:
                path.unlink()
                deleted_backups += 1
        deleted_artifacts = 0
        for path in JOB_ARTIFACTS.glob("*.zip"):
            if path.is_file() and path.stat().st_mtime < artifact_cutoff:
                path.unlink()
                deleted_artifacts += 1
        with conn() as db:
            expired_sessions = max(0, db.execute("DELETE FROM sessions WHERE expires_at < ?", (now(),)).rowcount)
            deleted_login_limits = max(0, db.execute(
                "DELETE FROM auth_login_limits WHERE updated_at < ? AND (blocked_until IS NULL OR blocked_until < ?)",
                (authentication_cutoff, now()),
            ).rowcount)
            deleted_recovery_tokens = max(0, db.execute(
                "DELETE FROM password_reset_tokens WHERE expires_at < ?",
                (authentication_cutoff,),
            ).rowcount)
            old_job_rows = db.execute(
                "SELECT id FROM background_jobs WHERE status IN ('succeeded','failed','cancelled') AND COALESCE(finished_at,updated_at,created_at) < ?",
                (job_cutoff,),
            ).fetchall()
            for row in old_job_rows:
                artifact_path = JOB_ARTIFACTS / f"{safe_filename(row['id'])}.zip"
                if artifact_path.exists() and artifact_path.is_file():
                    artifact_path.unlink()
                    deleted_artifacts += 1
            deleted_jobs = max(0, db.execute(
                "DELETE FROM background_jobs WHERE status IN ('succeeded','failed','cancelled') AND COALESCE(finished_at,updated_at,created_at) < ?",
                (job_cutoff,),
            ).rowcount)
            deleted_live_events = max(0, db.execute(
                "DELETE FROM tenant_events WHERE created_at < ?",
                (event_cutoff,),
            ).rowcount)
            deleted_audit = max(0, db.execute("DELETE FROM audit_log WHERE ts < ?", (audit_cutoff,)).rowcount)
            audit(db, user, "retention_executed", "maintenance", "retention", {
                "auditDays": audit_days,
                "backupDays": backup_days,
                "jobDays": job_days,
                "deletedAuditEvents": deleted_audit,
                "deletedBackups": deleted_backups,
                "deletedJobs": deleted_jobs,
                "deletedJobArtifacts": deleted_artifacts,
                "deletedLiveEvents": deleted_live_events,
                "deletedLoginLimits": deleted_login_limits,
                "deletedRecoveryTokens": deleted_recovery_tokens,
            }, self.client_address[0])
        self.send_json({
            "ok": True,
            "deletedAuditEvents": deleted_audit,
            "deletedBackups": deleted_backups,
            "deletedJobs": deleted_jobs,
            "deletedJobArtifacts": deleted_artifacts,
            "deletedLiveEvents": deleted_live_events,
            "deletedLoginLimits": deleted_login_limits,
            "deletedRecoveryTokens": deleted_recovery_tokens,
        })

    def handle_audit_log(self):
        user = self.require_admin()
        if not user:
            return
        with conn() as db:
            if user.get("platform_admin"):
                rows = db.execute(
                    "SELECT id, ts, tenant_id, username, action, target_type, target_id, detail_json, ip, previous_hash, event_hash "
                    "FROM audit_log ORDER BY id DESC LIMIT 250"
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT id, ts, tenant_id, username, action, target_type, target_id, detail_json, ip, previous_hash, event_hash "
                    "FROM audit_log WHERE tenant_id = ? ORDER BY id DESC LIMIT 250",
                    (user["tenant_id"],),
                ).fetchall()
        self.send_json({
            "events": [
                {
                    "id": row["id"],
                    "ts": row["ts"],
                    "tenantId": row["tenant_id"],
                    "username": row["username"],
                    "action": row["action"],
                    "targetType": row["target_type"],
                    "targetId": row["target_id"],
                    "detail": json.loads(row["detail_json"] or "{}"),
                    "ip": row["ip"],
                    "previousHash": row["previous_hash"],
                    "eventHash": row["event_hash"],
                }
                for row in rows
            ]
        })

    def handle_audit_log_integrity(self):
        user = self.require_admin()
        if not user:
            return
        with conn() as db:
            result = verify_audit_hash_chain(
                db,
                tenant_id=user.get("tenant_id"),
                all_tenants=bool(user.get("platform_admin")),
            )
        result["scope"] = "platform" if user.get("platform_admin") else user.get("tenant_id")
        result["note"] = "Hash-Verkettung erkennt nachträgliche Änderungen; sie ist keine externe Zeitstempelung oder Zertifizierung."
        self.send_json(result)

    def handle_audit_log_export(self):
        user = self.require_admin()
        if not user:
            return
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        export_format = (query.get("format", ["csv"])[0] or "csv").lower()
        if export_format not in {"csv", "json"}:
            self.send_error_json(400, "unsupported export format")
            return
        try:
            limit = int(query.get("limit", ["1000"])[0] or "1000")
        except ValueError:
            limit = 1000
        limit = max(1, min(5000, limit))
        with conn() as db:
            if user.get("platform_admin"):
                rows = db.execute(
                    "SELECT id, ts, tenant_id, username, action, target_type, target_id, detail_json, ip, previous_hash, event_hash "
                    "FROM audit_log ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT id, ts, tenant_id, username, action, target_type, target_id, detail_json, ip, previous_hash, event_hash "
                    "FROM audit_log WHERE tenant_id = ? ORDER BY id DESC LIMIT ?",
                    (user["tenant_id"], limit),
                ).fetchall()
            audit(db, user, "audit_log_exported", "audit_log", export_format, {"format": export_format, "rows": len(rows), "limit": limit}, self.client_address[0])

        events = []
        for row in rows:
            try:
                detail = json.loads(row["detail_json"] or "{}")
            except Exception:
                detail = {"raw": row["detail_json"] or ""}
            events.append({
                "id": row["id"],
                "ts": row["ts"],
                "tenantId": row["tenant_id"],
                "username": row["username"],
                "action": row["action"],
                "targetType": row["target_type"],
                "targetId": row["target_id"],
                "detail": detail,
                "ip": row["ip"],
                "previousHash": row["previous_hash"],
                "eventHash": row["event_hash"],
            })

        stamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"sfm-compliance-audit-log-{stamp}.{export_format}"
        if export_format == "json":
            self.send_json(
                {"exportedAt": now(), "scope": "platform" if user.get("platform_admin") else user.get("tenant_id"), "events": events},
                extra_headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
            return

        def csv_cell(value):
            if isinstance(value, (dict, list)):
                text = json.dumps(value, ensure_ascii=False, sort_keys=True)
            else:
                text = "" if value is None else str(value)
            text = text.replace("\r", " ").replace("\n", " ")
            return f'"{text.replace(chr(34), chr(34) + chr(34))}"'

        headers = ["id", "ts", "tenant_id", "username", "action", "target_type", "target_id", "detail_json", "ip", "previous_hash", "event_hash"]
        lines = [",".join(headers)]
        for event in events:
            lines.append(",".join([
                csv_cell(event["id"]),
                csv_cell(event["ts"]),
                csv_cell(event["tenantId"]),
                csv_cell(event["username"]),
                csv_cell(event["action"]),
                csv_cell(event["targetType"]),
                csv_cell(event["targetId"]),
                csv_cell(event["detail"]),
                csv_cell(event["ip"]),
                csv_cell(event["previousHash"]),
                csv_cell(event["eventHash"]),
            ]))
        content = ("\n".join(lines) + "\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)


def main():
    init_db()
    OPERATIONS_MONITOR_STOP.clear()
    NOTIFICATION_DELIVERY_STOP.clear()
    BACKGROUND_JOB_STOP.clear()
    start_operations_monitor()
    start_notification_delivery_worker()
    start_background_job_worker()
    host = os.environ.get("ISMS_HOST", "127.0.0.1")
    port = int(os.environ.get("ISMS_PORT", "5173"))
    httpd = ThreadingHTTPServer((host, port), App)
    print(f"{APP_NAME} backend running on http://{host}:{port}/")
    print(f"Static frontend: {STATIC_BASE}")
    print(f"Database: {DATABASE.dialect}")
    print(f"File storage: {FILE_STORAGE.backend}")
    print(f"OIDC SSO providers: {len(OIDC_PROVIDERS)}")
    print(f"Malware scanning: {MALWARE_SCANNER.mode} ({'required' if MALWARE_SCANNER.required else 'optional'})")
    print(f"Operations monitor: {'enabled' if OPERATIONS_MONITOR_ENABLED else 'startup check only'} ({OPERATIONS_MONITOR_SECONDS}s)")
    print(f"Notification delivery: {'enabled' if NOTIFICATION_DELIVERY_ENABLED else 'disabled'} ({NOTIFICATION_DELIVERY_SECONDS}s)")
    print(f"Background jobs: {'enabled' if BACKGROUND_JOB_WORKER_ENABLED else 'disabled'} ({BACKGROUND_JOB_WORKER_SECONDS}s)")
    if DEV_PASS.exists():
        print(f"Local dev admin credentials are stored in: {DEV_PASS}")
    try:
        httpd.serve_forever()
    finally:
        OPERATIONS_MONITOR_STOP.set()
        NOTIFICATION_DELIVERY_STOP.set()
        BACKGROUND_JOB_STOP.set()
        httpd.server_close()


if __name__ == "__main__":
    main()
