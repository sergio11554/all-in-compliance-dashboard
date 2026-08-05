import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "production_preflight.py"
SPEC = importlib.util.spec_from_file_location("production_preflight", SCRIPT)
PREFLIGHT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = PREFLIGHT
SPEC.loader.exec_module(PREFLIGHT)


class ProductionPreflightTests(unittest.TestCase):
    def test_secure_configuration_has_no_blockers(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text("# test\n", encoding="utf-8")
            env_file.chmod(0o600)
            config = {
                "ISMS_PUBLIC_URL": "https://compliance.example.invalid",
                "ISMS_COOKIE_SECURE": "1",
                "ISMS_HSTS": "1",
                "ISMS_OIDC_ALLOW_INSECURE": "0",
                "ISMS_ADMIN_PASSWORD": "a-strong-admin-password-2026",
                "ISMS_FILE_KEY": "a-strong-file-key-secret-2026",
                "POSTGRES_PASSWORD": "a-strong-database-password-2026",
                "DATABASE_URL": "postgresql://sfm:secret@postgres:5432/sfm",
                "ISMS_STORAGE_BACKEND": "s3",
                "ISMS_S3_BUCKET": "sfm-evidence",
                "ISMS_MALWARE_SCAN_MODE": "clamav",
                "ISMS_MALWARE_SCAN_REQUIRED": "1",
                "ISMS_JOB_WORKER_ENABLED": "1",
                "ISMS_OPERATIONS_MONITOR_ENABLED": "1",
                "ISMS_OIDC_PROVIDERS_JSON": "[{}]",
                "ISMS_MFA_ENFORCEMENT": "write",
                "ISMS_MFA_REQUIRED_ROLES": "admin,consultant,manager",
                "ISMS_ACCOUNT_RECOVERY_ENABLED": "1",
                "ISMS_INVITATION_EMAIL_ENABLED": "1",
                "ISMS_NOTIFICATION_SMTP_HOST": "smtp.internal.invalid",
                "ISMS_NOTIFICATION_SMTP_FROM": "security@internal.invalid",
            }
            checks = PREFLIGHT.evaluate_config(config, env_file)
            self.assertFalse([item for item in checks if item.level == "blocker"])

    def test_demo_defaults_are_blocked(self):
        missing_env = Path("/definitely/missing/sfm/.env")
        config = {
            "ISMS_PUBLIC_URL": "http://127.0.0.1:5173",
            "ISMS_COOKIE_SECURE": "0",
            "ISMS_HSTS": "0",
            "ISMS_ADMIN_PASSWORD": "replace-with-password",
            "ISMS_FILE_KEY": "change-me",
            "POSTGRES_PASSWORD": "change-me",
            "DATABASE_URL": "",
            "ISMS_STORAGE_BACKEND": "local",
            "ISMS_MALWARE_SCAN_MODE": "disabled",
            "ISMS_MALWARE_SCAN_REQUIRED": "0",
        }
        checks = PREFLIGHT.evaluate_config(config, missing_env)
        blocker_codes = {item.code for item in checks if item.level == "blocker"}
        self.assertIn("env.exists", blocker_codes)
        self.assertIn("https.public_url", blocker_codes)
        self.assertIn("secret.isms_admin_password", blocker_codes)
        self.assertIn("database.postgres", blocker_codes)
        self.assertIn("malware.mode", blocker_codes)
        self.assertIn("malware.required", blocker_codes)
        self.assertIn("mfa.enforcement", blocker_codes)
        self.assertIn("mfa.roles", blocker_codes)
        self.assertIn("recovery.enabled", blocker_codes)
        self.assertIn("recovery.delivery", blocker_codes)

    def test_enabled_invitation_delivery_requires_smtp(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text("# test\n", encoding="utf-8")
            config = {
                "ISMS_INVITATION_EMAIL_ENABLED": "1",
                "ISMS_NOTIFICATION_SMTP_HOST": "",
                "ISMS_NOTIFICATION_SMTP_FROM": "",
            }
            checks = PREFLIGHT.evaluate_config(config, env_file)
            invitation_check = next(item for item in checks if item.code == "invitation.delivery")
            self.assertEqual(invitation_check.level, "blocker")

    def test_disabled_invitation_delivery_is_explicit_warning(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text("# test\n", encoding="utf-8")
            checks = PREFLIGHT.evaluate_config({"ISMS_INVITATION_EMAIL_ENABLED": "0"}, env_file)
            invitation_check = next(item for item in checks if item.code == "invitation.delivery")
            self.assertEqual(invitation_check.level, "warning")

    def test_environment_overrides_file_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text("ISMS_COOKIE_SECURE=0\n", encoding="utf-8")
            merged = PREFLIGHT.merged_config(env_file, {"ISMS_COOKIE_SECURE": "1"})
            self.assertEqual(merged["ISMS_COOKIE_SECURE"], "1")


if __name__ == "__main__":
    unittest.main()
