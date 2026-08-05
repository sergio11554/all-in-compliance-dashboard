import http.cookiejar
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend_app.py"
FRONTEND = ROOT / "frontend-current"
ADMIN_PASSWORD = "Password-Policy-Admin-2026!"
TEMP_PASSWORD = "Cedar-Lantern-48!Quiet-River"
FINAL_PASSWORD = "Silver-Harbor-73!Calm-Cloud"
RESET_PASSWORD = "Amber-Forest-91!Clear-Stone"


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ApiClient:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )
        self.csrf = ""

    def request(self, method, path, payload=None, csrf=False):
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if csrf and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=body, headers=headers, method=method
        )
        try:
            response = self.opener.open(request, timeout=8)
        except urllib.error.HTTPError as error:
            response = error
        raw = response.read()
        status = response.status
        content_type = response.headers.get("Content-Type", "")
        response.close()
        parsed = json.loads(raw.decode("utf-8")) if raw and "json" in content_type else raw
        return status, parsed

    def login(self, username, password):
        status, payload = self.request(
            "POST", "/api/auth/login", {"username": username, "password": password}
        )
        if status == 200:
            self.csrf = payload.get("csrfToken", "")
        return status, payload


class PasswordPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="sfm-password-policy-")
        cls.data_dir = Path(cls.temp_dir.name)
        cls.port = free_port()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        env = os.environ.copy()
        env.update({
            "ISMS_HOST": "127.0.0.1",
            "ISMS_PORT": str(cls.port),
            "ISMS_PUBLIC_URL": cls.base_url,
            "ISMS_STATIC_BASE": str(FRONTEND),
            "ISMS_DATA_DIR": str(cls.data_dir),
            "ISMS_ADMIN_PASSWORD": ADMIN_PASSWORD,
            "ISMS_FILE_KEY": "test-password-policy-file-key-not-for-production",
            "ISMS_COOKIE_SECURE": "0",
            "ISMS_HSTS": "0",
            "ISMS_MFA_ENFORCEMENT": "off",
            "ISMS_PASSWORD_MIN_LENGTH": "14",
            "ISMS_PASSWORD_MAX_LENGTH": "128",
            "ISMS_PASSWORD_HISTORY_COUNT": "3",
            "ISMS_OPERATIONS_MONITOR_ENABLED": "0",
            "ISMS_NOTIFICATION_DELIVERY_ENABLED": "0",
            "ISMS_JOB_WORKER_ENABLED": "0",
        })
        cls.process = subprocess.Popen(
            [sys.executable, str(BACKEND)],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.time() + 12
        while time.time() < deadline:
            if cls.process.poll() is not None:
                stdout, stderr = cls.process.communicate(timeout=2)
                raise RuntimeError(
                    f"Password policy test server stopped early.\nstdout: {stdout}\nstderr: {stderr}"
                )
            try:
                with urllib.request.urlopen(f"{cls.base_url}/api/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("Password policy test server did not become ready")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "process", None):
            cls.process.terminate()
            try:
                cls.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.process.kill()
                cls.process.wait(timeout=5)
            if cls.process.stdout:
                cls.process.stdout.close()
            if cls.process.stderr:
                cls.process.stderr.close()
        if getattr(cls, "temp_dir", None):
            cls.temp_dir.cleanup()

    def test_policy_first_change_history_and_admin_reset(self):
        anonymous = ApiClient(self.base_url)
        status, session = anonymous.request("GET", "/api/session")
        self.assertEqual(status, 200)
        self.assertEqual(session["passwordPolicy"]["minLength"], 14)
        self.assertEqual(session["passwordPolicy"]["historyCount"], 3)
        self.assertFalse(session["passwordPolicy"]["compositionRequired"])

        admin = ApiClient(self.base_url)
        status, _ = admin.login("admin", ADMIN_PASSWORD)
        self.assertEqual(status, 200)

        status, rejected = admin.request(
            "POST",
            "/api/users",
            {"username": "short.password", "password": "too-short", "role": "admin"},
            csrf=True,
        )
        self.assertEqual(status, 400)
        self.assertEqual(rejected["code"], "password_too_short")

        status, rejected = admin.request(
            "POST",
            "/api/users",
            {
                "username": "policy.operator",
                "email": "policy.operator@example.invalid",
                "password": "PolicyOperator-Temporary-2026!",
                "role": "admin",
            },
            csrf=True,
        )
        self.assertEqual(status, 400)
        self.assertEqual(rejected["code"], "password_contains_account_identity")

        status, created = admin.request(
            "POST",
            "/api/users",
            {
                "username": "policy.operator",
                "email": "policy.operator@example.invalid",
                "password": TEMP_PASSWORD,
                "role": "admin",
            },
            csrf=True,
        )
        self.assertEqual(status, 201)
        self.assertTrue(created["user"]["passwordChangeRequired"])
        user_id = int(created["user"]["id"])

        user = ApiClient(self.base_url)
        status, login = user.login("policy.operator", TEMP_PASSWORD)
        self.assertEqual(status, 200)
        self.assertTrue(login["user"]["passwordChangeRequired"])
        self.assertFalse(login["user"]["writeAllowed"])

        status, _ = user.request("GET", "/api/state")
        self.assertEqual(status, 200)
        status, blocked = user.request(
            "POST",
            f"/api/users/{user_id}/sessions/revoke",
            {},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(blocked["code"], "password_change_required")

        status, changed = user.request(
            "POST",
            "/api/users/me/password",
            {"currentPassword": TEMP_PASSWORD, "newPassword": FINAL_PASSWORD},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertFalse(changed["user"]["passwordChangeRequired"])
        self.assertTrue(changed["user"]["writeAllowed"])

        status, saved = user.request(
            "POST",
            f"/api/users/{user_id}/sessions/revoke",
            {},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertTrue(saved["ok"])

        status, reused = user.request(
            "POST",
            "/api/users/me/password",
            {"currentPassword": FINAL_PASSWORD, "newPassword": TEMP_PASSWORD},
            csrf=True,
        )
        self.assertEqual(status, 400)
        self.assertEqual(reused["code"], "password_recently_used")

        status, reset = admin.request(
            "PUT",
            f"/api/users/{user_id}",
            {"password": RESET_PASSWORD},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertTrue(reset["ok"])

        status, _ = user.request("GET", "/api/state")
        self.assertEqual(status, 401)
        status, reset_login = ApiClient(self.base_url).login("policy.operator", RESET_PASSWORD)
        self.assertEqual(status, 200)
        self.assertTrue(reset_login["user"]["passwordChangeRequired"])

        status, users = admin.request("GET", "/api/users")
        self.assertEqual(status, 200)
        account = next(item for item in users["users"] if item["id"] == user_id)
        self.assertTrue(account["passwordChangeRequired"])

        with closing(sqlite3.connect(self.data_dir / "isms.db")) as db:
            history_count = db.execute(
                "SELECT COUNT(*) FROM password_history WHERE user_id = ?", (user_id,)
            ).fetchone()[0]
            required = db.execute(
                "SELECT password_change_required FROM users WHERE id = ?", (user_id,)
            ).fetchone()[0]
        self.assertEqual(history_count, 2)
        self.assertEqual(required, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
