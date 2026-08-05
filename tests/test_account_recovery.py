import hashlib
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
import urllib.parse
import urllib.request
import uuid
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend_app.py"
FRONTEND = ROOT / "frontend-current"
ADMIN_PASSWORD = "Test-Recovery-Admin-Password-2026!"
USER_PASSWORD = "Cedar-Lantern-48!Quiet-River"
NEW_PASSWORD = "Silver-Harbor-73!Calm-Cloud"


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


class AccountRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="sfm-account-recovery-")
        self.data_dir = Path(self.temp_dir.name)
        self.port = free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.env = os.environ.copy()
        self.env.update({
            "ISMS_HOST": "127.0.0.1",
            "ISMS_PORT": str(self.port),
            "ISMS_PUBLIC_URL": self.base_url,
            "ISMS_STATIC_BASE": str(FRONTEND),
            "ISMS_DATA_DIR": str(self.data_dir),
            "ISMS_ADMIN_PASSWORD": ADMIN_PASSWORD,
            "ISMS_FILE_KEY": "test-recovery-file-key-do-not-use-in-production",
            "ISMS_COOKIE_SECURE": "0",
            "ISMS_HSTS": "0",
            "ISMS_MFA_ENFORCEMENT": "off",
            "ISMS_LOGIN_ACCOUNT_MAX_ATTEMPTS": "3",
            "ISMS_LOGIN_IP_MAX_ATTEMPTS": "50",
            "ISMS_LOGIN_ATTEMPT_WINDOW_SECONDS": "900",
            "ISMS_LOGIN_LOCK_SECONDS": "60",
            "ISMS_ACCOUNT_RECOVERY_ENABLED": "1",
            "ISMS_ACCOUNT_RECOVERY_TOKEN_SECONDS": "3600",
            "ISMS_OPERATIONS_MONITOR_ENABLED": "0",
            "ISMS_NOTIFICATION_DELIVERY_ENABLED": "0",
            "ISMS_JOB_WORKER_ENABLED": "0",
        })
        self.process = None
        self.start_server()

    def tearDown(self):
        self.stop_server()
        self.temp_dir.cleanup()

    def start_server(self):
        self.process = subprocess.Popen(
            [sys.executable, str(BACKEND)],
            cwd=ROOT,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.time() + 12
        while time.time() < deadline:
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate(timeout=2)
                raise RuntimeError(f"Recovery test server stopped early.\nstdout: {stdout}\nstderr: {stderr}")
            try:
                with urllib.request.urlopen(f"{self.base_url}/api/health", timeout=1) as response:
                    if response.status == 200:
                        return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("Recovery test server did not become ready")

    def stop_server(self):
        if not self.process:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if self.process.stdout:
            self.process.stdout.close()
        if self.process.stderr:
            self.process.stderr.close()
        self.process = None

    def create_user(self):
        admin = ApiClient(self.base_url)
        status, _ = admin.login("admin", ADMIN_PASSWORD)
        self.assertEqual(status, 200)
        status, payload = admin.request(
            "POST",
            "/api/users",
            {
                "username": "recovery.user",
                "email": "recovery.user@example.invalid",
                "password": USER_PASSWORD,
                "role": "viewer",
            },
            csrf=True,
        )
        self.assertEqual(status, 201)
        return int(payload["user"]["id"])

    def test_persistent_lock_and_one_time_recovery(self):
        user_id = self.create_user()
        anonymous = ApiClient(self.base_url)

        for expected in (401, 401, 429):
            status, _ = anonymous.login("recovery.user", "definitely-wrong-password")
            self.assertEqual(status, expected)

        self.stop_server()
        self.start_server()
        status, locked = ApiClient(self.base_url).login("recovery.user", USER_PASSWORD)
        self.assertEqual(status, 429)
        self.assertEqual(locked["code"], "login_temporarily_locked")
        self.assertGreater(locked["retryAfter"], 0)

        admin = ApiClient(self.base_url)
        status, _ = admin.login("admin", ADMIN_PASSWORD)
        self.assertEqual(status, 200)
        status, unlocked = admin.request(
            "POST", f"/api/users/{user_id}/unlock", {}, csrf=True
        )
        self.assertEqual(status, 200)
        self.assertTrue(unlocked["wasLocked"])

        active_session = ApiClient(self.base_url)
        status, _ = active_session.login("recovery.user", USER_PASSWORD)
        self.assertEqual(status, 200)

        database_path = self.data_dir / "isms.db"
        token = "recovery-test-token-" + uuid.uuid4().hex
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        current = int(time.time())
        with closing(sqlite3.connect(database_path)) as db:
            db.execute(
                "INSERT INTO password_reset_tokens (id,token_hash,user_id,requested_at,expires_at,requested_ip_hash,delivered_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, token_hash, user_id, current, current + 3600, "test-ip-hash", current),
            )
            db.commit()

        encoded_token = urllib.parse.quote(token, safe="")
        status, info = ApiClient(self.base_url).request(
            "GET", f"/api/auth/recovery?token={encoded_token}"
        )
        self.assertEqual(status, 200)
        self.assertTrue(info["valid"])
        self.assertNotIn("recovery.user@example.invalid", info["accountHint"])

        status, result = ApiClient(self.base_url).request(
            "POST",
            "/api/auth/recovery/confirm",
            {"token": token, "newPassword": NEW_PASSWORD},
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["mfaPreserved"])
        self.assertGreaterEqual(result["sessionsRevoked"], 1)

        status, _ = active_session.request("GET", "/api/state")
        self.assertEqual(status, 401)
        status, _ = ApiClient(self.base_url).login("recovery.user", USER_PASSWORD)
        self.assertEqual(status, 401)
        status, _ = ApiClient(self.base_url).login("recovery.user", NEW_PASSWORD)
        self.assertEqual(status, 200)

        status, _ = ApiClient(self.base_url).request(
            "POST",
            "/api/auth/recovery/confirm",
            {"token": token, "newPassword": "Another-Recovery-Password-2026!"},
        )
        self.assertEqual(status, 404)

    def test_recovery_request_does_not_disclose_accounts(self):
        self.create_user()
        client = ApiClient(self.base_url)
        existing_status, existing = client.request(
            "POST", "/api/auth/recovery/request", {"identifier": "recovery.user"}
        )
        missing_status, missing = client.request(
            "POST", "/api/auth/recovery/request", {"identifier": "does.not.exist"}
        )
        self.assertEqual(existing_status, 202)
        self.assertEqual(missing_status, 202)
        self.assertEqual(existing, missing)


if __name__ == "__main__":
    unittest.main(verbosity=2)
