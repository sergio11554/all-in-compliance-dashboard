import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend_app.py"
FRONTEND = ROOT / "frontend-current"
ADMIN_PASSWORD = "Test-MFA-Admin-Password-2026!"


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def totp_code(secret):
    padded = secret.replace(" ", "").upper()
    padded += "=" * (-len(padded) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // 30)
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


class ApiClient:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        self.csrf = ""

    def request(self, method, path, payload=None, csrf=False):
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if csrf and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        request = urllib.request.Request(f"{self.base_url}{path}", data=body, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        raw = response.read()
        status = response.status
        content_type = response.headers.get("Content-Type", "")
        response.close()
        payload = json.loads(raw.decode("utf-8")) if raw and "json" in content_type else raw
        return status, payload

    def login(self):
        status, payload = self.request(
            "POST",
            "/api/auth/login",
            {"username": "admin", "password": ADMIN_PASSWORD},
        )
        if status == 200:
            self.csrf = payload.get("csrfToken", "")
        return status, payload


class MfaWriteEnforcementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="sfm-mfa-policy-")
        cls.port = free_port()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        env = os.environ.copy()
        env.update({
            "ISMS_HOST": "127.0.0.1",
            "ISMS_PORT": str(cls.port),
            "ISMS_PUBLIC_URL": cls.base_url,
            "ISMS_STATIC_BASE": str(FRONTEND),
            "ISMS_DATA_DIR": cls.temp_dir.name,
            "ISMS_ADMIN_PASSWORD": ADMIN_PASSWORD,
            "ISMS_FILE_KEY": "test-mfa-file-key-do-not-use-in-production",
            "ISMS_COOKIE_SECURE": "0",
            "ISMS_HSTS": "0",
            "ISMS_MFA_ENFORCEMENT": "write",
            "ISMS_MFA_REQUIRED_ROLES": "admin,consultant,manager",
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
                raise RuntimeError(f"MFA test server stopped early.\nstdout: {stdout}\nstderr: {stderr}")
            try:
                with urllib.request.urlopen(f"{cls.base_url}/api/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("MFA test server did not become ready")

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

    def test_privileged_write_requires_mfa_but_enrollment_remains_available(self):
        client = ApiClient(self.base_url)
        status, login = client.login()
        self.assertEqual(status, 200)
        self.assertTrue(login["user"]["mfaRequired"])
        self.assertFalse(login["user"]["writeAllowed"])

        status, state = client.request("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertIn("state", state)

        status, policy = client.request("GET", "/api/access-policy")
        self.assertEqual(status, 200)
        self.assertEqual(policy["accessPolicy"]["mfaEnforcement"], "write")
        self.assertFalse(policy["accessPolicy"]["currentUser"]["writeAllowed"])

        status, blocked = client.request("POST", "/api/backups", {}, csrf=True)
        self.assertEqual(status, 403)
        self.assertEqual(blocked["code"], "mfa_enrollment_required")
        self.assertTrue(blocked["mfaEnrollmentRequired"])

        status, setup = client.request("POST", "/api/mfa/setup", {}, csrf=True)
        self.assertEqual(status, 200)
        self.assertTrue(setup["secret"])

        status, enabled = client.request(
            "POST",
            "/api/mfa/enable",
            {"code": totp_code(setup["secret"])},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertTrue(enabled["ok"])

        status, session = client.request("GET", "/api/session")
        self.assertEqual(status, 200)
        self.assertTrue(session["user"]["mfaEnabled"])
        self.assertTrue(session["user"]["writeAllowed"])

        status, backup = client.request("POST", "/api/backups", {}, csrf=True)
        self.assertEqual(status, 200)
        self.assertTrue(backup["ok"])


if __name__ == "__main__":
    unittest.main()
