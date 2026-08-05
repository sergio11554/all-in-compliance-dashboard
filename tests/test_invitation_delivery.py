import email
import http.cookiejar
import json
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from email import policy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend_app.py"
FRONTEND = ROOT / "frontend-current"
ADMIN_PASSWORD = "Invitation-Admin-2026!Secure-Harbor"
INVITED_PASSWORD = "Calm-River-82!Invitation-Access"


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestSmtpHandler(socketserver.StreamRequestHandler):
    def write_reply(self, value):
        self.wfile.write(value)
        self.wfile.flush()

    def handle(self):
        self.write_reply(b"220 localhost SFM test SMTP\r\n")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            command = line.decode("utf-8", errors="replace").strip()
            upper = command.upper()
            if upper.startswith(("EHLO", "HELO")):
                self.write_reply(b"250-localhost\r\n250-8BITMIME\r\n250 SIZE 10485760\r\n")
            elif upper.startswith("MAIL FROM:"):
                self.write_reply(b"250 sender accepted\r\n")
            elif upper.startswith("RCPT TO:"):
                self.write_reply(b"250 recipient accepted\r\n")
            elif upper == "DATA":
                self.write_reply(b"354 end with <CRLF>.<CRLF>\r\n")
                chunks = []
                while True:
                    data_line = self.rfile.readline()
                    if data_line in {b".\r\n", b".\n", b""}:
                        break
                    if data_line.startswith(b".."):
                        data_line = data_line[1:]
                    chunks.append(data_line)
                with self.server.message_lock:
                    self.server.messages.append(b"".join(chunks))
                self.write_reply(b"250 queued\r\n")
            elif upper == "RSET":
                self.write_reply(b"250 reset\r\n")
            elif upper == "NOOP":
                self.write_reply(b"250 ok\r\n")
            elif upper == "QUIT":
                self.write_reply(b"221 bye\r\n")
                return
            else:
                self.write_reply(b"250 ok\r\n")


class TestSmtpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address):
        super().__init__(server_address, TestSmtpHandler)
        self.messages = []
        self.message_lock = threading.Lock()


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


class InvitationDeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="sfm-invitation-delivery-")
        cls.data_dir = Path(cls.temp_dir.name)
        cls.smtp = TestSmtpServer(("127.0.0.1", 0))
        cls.smtp_thread = threading.Thread(target=cls.smtp.serve_forever, daemon=True)
        cls.smtp_thread.start()
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
            "ISMS_FILE_KEY": "test-invitation-file-key-not-for-production",
            "ISMS_COOKIE_SECURE": "0",
            "ISMS_HSTS": "0",
            "ISMS_MFA_ENFORCEMENT": "off",
            "ISMS_OPERATIONS_MONITOR_ENABLED": "0",
            "ISMS_NOTIFICATION_DELIVERY_ENABLED": "0",
            "ISMS_JOB_WORKER_ENABLED": "0",
            "ISMS_INVITATION_EMAIL_ENABLED": "1",
            "ISMS_NOTIFICATION_SMTP_HOST": "127.0.0.1",
            "ISMS_NOTIFICATION_SMTP_PORT": str(cls.smtp.server_address[1]),
            "ISMS_NOTIFICATION_SMTP_FROM": "security@sfm.test",
            "ISMS_NOTIFICATION_SMTP_TLS": "0",
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
                    f"Invitation test server stopped early.\nstdout: {stdout}\nstderr: {stderr}"
                )
            try:
                with urllib.request.urlopen(f"{cls.base_url}/api/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("Invitation test server did not become ready")

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
        if getattr(cls, "smtp", None):
            cls.smtp.shutdown()
            cls.smtp.server_close()
        if getattr(cls, "smtp_thread", None):
            cls.smtp_thread.join(timeout=3)
        if getattr(cls, "temp_dir", None):
            cls.temp_dir.cleanup()

    def test_secure_delivery_rotation_acceptance_and_audit(self):
        admin = ApiClient(self.base_url)
        status, _ = admin.login("admin", ADMIN_PASSWORD)
        self.assertEqual(status, 200)

        invite_email = "invited.person@customer.test"
        status, created = admin.request(
            "POST",
            "/api/invitations",
            {
                "displayName": "Invited Person",
                "email": invite_email,
                "role": "customer",
                "expiresDays": 7,
            },
            csrf=True,
        )
        self.assertEqual(status, 201)
        self.assertTrue(created["deliveryConfigured"])
        self.assertEqual(created["invitation"]["deliveryStatus"], "delivered")
        invitation_id = created["invitation"]["id"]
        first_url = created["invitation"]["acceptUrl"]
        first_token = urllib.parse.parse_qs(urllib.parse.urlparse(first_url).fragment)["invite"][0]

        self.assertEqual(len(self.smtp.messages), 1)
        first_message = email.message_from_bytes(self.smtp.messages[0], policy=policy.default)
        self.assertEqual(first_message["To"], invite_email)
        self.assertIn("Einladung", first_message["Subject"])
        self.assertIn(first_url, first_message.get_content())

        status, listed = admin.request("GET", "/api/invitations")
        self.assertEqual(status, 200)
        listed_invitation = next(item for item in listed["invitations"] if item["id"] == invitation_id)
        self.assertEqual(listed_invitation["deliveryStatus"], "delivered")
        self.assertEqual(listed_invitation["deliveryAttempts"], 1)
        self.assertNotIn("acceptUrl", listed_invitation)

        status, duplicate = admin.request(
            "POST",
            "/api/invitations",
            {"email": invite_email, "role": "customer"},
            csrf=True,
        )
        self.assertEqual(status, 409)
        self.assertEqual(duplicate["code"], "invitation_already_pending")

        status, first_info = ApiClient(self.base_url).request(
            "GET", f"/api/invitations/accept?token={urllib.parse.quote(first_token)}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(first_info["invitation"]["email"], invite_email)

        status, reissued = admin.request(
            "POST",
            f"/api/invitations/{invitation_id}/resend",
            {"expiresDays": 7},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(reissued["invitation"]["deliveryStatus"], "delivered")
        second_url = reissued["invitation"]["acceptUrl"]
        self.assertNotEqual(first_url, second_url)
        second_token = urllib.parse.parse_qs(urllib.parse.urlparse(second_url).fragment)["invite"][0]
        self.assertEqual(len(self.smtp.messages), 2)

        status, _ = ApiClient(self.base_url).request(
            "GET", f"/api/invitations/accept?token={urllib.parse.quote(first_token)}"
        )
        self.assertEqual(status, 404)
        status, _ = ApiClient(self.base_url).request(
            "GET", f"/api/invitations/accept?token={urllib.parse.quote(second_token)}"
        )
        self.assertEqual(status, 200)

        invited = ApiClient(self.base_url)
        status, accepted = invited.request(
            "POST",
            "/api/invitations/accept",
            {
                "token": second_token,
                "username": "invited.operator",
                "password": INVITED_PASSWORD,
            },
        )
        self.assertEqual(status, 201)
        self.assertTrue(accepted["authenticated"])
        self.assertEqual(accepted["user"]["role"], "customer")
        self.assertFalse(accepted["user"]["passwordChangeRequired"])

        status, _ = ApiClient(self.base_url).request(
            "POST",
            "/api/invitations/accept",
            {
                "token": second_token,
                "username": "replay.operator",
                "password": "Another-Calm-River-91!Replay",
            },
        )
        self.assertEqual(status, 409)

        status, audit_payload = admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        actions = {event["action"] for event in audit_payload["events"]}
        self.assertTrue({
            "invitation_created",
            "invitation_delivered",
            "invitation_reissued",
            "invitation_accepted",
        }.issubset(actions))

        status, final_list = admin.request("GET", "/api/invitations")
        self.assertEqual(status, 200)
        final_invitation = next(item for item in final_list["invitations"] if item["id"] == invitation_id)
        self.assertEqual(final_invitation["status"], "accepted")
        self.assertEqual(final_invitation["deliveryAttempts"], 2)


if __name__ == "__main__":
    unittest.main()
