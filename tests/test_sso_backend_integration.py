import base64
import hashlib
import http.cookiejar
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    jwt = None
    rsa = None


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend_app.py"
FRONTEND = ROOT / "frontend-current"
ADMIN_PASSWORD = "SSO-Test-Admin-Password-2026!"


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class JsonClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = ""

    def request(self, method, path, payload=None, csrf=False):
        headers = {"Accept": "application/json"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if csrf:
            headers["X-CSRF-Token"] = self.csrf
        request = urllib.request.Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        raw = response.read()
        status = response.status
        response.close()
        return status, json.loads(raw.decode("utf-8")) if raw else {}

    def login(self):
        status, payload = self.request("POST", "/api/auth/login", {"username": "admin", "password": ADMIN_PASSWORD})
        self.csrf = payload.get("csrfToken", "")
        return status, payload


@unittest.skipIf(jwt is None or rsa is None, "PyJWT crypto dependencies are not installed")
class BackendSSOIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.kid = "backend-sso-test-key"
        cls.codes = {}
        cls.login_subject = "customer-person-1"
        cls.login_email = "person@sso-customer.example"
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.private_key.public_key()))
        jwk.update({"kid": cls.kid, "use": "sig", "alg": "RS256"})
        cls.jwk = jwk

        class IdentityProvider(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/jwks":
                    self.json_response({"keys": [cls.jwk]})
                    return
                if parsed.path != "/authorize":
                    self.send_response(404)
                    self.end_headers()
                    return
                query = urllib.parse.parse_qs(parsed.query)
                code = "mock-code-" + str(len(cls.codes) + 1)
                cls.codes[code] = {
                    "nonce": query["nonce"][0],
                    "challenge": query["code_challenge"][0],
                    "redirect_uri": query["redirect_uri"][0],
                }
                location = query["redirect_uri"][0] + "?" + urllib.parse.urlencode({
                    "state": query["state"][0],
                    "code": code,
                })
                self.send_response(302)
                self.send_header("Location", location)
                self.end_headers()

            def do_POST(self):
                if self.path != "/token":
                    self.send_response(404)
                    self.end_headers()
                    return
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8")
                form = urllib.parse.parse_qs(raw)
                record = cls.codes.pop(form.get("code", [""])[0], None)
                verifier = form.get("code_verifier", [""])[0]
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
                if not record or challenge != record["challenge"] or form.get("redirect_uri", [""])[0] != record["redirect_uri"]:
                    self.json_response({"error": "invalid_grant"}, status=400)
                    return
                now = int(time.time())
                token = jwt.encode(
                    {
                        "iss": cls.issuer,
                        "aud": "sfm-backend-test",
                        "sub": cls.login_subject,
                        "email": cls.login_email,
                        "email_verified": True,
                        "name": "Customer Person",
                        "nonce": record["nonce"],
                        "iat": now,
                        "exp": now + 300,
                    },
                    cls.private_key,
                    algorithm="RS256",
                    headers={"kid": cls.kid},
                )
                self.json_response({"id_token": token})

            def json_response(self, payload, status=200):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        cls.idp = ThreadingHTTPServer(("127.0.0.1", 0), IdentityProvider)
        cls.issuer = f"http://127.0.0.1:{cls.idp.server_port}"
        cls.idp_thread = threading.Thread(target=cls.idp.serve_forever, daemon=True)
        cls.idp_thread.start()

        cls.temp_dir = tempfile.TemporaryDirectory(prefix="sfm-sso-backend-")
        cls.port = free_port()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        provider = [{
            "id": "mock-sso",
            "name": "Test-Unternehmenskonto",
            "issuer": cls.issuer,
            "clientId": "sfm-backend-test",
            "tenantSlug": "sso-customer",
            "allowedDomains": ["sso-customer.example"],
            "authorizationEndpoint": f"{cls.issuer}/authorize",
            "tokenEndpoint": f"{cls.issuer}/token",
            "jwksUri": f"{cls.issuer}/jwks",
        }]
        env = os.environ.copy()
        env.update({
            "ISMS_HOST": "127.0.0.1",
            "ISMS_PORT": str(cls.port),
            "ISMS_PUBLIC_URL": cls.base_url,
            "ISMS_STATIC_BASE": str(FRONTEND),
            "ISMS_DATA_DIR": cls.temp_dir.name,
            "ISMS_ADMIN_PASSWORD": ADMIN_PASSWORD,
            "ISMS_FILE_KEY": "sso-test-file-key",
            "ISMS_OIDC_ALLOW_INSECURE": "1",
            "ISMS_OIDC_PROVIDERS_JSON": json.dumps(provider),
            "ISMS_OPERATIONS_MONITOR_ENABLED": "0",
            "ISMS_NOTIFICATION_DELIVERY_ENABLED": "0",
        })
        cls.backend = subprocess.Popen(
            [sys.executable, str(BACKEND)], cwd=ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for _ in range(80):
            try:
                with urllib.request.urlopen(cls.base_url + "/api/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("SSO test backend did not start")

    @classmethod
    def tearDownClass(cls):
        cls.backend.terminate()
        try:
            cls.backend.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.backend.kill()
            cls.backend.wait(timeout=5)
        if cls.backend.stdout:
            cls.backend.stdout.close()
        if cls.backend.stderr:
            cls.backend.stderr.close()
        cls.temp_dir.cleanup()
        cls.idp.shutdown()
        cls.idp.server_close()
        cls.idp_thread.join(timeout=3)

    def test_invited_user_can_sign_in_with_sso_and_is_tenant_bound(self):
        self.__class__.login_subject = "customer-person-1"
        self.__class__.login_email = "person@sso-customer.example"
        admin = JsonClient(self.base_url)
        self.assertEqual(admin.login()[0], 200)
        status, tenant_payload = admin.request("POST", "/api/tenants", {
            "name": "SSO Customer",
            "slug": "sso-customer",
            "adminUsername": "sso.customer.admin",
            "adminPassword": "SSO-Customer-Admin-2026!",
        }, csrf=True)
        self.assertEqual(status, 201)
        tenant_id = tenant_payload["tenant"]["id"]
        status, _ = admin.request("POST", "/api/invitations", {
            "email": "person@sso-customer.example",
            "displayName": "Customer Person",
            "role": "customer",
            "tenantId": tenant_id,
        }, csrf=True)
        self.assertEqual(status, 201)

        browser = JsonClient(self.base_url)
        with browser.opener.open(self.base_url + "/api/auth/sso/start?provider=mock-sso&next=%23dashboard", timeout=15) as response:
            self.assertEqual(response.status, 200)
            response.read()
        status, session = browser.request("GET", "/api/session")
        self.assertEqual(status, 200)
        self.assertTrue(session["authenticated"])
        self.assertEqual(session["user"]["tenant"]["id"], tenant_id)
        self.assertEqual(session["user"]["role"], "customer")
        self.assertTrue(session["user"]["ssoLinked"])

        status, invitations = admin.request("GET", "/api/invitations")
        self.assertEqual(status, 200)
        matching = [item for item in invitations["invitations"] if item["email"] == "person@sso-customer.example"]
        self.assertEqual(matching[0]["status"], "accepted")

    def test_uninvited_identity_cannot_self_register(self):
        self.__class__.login_subject = "uninvited-person-2"
        self.__class__.login_email = "uninvited@sso-customer.example"
        browser = JsonClient(self.base_url)
        with self.assertRaises(urllib.error.HTTPError) as context:
            browser.opener.open(self.base_url + "/api/auth/sso/start?provider=mock-sso", timeout=15)
        self.assertEqual(context.exception.code, 403)
        context.exception.close()
        status, session = browser.request("GET", "/api/session")
        self.assertEqual(status, 200)
        self.assertFalse(session["authenticated"])


if __name__ == "__main__":
    unittest.main()
