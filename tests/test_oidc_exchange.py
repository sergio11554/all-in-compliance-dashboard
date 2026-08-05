import json
import socket
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    jwt = None
    rsa = None

from oidc_auth import OIDCError, exchange_code, load_providers


@unittest.skipIf(jwt is None or rsa is None, "PyJWT crypto dependencies are not installed")
class OIDCExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.kid = "sfm-test-key"
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.private_key.public_key()))
        jwk.update({"kid": cls.kid, "use": "sig", "alg": "RS256"})
        cls.jwk = jwk
        cls.expected_nonce = "expected-test-nonce"
        cls.expected_verifier = "expected-test-verifier"

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_GET(self):
                if self.path != "/jwks":
                    self.send_response(404)
                    self.end_headers()
                    return
                payload = json.dumps({"keys": [cls.jwk]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self):
                if self.path != "/token":
                    self.send_response(404)
                    self.end_headers()
                    return
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8")
                form = urllib.parse.parse_qs(raw)
                if form.get("code_verifier") != [cls.expected_verifier]:
                    self.send_response(400)
                    self.end_headers()
                    return
                now = int(time.time())
                token = jwt.encode(
                    {
                        "iss": cls.issuer,
                        "aud": "sfm-test-client",
                        "sub": "external-user-123",
                        "email": "person@customer.example",
                        "email_verified": True,
                        "name": "Test Person",
                        "nonce": cls.expected_nonce,
                        "iat": now,
                        "exp": now + 300,
                    },
                    cls.private_key,
                    algorithm="RS256",
                    headers={"kid": cls.kid},
                )
                payload = json.dumps({"id_token": token}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.issuer = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def provider(self, domains=None):
        raw = json.dumps([{
            "id": "mock",
            "name": "Mock SSO",
            "issuer": self.issuer,
            "clientId": "sfm-test-client",
            "tenantSlug": "customer",
            "allowedDomains": domains if domains is not None else ["customer.example"],
            "authorizationEndpoint": f"{self.issuer}/authorize",
            "tokenEndpoint": f"{self.issuer}/token",
            "jwksUri": f"{self.issuer}/jwks",
        }])
        return load_providers(raw, allow_insecure=True)["mock"]

    def test_verified_signed_token_roundtrip(self):
        identity = exchange_code(
            self.provider(),
            "http://127.0.0.1/callback",
            "authorization-code",
            self.expected_verifier,
            self.expected_nonce,
        )
        self.assertEqual(identity["subject"], "external-user-123")
        self.assertEqual(identity["email"], "person@customer.example")

    def test_rejects_nonce_and_domain_mismatch(self):
        with self.assertRaises(OIDCError):
            exchange_code(
                self.provider(),
                "http://127.0.0.1/callback",
                "authorization-code",
                self.expected_verifier,
                "wrong-nonce",
            )
        with self.assertRaises(OIDCError):
            exchange_code(
                self.provider(["different.example"]),
                "http://127.0.0.1/callback",
                "authorization-code",
                self.expected_verifier,
                self.expected_nonce,
            )


if __name__ == "__main__":
    unittest.main()
