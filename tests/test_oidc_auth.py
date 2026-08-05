import json
import unittest
import urllib.parse

from oidc_auth import OIDCError, authorization_url, load_providers, new_login_values


def provider_payload(**overrides):
    value = {
        "id": "customer-sso",
        "name": "Unternehmenskonto",
        "issuer": "https://identity.example.com",
        "clientId": "sfm-compliance",
        "clientSecret": "not-a-real-secret",
        "tenantSlug": "customer",
        "allowedDomains": ["customer.example"],
        "authorizationEndpoint": "https://identity.example.com/authorize",
        "tokenEndpoint": "https://identity.example.com/token",
        "jwksUri": "https://identity.example.com/jwks",
    }
    value.update(overrides)
    return json.dumps([value])


class OIDCConfigurationTests(unittest.TestCase):
    def test_parses_provider_without_exposing_secret(self):
        providers = load_providers(provider_payload())
        provider = providers["customer-sso"]
        self.assertEqual(provider["tenant_slug"], "customer")
        self.assertEqual(provider["allowed_domains"], ["customer.example"])
        self.assertEqual(provider["algorithms"], ("RS256",))

    def test_requires_https_and_tenant_mapping(self):
        with self.assertRaises(OIDCError):
            load_providers(provider_payload(issuer="http://identity.example.com"))
        with self.assertRaises(OIDCError):
            load_providers(provider_payload(tenantSlug="", tenantId=""))

    def test_pkce_authorization_request(self):
        provider = load_providers(provider_payload())["customer-sso"]
        values = new_login_values()
        url = authorization_url(
            provider,
            "https://compliance.example.com/api/auth/sso/callback",
            values["state"],
            values["nonce"],
            values["challenge"],
        )
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(query["response_type"], ["code"])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["state"], [values["state"]])
        self.assertEqual(query["nonce"], [values["nonce"]])
        self.assertNotEqual(values["verifier"], values["challenge"])


if __name__ == "__main__":
    unittest.main()
