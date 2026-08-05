import base64
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.parse
import urllib.request


class OIDCError(RuntimeError):
    pass


_DISCOVERY_CACHE = {}
_DISCOVERY_LOCK = threading.Lock()


def _bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _safe_id(value):
    text = str(value or "").strip()
    if not text or len(text) > 80 or not all(char.isalnum() or char in "-_" for char in text):
        raise OIDCError("OIDC provider id must contain only letters, numbers, '-' or '_'")
    return text


def _https_url(value, label, allow_insecure=False):
    text = str(value or "").strip().rstrip("/")
    parsed = urllib.parse.urlparse(text)
    if not parsed.netloc or parsed.scheme not in ({"http", "https"} if allow_insecure else {"https"}):
        raise OIDCError(f"{label} must be an HTTPS URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise OIDCError(f"{label} contains unsupported URL components")
    return text


def load_providers(raw=None, allow_insecure=None):
    raw = os.environ.get("ISMS_OIDC_PROVIDERS_JSON", "") if raw is None else raw
    if not str(raw or "").strip():
        return {}
    allow_insecure = _bool(os.environ.get("ISMS_OIDC_ALLOW_INSECURE", "0")) if allow_insecure is None else allow_insecure
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OIDCError("ISMS_OIDC_PROVIDERS_JSON is not valid JSON") from exc
    if not isinstance(values, list):
        raise OIDCError("ISMS_OIDC_PROVIDERS_JSON must contain a JSON array")
    providers = {}
    for value in values:
        if not isinstance(value, dict):
            raise OIDCError("each OIDC provider must be a JSON object")
        provider_id = _safe_id(value.get("id"))
        if provider_id in providers:
            raise OIDCError(f"duplicate OIDC provider id: {provider_id}")
        issuer = _https_url(value.get("issuer"), "issuer", allow_insecure)
        client_id = str(value.get("clientId") or "").strip()
        if not client_id:
            raise OIDCError(f"clientId is required for OIDC provider {provider_id}")
        tenant_id = str(value.get("tenantId") or "").strip()
        tenant_slug = str(value.get("tenantSlug") or "").strip()
        if not tenant_id and not tenant_slug:
            raise OIDCError(f"tenantId or tenantSlug is required for OIDC provider {provider_id}")
        domains = value.get("allowedDomains") or []
        if isinstance(domains, str):
            domains = [item.strip() for item in domains.split(",") if item.strip()]
        if not isinstance(domains, list):
            raise OIDCError(f"allowedDomains must be an array for OIDC provider {provider_id}")
        endpoints = {}
        for source, target in (
            ("authorizationEndpoint", "authorization_endpoint"),
            ("tokenEndpoint", "token_endpoint"),
            ("jwksUri", "jwks_uri"),
        ):
            if value.get(source):
                endpoints[target] = _https_url(value[source], source, allow_insecure)
        providers[provider_id] = {
            "id": provider_id,
            "name": str(value.get("name") or provider_id).strip()[:120],
            "issuer": issuer,
            "client_id": client_id,
            "client_secret": str(value.get("clientSecret") or ""),
            "tenant_id": tenant_id,
            "tenant_slug": tenant_slug,
            "allowed_domains": sorted({str(item).strip().lower().lstrip("@") for item in domains if str(item).strip()}),
            "default_role": str(value.get("defaultRole") or "customer").strip(),
            "require_verified_email": _bool(value.get("requireVerifiedEmail"), True),
            "token_auth_method": str(value.get("tokenAuthMethod") or "client_secret_basic").strip(),
            "scopes": str(value.get("scopes") or "openid profile email").strip(),
            "algorithms": tuple(value.get("algorithms") or ["RS256"]),
            "endpoints": endpoints,
            "allow_insecure": bool(allow_insecure),
        }
    return providers


def public_provider(provider, tenant_name=""):
    return {
        "id": provider["id"],
        "name": provider["name"],
        "tenantName": tenant_name,
    }


def _fetch_json(url, headers=None, body=None, timeout=8):
    request = urllib.request.Request(url, data=body, headers=headers or {}, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status < 200 or response.status >= 300:
                raise OIDCError(f"OIDC endpoint returned HTTP {response.status}")
            return json.loads(response.read().decode("utf-8"))
    except OIDCError:
        raise
    except Exception as exc:
        raise OIDCError("OIDC provider could not be reached") from exc


def provider_configuration(provider):
    if {"authorization_endpoint", "token_endpoint", "jwks_uri"}.issubset(provider["endpoints"]):
        return {"issuer": provider["issuer"], **provider["endpoints"]}
    with _DISCOVERY_LOCK:
        cached = _DISCOVERY_CACHE.get(provider["issuer"])
        if cached and cached[0] > time.time():
            return cached[1]
    discovery_url = f"{provider['issuer']}/.well-known/openid-configuration"
    config = _fetch_json(discovery_url)
    if str(config.get("issuer") or "").rstrip("/") != provider["issuer"]:
        raise OIDCError("OIDC discovery issuer does not match configuration")
    normalized = {"issuer": provider["issuer"]}
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        normalized[key] = _https_url(config.get(key), key, provider["allow_insecure"])
    with _DISCOVERY_LOCK:
        _DISCOVERY_CACHE[provider["issuer"]] = (time.time() + 3600, normalized)
    return normalized


def new_login_values():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
    return {
        "state": secrets.token_urlsafe(32),
        "nonce": secrets.token_urlsafe(32),
        "verifier": verifier,
        "challenge": challenge,
    }


def authorization_url(provider, callback_url, state, nonce, challenge):
    config = provider_configuration(provider)
    query = urllib.parse.urlencode({
        "client_id": provider["client_id"],
        "response_type": "code",
        "redirect_uri": callback_url,
        "scope": provider["scopes"],
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    return f"{config['authorization_endpoint']}?{query}"


def exchange_code(provider, callback_url, code, verifier, expected_nonce):
    config = provider_configuration(provider)
    fields = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": callback_url,
        "client_id": provider["client_id"],
        "code_verifier": verifier,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    if provider["client_secret"]:
        if provider["token_auth_method"] == "client_secret_post":
            fields["client_secret"] = provider["client_secret"]
        elif provider["token_auth_method"] == "client_secret_basic":
            credential = f"{provider['client_id']}:{provider['client_secret']}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(credential).decode("ascii")
        else:
            raise OIDCError("unsupported OIDC token authentication method")
    tokens = _fetch_json(config["token_endpoint"], headers, urllib.parse.urlencode(fields).encode("utf-8"))
    id_token = str(tokens.get("id_token") or "")
    if not id_token:
        raise OIDCError("OIDC token response did not contain an id_token")
    try:
        import jwt

        header = jwt.get_unverified_header(id_token)
        algorithm = str(header.get("alg") or "")
        if algorithm not in provider["algorithms"] or algorithm.startswith("HS") or algorithm == "none":
            raise OIDCError("OIDC id_token uses an unsupported signing algorithm")
        signing_key = jwt.PyJWKClient(config["jwks_uri"], timeout=8).get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=list(provider["algorithms"]),
            audience=provider["client_id"],
            issuer=provider["issuer"],
            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
        )
    except OIDCError:
        raise
    except Exception as exc:
        raise OIDCError("OIDC id_token verification failed") from exc
    if not secrets.compare_digest(str(claims.get("nonce") or ""), str(expected_nonce or "")):
        raise OIDCError("OIDC nonce verification failed")
    email = str(claims.get("email") or "").strip().lower()
    if not email or "@" not in email:
        raise OIDCError("OIDC provider did not return an email address")
    if provider["require_verified_email"] and claims.get("email_verified") is not True:
        raise OIDCError("OIDC email address is not verified")
    if provider["allowed_domains"] and email.rsplit("@", 1)[1] not in provider["allowed_domains"]:
        raise OIDCError("email domain is not allowed for this customer workspace")
    return {
        "subject": str(claims["sub"]),
        "email": email,
        "name": str(claims.get("name") or email).strip()[:160],
    }
