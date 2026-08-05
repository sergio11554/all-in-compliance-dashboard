#!/usr/bin/env python3
import http.cookiejar
import json
import os
import secrets
import urllib.error
import urllib.request


BASE_URL = os.environ.get("SFM_SMOKE_BASE_URL", "http://127.0.0.1:5188").rstrip("/")
ADMIN_PASSWORD = os.environ.get("ISMS_ADMIN_PASSWORD", "")


class Client:
    def __init__(self):
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        self.csrf = ""

    def request(self, method, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        request = urllib.request.Request(f"{BASE_URL}{path}", data=data, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        raw = response.read()
        body = json.loads(raw.decode("utf-8")) if raw else {}
        if response.status >= 400:
            raise RuntimeError(f"{method} {path} failed with {response.status}: {body}")
        return body


def main():
    if not ADMIN_PASSWORD:
        raise SystemExit("ISMS_ADMIN_PASSWORD is required")
    client = Client()
    health = client.request("GET", "/api/health")
    if health.get("database") != "postgres":
        raise RuntimeError(f"expected postgres health status, got {health}")

    login = client.request("POST", "/api/auth/login", {
        "username": "admin",
        "password": ADMIN_PASSWORD,
    })
    client.csrf = login["csrfToken"]
    current = client.request("GET", "/api/state")
    workspace = current.get("state") or {
        "documents": [],
        "assets": [],
        "risks": [],
        "legal": [],
        "suppliers": [],
        "policies": [],
        "incidents": [],
        "contracts": [],
        "integrations": [],
        "tasks": [],
        "projectPlan": [],
        "templateDrafts": [],
    }
    workspace["tasks"] = [{"id": "postgres-smoke", "title": "PostgreSQL Smoke Test"}]
    saved = client.request("PUT", "/api/state", {
        "state": workspace,
        "expectedRevision": current.get("revision"),
    })
    loaded = client.request("GET", "/api/state")
    if loaded["state"]["tasks"][0]["id"] != "postgres-smoke":
        raise RuntimeError("workspace did not persist in PostgreSQL")

    smoke_suffix = secrets.token_hex(4)
    tenant_slug = f"postgres-smoke-{smoke_suffix}"
    tenant = client.request("POST", "/api/tenants", {
        "name": "PostgreSQL Smoke Tenant",
        "slug": tenant_slug,
        "adminUsername": f"postgres.smoke.{smoke_suffix}",
        "adminPassword": f"Smoke-{secrets.token_urlsafe(24)}-A1!",
    })
    integrity = client.request("GET", "/api/audit-log/integrity")
    if not integrity.get("valid"):
        raise RuntimeError(f"audit hash chain is invalid: {integrity}")

    print(json.dumps({
        "database": health["database"],
        "workspaceRevision": saved["revision"],
        "tenantCreated": tenant["tenant"]["slug"],
        "auditIntegrity": True,
        "auditEventsChecked": integrity["checkedEvents"],
    }))


if __name__ == "__main__":
    main()
