#!/usr/bin/env python3
"""Run a tenant-scoped acceptance flow against an already running backend."""

import hashlib
import http.cookiejar
import io
import json
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
import zipfile


BASE_URL = os.environ.get("SFM_ACCEPTANCE_BASE_URL", "http://127.0.0.1:5190").rstrip("/")
ADMIN_PASSWORD = os.environ.get("ISMS_ADMIN_PASSWORD", "")
EXPECTED_DATABASE = os.environ.get("SFM_ACCEPTANCE_EXPECT_DATABASE", "").strip()
EXPECTED_STORAGE = os.environ.get("SFM_ACCEPTANCE_EXPECT_STORAGE", "").strip()
EXPECTED_MALWARE = os.environ.get("SFM_ACCEPTANCE_EXPECT_MALWARE", "").strip()


class AcceptanceError(RuntimeError):
    pass


class Client:
    def __init__(self):
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
        )
        self.csrf = ""

    def request(self, method, path, payload=None, body=None, headers=None):
        request_headers = {"Accept": "application/json", **(headers or {})}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        if self.csrf:
            request_headers["X-CSRF-Token"] = self.csrf
        request = urllib.request.Request(
            f"{BASE_URL}{path}", data=body, headers=request_headers, method=method
        )
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        raw = response.read()
        status = response.status
        content_type = response.headers.get("Content-Type", "")
        response.close()
        if raw and "json" in content_type:
            parsed = json.loads(raw.decode("utf-8"))
        else:
            parsed = raw
        return status, parsed, content_type

    def expect(self, method, path, expected, payload=None, body=None, headers=None):
        status, response, content_type = self.request(
            method, path, payload=payload, body=body, headers=headers
        )
        if status != expected:
            raise AcceptanceError(
                f"{method} {path} returned {status}, expected {expected}: {response!r}"
            )
        return response, content_type

    def login(self, username, password):
        response, _ = self.expect(
            "POST",
            "/api/auth/login",
            200,
            payload={"username": username, "password": password},
        )
        self.csrf = response.get("csrfToken", "")
        if not self.csrf:
            raise AcceptanceError(f"login for {username} did not return a CSRF token")
        return response


def random_password(label):
    return f"Acceptance-{label}-{secrets.token_hex(10)}-A9!"


def create_tenant(platform_admin, suffix, label):
    username = f"acceptance.{label.lower()}.{suffix}"
    temporary_password = random_password(f"{label}-temporary")
    final_password = random_password(f"{label}-final")
    slug = f"acceptance-{label.lower()}-{suffix}"
    response, _ = platform_admin.expect(
        "POST",
        "/api/tenants",
        201,
        payload={
            "name": f"Acceptance Tenant {label} {suffix}",
            "slug": slug,
            "adminUsername": username,
            "adminPassword": temporary_password,
        },
    )
    tenant = response["tenant"]
    tenant_admin = Client()
    login = tenant_admin.login(username, temporary_password)
    if not login["user"].get("passwordChangeRequired"):
        raise AcceptanceError("new tenant admin did not require a password change")
    changed, _ = tenant_admin.expect(
        "POST",
        "/api/users/me/password",
        200,
        payload={
            "currentPassword": temporary_password,
            "newPassword": final_password,
        },
    )
    if changed["user"].get("passwordChangeRequired"):
        raise AcceptanceError("tenant admin password-change requirement was not cleared")
    return tenant, tenant_admin


def create_tenant_user(tenant_admin, suffix, role):
    username = f"acceptance.{role}.{suffix}"
    temporary_password = random_password(f"{role}-temporary")
    final_password = random_password(f"{role}-final")
    created, _ = tenant_admin.expect(
        "POST",
        "/api/users",
        201,
        payload={
            "username": username,
            "email": f"{username}@example.invalid",
            "password": temporary_password,
            "role": role,
        },
    )
    client = Client()
    login = client.login(username, temporary_password)
    if not login["user"].get("passwordChangeRequired"):
        raise AcceptanceError(f"new {role} did not require a password change")
    changed, _ = client.expect(
        "POST",
        "/api/users/me/password",
        200,
        payload={
            "currentPassword": temporary_password,
            "newPassword": final_password,
        },
    )
    if changed["user"].get("passwordChangeRequired"):
        raise AcceptanceError(f"{role} password-change requirement was not cleared")
    if created["user"].get("role") != role:
        raise AcceptanceError(f"created tenant user does not have the expected {role} role")
    return username, client


def multipart_file(filename, content, fields):
    boundary = f"----sfm-acceptance-{secrets.token_hex(12)}"
    chunks = []
    for name, value in fields.items():
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n"
            ).encode("utf-8")
        )
    chunks.append(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="files"; filename="{filename}"\r\n'
            "Content-Type: text/plain\r\n\r\n"
        ).encode("utf-8")
    )
    chunks.append(content)
    chunks.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))
    return boundary, b"".join(chunks)


def assert_runtime(health):
    expected = {
        "database": EXPECTED_DATABASE,
        "storage": EXPECTED_STORAGE,
        "malwareScanning": EXPECTED_MALWARE,
    }
    mismatches = {
        key: {"expected": value, "actual": health.get(key)}
        for key, value in expected.items()
        if value and health.get(key) != value
    }
    if mismatches:
        raise AcceptanceError(f"runtime does not match the acceptance target: {mismatches}")


def main():
    if not ADMIN_PASSWORD:
        raise SystemExit("ISMS_ADMIN_PASSWORD is required")

    health_client = Client()
    health, _ = health_client.expect("GET", "/api/health", 200)
    assert_runtime(health)

    platform_admin = Client()
    platform_admin.login("admin", ADMIN_PASSWORD)
    suffix = secrets.token_hex(4)
    tenant_a, admin_a = create_tenant(platform_admin, suffix, "A")
    tenant_b, admin_b = create_tenant(platform_admin, suffix, "B")

    state_a, _ = admin_a.expect("GET", "/api/state", 200)
    marker = f"tenant-a-marker-{suffix}"
    workspace_a = state_a["state"]
    workspace_a["tasks"].append(
        {
            "id": marker,
            "title": "Acceptance tenant isolation marker",
            "status": "Offen",
            "owner": "Acceptance Customer",
        }
    )
    saved, _ = admin_a.expect(
        "PUT",
        "/api/state",
        200,
        payload={"state": workspace_a, "expectedRevision": state_a["revision"]},
    )

    state_b, _ = admin_b.expect("GET", "/api/state", 200)
    if marker in json.dumps(state_b["state"], ensure_ascii=False):
        raise AcceptanceError("tenant B can see tenant A workspace data")

    invite_email = f"acceptance.customer.{suffix}@example.invalid"
    invitation, _ = admin_a.expect(
        "POST",
        "/api/invitations",
        201,
        payload={
            "displayName": "Acceptance Customer",
            "email": invite_email,
            "role": "customer",
            "expiresDays": 1,
        },
    )
    accept_url = invitation["invitation"].get("acceptUrl", "")
    token = urllib.parse.parse_qs(urllib.parse.urlparse(accept_url).fragment).get("invite", [""])[0]
    if not token:
        raise AcceptanceError("invitation response did not contain an acceptance token")

    customer = Client()
    accepted, _ = customer.expect(
        "POST",
        "/api/invitations/accept",
        201,
        payload={
            "token": token,
            "username": f"acceptance.customer.{suffix}",
            "password": random_password("customer"),
        },
    )
    customer.csrf = accepted.get("csrfToken", "")
    if accepted["user"]["tenant"]["id"] != tenant_a["id"]:
        raise AcceptanceError("invited customer was assigned to the wrong tenant")

    consultant_username, consultant = create_tenant_user(admin_a, suffix, "consultant")
    _, auditor = create_tenant_user(admin_a, suffix, "auditor")

    customer_state, _ = customer.expect("GET", "/api/state", 200)
    if marker not in json.dumps(customer_state["state"], ensure_ascii=False):
        raise AcceptanceError("invited customer cannot see its tenant workspace")

    evidence = f"SFM tenant acceptance evidence {marker}\n".encode("utf-8")
    boundary, body = multipart_file(
        f"acceptance-evidence-{suffix}.txt",
        evidence,
        {
            "documentId": marker,
            "linkedTo": f"Task:{marker}",
            "classification": "Internal",
        },
    )
    uploaded, _ = customer.expect(
        "POST",
        "/api/files",
        201,
        body=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    file_info = uploaded["files"][0]
    if file_info["sha256"] != hashlib.sha256(evidence).hexdigest():
        raise AcceptanceError("uploaded evidence checksum does not match")

    files_a, _ = admin_a.expect("GET", "/api/files", 200)
    if file_info["id"] not in {item["id"] for item in files_a["files"]}:
        raise AcceptanceError("tenant A admin cannot see customer evidence")
    files_b, _ = admin_b.expect("GET", "/api/files", 200)
    if file_info["id"] in {item["id"] for item in files_b["files"]}:
        raise AcceptanceError("tenant B can list tenant A evidence")
    admin_b.expect("GET", f"/api/files/{file_info['id']}/download", 404)

    forbidden, _ = customer.expect(
        "PUT",
        "/api/state",
        403,
        payload={
            "state": customer_state["state"],
            "expectedRevision": customer_state["revision"],
        },
    )
    if "permission" not in forbidden.get("error", ""):
        raise AcceptanceError("customer final-write rejection did not report a permission boundary")

    review_asset_id = f"acceptance-review-asset-{suffix}"
    submitted_asset, _ = customer.expect(
        "POST",
        "/api/assets",
        201,
        payload={
            "expectedRevision": customer_state["revision"],
            "asset": {
                "id": review_asset_id,
                "name": "Acceptance Review Asset",
                "type": "System",
                "owner": accepted["user"]["username"],
                "criticality": "Hoch",
                "note": "Initial customer submission",
            },
        },
    )
    if submitted_asset["asset"].get("reviewStatus") != "vom_kunden_eingereicht":
        raise AcceptanceError("customer asset was not marked as submitted")

    in_review, _ = consultant.expect(
        "PATCH",
        f"/api/assets/{review_asset_id}",
        200,
        payload={
            "expectedRevision": submitted_asset["revision"],
            "changes": {
                "reviewStatus": "in_beraterpruefung",
                "consultantInternalComment": "Acceptance internal review note",
            },
        },
    )
    rework, _ = consultant.expect(
        "PATCH",
        f"/api/assets/{review_asset_id}",
        200,
        payload={
            "expectedRevision": in_review["revision"],
            "changes": {
                "reviewStatus": "nacharbeit_noetig",
                "customerComment": "Bitte ergänze den konkreten Nachweis für dieses Asset.",
                "reworkMissing": "Verknüpfter Nachweis",
                "reworkWhy": "Die Kundeneingabe ist formal noch nicht vollständig.",
                "reworkAction": "Datei oder Dokumentverweis ergänzen und erneut einreichen.",
                "reworkReference": f"Asset:{review_asset_id}",
            },
        },
    )
    rework_task_id = f"acceptance-rework-task-{suffix}"
    rework_task, _ = consultant.expect(
        "POST",
        "/api/tasks",
        201,
        payload={
            "expectedRevision": rework["revision"],
            "task": {
                "id": rework_task_id,
                "title": "Nacharbeit: Nachweis für Acceptance Review Asset ergänzen",
                "module": "Asset Management",
                "owner": accepted["user"]["username"],
                "status": "Offen",
                "source": "Beraterprüfung",
                "linkedTo": f"Asset:{review_asset_id}",
                "customerComment": "Bitte ergänze den konkreten Nachweis für dieses Asset.",
                "reworkMissing": "Verknüpfter Nachweis",
                "reworkWhy": "Die Kundeneingabe ist formal noch nicht vollständig.",
                "reworkAction": "Datei oder Dokumentverweis ergänzen und erneut einreichen.",
                "reworkReference": f"Asset:{review_asset_id}",
            },
        },
    )

    customer_rework_state, _ = customer.expect("GET", "/api/state", 200)
    customer_task = next(
        (item for item in customer_rework_state["state"]["tasks"] if item.get("id") == rework_task_id),
        None,
    )
    if not customer_task or customer_task.get("reworkAction") == "":
        raise AcceptanceError("customer cannot see the consultant rework task")

    resubmitted, _ = customer.expect(
        "PATCH",
        f"/api/assets/{review_asset_id}",
        200,
        payload={
            "expectedRevision": rework_task["revision"],
            "changes": {
                "evidence": f"File:{file_info['id']}",
                "note": "Customer added the requested evidence and resubmitted.",
            },
        },
    )
    if resubmitted["asset"].get("reviewStatus") != "vom_kunden_eingereicht":
        raise AcceptanceError("customer rework was not resubmitted for consultant review")

    approved_asset, _ = consultant.expect(
        "PATCH",
        f"/api/assets/{review_asset_id}",
        200,
        payload={
            "expectedRevision": resubmitted["revision"],
            "changes": {
                "reviewStatus": "freigegeben",
                "reviewedBy": consultant_username,
                "customerComment": "Nachweis ist für diesen Arbeitsstand freigegeben.",
            },
        },
    )
    if approved_asset["asset"].get("reviewStatus") != "freigegeben":
        raise AcceptanceError("consultant approval was not persisted")

    auditor_assets, _ = auditor.expect("GET", "/api/assets", 200)
    if review_asset_id not in {item.get("id") for item in auditor_assets["assets"]}:
        raise AcceptanceError("auditor cannot read the reviewed asset")
    auditor.expect(
        "PATCH",
        f"/api/assets/{review_asset_id}",
        403,
        payload={
            "expectedRevision": auditor_assets["revision"],
            "changes": {"reviewStatus": "freigegeben"},
        },
    )
    customer.expect(
        "POST",
        "/api/audit-package/approve",
        403,
        payload={"expectedRevision": approved_asset["revision"]},
    )
    auditor.expect(
        "POST",
        "/api/audit-package/approve",
        403,
        payload={"expectedRevision": approved_asset["revision"]},
    )

    export_bytes, export_type = admin_a.expect(
        "POST", f"/api/tenants/{tenant_a['id']}/export", 200, payload={}
    )
    if "zip" not in export_type:
        raise AcceptanceError(f"tenant export is not a ZIP archive: {export_type}")
    with zipfile.ZipFile(io.BytesIO(export_bytes)) as archive:
        manifest_names = [name for name in archive.namelist() if name.endswith("manifest.json")]
        if not manifest_names:
            raise AcceptanceError("tenant export has no manifest.json")
        manifest = json.loads(archive.read(manifest_names[0]).decode("utf-8"))
    if tenant_a["id"] not in json.dumps(manifest, ensure_ascii=False):
        raise AcceptanceError("tenant export manifest does not identify tenant A")

    integrity, _ = admin_a.expect("GET", "/api/audit-log/integrity", 200)
    if not integrity.get("valid"):
        raise AcceptanceError(f"tenant A audit chain is invalid: {integrity}")

    print(
        json.dumps(
            {
                "ok": True,
                "runtime": {
                    "database": health.get("database"),
                    "storage": health.get("storage"),
                    "malwareScanning": health.get("malwareScanning"),
                },
                "tenantA": {"id": tenant_a["id"], "slug": tenant_a["slug"]},
                "tenantB": {"id": tenant_b["id"], "slug": tenant_b["slug"]},
                "workspaceRevision": approved_asset["revision"],
                "invitationAccepted": True,
                "evidenceRoundtrip": True,
                "crossTenantWorkspaceBlocked": True,
                "crossTenantFileBlocked": True,
                "customerFinalWriteBlocked": True,
                "reviewWorkflowVerified": True,
                "customerReworkTaskVisible": True,
                "consultantApprovalVerified": True,
                "auditorReadOnlyVerified": True,
                "auditPackageApprovalRoleBoundary": True,
                "tenantExportVerified": True,
                "auditIntegrity": True,
                "cleanup": "Run staging_stack.sh reset after inspection.",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
