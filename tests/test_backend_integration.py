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
import zipfile
from contextlib import closing
from io import BytesIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend_app.py"
FRONTEND = ROOT / "frontend-current"
ADMIN_PASSWORD = "Test-Admin-Password-2026!"
TENANT_ADMIN_TEMP_PASSWORD = "Copper-Valley-58!Quiet-Forest"
TENANT_ADMIN_PASSWORD = "Indigo-Harbor-72!Clear-Meadow"
VIEWER_PASSWORD = "Test-Viewer-Password-2026!"
CUSTOMER_TEMP_PASSWORD = "Test-Customer-Temp-2026!"
CUSTOMER_PASSWORD = "Test-Customer-Final-2026!"
CONTRIBUTOR_TEMP_PASSWORD = "Test-Contributor-Temp-2026!"
CONTRIBUTOR_PASSWORD = "Test-Contributor-Final-2026!"


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
            response = self.opener.open(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        raw = response.read()
        content_type = response.headers.get("Content-Type", "")
        status = response.status
        response_headers = response.headers
        response.close()
        parsed = json.loads(raw.decode("utf-8")) if raw and "json" in content_type else raw
        return status, parsed, response_headers

    def login(self, username, password):
        status, payload, headers = self.request(
            "POST", "/api/auth/login", {"username": username, "password": password}
        )
        if status == 200:
            self.csrf = payload.get("csrfToken", "")
        return status, payload, headers


class BackendIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="sfm-compliance-tests-")
        cls.port = free_port()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        env = os.environ.copy()
        env.update(
            {
                "ISMS_HOST": "127.0.0.1",
                "ISMS_PORT": str(cls.port),
                "ISMS_PUBLIC_URL": cls.base_url,
                "ISMS_STATIC_BASE": str(FRONTEND),
                "ISMS_DATA_DIR": cls.temp_dir.name,
                "ISMS_ADMIN_PASSWORD": ADMIN_PASSWORD,
                "ISMS_FILE_KEY": "test-file-key-do-not-use-in-production",
                "ISMS_COOKIE_SECURE": "0",
                "ISMS_HSTS": "0",
                "ISMS_OPERATIONS_MONITOR_ENABLED": "0",
                "ISMS_NOTIFICATION_DELIVERY_ENABLED": "0",
                "ISMS_JOB_WORKER_ENABLED": "0",
            }
        )
        cls.process = subprocess.Popen(
            [sys.executable, str(BACKEND)],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.time() + 12
        last_error = None
        while time.time() < deadline:
            if cls.process.poll() is not None:
                stdout, stderr = cls.process.communicate(timeout=2)
                raise RuntimeError(f"Testserver stopped early.\nstdout: {stdout}\nstderr: {stderr}")
            try:
                with urllib.request.urlopen(f"{cls.base_url}/api/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except Exception as error:
                last_error = error
                time.sleep(0.1)
        else:
            raise RuntimeError(f"Testserver did not become ready: {last_error}")

        cls.admin = ApiClient(cls.base_url)
        status, payload, _ = cls.admin.login("admin", ADMIN_PASSWORD)
        if status != 200:
            raise RuntimeError(f"Test admin login failed: {status} {payload}")

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

    def test_01_health_session_and_security_headers(self):
        anonymous = ApiClient(self.base_url)
        status, payload, headers = anonymous.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["database"], "sqlite")
        self.assertEqual(payload["jobWorker"], False)
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertIn("frame-ancestors 'none'", headers.get("Content-Security-Policy", ""))

        status, payload, _ = anonymous.request("GET", "/api/session")
        self.assertEqual(status, 200)
        self.assertFalse(payload["authenticated"])

        status, payload, headers = anonymous.login("admin", ADMIN_PASSWORD)
        self.assertEqual(status, 200)
        self.assertTrue(payload["authenticated"])
        self.assertTrue(payload["user"]["platformAdmin"])
        self.assertTrue(payload["csrfToken"])
        cookie = headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_02_csrf_roles_and_tenant_isolation(self):
        tenant_payload = {
            "name": "Testkunde Alpha",
            "slug": "testkunde-alpha",
            "adminUsername": "alpha.admin",
            "adminPassword": TENANT_ADMIN_TEMP_PASSWORD,
        }
        status, payload, _ = self.admin.request("POST", "/api/tenants", tenant_payload)
        self.assertEqual(status, 403)
        self.assertIn("csrf", payload["error"])

        status, payload, _ = self.admin.request(
            "POST", "/api/tenants", tenant_payload, csrf=True
        )
        self.assertEqual(status, 201)
        tenant_id = payload["tenant"]["id"]

        tenant_admin = ApiClient(self.base_url)
        status, payload, _ = tenant_admin.login("alpha.admin", TENANT_ADMIN_TEMP_PASSWORD)
        self.assertEqual(status, 200)
        self.assertEqual(payload["user"]["tenant"]["id"], tenant_id)
        self.assertFalse(payload["user"]["platformAdmin"])
        self.assertTrue(payload["user"]["passwordChangeRequired"])

        status, payload, _ = tenant_admin.request(
            "POST",
            "/api/users/me/password",
            {
                "currentPassword": TENANT_ADMIN_TEMP_PASSWORD,
                "newPassword": TENANT_ADMIN_PASSWORD,
            },
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertFalse(payload["user"]["passwordChangeRequired"])

        status, payload, _ = tenant_admin.request("GET", "/api/tenants")
        self.assertEqual(status, 200)
        self.assertEqual([tenant["id"] for tenant in payload["tenants"]], [tenant_id])

        status, payload, _ = tenant_admin.request("GET", "/api/users")
        self.assertEqual(status, 200)
        self.assertTrue(payload["users"])
        self.assertTrue(all(user["tenantId"] == tenant_id for user in payload["users"]))

        status, payload, _ = tenant_admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        self.assertTrue(all(event["tenantId"] == tenant_id for event in payload["events"]))

        status, payload, _ = self.admin.request("GET", "/api/tenants")
        self.assertEqual(status, 200)
        self.assertIn("default", {tenant["id"] for tenant in payload["tenants"]})
        self.assertIn(tenant_id, {tenant["id"] for tenant in payload["tenants"]})

    def test_03_read_only_role_cannot_modify_workspace(self):
        username = "readonly.viewer"
        status, payload, _ = self.admin.request(
            "POST",
            "/api/users",
            {"username": username, "password": VIEWER_PASSWORD, "role": "viewer"},
            csrf=True,
        )
        self.assertEqual(status, 201)

        viewer = ApiClient(self.base_url)
        status, payload, _ = viewer.login(username, VIEWER_PASSWORD)
        self.assertEqual(status, 200)
        self.assertEqual(payload["user"]["role"], "viewer")

        status, _, _ = viewer.request("GET", "/api/state")
        self.assertEqual(status, 200)
        status, payload, _ = viewer.request("PUT", "/api/state", {"state": {}}, csrf=True)
        self.assertEqual(status, 403)
        self.assertIn("permission", payload["error"])
        status, payload, _ = viewer.request("PUT", "/api/state/submission", {"state": {}}, csrf=True)
        self.assertEqual(status, 403)
        self.assertIn("submitWorkspace", payload["error"])

    def test_04_invalid_workspace_state_is_rejected(self):
        status, payload, _ = self.admin.request(
            "PUT", "/api/state", {"state": {}}, csrf=True
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "workspace state is incomplete")
        self.assertFalse(payload["validation"]["valid"])

    def test_05_workspace_revision_prevents_lost_updates(self):
        status, payload, _ = self.admin.request("GET", "/api/state")
        self.assertEqual(status, 200)
        revision = payload.get("revision")
        self.assertIn("updatedBy", payload)
        state = payload.get("state") or {
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

        first_state = {**state, "tasks": [{"id": "revision-a", "title": "Erste Fassung"}]}
        status, payload, _ = self.admin.request(
            "PUT",
            "/api/state",
            {"state": first_state, "expectedRevision": revision},
            csrf=True,
        )
        self.assertEqual(status, 200)
        first_revision = payload["revision"]
        self.assertEqual(payload["updatedBy"], "admin")

        second_state = {**state, "tasks": [{"id": "revision-b", "title": "Neuere Fassung"}]}
        status, payload, _ = self.admin.request(
            "PUT",
            "/api/state",
            {"state": second_state, "expectedRevision": first_revision},
            csrf=True,
        )
        self.assertEqual(status, 200)
        second_revision = payload["revision"]
        self.assertEqual(second_revision, first_revision + 1)

        status, meta, _ = self.admin.request("GET", "/api/state/meta")
        self.assertEqual(status, 200)
        self.assertTrue(meta["exists"])
        self.assertEqual(meta["revision"], second_revision)
        self.assertEqual(meta["updatedBy"], "admin")
        self.assertNotIn("state", meta)

        stale_state = {**state, "tasks": [{"id": "revision-stale", "title": "Veraltete Fassung"}]}
        status, payload, _ = self.admin.request(
            "PUT",
            "/api/state",
            {"state": stale_state, "expectedRevision": first_revision},
            csrf=True,
        )
        self.assertEqual(status, 409)
        self.assertEqual(payload["error"], "workspace_conflict")
        self.assertEqual(payload["currentRevision"], second_revision)
        self.assertEqual(payload["currentUpdatedBy"], "admin")

        status, payload, _ = self.admin.request("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(payload["revision"], second_revision)
        self.assertEqual(payload["updatedBy"], "admin")
        self.assertEqual(payload["state"]["tasks"][0]["id"], "revision-b")

    def test_05b_customer_submission_is_persisted_without_review_privileges(self):
        username = "workspace.customer"
        status, payload, _ = self.admin.request(
            "POST",
            "/api/users",
            {"username": username, "password": CUSTOMER_TEMP_PASSWORD, "role": "customer"},
            csrf=True,
        )
        self.assertEqual(status, 201)

        customer = ApiClient(self.base_url)
        status, payload, _ = customer.login(username, CUSTOMER_TEMP_PASSWORD)
        self.assertEqual(status, 200)
        self.assertIn("submitWorkspace", payload["user"]["permissions"])
        self.assertNotIn("saveWorkspace", payload["user"]["permissions"])
        self.assertNotIn("reviewDocument", payload["user"]["permissions"])

        status, payload, _ = customer.request(
            "POST",
            "/api/users/me/password",
            {"currentPassword": CUSTOMER_TEMP_PASSWORD, "newPassword": CUSTOMER_PASSWORD},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, workspace, _ = customer.request("GET", "/api/state")
        self.assertEqual(status, 200)
        revision = workspace["revision"]
        customer_state = json.loads(json.dumps(workspace["state"]))
        customer_state["assets"].append({
            "id": "customer-asset-1",
            "title": "Kundenportal",
            "type": "Anwendung",
            "owner": "IT",
            "criticality": "Hoch",
            "reviewStatus": "vom_kunden_eingereicht",
            "auditRelevant": False,
        })

        status, payload, _ = customer.request(
            "PUT",
            "/api/state",
            {"state": customer_state, "expectedRevision": revision},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertIn("saveWorkspace", payload["error"])

        status, payload, _ = customer.request(
            "PUT",
            "/api/state/submission",
            {"state": customer_state, "expectedRevision": revision},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["submission"]["changedSections"], ["assets"])
        self.assertTrue(payload["submission"]["allowed"])
        submitted_revision = payload["revision"]

        status, persisted, _ = customer.request("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(persisted["revision"], submitted_revision)
        saved_asset = next(item for item in persisted["state"]["assets"] if item["id"] == "customer-asset-1")
        self.assertEqual(saved_asset["title"], "Kundenportal")

        protected_state = json.loads(json.dumps(persisted["state"]))
        protected_asset = next(item for item in protected_state["assets"] if item["id"] == "customer-asset-1")
        protected_asset["reviewStatus"] = "freigegeben"
        status, payload, _ = customer.request(
            "PUT",
            "/api/state/submission",
            {"state": protected_state, "expectedRevision": submitted_revision},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "submission_policy_violation")
        self.assertIn("advisor_status_required", {item["reason"] for item in payload["submission"]["violations"]})

        deletion_state = json.loads(json.dumps(persisted["state"]))
        deletion_state["assets"] = [item for item in deletion_state["assets"] if item.get("id") != "customer-asset-1"]
        status, payload, _ = customer.request(
            "PUT",
            "/api/state/submission",
            {"state": deletion_state, "expectedRevision": submitted_revision},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertIn("existing_record_cannot_be_deleted", {item["reason"] for item in payload["submission"]["violations"]})

        restricted_state = json.loads(json.dumps(persisted["state"]))
        restricted_state["auditPackage"] = {"status": "vorbereitet"}
        status, payload, _ = customer.request(
            "PUT",
            "/api/state/submission",
            {"state": restricted_state, "expectedRevision": submitted_revision},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertIn("section_requires_advisor", {item["reason"] for item in payload["submission"]["violations"]})

        status, audit_log, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        customer_actions = [event["action"] for event in audit_log["events"] if event["username"] == username]
        self.assertIn("state_submission_saved", customer_actions)
        self.assertIn("state_submission_rejected", customer_actions)

    def test_05c_contributors_can_only_change_owned_or_assigned_records(self):
        def create_submitter(username, role, temporary_password, final_password):
            status, payload, _ = self.admin.request(
                "POST",
                "/api/users",
                {"username": username, "password": temporary_password, "role": role},
                csrf=True,
            )
            self.assertEqual(status, 201)
            client = ApiClient(self.base_url)
            status, payload, _ = client.login(username, temporary_password)
            self.assertEqual(status, 200)
            status, payload, _ = client.request(
                "POST",
                "/api/users/me/password",
                {"currentPassword": temporary_password, "newPassword": final_password},
                csrf=True,
            )
            self.assertEqual(status, 200)
            return client

        contributor_a = create_submitter(
            "workspace.contributor.a",
            "contributor",
            CONTRIBUTOR_TEMP_PASSWORD,
            CONTRIBUTOR_PASSWORD,
        )
        contributor_b = create_submitter(
            "workspace.contributor.b",
            "contributor",
            "Second-Contributor-Temp-2026!",
            "Second-Contributor-Final-2026!",
        )
        coordinator = create_submitter(
            "workspace.coordinator",
            "customer",
            "Test-Coordinator-Temp-2026!",
            "Test-Coordinator-Final-2026!",
        )

        status, workspace, _ = contributor_a.request("GET", "/api/state")
        self.assertEqual(status, 200)
        contributor_a_state = json.loads(json.dumps(workspace["state"]))
        contributor_a_state["assets"].append({
            "id": "contributor-owned-a",
            "title": "System von Mitwirkendem A",
            "type": "Anwendung",
            "owner": "IT",
            "reviewStatus": "vom_kunden_eingereicht",
        })
        status, payload, _ = contributor_a.request(
            "PUT",
            "/api/state/submission",
            {"state": contributor_a_state, "expectedRevision": workspace["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["submission"]["ownershipEnforced"])
        self.assertEqual(payload["submission"]["recordChanges"]["created"], 1)

        status, workspace, _ = contributor_b.request("GET", "/api/state")
        self.assertEqual(status, 200)
        foreign_edit = json.loads(json.dumps(workspace["state"]))
        foreign_asset = next(item for item in foreign_edit["assets"] if item.get("id") == "contributor-owned-a")
        foreign_asset["title"] = "Unerlaubte Änderung durch B"
        status, payload, _ = contributor_b.request(
            "PUT",
            "/api/state/submission",
            {"state": foreign_edit, "expectedRevision": workspace["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertIn(
            "record_owned_by_another_user",
            {item["reason"] for item in payload["submission"]["violations"]},
        )

        contributor_b_state = json.loads(json.dumps(workspace["state"]))
        contributor_b_state["assets"].append({
            "id": "contributor-owned-b",
            "title": "System von Mitwirkendem B",
            "type": "Dienst",
            "owner": "Einkauf",
            "reviewStatus": "vom_kunden_eingereicht",
        })
        status, payload, _ = contributor_b.request(
            "PUT",
            "/api/state/submission",
            {"state": contributor_b_state, "expectedRevision": workspace["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, workspace, _ = contributor_a.request("GET", "/api/state")
        self.assertEqual(status, 200)
        own_edit = json.loads(json.dumps(workspace["state"]))
        own_asset = next(item for item in own_edit["assets"] if item.get("id") == "contributor-owned-a")
        own_asset["title"] = "Eigene Änderung durch A"
        status, payload, _ = contributor_a.request(
            "PUT",
            "/api/state/submission",
            {"state": own_edit, "expectedRevision": workspace["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["submission"]["recordChanges"]["updated"], 1)

        status, workspace, _ = contributor_b.request("GET", "/api/state")
        self.assertEqual(status, 200)
        restricted_section = json.loads(json.dumps(workspace["state"]))
        restricted_section["setup"] = {
            **(restricted_section.get("setup") or {}),
            "organization": "Unzulässige globale Änderung",
        }
        status, payload, _ = contributor_b.request(
            "PUT",
            "/api/state/submission",
            {"state": restricted_section, "expectedRevision": workspace["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertIn(
            "contributor_section_restricted",
            {item["reason"] for item in payload["submission"]["violations"]},
        )

        status, workspace, _ = coordinator.request("GET", "/api/state")
        self.assertEqual(status, 200)
        coordinated_edit = json.loads(json.dumps(workspace["state"]))
        coordinated_asset = next(item for item in coordinated_edit["assets"] if item.get("id") == "contributor-owned-a")
        coordinated_asset["title"] = "Koordiniert durch Kundenansprechpartner"
        coordinated_asset["assignedUsername"] = "workspace.contributor.b"
        status, payload, _ = coordinator.request(
            "PUT",
            "/api/state/submission",
            {"state": coordinated_edit, "expectedRevision": workspace["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, workspace, _ = contributor_b.request("GET", "/api/state")
        self.assertEqual(status, 200)
        assigned_edit = json.loads(json.dumps(workspace["state"]))
        assigned_asset = next(item for item in assigned_edit["assets"] if item.get("id") == "contributor-owned-a")
        assigned_asset["title"] = "Bearbeitet durch zugewiesenen Mitwirkenden B"
        status, payload, _ = contributor_b.request(
            "PUT",
            "/api/state/submission",
            {"state": assigned_edit, "expectedRevision": workspace["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, workspace, _ = contributor_b.request("GET", "/api/state")
        self.assertEqual(status, 200)
        assignment_tamper = json.loads(json.dumps(workspace["state"]))
        tampered_asset = next(item for item in assignment_tamper["assets"] if item.get("id") == "contributor-owned-a")
        tampered_asset["assignedUsername"] = "workspace.contributor.a"
        status, payload, _ = contributor_b.request(
            "PUT",
            "/api/state/submission",
            {"state": assignment_tamper, "expectedRevision": workspace["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertIn(
            "assignment_requires_coordinator",
            {item["reason"] for item in payload["submission"]["violations"]},
        )

        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            owners = dict(
                db.execute(
                    "SELECT record_key, owner_username FROM workspace_record_ownership "
                    "WHERE tenant_id = 'default' AND section = 'assets'"
                ).fetchall()
            )
        self.assertEqual(owners["id:contributor-owned-a"], "workspace.contributor.a")
        self.assertEqual(owners["id:contributor-owned-b"], "workspace.contributor.b")

    def test_05d_asset_record_api_is_atomic_role_aware_and_audited(self):
        def create_submitter(username, role, temporary_password, final_password):
            status, payload, _ = self.admin.request(
                "POST",
                "/api/users",
                {"username": username, "password": temporary_password, "role": role},
                csrf=True,
            )
            self.assertEqual(status, 201)
            client = ApiClient(self.base_url)
            status, payload, _ = client.login(username, temporary_password)
            self.assertEqual(status, 200)
            status, payload, _ = client.request(
                "POST",
                "/api/users/me/password",
                {"currentPassword": temporary_password, "newPassword": final_password},
                csrf=True,
            )
            self.assertEqual(status, 200)
            return client

        contributor_a = create_submitter(
            "asset.api.contributor.a",
            "contributor",
            "Violet-Harbor-63!Quiet-Forest",
            "Cobalt-Meadow-74!Clear-River",
        )
        contributor_b = create_submitter(
            "asset.api.contributor.b",
            "contributor",
            "Amber-Plateau-52!Silver-Cloud",
            "Indigo-Valley-81!Bright-Cedar",
        )
        coordinator = create_submitter(
            "asset.api.coordinator",
            "customer",
            "Copper-Summit-46!Calm-Lantern",
            "Marble-Garden-93!Fresh-Stream",
        )

        status, listed, _ = self.admin.request("GET", "/api/assets")
        self.assertEqual(status, 200)
        revision = listed["revision"]

        status, created, _ = self.admin.request(
            "POST",
            "/api/assets",
            {
                "asset": {
                    "id": "asset-api-admin",
                    "name": "Admin Asset",
                    "type": "System",
                    "owner": "IT",
                    "criticality": "Hoch",
                },
                "expectedRevision": revision,
            },
            csrf=True,
        )
        self.assertEqual(status, 201)
        self.assertEqual(created["asset"]["id"], "asset-api-admin")
        self.assertEqual(created["revision"], revision + 1)

        status, conflict, _ = self.admin.request(
            "PATCH",
            "/api/assets/asset-api-admin",
            {"changes": {"owner": "Veraltet"}, "expectedRevision": revision},
            csrf=True,
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"], "workspace_conflict")
        self.assertEqual(conflict["currentRevision"], created["revision"])

        status, contributor_list, _ = contributor_a.request("GET", "/api/assets")
        self.assertEqual(status, 200)
        status, contributor_created, _ = contributor_a.request(
            "POST",
            "/api/assets",
            {
                "asset": {
                    "id": "asset-api-owned-a",
                    "name": "Asset von Mitwirkendem A",
                    "type": "Anwendung",
                    "owner": "Fachbereich",
                    "status": "In Arbeit",
                },
                "expectedRevision": contributor_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 201)
        self.assertEqual(contributor_created["asset"]["reviewStatus"], "vom_kunden_eingereicht")
        self.assertTrue(contributor_created["submission"]["ownershipEnforced"])

        status, contributor_b_list, _ = contributor_b.request("GET", "/api/assets")
        self.assertEqual(status, 200)
        status, rejected, _ = contributor_b.request(
            "PATCH",
            "/api/assets/asset-api-owned-a",
            {
                "changes": {"name": "Fremde Änderung"},
                "expectedRevision": contributor_b_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(rejected["error"], "submission_policy_violation")
        self.assertIn(
            "record_owned_by_another_user",
            {item["reason"] for item in rejected["submission"]["violations"]},
        )

        status, contributor_a_list, _ = contributor_a.request("GET", "/api/assets")
        self.assertEqual(status, 200)
        status, updated, _ = contributor_a.request(
            "PATCH",
            "/api/assets/asset-api-owned-a",
            {
                "changes": {"name": "Eigene Änderung über Asset API"},
                "expectedRevision": contributor_a_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(updated["asset"]["name"], "Eigene Änderung über Asset API")

        status, coordinator_list, _ = coordinator.request("GET", "/api/assets")
        self.assertEqual(status, 200)
        status, coordinated, _ = coordinator.request(
            "PATCH",
            "/api/assets/asset-api-owned-a",
            {
                "changes": {
                    "owner": "Kundenkoordination",
                    "assignedUsername": "asset.api.contributor.b",
                },
                "expectedRevision": coordinator_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(coordinated["asset"]["assignedUsername"], "asset.api.contributor.b")

        status, assigned_list, _ = contributor_b.request("GET", "/api/assets")
        self.assertEqual(status, 200)
        status, assigned_update, _ = contributor_b.request(
            "PATCH",
            "/api/assets/asset-api-owned-a",
            {
                "changes": {"protection": "Verfügbarkeit hoch"},
                "expectedRevision": assigned_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(assigned_update["asset"]["protection"], "Verfügbarkeit hoch")

        status, customer_list, _ = coordinator.request("GET", "/api/assets")
        self.assertEqual(status, 200)
        status, forbidden_final, _ = coordinator.request(
            "PATCH",
            "/api/assets/asset-api-owned-a",
            {
                "changes": {"status": "Freigegeben"},
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(forbidden_final["error"], "submission_policy_violation")
        self.assertIn(
            "advisor_status_required",
            {item["reason"] for item in forbidden_final["submission"]["violations"]},
        )

        status, delete_forbidden, _ = coordinator.request(
            "DELETE",
            "/api/assets/asset-api-owned-a",
            {"expectedRevision": customer_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertIn("saveWorkspace", delete_forbidden["error"])

        status, admin_list, _ = self.admin.request("GET", "/api/assets")
        self.assertEqual(status, 200)
        status, deleted, _ = self.admin.request(
            "DELETE",
            "/api/assets/asset-api-admin",
            {"expectedRevision": admin_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(deleted["deletedId"], "asset-api-admin")

        status, final_list, _ = self.admin.request("GET", "/api/assets")
        self.assertEqual(status, 200)
        self.assertNotIn("asset-api-admin", {item["id"] for item in final_list["assets"]})
        self.assertEqual(
            next(item for item in final_list["assets"] if item["id"] == "asset-api-owned-a")["owner"],
            "Kundenkoordination",
        )

        status, audit_log, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        actions = {event["action"] for event in audit_log["events"]}
        self.assertTrue({"asset_created", "asset_updated", "asset_deleted"}.issubset(actions))

        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            ownership = db.execute(
                "SELECT owner_username FROM workspace_record_ownership "
                "WHERE tenant_id = 'default' AND section = 'assets' AND record_key = 'id:asset-api-owned-a'"
            ).fetchone()
            event = db.execute(
                "SELECT event_type,workspace_revision FROM tenant_events "
                "WHERE tenant_id = 'default' AND action = 'asset_deleted' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(ownership[0], "asset.api.contributor.a")
        self.assertEqual(event[0], "workspace.updated")
        self.assertEqual(event[1], deleted["revision"])

    def test_05e_risk_record_api_is_atomic_role_aware_and_audited(self):
        temporary_password = "Glacier-Harbor-42!Quiet-Pine"
        final_password = "Crystal-Meadow-73!Bright-Oak"
        status, payload, _ = self.admin.request(
            "POST",
            "/api/users",
            {"username": "risk.api.customer", "password": temporary_password, "role": "customer"},
            csrf=True,
        )
        self.assertEqual(status, 201)
        customer = ApiClient(self.base_url)
        status, payload, _ = customer.login("risk.api.customer", temporary_password)
        self.assertEqual(status, 200)
        status, payload, _ = customer.request(
            "POST",
            "/api/users/me/password",
            {"currentPassword": temporary_password, "newPassword": final_password},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, listed, _ = self.admin.request("GET", "/api/risks")
        self.assertEqual(status, 200)
        revision = listed["revision"]

        status, created, _ = self.admin.request(
            "POST",
            "/api/risks",
            {
                "risk": {
                    "id": "risk-api-admin",
                    "riskId": "R-API-001",
                    "asset": "M365",
                    "scenario": "Privilegiertes Konto wird ohne ausreichende Prüfung missbraucht.",
                    "owner": "IT Security",
                    "likelihood": 3,
                    "impact": 5,
                    "status": "In Bewertung",
                },
                "expectedRevision": revision,
            },
            csrf=True,
        )
        self.assertEqual(status, 201, created)
        self.assertEqual(created["risk"]["id"], "risk-api-admin")
        self.assertEqual(created["revision"], revision + 1)

        status, conflict, _ = self.admin.request(
            "PATCH",
            "/api/risks/risk-api-admin",
            {"changes": {"owner": "Veraltet"}, "expectedRevision": revision},
            csrf=True,
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"], "workspace_conflict")

        status, customer_list, _ = customer.request("GET", "/api/risks")
        self.assertEqual(status, 200)
        status, customer_created, _ = customer.request(
            "POST",
            "/api/risks",
            {
                "risk": {
                    "id": "risk-api-customer",
                    "riskId": "R-API-002",
                    "asset": "Kundenportal",
                    "scenario": "Ein externer Zugriff führt zu einer Betriebsunterbrechung.",
                    "owner": "Application Owner",
                    "likelihood": "3",
                    "impact": "4",
                    "treatment": "MFA und Wiederanlauf testen.",
                    "status": "In Behandlung",
                },
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 201)
        self.assertEqual(customer_created["risk"]["reviewStatus"], "vom_kunden_eingereicht")

        status, customer_list, _ = customer.request("GET", "/api/risks")
        self.assertEqual(status, 200)
        status, forbidden_decision, _ = customer.request(
            "PATCH",
            "/api/risks/risk-api-customer",
            {
                "changes": {"status": "Akzeptiert"},
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(forbidden_decision["error"], "submission_policy_violation")
        self.assertIn(
            "risk_decision_requires_advisor",
            {item["reason"] for item in forbidden_decision["submission"]["violations"]},
        )

        status, invalid_score, _ = self.admin.request(
            "PATCH",
            "/api/risks/risk-api-admin",
            {
                "changes": {"impact": 6},
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 400)
        self.assertIn("between 1 and 5", invalid_score["error"])

        status, delete_forbidden, _ = customer.request(
            "DELETE",
            "/api/risks/risk-api-customer",
            {"expectedRevision": customer_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertIn("saveWorkspace", delete_forbidden["error"])

        status, admin_list, _ = self.admin.request("GET", "/api/risks")
        self.assertEqual(status, 200)
        status, approved, _ = self.admin.request(
            "PATCH",
            "/api/risks/risk-api-customer",
            {
                "changes": {"status": "Akzeptiert", "acceptanceOwner": "Geschäftsleitung"},
                "expectedRevision": admin_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(approved["risk"]["status"], "Akzeptiert")

        status, deleted, _ = self.admin.request(
            "DELETE",
            "/api/risks/risk-api-admin",
            {"expectedRevision": approved["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(deleted["deletedId"], "risk-api-admin")

        status, final_list, _ = self.admin.request("GET", "/api/risks")
        self.assertEqual(status, 200)
        self.assertNotIn("risk-api-admin", {item["id"] for item in final_list["risks"]})
        self.assertEqual(
            next(item for item in final_list["risks"] if item["id"] == "risk-api-customer")["status"],
            "Akzeptiert",
        )

        status, audit_log, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        actions = {event["action"] for event in audit_log["events"]}
        self.assertTrue({"risk_created", "risk_updated", "risk_deleted"}.issubset(actions))

        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            event = db.execute(
                "SELECT event_type,workspace_revision FROM tenant_events "
                "WHERE tenant_id = 'default' AND action = 'risk_deleted' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(event[0], "workspace.updated")
        self.assertEqual(event[1], deleted["revision"])

    def test_05f_supplier_record_api_is_atomic_role_aware_and_audited(self):
        temporary_password = "River-Cedar-52!Quiet-Cloud"
        final_password = "Harbor-Willow-84!Bright-Sky"
        status, payload, _ = self.admin.request(
            "POST",
            "/api/users",
            {"username": "supplier.api.customer", "password": temporary_password, "role": "customer"},
            csrf=True,
        )
        self.assertEqual(status, 201)
        customer = ApiClient(self.base_url)
        status, payload, _ = customer.login("supplier.api.customer", temporary_password)
        self.assertEqual(status, 200)
        status, payload, _ = customer.request(
            "POST",
            "/api/users/me/password",
            {"currentPassword": temporary_password, "newPassword": final_password},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, listed, _ = self.admin.request("GET", "/api/suppliers")
        self.assertEqual(status, 200)
        revision = listed["revision"]

        status, created, _ = self.admin.request(
            "POST",
            "/api/suppliers",
            {
                "supplier": {
                    "id": "supplier-api-admin",
                    "name": "Admin Cloud GmbH",
                    "service": "Cloud Hosting",
                    "owner": "Einkauf",
                    "criticality": "Hoch",
                    "review": "In Prüfung",
                    "contractStatus": "Vorhanden",
                },
                "expectedRevision": revision,
            },
            csrf=True,
        )
        self.assertEqual(status, 201, created)
        self.assertEqual(created["supplier"]["id"], "supplier-api-admin")

        status, conflict, _ = self.admin.request(
            "PATCH",
            "/api/suppliers/supplier-api-admin",
            {"changes": {"owner": "Veraltet"}, "expectedRevision": revision},
            csrf=True,
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"], "workspace_conflict")

        status, customer_list, _ = customer.request("GET", "/api/suppliers")
        self.assertEqual(status, 200)
        status, customer_created, _ = customer.request(
            "POST",
            "/api/suppliers",
            {
                "supplier": {
                    "id": "supplier-api-customer",
                    "name": "Customer SOC AG",
                    "service": "Monitoring und SIEM",
                    "owner": "IT Security",
                    "criticality": "Sehr hoch",
                    "review": "In Prüfung",
                    "contractStatus": "Prüfen",
                    "evidence": "Sicherheitsfragebogen.pdf",
                },
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 201, customer_created)
        self.assertEqual(customer_created["supplier"]["reviewStatus"], "vom_kunden_eingereicht")

        status, customer_list, _ = customer.request("GET", "/api/suppliers")
        self.assertEqual(status, 200)
        status, forbidden_approval, _ = customer.request(
            "PATCH",
            "/api/suppliers/supplier-api-customer",
            {
                "changes": {"review": "Freigegeben"},
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(forbidden_approval["error"], "submission_policy_violation")
        self.assertIn(
            "supplier_review_requires_advisor",
            {item["reason"] for item in forbidden_approval["submission"]["violations"]},
        )

        status, delete_forbidden, _ = customer.request(
            "DELETE",
            "/api/suppliers/supplier-api-customer",
            {"expectedRevision": customer_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertIn("saveWorkspace", delete_forbidden["error"])

        status, admin_list, _ = self.admin.request("GET", "/api/suppliers")
        self.assertEqual(status, 200)
        status, approved, _ = self.admin.request(
            "PATCH",
            "/api/suppliers/supplier-api-customer",
            {
                "changes": {"review": "Freigegeben", "contractStatus": "Freigegeben"},
                "expectedRevision": admin_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, approved)
        self.assertEqual(approved["supplier"]["review"], "Freigegeben")

        status, deleted, _ = self.admin.request(
            "DELETE",
            "/api/suppliers/supplier-api-admin",
            {"expectedRevision": approved["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(deleted["deletedId"], "supplier-api-admin")

        status, final_list, _ = self.admin.request("GET", "/api/suppliers")
        self.assertEqual(status, 200)
        self.assertNotIn("supplier-api-admin", {item["id"] for item in final_list["suppliers"]})
        self.assertEqual(
            next(item for item in final_list["suppliers"] if item["id"] == "supplier-api-customer")["review"],
            "Freigegeben",
        )

        status, audit_log, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        actions = {event["action"] for event in audit_log["events"]}
        self.assertTrue({"supplier_created", "supplier_updated", "supplier_deleted"}.issubset(actions))

        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            event = db.execute(
                "SELECT event_type,workspace_revision FROM tenant_events "
                "WHERE tenant_id = 'default' AND action = 'supplier_deleted' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(event[0], "workspace.updated")
        self.assertEqual(event[1], deleted["revision"])

    def test_05g_policy_record_api_versions_records_and_protects_approvals(self):
        temporary_password = "Harbor-Cedar-41!Policy-Draft"
        final_password = "Willow-River-73!Policy-Review"
        status, payload, _ = self.admin.request(
            "POST",
            "/api/users",
            {"username": "policy.api.customer", "password": temporary_password, "role": "customer"},
            csrf=True,
        )
        self.assertEqual(status, 201)
        customer = ApiClient(self.base_url)
        status, payload, _ = customer.login("policy.api.customer", temporary_password)
        self.assertEqual(status, 200)
        status, payload, _ = customer.request(
            "POST",
            "/api/users/me/password",
            {"currentPassword": temporary_password, "newPassword": final_password},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, listed, _ = self.admin.request("GET", "/api/policies")
        self.assertEqual(status, 200)
        revision = listed["revision"]
        status, created, _ = self.admin.request(
            "POST",
            "/api/policies",
            {
                "policy": {
                    "id": "policy-api-admin",
                    "title": "Admin Information Security Policy",
                    "owner": "ISB",
                    "version": "0.1",
                    "status": "Entwurf",
                    "linkedTo": "Clause 5.2 / A.5.1",
                },
                "expectedRevision": revision,
            },
            csrf=True,
        )
        self.assertEqual(status, 201, created)
        self.assertEqual(created["policy"]["id"], "policy-api-admin")
        self.assertEqual(created["policy"]["workflowHistory"][0]["action"], "Policy angelegt")
        self.assertEqual(created["policy"]["versionHistory"][0]["version"], "0.1")

        status, conflict, _ = self.admin.request(
            "PATCH",
            "/api/policies/policy-api-admin",
            {"changes": {"owner": "Veraltet"}, "expectedRevision": revision},
            csrf=True,
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"], "workspace_conflict")

        status, customer_list, _ = customer.request("GET", "/api/policies")
        self.assertEqual(status, 200)
        status, customer_created, _ = customer.request(
            "POST",
            "/api/policies",
            {
                "policy": {
                    "id": "policy-api-customer",
                    "title": "Customer Access Control Policy",
                    "owner": "IT-Leitung",
                    "version": "0.1",
                    "status": "Entwurf",
                    "linkedTo": "A.5.15",
                },
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 201, customer_created)
        self.assertEqual(customer_created["policy"]["reviewStatus"], "vom_kunden_eingereicht")

        status, customer_list, _ = customer.request("GET", "/api/policies")
        self.assertEqual(status, 200)
        status, customer_updated, _ = customer.request(
            "PATCH",
            "/api/policies/policy-api-customer",
            {
                "changes": {"scope": "Alle Mitarbeitenden und administrativen Konten", "version": "0.2"},
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, customer_updated)
        self.assertEqual(customer_updated["policy"]["version"], "0.2")
        self.assertGreaterEqual(len(customer_updated["policy"]["versionHistory"]), 2)
        self.assertEqual(customer_updated["policy"]["versionHistory"][0]["previousVersion"], "0.1")
        self.assertEqual(
            customer_updated["policy"]["versionHistory"][0]["snapshot"]["scope"],
            "Alle Mitarbeitenden und administrativen Konten",
        )

        status, customer_list, _ = customer.request("GET", "/api/policies")
        self.assertEqual(status, 200)
        status, forbidden_approval, _ = customer.request(
            "PATCH",
            "/api/policies/policy-api-customer",
            {"changes": {"status": "Freigegeben"}, "expectedRevision": customer_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(forbidden_approval["error"], "submission_policy_violation")
        self.assertIn(
            "policy_approval_requires_advisor",
            {item["reason"] for item in forbidden_approval["submission"]["violations"]},
        )

        status, admin_list, _ = self.admin.request("GET", "/api/policies")
        self.assertEqual(status, 200)
        status, approved, _ = self.admin.request(
            "PATCH",
            "/api/policies/policy-api-customer",
            {
                "changes": {"status": "Freigegeben", "version": "1.0", "approvedBy": "admin"},
                "expectedRevision": admin_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, approved)
        self.assertEqual(approved["policy"]["status"], "Freigegeben")
        self.assertEqual(approved["policy"]["versionHistory"][0]["previousVersion"], "0.2")

        status, deleted, _ = self.admin.request(
            "DELETE",
            "/api/policies/policy-api-admin",
            {"expectedRevision": approved["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(deleted["deletedId"], "policy-api-admin")

        status, final_list, _ = self.admin.request("GET", "/api/policies")
        self.assertEqual(status, 200)
        self.assertNotIn("policy-api-admin", {item["id"] for item in final_list["policies"]})
        final_policy = next(item for item in final_list["policies"] if item["id"] == "policy-api-customer")
        self.assertEqual(final_policy["status"], "Freigegeben")
        self.assertEqual(final_policy["version"], "1.0")

        status, audit_log, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        actions = {event["action"] for event in audit_log["events"]}
        self.assertTrue({"policy_created", "policy_updated", "policy_deleted"}.issubset(actions))

        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            event = db.execute(
                "SELECT event_type,workspace_revision FROM tenant_events "
                "WHERE tenant_id = 'default' AND action = 'policy_deleted' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(event[0], "workspace.updated")
        self.assertEqual(event[1], deleted["revision"])

    def test_05h_incident_record_api_tracks_workflow_and_protects_closure(self):
        temporary_password = "Harbor-Cedar-42!Incident-Draft"
        final_password = "Willow-River-74!Incident-Review"
        status, payload, _ = self.admin.request(
            "POST",
            "/api/users",
            {"username": "incident.api.customer", "password": temporary_password, "role": "customer"},
            csrf=True,
        )
        self.assertEqual(status, 201)
        customer = ApiClient(self.base_url)
        status, payload, _ = customer.login("incident.api.customer", temporary_password)
        self.assertEqual(status, 200)
        status, payload, _ = customer.request(
            "POST",
            "/api/users/me/password",
            {"currentPassword": temporary_password, "newPassword": final_password},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, listed, _ = self.admin.request("GET", "/api/incidents")
        self.assertEqual(status, 200)
        revision = listed["revision"]
        status, created, _ = self.admin.request(
            "POST",
            "/api/incidents",
            {
                "incident": {
                    "id": "incident-api-admin",
                    "title": "Admin Incident",
                    "owner": "ISB",
                    "severity": "Mittel",
                    "status": "Offen",
                    "framework": "ISO 27001 + NIS-2",
                },
                "expectedRevision": revision,
            },
            csrf=True,
        )
        self.assertEqual(status, 201, created)
        self.assertEqual(created["incident"]["id"], "incident-api-admin")
        self.assertEqual(created["incident"]["workflowHistory"][0]["action"], "Incident angelegt")

        status, conflict, _ = self.admin.request(
            "PATCH",
            "/api/incidents/incident-api-admin",
            {"changes": {"owner": "Veraltet"}, "expectedRevision": revision},
            csrf=True,
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"], "workspace_conflict")

        status, customer_list, _ = customer.request("GET", "/api/incidents")
        self.assertEqual(status, 200)
        status, customer_created, _ = customer.request(
            "POST",
            "/api/incidents",
            {
                "incident": {
                    "id": "incident-api-customer",
                    "title": "Verdächtige Anmeldung",
                    "owner": "IT-Betrieb",
                    "severity": "Hoch",
                    "status": "In Bewertung",
                    "framework": "ISO 27001 + NIS-2",
                    "note": "Administratorkonto wurde vorsorglich gesperrt.",
                },
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 201, customer_created)
        self.assertEqual(customer_created["incident"]["reviewStatus"], "vom_kunden_eingereicht")

        status, customer_list, _ = customer.request("GET", "/api/incidents")
        self.assertEqual(status, 200)
        status, customer_updated, _ = customer.request(
            "PATCH",
            "/api/incidents/incident-api-customer",
            {
                "changes": {
                    "status": "In Behandlung",
                    "evidence": "Ticket SEC-1042",
                    "note": "Logs gesichert und Passwort zurückgesetzt.",
                },
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, customer_updated)
        self.assertEqual(customer_updated["incident"]["evidence"], "Ticket SEC-1042")
        self.assertGreaterEqual(len(customer_updated["incident"]["workflowHistory"]), 2)

        status, customer_list, _ = customer.request("GET", "/api/incidents")
        self.assertEqual(status, 200)
        status, forbidden_closure, _ = customer.request(
            "PATCH",
            "/api/incidents/incident-api-customer",
            {"changes": {"status": "Geschlossen"}, "expectedRevision": customer_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(forbidden_closure["error"], "submission_policy_violation")
        self.assertIn(
            "incident_closure_requires_advisor",
            {item["reason"] for item in forbidden_closure["submission"]["violations"]},
        )

        status, forbidden_delete, _ = customer.request(
            "DELETE",
            "/api/incidents/incident-api-customer",
            {"expectedRevision": customer_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)

        status, admin_list, _ = self.admin.request("GET", "/api/incidents")
        self.assertEqual(status, 200)
        status, closed, _ = self.admin.request(
            "PATCH",
            "/api/incidents/incident-api-customer",
            {
                "changes": {"status": "Geschlossen", "consultantInternalComment": "Abschluss fachlich geprüft."},
                "expectedRevision": admin_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, closed)
        self.assertEqual(closed["incident"]["status"], "Geschlossen")

        status, deleted, _ = self.admin.request(
            "DELETE",
            "/api/incidents/incident-api-admin",
            {"expectedRevision": closed["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(deleted["deletedId"], "incident-api-admin")

        status, final_list, _ = self.admin.request("GET", "/api/incidents")
        self.assertEqual(status, 200)
        self.assertNotIn("incident-api-admin", {item["id"] for item in final_list["incidents"]})
        final_incident = next(item for item in final_list["incidents"] if item["id"] == "incident-api-customer")
        self.assertEqual(final_incident["status"], "Geschlossen")

        status, audit_log, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        actions = {event["action"] for event in audit_log["events"]}
        self.assertTrue({"incident_created", "incident_updated", "incident_deleted"}.issubset(actions))

        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            event = db.execute(
                "SELECT event_type,workspace_revision FROM tenant_events "
                "WHERE tenant_id = 'default' AND action = 'incident_deleted' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(event[0], "workspace.updated")
        self.assertEqual(event[1], deleted["revision"])

    def test_05i_contract_record_api_tracks_workflow_and_protects_approval(self):
        temporary_password = "Harbor-Cedar-42!Contract-Draft"
        final_password = "Willow-River-74!Contract-Review"
        status, payload, _ = self.admin.request(
            "POST",
            "/api/users",
            {"username": "contract.api.customer", "password": temporary_password, "role": "customer"},
            csrf=True,
        )
        self.assertEqual(status, 201)
        customer = ApiClient(self.base_url)
        status, payload, _ = customer.login("contract.api.customer", temporary_password)
        self.assertEqual(status, 200)
        status, payload, _ = customer.request(
            "POST",
            "/api/users/me/password",
            {"currentPassword": temporary_password, "newPassword": final_password},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, listed, _ = self.admin.request("GET", "/api/contracts")
        self.assertEqual(status, 200)
        revision = listed["revision"]
        status, created, _ = self.admin.request(
            "POST",
            "/api/contracts",
            {
                "contract": {
                    "id": "contract-api-admin",
                    "title": "Admin Lieferantenvertrag",
                    "vendor": "Cloud Provider GmbH",
                    "owner": "Einkauf / Legal",
                    "status": "Prüfen",
                    "framework": "ISO 27001 + NIS-2",
                },
                "expectedRevision": revision,
            },
            csrf=True,
        )
        self.assertEqual(status, 201, created)
        self.assertEqual(created["contract"]["id"], "contract-api-admin")
        self.assertEqual(created["contract"]["workflowHistory"][0]["action"], "Vertrag angelegt")

        status, conflict, _ = self.admin.request(
            "PATCH",
            "/api/contracts/contract-api-admin",
            {"changes": {"owner": "Veraltet"}, "expectedRevision": revision},
            csrf=True,
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"], "workspace_conflict")

        status, customer_list, _ = customer.request("GET", "/api/contracts")
        self.assertEqual(status, 200)
        status, customer_created, _ = customer.request(
            "POST",
            "/api/contracts",
            {
                "contract": {
                    "id": "contract-api-customer",
                    "title": "SaaS-Vertrag Sicherheitsklauseln prüfen",
                    "vendor": "SaaS Dienstleister GmbH",
                    "owner": "Einkauf",
                    "status": "Prüfen",
                    "framework": "ISO 27001 + NIS-2",
                    "linkedTo": "A.5.20",
                },
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 201, customer_created)
        self.assertEqual(customer_created["contract"]["reviewStatus"], "vom_kunden_eingereicht")

        status, customer_list, _ = customer.request("GET", "/api/contracts")
        self.assertEqual(status, 200)
        status, customer_updated, _ = customer.request(
            "PATCH",
            "/api/contracts/contract-api-customer",
            {
                "changes": {
                    "status": "Nachbesserung",
                    "evidence": "AVV und Sicherheitsanlage Version 0.2",
                    "review": "2026-12-31",
                },
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, customer_updated)
        self.assertEqual(customer_updated["contract"]["evidence"], "AVV und Sicherheitsanlage Version 0.2")
        self.assertGreaterEqual(len(customer_updated["contract"]["workflowHistory"]), 2)

        status, customer_list, _ = customer.request("GET", "/api/contracts")
        self.assertEqual(status, 200)
        status, forbidden_approval, _ = customer.request(
            "PATCH",
            "/api/contracts/contract-api-customer",
            {"changes": {"status": "Geprüft"}, "expectedRevision": customer_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(forbidden_approval["error"], "submission_policy_violation")
        self.assertIn(
            "contract_approval_requires_advisor",
            {item["reason"] for item in forbidden_approval["submission"]["violations"]},
        )

        status, forbidden_delete, _ = customer.request(
            "DELETE",
            "/api/contracts/contract-api-customer",
            {"expectedRevision": customer_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)

        status, admin_list, _ = self.admin.request("GET", "/api/contracts")
        self.assertEqual(status, 200)
        status, approved, _ = self.admin.request(
            "PATCH",
            "/api/contracts/contract-api-customer",
            {
                "changes": {"status": "Geprüft", "consultantInternalComment": "Vertragsstand fachlich geprüft."},
                "expectedRevision": admin_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, approved)
        self.assertEqual(approved["contract"]["status"], "Geprüft")

        status, deleted, _ = self.admin.request(
            "DELETE",
            "/api/contracts/contract-api-admin",
            {"expectedRevision": approved["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(deleted["deletedId"], "contract-api-admin")

        status, final_list, _ = self.admin.request("GET", "/api/contracts")
        self.assertEqual(status, 200)
        self.assertNotIn("contract-api-admin", {item["id"] for item in final_list["contracts"]})
        final_contract = next(item for item in final_list["contracts"] if item["id"] == "contract-api-customer")
        self.assertEqual(final_contract["status"], "Geprüft")

        status, audit_log, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        actions = {event["action"] for event in audit_log["events"]}
        self.assertTrue({"contract_created", "contract_updated", "contract_deleted"}.issubset(actions))

        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            event = db.execute(
                "SELECT event_type,workspace_revision FROM tenant_events "
                "WHERE tenant_id = 'default' AND action = 'contract_deleted' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(event[0], "workspace.updated")
        self.assertEqual(event[1], deleted["revision"])

    def test_05j_task_record_api_tracks_workflow_and_protects_completion(self):
        temporary_password = "Silver-Lake-31!Task-Draft"
        final_password = "Amber-Forest-86!Task-Review"
        status, payload, _ = self.admin.request(
            "POST",
            "/api/users",
            {"username": "task.api.customer", "password": temporary_password, "role": "customer"},
            csrf=True,
        )
        self.assertEqual(status, 201)
        customer = ApiClient(self.base_url)
        status, payload, _ = customer.login("task.api.customer", temporary_password)
        self.assertEqual(status, 200)
        status, payload, _ = customer.request(
            "POST",
            "/api/users/me/password",
            {"currentPassword": temporary_password, "newPassword": final_password},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, listed, _ = self.admin.request("GET", "/api/tasks")
        self.assertEqual(status, 200)
        revision = listed["revision"]
        status, created, _ = self.admin.request(
            "POST",
            "/api/tasks",
            {
                "task": {
                    "id": "task-api-admin",
                    "title": "Admin Auditpaket prüfen",
                    "module": "Audit",
                    "owner": "Berater / ISB",
                    "status": "Offen",
                },
                "expectedRevision": revision,
            },
            csrf=True,
        )
        self.assertEqual(status, 201, created)
        self.assertEqual(created["task"]["id"], "task-api-admin")
        self.assertEqual(created["task"]["workflowHistory"][0]["action"], "Aufgabe angelegt")

        status, conflict, _ = self.admin.request(
            "PATCH",
            "/api/tasks/task-api-admin",
            {"changes": {"owner": "Veraltet"}, "expectedRevision": revision},
            csrf=True,
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"], "workspace_conflict")

        status, customer_list, _ = customer.request("GET", "/api/tasks")
        self.assertEqual(status, 200)
        status, customer_created, _ = customer.request(
            "POST",
            "/api/tasks",
            {
                "task": {
                    "id": "task-api-customer",
                    "title": "Backup-Nachweis für Q2 ergänzen",
                    "module": "Dokumentation",
                    "owner": "IT-Betrieb",
                    "status": "Offen",
                    "linkedTo": "Backup & Restore Policy",
                },
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 201, customer_created)
        self.assertEqual(customer_created["task"]["reviewStatus"], "vom_kunden_eingereicht")

        status, customer_list, _ = customer.request("GET", "/api/tasks")
        self.assertEqual(status, 200)
        status, customer_updated, _ = customer.request(
            "PATCH",
            "/api/tasks/task-api-customer",
            {
                "changes": {
                    "status": "In Arbeit",
                    "evidence": "Backup-Report Q2 und Restore-Ticket OPS-204",
                    "due": "2026-12-31",
                },
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, customer_updated)
        self.assertEqual(customer_updated["task"]["status"], "In Arbeit")
        self.assertEqual(customer_updated["task"]["evidence"], "Backup-Report Q2 und Restore-Ticket OPS-204")
        self.assertGreaterEqual(len(customer_updated["task"]["workflowHistory"]), 2)

        status, customer_list, _ = customer.request("GET", "/api/tasks")
        self.assertEqual(status, 200)
        status, forbidden_completion, _ = customer.request(
            "PATCH",
            "/api/tasks/task-api-customer",
            {"changes": {"status": "Erledigt"}, "expectedRevision": customer_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(forbidden_completion["error"], "submission_policy_violation")
        self.assertIn(
            "task_completion_requires_advisor",
            {item["reason"] for item in forbidden_completion["submission"]["violations"]},
        )

        status, forbidden_approval, _ = customer.request(
            "PATCH",
            "/api/tasks/task-api-customer",
            {"changes": {"reviewStatus": "freigegeben"}, "expectedRevision": customer_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(forbidden_approval["error"], "submission_policy_violation")

        status, forbidden_delete, _ = customer.request(
            "DELETE",
            "/api/tasks/task-api-customer",
            {"expectedRevision": customer_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)

        status, admin_list, _ = self.admin.request("GET", "/api/tasks")
        self.assertEqual(status, 200)
        status, completed, _ = self.admin.request(
            "PATCH",
            "/api/tasks/task-api-customer",
            {
                "changes": {
                    "status": "Erledigt",
                    "reviewStatus": "freigegeben",
                    "consultantInternalComment": "Ergebnis und Nachweis fachlich geprüft.",
                },
                "expectedRevision": admin_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, completed)
        self.assertEqual(completed["task"]["status"], "Erledigt")
        self.assertEqual(completed["task"]["reviewStatus"], "freigegeben")

        status, deleted, _ = self.admin.request(
            "DELETE",
            "/api/tasks/task-api-admin",
            {"expectedRevision": completed["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(deleted["deletedId"], "task-api-admin")

        status, final_list, _ = self.admin.request("GET", "/api/tasks")
        self.assertEqual(status, 200)
        self.assertNotIn("task-api-admin", {item["id"] for item in final_list["tasks"]})
        final_task = next(item for item in final_list["tasks"] if item["id"] == "task-api-customer")
        self.assertEqual(final_task["status"], "Erledigt")

        status, audit_log, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        actions = {event["action"] for event in audit_log["events"]}
        self.assertTrue({"task_created", "task_updated", "task_deleted"}.issubset(actions))

        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            event = db.execute(
                "SELECT event_type,workspace_revision FROM tenant_events "
                "WHERE tenant_id = 'default' AND action = 'task_deleted' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(event[0], "workspace.updated")
        self.assertEqual(event[1], deleted["revision"])

    def test_05k_legal_register_api_tracks_workflow_and_protects_decisions(self):
        temporary_password = "Silver-Lake-31!Legal-Draft"
        final_password = "Amber-Forest-86!Legal-Review"
        status, payload, _ = self.admin.request(
            "POST",
            "/api/users",
            {"username": "legal.api.customer", "password": temporary_password, "role": "customer"},
            csrf=True,
        )
        self.assertEqual(status, 201)
        customer = ApiClient(self.base_url)
        status, payload, _ = customer.login("legal.api.customer", temporary_password)
        self.assertEqual(status, 200)
        status, payload, _ = customer.request(
            "POST",
            "/api/users/me/password",
            {"currentPassword": temporary_password, "newPassword": final_password},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, listed, _ = self.admin.request("GET", "/api/legal")
        self.assertEqual(status, 200)
        status, created, _ = self.admin.request(
            "POST",
            "/api/legal",
            {
                "legalEntry": {
                    "id": "legal-api-admin",
                    "requirement": "Vertragliche Aufbewahrungsfrist fachlich prüfen",
                    "source": "Kundenvertrag",
                    "framework": "ISO 27001",
                    "owner": "Legal",
                    "status": "Prüfen",
                },
                "expectedRevision": listed["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 201, created)
        self.assertEqual(created["legalEntry"]["id"], "legal-api-admin")
        self.assertEqual(created["legalEntry"]["workflowHistory"][0]["action"], "Rechtsanforderung angelegt")

        status, conflict, _ = self.admin.request(
            "PATCH",
            "/api/legal/legal-api-admin",
            {"changes": {"owner": "Veraltet"}, "expectedRevision": listed["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"], "workspace_conflict")

        status, customer_list, _ = customer.request("GET", "/api/legal")
        self.assertEqual(status, 200)
        status, customer_created, _ = customer.request(
            "POST",
            "/api/legal",
            {
                "legalEntry": {
                    "id": "legal-api-customer",
                    "requirement": "Registrierungspflicht bewerten",
                    "source": "NIS-2-Dokument, §33",
                    "framework": "NIS-2",
                    "owner": "Legal / Geschäftsleitung",
                    "status": "Prüfen",
                },
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 201, customer_created)
        self.assertEqual(customer_created["legalEntry"]["reviewStatus"], "vom_kunden_eingereicht")

        status, customer_list, _ = customer.request("GET", "/api/legal")
        self.assertEqual(status, 200)
        status, customer_updated, _ = customer.request(
            "PATCH",
            "/api/legal/legal-api-customer",
            {
                "changes": {
                    "evidence": "Interne Betroffenheitsnotiz und Registerauszug",
                    "due": "2026-12-31",
                    "note": "Entscheidung durch Legal steht aus.",
                },
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, customer_updated)
        self.assertEqual(customer_updated["legalEntry"]["evidence"], "Interne Betroffenheitsnotiz und Registerauszug")
        self.assertGreaterEqual(len(customer_updated["legalEntry"]["workflowHistory"]), 2)

        status, customer_list, _ = customer.request("GET", "/api/legal")
        self.assertEqual(status, 200)
        status, forbidden_decision, _ = customer.request(
            "PATCH",
            "/api/legal/legal-api-customer",
            {"changes": {"status": "Anwendbar"}, "expectedRevision": customer_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(forbidden_decision["error"], "submission_policy_violation")
        self.assertIn(
            "legal_decision_requires_advisor",
            {item["reason"] for item in forbidden_decision["submission"]["violations"]},
        )

        status, forbidden_approval, _ = customer.request(
            "PATCH",
            "/api/legal/legal-api-customer",
            {"changes": {"reviewStatus": "freigegeben"}, "expectedRevision": customer_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(forbidden_approval["error"], "submission_policy_violation")

        status, forbidden_delete, _ = customer.request(
            "DELETE",
            "/api/legal/legal-api-customer",
            {"expectedRevision": customer_list["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 403)

        status, admin_list, _ = self.admin.request("GET", "/api/legal")
        self.assertEqual(status, 200)
        status, approved, _ = self.admin.request(
            "PATCH",
            "/api/legal/legal-api-customer",
            {
                "changes": {
                    "status": "Anwendbar",
                    "reviewStatus": "freigegeben",
                    "consultantInternalComment": "Quelle und Einordnung fachlich geprüft.",
                },
                "expectedRevision": admin_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, approved)
        self.assertEqual(approved["legalEntry"]["status"], "Anwendbar")
        self.assertEqual(approved["legalEntry"]["reviewStatus"], "freigegeben")

        status, deleted, _ = self.admin.request(
            "DELETE",
            "/api/legal/legal-api-admin",
            {"expectedRevision": approved["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(deleted["deletedId"], "legal-api-admin")

        status, final_list, _ = self.admin.request("GET", "/api/legal")
        self.assertEqual(status, 200)
        self.assertNotIn("legal-api-admin", {item["id"] for item in final_list["legal"]})
        final_entry = next(item for item in final_list["legal"] if item["id"] == "legal-api-customer")
        self.assertEqual(final_entry["status"], "Anwendbar")

        status, audit_log, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        actions = {event["action"] for event in audit_log["events"]}
        self.assertTrue({"legal_created", "legal_updated", "legal_deleted"}.issubset(actions))

        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            event = db.execute(
                "SELECT event_type,workspace_revision FROM tenant_events "
                "WHERE tenant_id = 'default' AND action = 'legal_deleted' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(event[0], "workspace.updated")
        self.assertEqual(event[1], deleted["revision"])

    def test_05l_soa_control_api_is_atomic_role_aware_and_audited(self):
        temporary_password = "Silver-Harbor-47!SoA-Draft"
        final_password = "Amber-Valley-63!SoA-Review"
        status, payload, _ = self.admin.request(
            "POST",
            "/api/users",
            {"username": "soa.api.customer", "password": temporary_password, "role": "customer"},
            csrf=True,
        )
        self.assertEqual(status, 201)
        customer = ApiClient(self.base_url)
        status, payload, _ = customer.login("soa.api.customer", temporary_password)
        self.assertEqual(status, 200)
        status, payload, _ = customer.request(
            "POST",
            "/api/users/me/password",
            {"currentPassword": temporary_password, "newPassword": final_password},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, listed, _ = self.admin.request("GET", "/api/soa")
        self.assertEqual(status, 200)
        self.assertIsInstance(listed["soa"], list)
        initial_revision = listed["revision"]
        status, seeded, _ = self.admin.request(
            "PATCH",
            "/api/soa/A.8.34",
            {
                "changes": {
                    "applicability": "Anwendbar",
                    "implementation": "Geplant",
                    "owner": "ISB / Audit",
                    "justification": "Schutzmaßnahmen für Audittests werden vorbereitet.",
                },
                "expectedRevision": initial_revision,
            },
            csrf=True,
        )
        self.assertEqual(status, 200, seeded)
        self.assertEqual(seeded["soaControl"]["controlId"], "A.8.34")
        self.assertEqual(seeded["soaControl"]["workflowHistory"][0]["action"], "SoA-Control angelegt")

        status, conflict, _ = self.admin.request(
            "PATCH",
            "/api/soa/A.8.34",
            {"changes": {"owner": "Veraltet"}, "expectedRevision": initial_revision},
            csrf=True,
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"], "workspace_conflict")

        status, customer_list, _ = customer.request("GET", "/api/soa")
        self.assertEqual(status, 200)
        status, submitted, _ = customer.request(
            "PATCH",
            "/api/soa/A.8.34",
            {
                "changes": {
                    "implementation": "In Umsetzung",
                    "evidence": "Interner Prüfplan und Testfreigabe",
                    "risk": "R-034 Beeinträchtigung produktiver Systeme",
                    "review": "2026-12-31",
                },
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, submitted)
        self.assertEqual(submitted["soaControl"]["reviewStatus"], "vom_kunden_eingereicht")
        self.assertEqual(submitted["soaControl"]["evidence"], "Interner Prüfplan und Testfreigabe")
        self.assertGreaterEqual(len(submitted["soaControl"]["workflowHistory"]), 2)

        status, customer_list, _ = customer.request("GET", "/api/soa")
        self.assertEqual(status, 200)
        status, forbidden, _ = customer.request(
            "PATCH",
            "/api/soa/A.8.34",
            {
                "changes": {"reviewStatus": "freigegeben"},
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(forbidden["error"], "submission_policy_violation")
        self.assertIn(
            "soa_decision_requires_advisor",
            {item["reason"] for item in forbidden["submission"]["violations"]},
        )

        status, admin_list, _ = self.admin.request("GET", "/api/soa")
        self.assertEqual(status, 200)
        status, approved, _ = self.admin.request(
            "PATCH",
            "/api/soa/A.8.34",
            {
                "changes": {
                    "reviewStatus": "freigegeben",
                    "consultantInternalComment": "Begründung und Nachweis fachlich geprüft.",
                    "auditRelevant": True,
                },
                "expectedRevision": admin_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, approved)
        self.assertEqual(approved["soaControl"]["reviewStatus"], "freigegeben")
        self.assertTrue(approved["soaControl"]["auditRelevant"])

        status, final_list, _ = self.admin.request("GET", "/api/soa")
        self.assertEqual(status, 200)
        final_record = next(item for item in final_list["soa"] if item["controlId"] == "A.8.34")
        self.assertEqual(final_record["reviewStatus"], "freigegeben")
        self.assertEqual(final_record["implementation"], "In Umsetzung")

        status, audit_log, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        self.assertIn("soa_updated", {event["action"] for event in audit_log["events"]})

        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            event = db.execute(
                "SELECT event_type,workspace_revision FROM tenant_events "
                "WHERE tenant_id = 'default' AND action = 'soa_updated' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(event[0], "workspace.updated")
        self.assertEqual(event[1], approved["revision"])

    def test_05m_audit_finding_api_is_atomic_role_aware_and_audited(self):
        status, workspace, _ = self.admin.request("GET", "/api/state")
        self.assertEqual(status, 200)
        if workspace.get("revision") is None:
            starter_state = {
                "documents": [], "assets": [], "risks": [], "legal": [], "suppliers": [],
                "policies": [], "incidents": [], "contracts": [], "integrations": [], "tasks": [],
                "projectPlan": [], "templateDrafts": [], "auditFindings": [],
            }
            status, initialized, _ = self.admin.request(
                "PUT",
                "/api/state",
                {"state": starter_state, "expectedRevision": None},
                csrf=True,
            )
            self.assertEqual(status, 200, initialized)

        temporary_password = "Silver-Harbor-48!Finding-Draft"
        final_password = "Amber-Valley-64!Finding-Review"
        status, payload, _ = self.admin.request(
            "POST",
            "/api/users",
            {"username": "finding.api.customer", "password": temporary_password, "role": "customer"},
            csrf=True,
        )
        self.assertEqual(status, 201)
        customer = ApiClient(self.base_url)
        status, payload, _ = customer.login("finding.api.customer", temporary_password)
        self.assertEqual(status, 200)
        status, payload, _ = customer.request(
            "POST",
            "/api/users/me/password",
            {"currentPassword": temporary_password, "newPassword": final_password},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, listed, _ = self.admin.request("GET", "/api/audit-findings")
        self.assertEqual(status, 200)
        self.assertIsInstance(listed["auditFindings"], list)
        initial_revision = listed["revision"]
        status, created, _ = self.admin.request(
            "POST",
            "/api/audit-findings",
            {
                "auditFinding": {
                    "id": "finding-api-001",
                    "title": "Privilegierte Konten ohne vollständige MFA-Prüfung",
                    "type": "Kontrollabweichung",
                    "severity": "Hoch",
                    "status": "offen",
                    "owner": "IT Security",
                    "due": "2026-12-31",
                    "mapping": "A.5.15 / A.8.5",
                    "note": "Nachweis und Stichprobe fachlich prüfen.",
                    "sourceView": "audit",
                },
                "expectedRevision": initial_revision,
            },
            csrf=True,
        )
        self.assertEqual(status, 201, created)
        self.assertEqual(created["auditFinding"]["id"], "finding-api-001")
        self.assertEqual(created["auditFinding"]["workflowHistory"][0]["action"], "Audit-Finding angelegt")

        status, conflict, _ = self.admin.request(
            "PATCH",
            "/api/audit-findings/finding-api-001",
            {"changes": {"owner": "Veraltet"}, "expectedRevision": initial_revision},
            csrf=True,
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"], "workspace_conflict")

        status, customer_list, _ = customer.request("GET", "/api/audit-findings")
        self.assertEqual(status, 200)
        status, submitted, _ = customer.request(
            "PATCH",
            "/api/audit-findings/finding-api-001",
            {
                "changes": {
                    "evidence": "MFA-Konfigurationsreport und Stichprobenliste",
                    "customerComment": "Die technischen Nachweise wurden ergänzt.",
                },
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, submitted)
        self.assertEqual(submitted["auditFinding"]["reviewStatus"], "vom_kunden_eingereicht")
        self.assertEqual(submitted["auditFinding"]["evidence"], "MFA-Konfigurationsreport und Stichprobenliste")

        status, customer_list, _ = customer.request("GET", "/api/audit-findings")
        self.assertEqual(status, 200)
        status, forbidden, _ = customer.request(
            "PATCH",
            "/api/audit-findings/finding-api-001",
            {
                "changes": {"status": "freigegeben", "reviewStatus": "freigegeben"},
                "expectedRevision": customer_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(forbidden["error"], "submission_policy_violation")
        self.assertIn(
            "audit_finding_decision_requires_advisor",
            {item["reason"] for item in forbidden["submission"]["violations"]},
        )

        status, admin_list, _ = self.admin.request("GET", "/api/audit-findings")
        self.assertEqual(status, 200)
        status, approved, _ = self.admin.request(
            "PATCH",
            "/api/audit-findings/finding-api-001",
            {
                "changes": {
                    "status": "auditrelevant",
                    "reviewStatus": "auditrelevant",
                    "consultantInternalComment": "Finding ist für die Auditstichprobe relevant.",
                    "auditRelevant": True,
                },
                "expectedRevision": admin_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, approved)
        self.assertEqual(approved["auditFinding"]["status"], "auditrelevant")
        self.assertTrue(approved["auditFinding"]["auditRelevant"])

        status, final_list, _ = self.admin.request("GET", "/api/audit-findings")
        self.assertEqual(status, 200)
        final_record = next(item for item in final_list["auditFindings"] if item["id"] == "finding-api-001")
        self.assertEqual(final_record["reviewStatus"], "auditrelevant")
        self.assertGreaterEqual(len(final_record["workflowHistory"]), 3)

        status, capa_created, _ = self.admin.request(
            "POST",
            "/api/audit-findings",
            {
                "auditFinding": {
                    "id": "capa-api-001",
                    "title": "MFA-Prüfung privilegierter Konten vervollständigen",
                    "type": "CAPA",
                    "severity": "Hoch",
                    "status": "offen",
                    "owner": "IT Security",
                    "due": "2026-12-31",
                    "mapping": "A.5.15 / Audit-Finding finding-api-001",
                    "sourceFindingId": "finding-api-001",
                    "nonconformity": "Die MFA-Prüfung privilegierter Konten war nicht vollständig belegt.",
                    "immediateCorrection": "Fehlende Konten wurden in die Stichprobe aufgenommen.",
                    "rootCause": "Die monatliche Kontrollliste enthielt nicht alle privilegierten Identitäten.",
                    "correctiveAction": "Kontrollliste automatisiert mit dem IAM-Bestand abgleichen.",
                    "effectivenessCriteria": "Drei aufeinanderfolgende Monatsprüfungen ohne Abweichung.",
                    "effectivenessEvidence": "Monatsreports und signierte Stichprobenliste",
                    "sourceView": "capa",
                    "auditRelevant": True,
                },
                "expectedRevision": final_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 201, capa_created)
        self.assertEqual(capa_created["auditFinding"]["type"], "CAPA")
        self.assertEqual(capa_created["auditFinding"]["sourceFindingId"], "finding-api-001")

        status, capa_rework, _ = self.admin.request(
            "PATCH",
            "/api/audit-findings/capa-api-001",
            {
                "changes": {
                    "status": "nacharbeit_noetig",
                    "reviewStatus": "nacharbeit_noetig",
                    "customerComment": "Bitte den zweiten Monatsreport als Wirksamkeitsnachweis ergänzen.",
                },
                "expectedRevision": capa_created["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, capa_rework)
        self.assertEqual(capa_rework["customerTask"]["module"], "Maßnahmen & CAPA")
        self.assertEqual(capa_rework["customerTask"]["status"], "Offen")

        status, capa_approved, _ = self.admin.request(
            "PATCH",
            "/api/audit-findings/capa-api-001",
            {
                "changes": {
                    "status": "freigegeben",
                    "reviewStatus": "freigegeben",
                    "effectivenessAssessment": "Die drei Monatsreports belegen die nachhaltige Umsetzung.",
                    "consultantDecision": "Wirksamkeit fachlich bestätigt",
                },
                "expectedRevision": capa_rework["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, capa_approved)
        self.assertEqual(capa_approved["auditFinding"]["reviewStatus"], "freigegeben")
        self.assertEqual(capa_approved["auditFinding"]["effectivenessVerifiedBy"], "admin")
        self.assertEqual(capa_approved["customerTask"]["status"], "Erledigt")

        status, audit_log, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        self.assertIn("audit_finding_updated", {event["action"] for event in audit_log["events"]})

        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            event = db.execute(
                "SELECT event_type,workspace_revision FROM tenant_events "
                "WHERE tenant_id = 'default' AND action = 'audit_finding_updated' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(event[0], "workspace.updated")
        self.assertEqual(event[1], capa_approved["revision"])

    def test_05n_management_review_api_is_atomic_role_aware_and_creates_rework_tasks(self):
        status, workspace, _ = self.admin.request("GET", "/api/state")
        self.assertEqual(status, 200, workspace)
        if workspace.get("revision") is None:
            starter_state = {
                "documents": [], "assets": [], "risks": [], "legal": [], "suppliers": [],
                "policies": [], "incidents": [], "contracts": [], "integrations": [], "tasks": [],
                "projectPlan": [], "templateDrafts": [], "auditFindings": [],
                "managementReview": {},
            }
            status, initialized, _ = self.admin.request(
                "PUT",
                "/api/state",
                {"state": starter_state, "expectedRevision": None},
                csrf=True,
            )
            self.assertEqual(status, 200, initialized)

        temporary_password = "Silver-Harbor-48!Review-Draft"
        final_password = "Amber-Valley-64!Review-Submit"
        status, payload, _ = self.admin.request(
            "POST",
            "/api/users",
            {"username": "management.review.customer", "password": temporary_password, "role": "customer"},
            csrf=True,
        )
        self.assertEqual(status, 201, payload)
        customer = ApiClient(self.base_url)
        status, payload, _ = customer.login("management.review.customer", temporary_password)
        self.assertEqual(status, 200, payload)
        status, payload, _ = customer.request(
            "POST",
            "/api/users/me/password",
            {"currentPassword": temporary_password, "newPassword": final_password},
            csrf=True,
        )
        self.assertEqual(status, 200, payload)

        status, listed, _ = self.admin.request("GET", "/api/management-review")
        self.assertEqual(status, 200, listed)
        initial_revision = listed["revision"]
        status, prepared, _ = self.admin.request(
            "PATCH",
            "/api/management-review",
            {
                "changes": {
                    "title": "Managementbewertung Informationssicherheit 2026",
                    "reviewPeriod": "Januar bis Juni 2026",
                    "meetingDate": "2026-07-20",
                    "nextReview": "2027-01-20",
                    "chair": "Geschäftsführung",
                    "participants": "Geschäftsführung, ISB, IT",
                    "summary": "Risiken, Auditergebnisse, Vorfälle und Zielerreichung wurden bewertet.",
                    "decisions": "Offene Maßnahmen werden priorisiert und mit Verantwortlichen versehen.",
                    "status": "vorbereitet",
                    "reviewStatus": "vorbereitet",
                    "auditRelevant": True,
                },
                "expectedRevision": initial_revision,
            },
            csrf=True,
        )
        self.assertEqual(status, 200, prepared)
        self.assertEqual(prepared["managementReview"]["reviewStatus"], "vorbereitet")

        status, conflict, _ = self.admin.request(
            "PATCH",
            "/api/management-review",
            {"changes": {"chair": "Veraltet"}, "expectedRevision": initial_revision},
            csrf=True,
        )
        self.assertEqual(status, 409, conflict)
        self.assertEqual(conflict["error"], "workspace_conflict")

        status, customer_review, _ = customer.request("GET", "/api/management-review")
        self.assertEqual(status, 200, customer_review)
        status, submitted, _ = customer.request(
            "PATCH",
            "/api/management-review",
            {
                "changes": {
                    "summary": "Die Leitung hat die aktuelle Lage und wesentliche Änderungen erörtert.",
                    "customerComment": "Die Sitzungsnotizen und Entscheidungen wurden ergänzt.",
                },
                "expectedRevision": customer_review["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, submitted)
        self.assertEqual(submitted["managementReview"]["reviewStatus"], "vom_kunden_eingereicht")
        self.assertEqual(submitted["managementReview"]["submittedBy"], "management.review.customer")

        status, customer_review, _ = customer.request("GET", "/api/management-review")
        self.assertEqual(status, 200, customer_review)
        status, forbidden, _ = customer.request(
            "PATCH",
            "/api/management-review",
            {
                "changes": {
                    "status": "freigegeben",
                    "reviewStatus": "freigegeben",
                    "consultantInternalComment": "Kunde darf das nicht setzen.",
                },
                "expectedRevision": customer_review["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 403, forbidden)
        self.assertEqual(forbidden["error"], "submission_policy_violation")
        self.assertIn(
            "management_review_decision_requires_advisor",
            {item["reason"] for item in forbidden["submission"]["violations"]},
        )

        status, advisor_review, _ = self.admin.request("GET", "/api/management-review")
        self.assertEqual(status, 200, advisor_review)
        status, returned, _ = self.admin.request(
            "PATCH",
            "/api/management-review",
            {
                "changes": {
                    "status": "nacharbeit_noetig",
                    "reviewStatus": "nacharbeit_noetig",
                    "customerComment": "Bitte Verantwortliche und Termine für alle Entscheidungen ergänzen.",
                    "consultantInternalComment": "Beschlüsse sind noch nicht vollständig operationalisiert.",
                    "consultantDecision": "Nacharbeit nötig",
                    "auditRelevant": True,
                },
                "expectedRevision": advisor_review["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, returned)
        self.assertEqual(returned["managementReview"]["reviewStatus"], "nacharbeit_noetig")
        self.assertEqual(returned["customerTask"]["workflowType"], "review-rework")
        self.assertEqual(returned["customerTask"]["reviewItemKey"], "managementReview:management-review")
        self.assertIn("Verantwortliche und Termine", returned["customerTask"]["reworkMissing"])

        status, task_list, _ = self.admin.request("GET", "/api/tasks")
        self.assertEqual(status, 200, task_list)
        rework_task = next(
            task for task in task_list["tasks"]
            if task.get("reviewItemKey") == "managementReview:management-review"
        )
        self.assertEqual(rework_task["status"], "Offen")

        status, approved, _ = self.admin.request(
            "PATCH",
            "/api/management-review",
            {
                "changes": {
                    "status": "freigegeben",
                    "reviewStatus": "freigegeben",
                    "consultantInternalComment": "Managementbewertung fachlich geprüft.",
                    "consultantDecision": "Freigegeben durch Berater/Admin",
                    "auditRelevant": True,
                },
                "expectedRevision": task_list["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, approved)
        self.assertEqual(approved["managementReview"]["reviewStatus"], "freigegeben")
        self.assertEqual(approved["managementReview"]["approvedBy"], "admin")
        self.assertEqual(approved["customerTask"]["status"], "Erledigt")
        self.assertGreaterEqual(len(approved["managementReview"]["workflowHistory"]), 4)

        status, audit_log, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200, audit_log)
        self.assertIn("management_review_updated", {event["action"] for event in audit_log["events"]})

        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            event = db.execute(
                "SELECT event_type,workspace_revision FROM tenant_events "
                "WHERE tenant_id = 'default' AND action = 'management_review_updated' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(event[0], "workspace.updated")
        self.assertEqual(event[1], approved["revision"])

    def test_05o_internal_audit_plan_is_persistent_role_aware_and_creates_rework_tasks(self):
        status, listed, _ = self.admin.request("GET", "/api/internal-audit-plan")
        self.assertEqual(status, 200, listed)
        if listed.get("revision") is None:
            starter_state = {
                "documents": [], "assets": [], "risks": [], "legal": [], "suppliers": [],
                "policies": [], "incidents": [], "contracts": [], "integrations": [], "tasks": [],
                "projectPlan": [], "templateDrafts": [], "auditFindings": [],
                "managementReview": {}, "internalAuditPlan": {},
            }
            status, initialized, _ = self.admin.request(
                "PUT",
                "/api/state",
                {"state": starter_state, "expectedRevision": None},
                csrf=True,
            )
            self.assertEqual(status, 200, initialized)
            status, listed, _ = self.admin.request("GET", "/api/internal-audit-plan")
            self.assertEqual(status, 200, listed)
        initial_revision = listed["revision"]
        status, prepared, _ = self.admin.request(
            "PATCH",
            "/api/internal-audit-plan",
            {
                "changes": {
                    "title": "Internes Audit Informationssicherheit 2026",
                    "auditPeriod": "Q3 2026",
                    "plannedDate": "2026-09-15",
                    "reportDue": "2026-09-30",
                    "leadAuditor": "Interne Revision",
                    "participants": "ISB, IT, HR, Einkauf",
                    "scope": "Zentrale Prozesse, Cloud-Dienste und Hauptstandort",
                    "objectives": "Umsetzungsstand und Wirksamkeit der internen Vorgaben prüfen",
                    "criteria": "Freigegebene interne Richtlinien und dokumentierte Verfahren",
                    "status": "vorbereitet",
                    "reviewStatus": "vorbereitet",
                    "auditRelevant": True,
                },
                "expectedRevision": initial_revision,
            },
            csrf=True,
        )
        self.assertEqual(status, 200, prepared)
        self.assertEqual(prepared["internalAuditPlan"]["leadAuditor"], "Interne Revision")

        temporary_password = "Silver-Harbor-49!Audit-Plan"
        final_password = "Amber-Valley-65!Audit-Plan"
        status, payload, _ = self.admin.request(
            "POST",
            "/api/users",
            {"username": "audit.plan.customer", "password": temporary_password, "role": "customer"},
            csrf=True,
        )
        self.assertEqual(status, 201, payload)
        customer = ApiClient(self.base_url)
        status, payload, _ = customer.login("audit.plan.customer", temporary_password)
        self.assertEqual(status, 200, payload)
        status, payload, _ = customer.request(
            "POST",
            "/api/users/me/password",
            {"currentPassword": temporary_password, "newPassword": final_password},
            csrf=True,
        )
        self.assertEqual(status, 200, payload)

        status, customer_plan, _ = customer.request("GET", "/api/internal-audit-plan")
        self.assertEqual(status, 200, customer_plan)
        status, submitted, _ = customer.request(
            "PATCH",
            "/api/internal-audit-plan",
            {
                "changes": {
                    "interviewPlan": "Geschäftsführung, ISB, IT und Einkauf interviewen",
                    "samplingPlan": "Zugriffsreviews, Lieferantenakten und Vorfallnachweise prüfen",
                    "customerComment": "Interview- und Stichprobenplan wurden ergänzt.",
                },
                "expectedRevision": customer_plan["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, submitted)
        self.assertEqual(submitted["internalAuditPlan"]["reviewStatus"], "vom_kunden_eingereicht")

        status, customer_plan, _ = customer.request("GET", "/api/internal-audit-plan")
        status, forbidden, _ = customer.request(
            "PATCH",
            "/api/internal-audit-plan",
            {
                "changes": {
                    "reviewStatus": "freigegeben",
                    "consultantInternalComment": "Kunde darf dies nicht setzen.",
                },
                "expectedRevision": customer_plan["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 403, forbidden)
        self.assertIn(
            "internal_audit_plan_decision_requires_advisor",
            {item["reason"] for item in forbidden["submission"]["violations"]},
        )

        status, advisor_plan, _ = self.admin.request("GET", "/api/internal-audit-plan")
        status, returned, _ = self.admin.request(
            "PATCH",
            "/api/internal-audit-plan",
            {
                "changes": {
                    "status": "nacharbeit_noetig",
                    "reviewStatus": "nacharbeit_noetig",
                    "customerComment": "Bitte Interviewtermine und verantwortliche Ansprechpartner ergänzen.",
                    "consultantInternalComment": "Plan ist organisatorisch noch nicht ausführbar.",
                    "auditRelevant": True,
                },
                "expectedRevision": advisor_plan["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, returned)
        self.assertEqual(returned["customerTask"]["reviewItemKey"], "internalAuditPlan:internal-audit-plan")
        self.assertEqual(returned["customerTask"]["status"], "Offen")

        status, approved, _ = self.admin.request(
            "PATCH",
            "/api/internal-audit-plan",
            {
                "changes": {
                    "status": "freigegeben",
                    "reviewStatus": "freigegeben",
                    "consultantInternalComment": "Auditplanung fachlich geprüft.",
                    "auditRelevant": True,
                },
                "expectedRevision": returned["revision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 200, approved)
        self.assertEqual(approved["internalAuditPlan"]["reviewStatus"], "freigegeben")
        self.assertEqual(approved["internalAuditPlan"]["approvedBy"], "admin")
        self.assertEqual(approved["customerTask"]["status"], "Erledigt")

        status, audit_log, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200, audit_log)
        self.assertIn("internal_audit_plan_updated", {event["action"] for event in audit_log["events"]})

        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            event = db.execute(
                "SELECT event_type,workspace_revision FROM tenant_events "
                "WHERE tenant_id = 'default' AND action = 'internal_audit_plan_updated' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(event[0], "workspace.updated")
        self.assertEqual(event[1], approved["revision"])

    def test_05p_audit_package_requires_current_advisor_approval(self):
        customer_username = "audit.package.customer"
        customer_temp_password = "Violet-River-83!Quiet-Stone"
        customer_password = "Copper-Meadow-47!Clear-Harbor"
        status, payload, _ = self.admin.request(
            "POST",
            "/api/users",
            {
                "username": customer_username,
                "password": customer_temp_password,
                "role": "customer",
            },
            csrf=True,
        )
        self.assertEqual(status, 201)
        customer = ApiClient(self.base_url)
        status, payload, _ = customer.login(customer_username, customer_temp_password)
        self.assertEqual(status, 200)
        status, payload, _ = customer.request(
            "POST",
            "/api/users/me/password",
            {
                "currentPassword": customer_temp_password,
                "newPassword": customer_password,
            },
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, workspace, _ = self.admin.request("GET", "/api/state")
        self.assertEqual(status, 200)
        if workspace["state"] is None:
            initial_state = {key: [] for key in (
                "documents", "assets", "risks", "legal", "suppliers", "policies",
                "incidents", "contracts", "integrations", "tasks", "projectPlan",
                "templateDrafts",
            )}
            initial_state.update({
                "soa": [],
                "gaps": [],
                "auditFindings": [],
                "managementReview": {
                    "id": "management-review",
                    "title": "Managementbewertung",
                    "auditRelevant": True,
                    "reviewStatus": "offen",
                },
                "internalAuditPlan": {
                    "id": "internal-audit-plan",
                    "title": "Interne Auditplanung",
                    "auditRelevant": False,
                    "reviewStatus": "offen",
                },
            })
            status, workspace, _ = self.admin.request(
                "PUT",
                "/api/state",
                {"state": initial_state, "expectedRevision": 0},
                csrf=True,
            )
            self.assertEqual(status, 200)

        status, initial, _ = self.admin.request("GET", "/api/audit-package/status")
        self.assertEqual(status, 200)
        self.assertFalse(initial["auditPackage"]["advisorApproved"])

        status, forbidden, _ = customer.request(
            "POST",
            "/api/audit-package/approve",
            {
                "fingerprint": initial["auditPackage"]["fingerprint"],
                "expectedRevision": initial["auditPackage"]["workspaceRevision"],
            },
            csrf=True,
        )
        self.assertEqual(status, 403)
        self.assertIn("permission", forbidden["error"])

        status, current, _ = self.admin.request("GET", "/api/state")
        self.assertEqual(status, 200)
        minimal_state = current["state"]
        for key in (
            "documents", "assets", "risks", "legal", "suppliers", "policies",
            "incidents", "contracts", "integrations", "tasks", "projectPlan",
            "templateDrafts", "soa", "gaps", "auditFindings",
        ):
            minimal_state[key] = []
        minimal_state["managementReview"] = {
            "id": "management-review",
            "title": "Managementbewertung",
            "auditRelevant": False,
            "reviewStatus": "offen",
            "consultantInternalComment": "must-not-be-exported",
        }
        minimal_state["internalAuditPlan"] = {
            "id": "internal-audit-plan",
            "title": "Interne Auditplanung",
            "auditRelevant": False,
            "reviewStatus": "offen",
        }
        minimal_state["auditPackage"] = {"status": "vorbereitet", "approvals": []}
        status, saved, _ = self.admin.request(
            "PUT",
            "/api/state",
            {"state": minimal_state, "expectedRevision": current["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, prepared, _ = self.admin.request("GET", "/api/audit-package/status")
        self.assertEqual(status, 200)
        self.assertTrue(prepared["auditPackage"]["formalGateClear"])
        self.assertFalse(prepared["auditPackage"]["advisorApproved"])
        self.assertFalse(prepared["auditPackage"]["exportReady"])
        self.assertEqual(prepared["auditPackage"]["status"], "formal_vorbereitet")

        status, not_ready, _ = customer.request("GET", "/api/audit-package/export")
        self.assertEqual(status, 409)
        self.assertEqual(not_ready["error"], "audit_package_not_approved")

        status, approved, _ = self.admin.request(
            "POST",
            "/api/audit-package/approve",
            {
                "fingerprint": prepared["auditPackage"]["fingerprint"],
                "expectedRevision": saved["revision"],
                "comment": "Technische Paketfreigabe fuer den Integrationstest.",
            },
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertTrue(approved["auditPackage"]["advisorApproved"])
        self.assertTrue(approved["auditPackage"]["exportReady"])
        self.assertEqual(approved["approval"]["approvedBy"], "admin")

        status, export_bytes, headers = customer.request("GET", "/api/audit-package/export")
        self.assertEqual(status, 200)
        self.assertIn("application/zip", headers.get("Content-Type", ""))
        with zipfile.ZipFile(BytesIO(export_bytes)) as archive:
            self.assertIn("manifest.json", archive.namelist())
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            registers = archive.read("workspace/registers.json").decode("utf-8")
        self.assertEqual(manifest["fingerprint"], approved["auditPackage"]["fingerprint"])
        self.assertEqual(manifest["advisorApproval"]["approvedBy"], "admin")
        self.assertNotIn("must-not-be-exported", registers)

        status, current, _ = self.admin.request("GET", "/api/state")
        self.assertEqual(status, 200)
        changed_state = current["state"]
        changed_state["documents"].append({
            "id": "audit-package-new-evidence",
            "name": "Neuer auditrelevanter Nachweis",
            "status": "In Pruefung",
            "reviewStatus": "vom_kunden_eingereicht",
            "auditRelevant": True,
        })
        status, _, _ = self.admin.request(
            "PUT",
            "/api/state",
            {"state": changed_state, "expectedRevision": current["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, stale, _ = self.admin.request("GET", "/api/audit-package/status")
        self.assertEqual(status, 200)
        self.assertTrue(stale["auditPackage"]["approvalStale"])
        self.assertFalse(stale["auditPackage"]["advisorApproved"])
        self.assertGreater(stale["auditPackage"]["blockerCount"], 0)
        status, blocked_export, _ = customer.request("GET", "/api/audit-package/export")
        self.assertEqual(status, 409)
        self.assertEqual(blocked_export["error"], "audit_package_not_approved")

    def test_06_audit_hash_chain_detects_tampering(self):
        anonymous = ApiClient(self.base_url)
        status, payload, _ = anonymous.request("GET", "/api/audit-log/integrity")
        self.assertEqual(status, 401)

        status, integrity, _ = self.admin.request("GET", "/api/audit-log/integrity")
        self.assertEqual(status, 200)
        self.assertTrue(integrity["valid"])
        db_path = Path(self.temp_dir.name) / "isms.db"

        # A restart migration must not reassign already chained system events.
        with closing(sqlite3.connect(db_path)) as db:
            system_event = db.execute(
                "SELECT id, tenant_id, event_hash FROM audit_log WHERE tenant_id IS NULL ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if system_event:
                self.assertIsNone(system_event[1])
                self.assertEqual(len(system_event[2]), 64)
        self.assertGreater(integrity["checkedEvents"], 0)

        status, audit_log, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        self.assertTrue(audit_log["events"])
        latest = audit_log["events"][0]
        self.assertEqual(len(latest["eventHash"]), 64)
        self.assertIn("previousHash", latest)

        with closing(sqlite3.connect(db_path)) as db:
            row = db.execute(
                "SELECT id, action FROM audit_log WHERE tenant_id = ? ORDER BY id DESC LIMIT 1",
                ("default",),
            ).fetchone()
            self.assertIsNotNone(row)
            event_id, original_action = row
            db.execute(
                "UPDATE audit_log SET action = ? WHERE id = ?",
                (f"{original_action}_tampered", event_id),
            )
            db.commit()

        status, integrity, _ = self.admin.request("GET", "/api/audit-log/integrity")
        self.assertEqual(status, 200)
        self.assertFalse(integrity["valid"])
        invalid_ids = {
            event["id"]
            for chain in integrity["chains"]
            for event in chain["invalidEvents"]
        }
        self.assertIn(event_id, invalid_ids)

        status, operations, _ = self.admin.request(
            "POST", "/api/operations/alerts/refresh", {}, csrf=True
        )
        self.assertEqual(status, 200)
        audit_alert = next(
            alert
            for alert in operations["alerts"]
            if alert["key"] == "platform:audit-chain-integrity"
        )
        self.assertEqual(audit_alert["severity"], "critical")
        self.assertEqual(audit_alert["status"], "open")
        self.assertEqual(audit_alert["actionView"], "audittrail")

        with closing(sqlite3.connect(db_path)) as db:
            db.execute(
                "UPDATE audit_log SET action = ? WHERE id = ?",
                (original_action, event_id),
            )
            db.commit()

        status, integrity, _ = self.admin.request("GET", "/api/audit-log/integrity")
        self.assertEqual(status, 200)
        self.assertTrue(integrity["valid"])

        status, operations, _ = self.admin.request(
            "POST", "/api/operations/alerts/refresh", {}, csrf=True
        )
        self.assertEqual(status, 200)
        audit_alert = next(
            alert
            for alert in operations["alerts"]
            if alert["key"] == "platform:audit-chain-integrity"
        )
        self.assertEqual(audit_alert["status"], "resolved")

    def test_07_static_path_traversal_is_blocked(self):
        anonymous = ApiClient(self.base_url)
        status, payload, _ = anonymous.request("GET", "/%2e%2e/backend_app.py")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "not found")

        status, content, headers = anonymous.request("GET", "/app.js")
        self.assertEqual(status, 200)
        self.assertTrue(content)
        self.assertIn("max-age=300", headers.get("Cache-Control", ""))
        self.assertTrue(headers.get("ETag"))

    def test_08_background_jobs_are_admin_controlled(self):
        anonymous = ApiClient(self.base_url)
        status, payload, _ = anonymous.request("GET", "/api/jobs")
        self.assertEqual(status, 401)

        status, payload, _ = self.admin.request("GET", "/api/jobs")
        self.assertEqual(status, 200)
        self.assertFalse(payload["enabled"])
        self.assertIn("operations_alert_refresh", payload["types"])

        status, payload, _ = self.admin.request(
            "POST",
            "/api/jobs",
            {"jobType": "operations_alert_refresh", "priority": 75},
        )
        self.assertEqual(status, 403)
        self.assertIn("csrf", payload["error"])

        status, payload, _ = self.admin.request(
            "POST",
            "/api/jobs",
            {"jobType": "operations_alert_refresh", "priority": 75},
            csrf=True,
        )
        self.assertEqual(status, 201)
        job_id = payload["queuedId"]
        queued = next(job for job in payload["jobs"] if job["id"] == job_id)
        self.assertEqual(queued["status"], "queued")
        self.assertEqual(queued["jobType"], "operations_alert_refresh")

        status, payload, _ = self.admin.request(
            "POST", f"/api/jobs/{job_id}/cancel", {}, csrf=True
        )
        self.assertEqual(status, 200)
        cancelled = next(job for job in payload["jobs"] if job["id"] == job_id)
        self.assertEqual(cancelled["status"], "cancelled")

        status, payload, _ = self.admin.request(
            "POST", f"/api/jobs/{job_id}/retry", {}, csrf=True
        )
        self.assertEqual(status, 200)
        retried = next(job for job in payload["jobs"] if job["id"] == job_id)
        self.assertEqual(retried["status"], "queued")

        status, payload, _ = self.admin.request(
            "POST", "/api/tenants/default/export-job", {}, csrf=True
        )
        self.assertEqual(status, 202)
        export_job = next(job for job in payload["jobs"] if job["id"] == payload["queuedId"])
        self.assertEqual(export_job["jobType"], "tenant_export_preflight")
        self.assertEqual(export_job["status"], "queued")

        status, payload, _ = self.admin.request(
            "POST", "/api/tenants/default/export-artifact-job", {}, csrf=True
        )
        self.assertEqual(status, 202)
        artifact_job_id = payload["queuedId"]
        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            db.execute(
                "UPDATE background_jobs SET status='succeeded',result_json=? WHERE id=?",
                (
                    json.dumps({
                        "tenantExport": {
                            "filename": "test-export.zip",
                            "size": 122,
                            "sha256": "",
                            "downloadUrl": f"/api/jobs/{artifact_job_id}/artifact",
                        }
                    }),
                    artifact_job_id,
                ),
            )
            db.commit()
        artifact_dir = Path(self.temp_dir.name) / "job-artifacts"
        artifact_dir.mkdir(exist_ok=True)
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("manifest.json", "{}")
        (artifact_dir / f"{artifact_job_id}.zip").write_bytes(buffer.getvalue())
        status, content, headers = self.admin.request("GET", f"/api/jobs/{artifact_job_id}/artifact")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/zip")
        with zipfile.ZipFile(BytesIO(content)) as archive:
            self.assertIn("manifest.json", archive.namelist())

        failed_job_id = "job-failed-monitor-test"
        with closing(sqlite3.connect(db_path)) as db:
            db.execute(
                "INSERT INTO background_jobs (id,tenant_id,job_type,status,priority,payload_json,attempts,max_attempts,created_at,created_by,updated_at,finished_at,last_error) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    failed_job_id,
                    "default",
                    "backup_create",
                    "failed",
                    20,
                    "{}",
                    1,
                    1,
                    int(time.time()),
                    1,
                    int(time.time()),
                    int(time.time()),
                    "simulated failure",
                ),
            )
            db.commit()
        status, operations, _ = self.admin.request(
            "POST", "/api/operations/alerts/refresh", {}, csrf=True
        )
        self.assertEqual(status, 200)
        job_alert = next(
            alert
            for alert in operations["alerts"]
            if alert["key"] == "platform:background-jobs-failed"
        )
        self.assertEqual(job_alert["severity"], "warning")
        self.assertEqual(job_alert["actionView"], "jobs")

        status, security, _ = self.admin.request("GET", "/api/security/status")
        self.assertEqual(status, 200)
        self.assertEqual(security["backgroundJobs"]["status"], "warning")
        self.assertGreaterEqual(security["backgroundJobs"]["failed"], 1)

        status, payload, _ = self.admin.request(
            "POST", "/api/maintenance/actions/cleanup-job-artifacts", {}, csrf=True
        )
        self.assertEqual(status, 200)
        self.assertGreaterEqual(payload["affected"], 1)
        self.assertTrue((artifact_dir / f"{artifact_job_id}.zip").exists())

        old_job_id = "job-old-retention-test"
        queued_job_id = "job-queued-retention-test"
        old_timestamp = int(time.time()) - 10 * 86400
        with closing(sqlite3.connect(db_path)) as db:
            db.execute(
                "INSERT INTO background_jobs (id,tenant_id,job_type,status,priority,payload_json,attempts,max_attempts,created_at,created_by,updated_at,finished_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (old_job_id, "default", "tenant_export_create", "succeeded", 10, "{}", 1, 1, old_timestamp, 1, old_timestamp, old_timestamp),
            )
            db.execute(
                "INSERT INTO background_jobs (id,tenant_id,job_type,status,priority,payload_json,attempts,max_attempts,created_at,created_by,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (queued_job_id, "default", "tenant_export_create", "queued", 10, "{}", 0, 1, old_timestamp, 1, old_timestamp),
            )
            db.execute(
                "INSERT INTO tenant_events (tenant_id,event_type,action,entity_type,entity_id,actor_user_id,actor_username,created_at,workspace_revision) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                ("default", "workspace.updated", "state_saved", "workspace", "old-live-event", 1, "admin", old_timestamp, 1),
            )
            db.commit()
        old_artifact = artifact_dir / f"{old_job_id}.zip"
        old_artifact.write_bytes(buffer.getvalue())
        old_mtime = time.time() - 10 * 86400
        os.utime(old_artifact, (old_mtime, old_mtime))
        status, payload, _ = self.admin.request(
            "POST",
            "/api/maintenance/retention",
            {"auditDays": 3650, "backupDays": 3650, "jobDays": 7},
            csrf=True,
        )
        self.assertEqual(status, 200)
        self.assertGreaterEqual(payload["deletedJobs"], 1)
        self.assertGreaterEqual(payload["deletedJobArtifacts"], 1)
        self.assertGreaterEqual(payload["deletedLiveEvents"], 1)
        self.assertFalse(old_artifact.exists())
        with closing(sqlite3.connect(db_path)) as db:
            self.assertIsNone(db.execute("SELECT id FROM background_jobs WHERE id=?", (old_job_id,)).fetchone())
            self.assertIsNotNone(db.execute("SELECT id FROM background_jobs WHERE id=?", (queued_job_id,)).fetchone())
            self.assertIsNone(db.execute("SELECT id FROM tenant_events WHERE entity_id='old-live-event'").fetchone())

    def test_09_live_event_stream_is_authenticated_and_tenant_scoped(self):
        anonymous = ApiClient(self.base_url)
        status, payload, _ = anonymous.request("GET", "/api/events?once=1")
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "not authenticated")

        db_path = Path(self.temp_dir.name) / "isms.db"
        with closing(sqlite3.connect(db_path)) as db:
            cursor = db.execute("SELECT COALESCE(MAX(id), 0) FROM tenant_events").fetchone()[0]

        tenant_admin = ApiClient(self.base_url)
        status, _, _ = tenant_admin.login("alpha.admin", TENANT_ADMIN_PASSWORD)
        self.assertEqual(status, 200)
        status, tenant_state, _ = tenant_admin.request("GET", "/api/state")
        self.assertEqual(status, 200)
        alpha_workspace = tenant_state.get("state") or {
            "documents": [], "assets": [], "risks": [], "legal": [], "suppliers": [],
            "policies": [], "incidents": [], "contracts": [], "integrations": [],
            "tasks": [], "projectPlan": [], "templateDrafts": [],
        }
        alpha_workspace["tasks"] = [{"id": "alpha-live-event", "title": "Tenant scoped event"}]
        status, _, _ = tenant_admin.request(
            "PUT",
            "/api/state",
            {"state": alpha_workspace, "expectedRevision": tenant_state.get("revision")},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, default_state, _ = self.admin.request("GET", "/api/state")
        self.assertEqual(status, 200)
        workspace = default_state["state"]
        workspace["tasks"].append({"id": "default-live-event", "title": "Live event"})
        status, saved, _ = self.admin.request(
            "PUT",
            "/api/state",
            {"state": workspace, "expectedRevision": default_state["revision"]},
            csrf=True,
        )
        self.assertEqual(status, 200)

        status, stream, headers = self.admin.request("GET", f"/api/events?after={cursor}&once=1")
        self.assertEqual(status, 200)
        self.assertIn("text/event-stream", headers.get("Content-Type", ""))
        text = stream.decode("utf-8")
        payloads = [
            json.loads(line[6:])
            for line in text.splitlines()
            if line.startswith("data: ")
        ]
        updates = [item for item in payloads if item.get("eventType") == "workspace.updated"]
        self.assertTrue(updates)
        self.assertTrue(any(item.get("workspaceRevision") == saved["revision"] for item in updates))
        self.assertTrue(all(item.get("entityId") == "default" for item in updates))

    def test_10_restore_drill_requires_platform_admin_and_records_audit_event(self):
        status, backup_payload, _ = self.admin.request("POST", "/api/backups", {}, csrf=True)
        self.assertEqual(status, 200)
        backup_name = backup_payload["backup"]["name"]
        verification = {
            "backupName": backup_name,
            "sourceDatabase": "sqlite",
            "restoredDatabase": "postgres",
            "restoredStorage": "s3",
            "workspaceRevision": 2,
            "files": 2,
            "downloadsVerified": 2,
            "auditEventsChecked": 10,
            "stateMatches": True,
            "fileMetadataMatches": True,
            "auditIntegrity": True,
        }

        status, payload, _ = self.admin.request("POST", "/api/restore-drills", verification)
        self.assertEqual(status, 403)
        self.assertIn("csrf", payload["error"])

        tenant_admin = ApiClient(self.base_url)
        status, _, _ = tenant_admin.login("alpha.admin", TENANT_ADMIN_PASSWORD)
        self.assertEqual(status, 200)
        status, payload, _ = tenant_admin.request(
            "POST", "/api/restore-drills", verification, csrf=True
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "platform admin required")

        status, payload, _ = self.admin.request(
            "POST", "/api/restore-drills", verification, csrf=True
        )
        self.assertEqual(status, 201)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["technicalVerificationOnly"])

        status, payload, _ = self.admin.request("GET", "/api/audit-log")
        self.assertEqual(status, 200)
        self.assertTrue(any(
            event["action"] == "restore_drill_verified" and event["targetId"] == backup_name
            for event in payload["events"]
        ))


if __name__ == "__main__":
    unittest.main(verbosity=2)
