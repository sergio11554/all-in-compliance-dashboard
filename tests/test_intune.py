import io
import json
import os
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.fernet import Fernet

from database import Database
from intune_connector import IntuneError, fetch_devices, load_config, merge_inventory, normalize_device, request_json, setup_transport_allowed, validate_credentials
from intune_sync import IntuneSync


CONFIG = {"tenantId": "11111111-1111-1111-1111-111111111111", "clientId": "22222222-2222-2222-2222-222222222222", "clientSecret": "synthetic-test-secret", "key": "binding-one"}
DEVICE = normalize_device({"id": "device-1", "deviceName": "TEST-LAP-001", "operatingSystem": "Windows", "isEncrypted": True, "complianceState": "compliant"})


class IntuneConnectorTests(unittest.TestCase):
    def test_credentials_validation_and_transport(self):
        self.assertEqual(validate_credentials(CONFIG)["clientId"], CONFIG["clientId"])
        for payload in [{}, {**CONFIG, "tenantId": "https://evil.invalid"}, {**CONFIG, "clientId": "invalid"}, {**CONFIG, "clientSecret": ""}, {**CONFIG, "clientSecret": "x" * 4097}, {**CONFIG, "clientSecret": "secret\nheader"}]:
            with self.assertRaises(IntuneError):
                validate_credentials(payload)
        self.assertTrue(setup_transport_allowed("https://compliance.example", "10.0.0.1"))
        self.assertTrue(setup_transport_allowed("http://127.0.0.1:5174", "127.0.0.1"))
        self.assertFalse(setup_transport_allowed("http://127.0.0.1:5174", "10.0.0.1"))
        self.assertFalse(setup_transport_allowed("http://compliance.example", "127.0.0.1"))
        self.assertFalse(setup_transport_allowed("file:///app", "127.0.0.1"))

    def test_pagination_allowlist_and_data_minimization(self):
        requests = []

        def request(req):
            requests.append(req)
            if len(requests) == 1:
                self.assertEqual(req.get_method(), "POST")
                return {"access_token": "test-token"}
            self.assertEqual(req.get_method(), "GET")
            self.assertEqual(req.headers["Authorization"], "Bearer test-token")
            if len(requests) == 2:
                return {"value": [{**DEVICE, "emailAddress": "private@example.invalid", "activationLockBypassCode": "private"}], "@odata.nextLink": "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=next"}
            return {"value": [DEVICE, {**DEVICE, "id": "device-2"}]}

        result = fetch_devices(CONFIG, request)
        self.assertEqual(len(result), 2)
        self.assertNotIn("emailAddress", result[0])
        self.assertNotIn("activationLockBypassCode", result[0])
        self.assertNotIn("clientSecret", json.dumps(result))

    def test_untrusted_nextlinks_never_receive_bearer_token(self):
        for url in ["https://evil.example/devices", "http://graph.microsoft.com/v1.0/deviceManagement/managedDevices", "https://graph.microsoft.com/v1.0/users", "https://graph.microsoft.com@evil.example/v1.0/deviceManagement/managedDevices"]:
            requester = Mock(side_effect=[{"access_token": "synthetic"}, {"value": [DEVICE], "@odata.nextLink": url}])
            with self.subTest(url=url), self.assertRaises(IntuneError):
                fetch_devices(CONFIG, requester)
            self.assertEqual(requester.call_count, 2)

    def test_partial_failure_returns_no_inventory(self):
        requester = Mock(side_effect=[{"access_token": "synthetic"}, {"value": [DEVICE], "@odata.nextLink": "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?page=2"}, IntuneError("unavailable", 503, 60)])
        with self.assertRaises(IntuneError):
            fetch_devices(CONFIG, requester)

    def test_pagination_cycle_fails(self):
        url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?page=2"
        requester = Mock(side_effect=[{"access_token": "synthetic"}, {"value": [], "@odata.nextLink": url}, {"value": [], "@odata.nextLink": url}])
        with self.assertRaises(IntuneError):
            fetch_devices(CONFIG, requester)

    def test_api_errors_are_redacted_and_retry_after_retained(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.HTTPError("https://graph.microsoft.com", 429, "secret=should-not-leak", {"Retry-After": "120"}, io.BytesIO(b"private response"))
        with self.assertRaises(IntuneError) as caught:
            request_json(Mock(), opener)
        self.assertEqual(caught.exception.retry_after, 120)
        self.assertNotIn("should-not-leak", str(caught.exception))

    def test_no_unknown_encryption_is_treated_as_true(self):
        for value in [None, "false", 1]:
            self.assertIsNone(normalize_device({"id": "one", "isEncrypted": value})["isEncrypted"])
        with self.assertRaises(IntuneError):
            normalize_device({"deviceName": "Missing ID"})

    def test_config_is_tenant_scoped_and_requires_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "intune.json"
            path.write_text(json.dumps({"alpha": CONFIG}))
            path.chmod(0o600)
            with patch.dict(os.environ, {"ISMS_INTUNE_CONFIG_FILE": str(path)}):
                self.assertIsNone(load_config("beta"))
                self.assertEqual(load_config("alpha")["clientId"], CONFIG["clientId"])
                path.chmod(0o644)
                with self.assertRaises(IntuneError):
                    load_config("alpha")

    def test_merge_is_idempotent_and_preserves_manual_assessments(self):
        assets, counts, _ = merge_inventory([], [DEVICE], "alpha", CONFIG, 100)
        self.assertEqual(counts["new"], 1)
        assets[0].update(owner="Manual Owner", criticality="Hoch", reviewStatus="freigegeben", name="Manual name", evidence="Manual document")
        changed = {**DEVICE, "deviceName": "Changed source", "isEncrypted": False}
        merged, counts, _ = merge_inventory(assets, [changed], "alpha", CONFIG, 200)
        self.assertEqual(len(merged), 1)
        self.assertEqual(counts["updated"], 1)
        for field in ["owner", "criticality", "reviewStatus", "name", "evidence"]:
            self.assertEqual(merged[0][field], assets[0][field])
        again, counts, _ = merge_inventory(merged, [changed], "alpha", CONFIG, 300)
        self.assertEqual(counts["unchanged"], 1)
        self.assertEqual(len(again), 1)
        other, _, _ = merge_inventory([], [DEVICE], "beta", CONFIG, 100)
        self.assertNotEqual(other[0]["id"], assets[0]["id"])

    def test_missing_is_marked_without_delete_and_return_clears_marker(self):
        assets, _, _ = merge_inventory([], [DEVICE], "alpha", CONFIG, 100)
        missing, counts, _ = merge_inventory(assets, [], "alpha", CONFIG, 200)
        self.assertEqual(counts["missing"], 1)
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["intune"]["missingSince"], 200)
        returned, _, _ = merge_inventory(missing, [DEVICE], "alpha", CONFIG, 300)
        self.assertIsNone(returned[0]["intune"]["missingSince"])


class IntuneSyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = Database(sqlite_path=Path(self.temp.name) / "test.db")
        self.crypto = Fernet(Fernet.generate_key())
        self.events = []
        self.service = IntuneSync(database=self.database, connect=self.database.connect,
            seal=lambda raw: ("test-nonce", self.crypto.encrypt(raw).decode()),
            unseal=lambda nonce, raw: self.crypto.decrypt(raw.encode()),
            audit=lambda *args: self.events.append(args), snapshot=lambda *args: 1,
            validate=lambda *args: {"valid": True}, max_bytes=1000000)
        self.actor = {"id": 1, "username": "test-admin", "tenant_id": "alpha"}
        with self.database.connect() as db:
            self.database.initialize_schema(db)
            for tenant in ["alpha", "beta"]:
                db.execute("INSERT INTO tenants (id,name,slug,created_at) VALUES (?,?,?,?)", (tenant, tenant, tenant, 1))
                db.execute("INSERT INTO tenant_workspace_state (tenant_id,state_json,updated_at,revision) VALUES (?,?,?,?)", (tenant, '{"assets":[]}', 1, 1))
            db.execute("INSERT INTO users (id,username,password_hash,role,created_at,tenant_id) VALUES (1,'test-admin','unused','admin',1,'alpha')")
        self.config = patch("intune_sync.load_config", return_value=CONFIG)
        self.config.start()
        self.addCleanup(self.config.stop)
        self.fetch = patch("intune_sync.fetch_devices", return_value=[DEVICE])
        self.fetcher = self.fetch.start()
        self.addCleanup(self.fetch.stop)

    def stored(self):
        with self.database.connect() as db:
            return dict(db.execute("SELECT * FROM tenant_workspace_state WHERE tenant_id='alpha'").fetchone())

    def preview(self):
        return self.service.run(self.actor)["previewId"]

    def test_preview_apply_replay_and_audit(self):
        preview = self.preview()
        self.assertEqual(self.stored()["revision"], 1)
        status = self.service.status("alpha")
        self.assertEqual(status["preview"]["counts"]["new"], 1)
        self.assertNotIn("synthetic-test-secret", json.dumps(status))
        with self.database.connect() as db:
            self.assertNotIn("TEST-LAP", self.service.row(db, "alpha")["preview_data"])
        result = self.service.apply(self.actor, preview_id=preview)
        self.assertEqual(result["revision"], 2)
        self.assertEqual(self.events[-1][2], "intune_assets_synced")
        with self.assertRaises(IntuneError):
            self.service.apply(self.actor, preview_id=preview)
        self.assertEqual(len(json.loads(self.stored()["state_json"])["assets"]), 1)

    def test_revision_conflict_preserves_workspace(self):
        preview = self.preview()
        with self.database.connect() as db:
            db.execute("UPDATE tenant_workspace_state SET revision=2 WHERE tenant_id='alpha'")
        with self.assertRaises(IntuneError):
            self.service.apply(self.actor, preview_id=preview)
        self.assertEqual(json.loads(self.stored()["state_json"])["assets"], [])

    def test_expired_preview_rejected(self):
        preview = self.preview()
        with self.database.connect() as db:
            db.execute("UPDATE intune_connections SET preview_expires=1 WHERE tenant_id='alpha'")
        with self.assertRaises(IntuneError):
            self.service.apply(self.actor, preview_id=preview)

    def test_other_tenant_and_revoked_role_rejected(self):
        preview = self.preview()
        self.assertIsNone(self.service.status("beta")["preview"])
        with self.assertRaises(IntuneError):
            self.service.apply({**self.actor, "tenant_id": "beta"}, preview_id=preview)
        with self.database.connect() as db:
            db.execute("UPDATE users SET role='viewer' WHERE id=1")
        with self.assertRaises(IntuneError):
            self.service.apply(self.actor, preview_id=preview)

    def test_scheduler_and_background_sync_require_explicit_approval(self):
        with self.database.connect() as db, self.assertRaises(IntuneError):
            self.service.schedule(db, self.actor, True)
        self.service.apply(self.actor, preview_id=self.preview())
        with self.assertRaises(IntuneError):
            self.service.run(self.actor, automatic=True)
        with self.database.connect() as db:
            self.service.schedule(db, self.actor, True)
            db.execute("UPDATE intune_connections SET next_run_at=1 WHERE tenant_id='alpha'")
        queue = Mock()
        self.service.queue_due(queue)
        self.assertEqual(queue.call_count, 1)
        self.assertEqual(queue.call_args.args[1], "intune_sync")
        self.service.run(self.actor, automatic=True)
        self.assertEqual(len(json.loads(self.stored()["state_json"])["assets"]), 1)
        with self.database.connect() as db:
            self.service.schedule(db, self.actor, False)
        with self.assertRaises(IntuneError):
            self.service.run(self.actor, automatic=True)

    def test_changed_binding_requires_new_import_and_reapproval(self):
        self.service.apply(self.actor, preview_id=self.preview())
        with self.database.connect() as db:
            self.service.schedule(db, self.actor, True)
        with patch("intune_sync.load_config", return_value={**CONFIG, "key": "different-app"}):
            self.preview()
            status = self.service.status("alpha")
            self.assertFalse(status["enabled"])
            self.assertIsNone(status["lastSuccessAt"])

    def test_outage_and_empty_automatic_inventory_preserve_last_data(self):
        self.service.apply(self.actor, preview_id=self.preview())
        with self.database.connect() as db:
            self.service.schedule(db, self.actor, True)
        before = self.stored()
        self.fetcher.side_effect = IntuneError("Microsoft unavailable", 503, 60)
        with self.assertRaises(IntuneError):
            self.service.run(self.actor, automatic=True)
        self.assertEqual(before, self.stored())
        self.assertIsNotNone(self.service.status("alpha")["lastSuccessAt"])
        self.fetcher.side_effect = None
        self.fetcher.return_value = []
        with self.assertRaises(IntuneError):
            self.service.run(self.actor, automatic=True)
        self.assertEqual(before, self.stored())

    def save_config(self, payload):
        with self.database.connect() as db:
            self.database.begin_workspace_write(db)
            self.service.configure(db, self.actor, payload)

    def test_ui_credentials_encrypted_scoped_and_never_exported(self):
        with patch("intune_sync.load_config", return_value=None):
            before = self.stored()
            self.save_config({**CONFIG, "expectedVersion": ""})
            status = self.service.status("alpha")
            self.assertTrue(status["configured"])
            self.assertIsNone(status["verifiedAt"])
            self.assertEqual(status["configurationSource"], "platform")
            self.assertNotIn(CONFIG["clientSecret"], json.dumps(status))
            self.assertNotIn(CONFIG["clientSecret"], str(self.events))
            self.assertEqual(before, self.stored())
            self.assertFalse(self.service.status("beta")["configured"])
            with self.database.connect() as db:
                row = db.execute("SELECT * FROM intune_credentials WHERE tenant_id='alpha'").fetchone()
                self.assertNotIn(CONFIG["clientSecret"], str(dict(row)))
                self.assertEqual(self.service.config(db, "alpha")["clientSecret"], CONFIG["clientSecret"])
                db.execute("INSERT INTO intune_credentials (tenant_id,nonce,ciphertext) VALUES ('beta',?,?)", (row["nonce"], row["ciphertext"]))
                with self.assertRaises(IntuneError):
                    self.service.config(db, "beta")
            self.preview()
            self.assertIsNotNone(self.service.status("alpha")["verifiedAt"])
            self.assertEqual(before, self.stored())

    def test_ui_rotation_invalidates_preview_and_requires_reapproval(self):
        with patch("intune_sync.load_config", return_value=None):
            self.save_config({**CONFIG, "expectedVersion": ""})
            preview = self.preview()
            version = self.service.status("alpha")["configurationVersion"]
            with self.assertRaises(IntuneError):
                self.save_config({**CONFIG, "expectedVersion": "stale"})
            self.save_config({**CONFIG, "clientSecret": "rotated-synthetic-secret", "expectedVersion": version})
            status = self.service.status("alpha")
            self.assertNotEqual(version, status["configurationVersion"])
            self.assertFalse(status["enabled"])
            self.assertIsNone(status["verifiedAt"])
            with self.assertRaises(IntuneError):
                self.service.apply(self.actor, preview_id=preview)
            with self.database.connect() as db:
                self.service.configure(db, self.actor, {"expectedVersion": status["configurationVersion"]}, remove=True)
            self.assertFalse(self.service.status("alpha")["configured"])

    def test_configuration_enforces_admin_and_operator_file_ownership(self):
        with self.assertRaises(IntuneError):
            self.save_config({**CONFIG, "expectedVersion": "binding-one"})
        with patch("intune_sync.load_config", return_value=None):
            with self.database.connect() as db:
                with self.assertRaises(IntuneError):
                    self.service.configure(db, {**self.actor, "tenant_id": "beta"}, {**CONFIG, "expectedVersion": ""})
                db.execute("UPDATE users SET role='viewer' WHERE id=1")
                with self.assertRaises(IntuneError):
                    self.service.configure(db, self.actor, {**CONFIG, "expectedVersion": ""})
if __name__ == "__main__":
    unittest.main()
