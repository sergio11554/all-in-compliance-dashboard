import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from test_backend_integration import ApiClient, free_port
from test_intune import CONFIG, DEVICE


ROOT = Path(__file__).resolve().parents[1]


class IntuneBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="sfm-intune-api-")
        cls.base = f"http://127.0.0.1:{free_port()}"
        cls.config = Path(cls.temp.name) / "intune-config.json"
        cls.config.write_text(json.dumps({"default": CONFIG}))
        cls.config.chmod(0o600)
        env = {**os.environ, "ISMS_DATA_DIR": cls.temp.name, "ISMS_HOST": "127.0.0.1", "ISMS_PORT": cls.base.rsplit(":", 1)[1], "ISMS_PUBLIC_URL": cls.base, "ISMS_ADMIN_PASSWORD": "Intune-Test-Admin-2026!", "ISMS_FILE_KEY": "synthetic-intune-api-test-key", "ISMS_COOKIE_SECURE": "0", "ISMS_HSTS": "0", "ISMS_JOB_WORKER_ENABLED": "1", "ISMS_JOB_WORKER_SECONDS": "1", "ISMS_OPERATIONS_MONITOR_ENABLED": "0", "ISMS_NOTIFICATION_DELIVERY_ENABLED": "0", "ISMS_INTUNE_CONFIG_FILE": str(cls.config)}
        env["ISMS_STATIC_BASE"] = cls.temp.name
        # Replace only the external fetch in this isolated test process, not production APIs.
        code = "import runpy, intune_sync; intune_sync.fetch_devices = lambda config: " + repr([DEVICE]) + "; runpy.run_path('backend_app.py', run_name='__main__')"
        cls.process = subprocess.Popen([sys.executable, "-c", code], cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        cls.admin = ApiClient(cls.base)
        for _ in range(100):
            try:
                if cls.admin.login("admin", "Intune-Test-Admin-2026!")[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(.1)
        else:
            cls.process.terminate()
            output = cls.process.communicate(timeout=5)
            raise RuntimeError(f"Intune test server failed: {output}")

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.communicate(timeout=5)
        cls.temp.cleanup()

    def request(self, method, path, payload=None, expected=200):
        status, result, _ = self.admin.request(method, path, payload, csrf=True)
        self.assertEqual(status, expected, result)
        return result

    def test_complete_preview_import_and_access_contract(self):
        anonymous = ApiClient(self.base)
        self.assertEqual(anonymous.request("GET", "/intune-config.json")[0], 404)
        self.assertEqual(anonymous.request("HEAD", "/intune-config.json")[0], 404)
        self.assertEqual(anonymous.request("GET", "/api/integrations/intune")[0], 401)
        self.assertEqual(self.admin.request("POST", "/api/integrations/intune/preview", {})[0], 403)
        state = {name: [] for name in ["documents", "assets", "risks", "legal", "suppliers", "policies", "incidents", "contracts", "integrations", "tasks", "projectPlan", "templateDrafts"]}
        current = self.request("GET", "/api/state")
        self.request("PUT", "/api/state", {"state": state, "expectedRevision": current["revision"]})
        status = self.request("GET", "/api/integrations/intune")
        self.assertTrue(status["configured"])
        self.assertFalse(status["enabled"])
        self.assertNotIn(CONFIG["clientSecret"], json.dumps(status))
        self.request("POST", "/api/jobs", {"jobType": "intune_sync"}, expected=400)
        self.request("POST", "/api/integrations/intune/schedule", {"enabled": True}, expected=409)
        self.request("POST", "/api/integrations/intune/preview", {}, expected=202)
        for _ in range(120):
            status = self.request("GET", "/api/integrations/intune")
            if status["preview"]:
                break
            if status.get("job", {}).get("status") == "failed":
                self.fail(str(status))
            time.sleep(.1)
        self.assertIsNotNone(status["preview"], status)
        self.assertEqual(self.request("GET", "/api/assets")["assets"], [])
        preview = status["preview"]["id"]
        self.request("POST", "/api/integrations/intune/apply", {"previewId": preview})
        assets = self.request("GET", "/api/assets")["assets"]
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["intune"]["device"], DEVICE)
        self.assertEqual(assets[0]["owner"], "")
        self.assertNotIn("reviewStatus", assets[0])
        self.request("POST", "/api/integrations/intune/apply", {"previewId": preview}, expected=409)
        self.request("POST", "/api/integrations/intune/schedule", {"enabled": True})
        self.assertTrue(self.request("GET", "/api/integrations/intune")["enabled"])
        self.request("POST", "/api/integrations/intune/schedule", {"enabled": False})
        audit = self.request("GET", "/api/audit-log")["events"]
        self.assertTrue(any(item["action"] == "intune_assets_synced" for item in audit))
        self.request("POST", "/api/users", {"username": "intune.viewer", "password": "Copper-Harbor-97!Quiet-Road", "role": "viewer"}, expected=201)
        viewer = ApiClient(self.base)
        self.assertEqual(viewer.login("intune.viewer", "Copper-Harbor-97!Quiet-Road")[0], 200)
        self.assertEqual(viewer.request("GET", "/api/integrations/intune")[0], 200)
        for action, payload in [("apply", {"previewId": preview}), ("preview", {}), ("schedule", {"enabled": True}), ("configure", CONFIG), ("disconnect", {})]:
            self.assertEqual(viewer.request("POST", f"/api/integrations/intune/{action}", payload, csrf=True)[0], 403)

    def test_configuration_api_never_returns_secrets_or_auto_imports(self):
        before = self.request("GET", "/api/state")
        original = self.config.read_text()
        self.addCleanup(lambda: self.config.write_text(original))
        self.request("POST", "/api/integrations/intune/configure", {**CONFIG, "expectedVersion": ""}, expected=409)
        self.config.write_text("{}")
        self.assertEqual(self.admin.request("POST", "/api/integrations/intune/configure", CONFIG)[0], 403)
        self.assertEqual(ApiClient(self.base).request("POST", "/api/integrations/intune/configure", CONFIG)[0], 401)
        self.request("POST", "/api/integrations/intune/configure", {"expectedVersion": "", "clientSecret": "do-not-echo"}, expected=400)
        self.assertFalse(self.request("GET", "/api/integrations/intune")["configured"])
        self.request("POST", "/api/integrations/intune/configure", {**CONFIG, "expectedVersion": ""})
        status = self.request("GET", "/api/integrations/intune")
        self.assertTrue(status["configured"])
        self.assertTrue(status["setupTransportAllowed"])
        self.assertIsNone(status["verifiedAt"])
        self.assertIsNone(status["preview"])
        self.assertIsNone(status["lastSuccessAt"])
        self.assertNotIn(CONFIG["clientSecret"], json.dumps(status))
        audit = self.request("GET", "/api/audit-log")
        self.assertNotIn(CONFIG["clientSecret"], json.dumps(audit))
        self.request("POST", "/api/integrations/intune/configure", {**CONFIG, "expectedVersion": ""}, expected=409)
        self.request("POST", "/api/integrations/intune/preview", {}, expected=202)
        for _ in range(120):
            status = self.request("GET", "/api/integrations/intune")
            if status["preview"] and status["job"]["status"] not in {"queued", "running", "retry"}:
                break
            time.sleep(.1)
        self.assertIsNotNone(status["preview"])
        self.assertIsNotNone(status["verifiedAt"])
        self.assertIsNone(status["lastSuccessAt"])
        self.request("POST", "/api/integrations/intune/disconnect", {"expectedVersion": status["configurationVersion"]})
        self.assertFalse(self.request("GET", "/api/integrations/intune")["configured"])
        self.assertEqual(before, self.request("GET", "/api/state"))


if __name__ == "__main__":
    unittest.main()
