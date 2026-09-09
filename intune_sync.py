"""Tenant-scoped, preview-first synchronization using the existing workspace transaction."""

import json
import time
import uuid

from intune_connector import IntuneError, fetch_devices, load_config, merge_inventory, validate_credentials


class IntuneSync:
    def __init__(self, *, database, connect, seal, unseal, audit, snapshot, validate, max_bytes):
        self.database, self.connect = database, connect
        self.seal, self.unseal = seal, unseal
        self.audit, self.snapshot, self.validate = audit, snapshot, validate
        self.max_bytes = max_bytes

    def actor(self, db, actor):
        row = db.execute("SELECT * FROM users WHERE id=?", (actor["id"],)).fetchone()
        tenant = db.execute("SELECT status FROM tenants WHERE id=?", (actor["tenant_id"],)).fetchone()
        if not row or not row["active"] or row["role"] != "admin" or not tenant or tenant["status"] != "active":
            raise IntuneError("Intune-Verwaltung benoetigt einen aktiven Administrator.", 403)
        if row["tenant_id"] != actor["tenant_id"] and not row["platform_admin"]:
            raise IntuneError("Keine Berechtigung fuer diesen Kundenraum.", 403)

    def row(self, db, tenant):
        return db.execute("SELECT * FROM intune_connections WHERE tenant_id=?", (tenant,)).fetchone()

    def ensure(self, db, tenant):
        db.execute("INSERT INTO intune_connections (tenant_id) VALUES (?) ON CONFLICT(tenant_id) DO NOTHING", (tenant,))

    def workspace(self, db, tenant):
        row = db.execute("SELECT * FROM tenant_workspace_state WHERE tenant_id=?", (tenant,)).fetchone()
        if not row:
            raise IntuneError("Kunden-Workspace zuerst initialisieren.", 409)
        return row

    def config(self, db, tenant):
        # Operator-managed configuration is authoritative, never silently overwritten by UI.
        external = load_config(tenant)
        if external:
            return {**external, "source": "server"}
        row = db.execute("SELECT * FROM intune_credentials WHERE tenant_id=?", (tenant,)).fetchone()
        if not row:
            return None
        try:
            saved = json.loads(self.unseal(row["nonce"], row["ciphertext"]))
            if saved["localTenantId"] != tenant or not isinstance(saved["key"], str):
                raise ValueError("binding")
            return {**validate_credentials(saved), "key": saved["key"], "source": "platform", "verifiedAt": row["verified_at"]}
        except (ValueError, TypeError, KeyError, IntuneError):
            raise IntuneError("Gespeicherter Intune-Zugang nicht lesbar. Serverschluessel und Konfiguration pruefen.", 409) from None

    def configure(self, db, actor, payload, remove=False):
        self.actor(db, actor)
        tenant = actor["tenant_id"]
        current = self.config(db, tenant)
        if current and current["source"] == "server":
            raise IntuneError("Zugang wird per Serverdatei verwaltet. Keine Aenderung ueber die Plattform.", 409)
        if payload.get("expectedVersion") != (current["key"] if current else ""):
            raise IntuneError("Konfiguration wurde geaendert. Status neu laden und erneut pruefen.", 409)
        if db.execute("SELECT id FROM background_jobs WHERE tenant_id=? AND job_type IN ('intune_preview','intune_sync') AND status IN ('queued','running','retry')", (tenant,)).fetchone():
            raise IntuneError("Geraeteabruf laeuft. Konfiguration nach Abschluss aendern.", 409)
        if remove:
            db.execute("DELETE FROM intune_credentials WHERE tenant_id=?", (tenant,))
        else:
            config = validate_credentials(payload)
            config.update({"localTenantId": tenant, "key": uuid.uuid4().hex})
            nonce, ciphertext = self.seal(json.dumps(config).encode())
            db.execute("INSERT INTO intune_credentials (tenant_id,nonce,ciphertext) VALUES (?,?,?) ON CONFLICT(tenant_id) DO UPDATE SET nonce=excluded.nonce,ciphertext=excluded.ciphertext,verified_at=NULL", (tenant, nonce, ciphertext))
        self.ensure(db, tenant)
        db.execute("UPDATE intune_connections SET config_key=NULL,enabled=0,approved_by=NULL,last_attempt_at=NULL,last_success_at=NULL,last_error=NULL,next_run_at=NULL,preview_id=NULL,preview_nonce=NULL,preview_data=NULL,preview_revision=NULL,preview_expires=NULL WHERE tenant_id=?", (tenant,))
        self.audit(db, actor, "intune_configuration_removed" if remove else "intune_configuration_saved", "integration", "intune", {}, "api")

    def status(self, tenant):
        error, config = "", None
        with self.connect() as db:
            try:
                config = self.config(db, tenant)
            except IntuneError as exc:
                error = str(exc)
            row = self.row(db, tenant)
            job = db.execute("SELECT id,status,last_error FROM background_jobs WHERE tenant_id=? AND job_type IN ('intune_preview','intune_sync') ORDER BY CASE WHEN status IN ('queued','running','retry') THEN 0 ELSE 1 END,created_at DESC,updated_at DESC,id DESC LIMIT 1", (tenant,)).fetchone()
            result = {"configured": bool(config), "configurationError": error, "microsoftTenantId": config["tenantId"] if config else "", "enabled": False, "lastSuccessAt": None, "lastError": "", "preview": None, "job": dict(job) if job else None}
            result.update({"clientId": config["clientId"] if config else "", "configurationSource": config["source"] if config else "", "configurationVersion": config["key"] if config else "", "verifiedAt": config.get("verifiedAt") if config else None})
            if not row:
                return result
            if not row["last_attempt_at"] and job and job["status"] not in {"queued", "running", "retry"}:
                result["job"] = None
            same = bool(config and row["config_key"] == config["key"])
            result.update({"enabled": bool(same and row["enabled"]), "lastSuccessAt": row["last_success_at"] if same else None, "lastAttemptAt": row["last_attempt_at"], "lastError": row["last_error"] or "", "nextRunAt": row["next_run_at"] if same and row["enabled"] else None})
            if same and row["preview_id"] and (row["preview_expires"] or 0) > time.time():
                preview = json.loads(self.unseal(row["preview_nonce"], row["preview_data"]))
                workspace = self.workspace(db, tenant)
                _, counts, changes = merge_inventory(json.loads(workspace["state_json"])["assets"], preview, tenant, config, int(time.time()))
                result["preview"] = {"id": row["preview_id"], "revision": row["preview_revision"], "currentRevision": workspace["revision"], "expiresAt": row["preview_expires"], "counts": counts, "devices": changes[:100], "total": len(changes)}
            return result

    def enqueue(self, db, actor, enqueue):
        self.actor(db, actor)
        if not self.config(db, actor["tenant_id"]):
            raise IntuneError("Microsoft Intune ist noch nicht serverseitig eingerichtet.", 409)
        self.workspace(db, actor["tenant_id"])
        running = db.execute("SELECT id FROM background_jobs WHERE tenant_id=? AND job_type IN ('intune_preview','intune_sync') AND status IN ('queued','retry','running')", (actor["tenant_id"],)).fetchone()
        if running:
            return running["id"]
        self.ensure(db, actor["tenant_id"])
        db.execute("UPDATE intune_connections SET preview_id=NULL,preview_data=NULL,preview_nonce=NULL WHERE tenant_id=?", (actor["tenant_id"],))
        return enqueue(db, "intune_preview", actor, max_attempts=3)

    def apply(self, actor, preview_id=None, devices=None, config=None):
        tenant, timestamp = actor["tenant_id"], int(time.time())
        with self.connect() as db:
            self.database.begin_workspace_write(db)
            self.actor(db, actor)
            current_config = self.config(db, tenant)
            row = self.row(db, tenant)
            workspace = self.workspace(db, tenant)
            if not current_config or not row:
                raise IntuneError("Intune-Konfiguration fehlt.", 409)
            if preview_id is not None:
                if not preview_id or preview_id != row["preview_id"] or (row["preview_expires"] or 0) <= timestamp or row["config_key"] != current_config["key"]:
                    raise IntuneError("Vorschau abgelaufen oder Konfiguration geaendert. Bitte neu abrufen.", 409)
                if row["preview_revision"] != workspace["revision"]:
                    raise IntuneError("Workspace wurde geaendert. Bitte eine neue Vorschau abrufen.", 409)
                devices = json.loads(self.unseal(row["preview_nonce"], row["preview_data"]))
            elif not row["enabled"] or not config or config["key"] != current_config["key"] or row["config_key"] != config["key"]:
                raise IntuneError("Automatische Synchronisierung wurde pausiert oder neu konfiguriert.", 409)
            state = json.loads(workspace["state_json"])
            assets, counts, _ = merge_inventory(state["assets"], devices, tenant, current_config, timestamp)
            # An empty response must be reviewed; never mass-mark devices on unattended sync.
            if preview_id is None and not devices and counts["missing"]:
                raise IntuneError("Leere Intune-Antwort: bitte manuell per Vorschau pruefen.", 409)
            state["assets"] = assets
            raw = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
            if len(raw.encode()) > self.max_bytes or not self.validate(state, raw)["valid"]:
                raise IntuneError("Import passt nicht in den Workspace. Es wurde nichts uebernommen.", 409)
            snapshot = self.snapshot(db, tenant, workspace["state_json"], workspace["updated_by"], "before_intune_sync")
            revision = workspace["revision"] + 1
            db.execute("UPDATE tenant_workspace_state SET state_json=?,updated_at=?,updated_by=?,revision=? WHERE tenant_id=?", (raw, timestamp, actor["id"], revision, tenant))
            db.execute("UPDATE intune_connections SET config_key=?,last_success_at=?,last_error=NULL,preview_id=NULL,preview_data=NULL,preview_nonce=NULL WHERE tenant_id=?", (current_config["key"], timestamp, tenant))
            self.audit(db, actor, "intune_assets_synced", "integration", "intune", {"counts": counts, "revision": revision, "snapshotId": snapshot}, "intune-worker")
        return {"counts": counts, "revision": revision}

    def run(self, actor, automatic=False):
        tenant = actor["tenant_id"]
        try:
            with self.connect() as db:
                self.actor(db, actor)
                row = self.workspace(db, tenant)
                revision = row["revision"]
                self.ensure(db, tenant)
                connection = self.row(db, tenant)
                config = self.config(db, tenant)
                if not config:
                    raise IntuneError("Intune ist nicht eingerichtet.", 409)
                if automatic and (not connection["enabled"] or connection["config_key"] != config["key"]):
                    raise IntuneError("Automatische Synchronisierung ist pausiert.", 409)
                db.execute("UPDATE intune_connections SET last_attempt_at=?,last_error=NULL WHERE tenant_id=?", (int(time.time()), tenant))
            devices = fetch_devices(config)
            if automatic:
                return self.apply(actor, devices=devices, config=config)
            preview_id = uuid.uuid4().hex
            nonce, data = self.seal(json.dumps(devices).encode())
            with self.connect() as db:
                self.database.begin_workspace_write(db)
                self.actor(db, actor)
                latest = self.config(db, tenant)
                if not latest or latest["key"] != config["key"]:
                    raise IntuneError("Intune-Konfiguration wurde geaendert.", 409)
                previous = self.row(db, tenant)
                if previous["config_key"] != config["key"]:
                    db.execute("UPDATE intune_connections SET enabled=0,last_success_at=NULL,next_run_at=NULL WHERE tenant_id=?", (tenant,))
                db.execute("UPDATE intune_connections SET config_key=?,preview_id=?,preview_nonce=?,preview_data=?,preview_revision=?,preview_expires=?,last_error=NULL WHERE tenant_id=?", (config["key"], preview_id, nonce, data, revision, int(time.time()) + 600, tenant))
                db.execute("UPDATE intune_credentials SET verified_at=? WHERE tenant_id=?", (int(time.time()), tenant))
                self.audit(db, actor, "intune_preview_ready", "integration", "intune", {"devices": len(devices)}, "intune-worker")
            return {"previewId": preview_id, "devices": len(devices)}
        except IntuneError as exc:
            with self.connect() as db:
                db.execute("UPDATE intune_connections SET last_error=? WHERE tenant_id=?", (str(exc), tenant))
            raise

    def schedule(self, db, actor, enabled):
        self.actor(db, actor)
        self.ensure(db, actor["tenant_id"])
        row, config = self.row(db, actor["tenant_id"]), self.config(db, actor["tenant_id"])
        if enabled and (not config or not row["last_success_at"] or row["config_key"] != config["key"]):
            raise IntuneError("Zuerst einen echten Import pruefen und uebernehmen.", 409)
        db.execute("UPDATE intune_connections SET enabled=?,approved_by=?,next_run_at=? WHERE tenant_id=?", (int(enabled), actor["id"], int(time.time()) + 3600 if enabled else None, actor["tenant_id"]))
        self.audit(db, actor, "intune_schedule_changed", "integration", "intune", {"enabled": enabled}, "api")

    def queue_due(self, enqueue):
        with self.connect() as db:
            self.database.begin_workspace_write(db)
            db.execute("UPDATE intune_connections SET preview_id=NULL,preview_data=NULL,preview_nonce=NULL WHERE preview_expires<=? AND preview_id IS NOT NULL", (int(time.time()),))
            rows = db.execute("SELECT * FROM intune_connections WHERE enabled=1 AND next_run_at<=?", (int(time.time()),)).fetchall()
            for row in rows:
                user = db.execute("SELECT id,username FROM users WHERE id=?", (row["approved_by"],)).fetchone()
                actor = {"id": row["approved_by"], "username": user["username"] if user else "", "tenant_id": row["tenant_id"]}
                try:
                    self.actor(db, actor)
                    config = self.config(db, row["tenant_id"])
                    if not config or config["key"] != row["config_key"]:
                        raise IntuneError("Konfiguration geaendert: erneuten Import freigeben.")
                except IntuneError as exc:
                    db.execute("UPDATE intune_connections SET enabled=0,last_error=? WHERE tenant_id=?", (str(exc), row["tenant_id"]))
                    continue
                busy = db.execute("SELECT id FROM background_jobs WHERE tenant_id=? AND job_type IN ('intune_preview','intune_sync') AND status IN ('queued','running','retry')", (row["tenant_id"],)).fetchone()
                if not busy:
                    enqueue(db, "intune_sync", actor, max_attempts=3)
                db.execute("UPDATE intune_connections SET next_run_at=? WHERE tenant_id=?", (int(time.time()) + 3600, row["tenant_id"]))
