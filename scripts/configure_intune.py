#!/usr/bin/env python3
"""Interactive server-side setup. Never pass a secret as a command-line argument."""

import getpass
import json
import os
import tempfile
import uuid
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    data = Path(os.environ.get("ISMS_DATA_DIR", root / "data"))
    path = Path(os.environ.get("ISMS_INTUNE_CONFIG_FILE", data / "intune-config.json"))
    local_tenant = input("SFM-Kundenraum-ID (nicht Microsoft-Tenant-ID): ").strip()
    if not local_tenant or len(local_tenant) > 200:
        raise SystemExit("Ungueltige Kundenraum-ID.")
    tenant_id = str(uuid.UUID(input("Microsoft Directory/Tenant-ID: ").strip()))
    client_id = str(uuid.UUID(input("Microsoft Application/Client-ID: ").strip()))
    secret = getpass.getpass("App-Secret-Wert (wird nicht angezeigt): ").strip()
    if not secret:
        raise SystemExit("Kein App-Secret angegeben. Nichts gespeichert.")
    if input("Leseberechtigung und Adminfreigabe eingerichtet? [ja/nein]: ").strip().lower() != "ja":
        raise SystemExit("Nichts gespeichert. Bitte zuerst Microsoft-Freigabe einrichten.")
    path.parent.mkdir(parents=True, exist_ok=True)
    config = {}
    if path.exists():
        if path.stat().st_mode & 0o077:
            raise SystemExit("Konfigurationsdatei muss Modus 0600 haben.")
        config = json.loads(path.read_text(encoding="utf-8"))
    if local_tenant in config and input("Vorhandene Anbindung ersetzen? [ja/nein]: ").strip().lower() != "ja":
        raise SystemExit("Vorhandene Konfiguration unveraendert.")
    config[local_tenant] = {"tenantId": tenant_id, "clientId": client_id, "clientSecret": secret}
    fd, temporary = tempfile.mkstemp(prefix=".intune-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print("Anbindung serverseitig gespeichert. Im Asset Management nun Geraete abrufen.")
    print("Automatische Synchronisierung bleibt bis zur ausdruecklichen Aktivierung pausiert.")


if __name__ == "__main__":
    main()
