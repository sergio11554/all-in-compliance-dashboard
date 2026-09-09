"""Read-only Intune inventory. Credentials and tokens never enter workspace state."""

import hashlib
import ipaddress
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


FIELDS = (
    "id", "deviceName", "operatingSystem", "osVersion", "serialNumber",
    "manufacturer", "model", "isEncrypted", "complianceState", "lastSyncDateTime",
)
GRAPH_PATH = "/v1.0/deviceManagement/managedDevices"
MAX_DEVICES = 5000


class IntuneError(Exception):
    def __init__(self, message, status=400, retry_after=0):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


def setup_transport_allowed(public_url, peer):
    """HTTPS at the configured proxy, or a loopback-only development connection."""
    try:
        url = urllib.parse.urlsplit(public_url)
        if url.scheme == "https" and url.hostname:
            return True
        return url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"} and ipaddress.ip_address(peer).is_loopback
    except ValueError:
        return False


def validate_credentials(entry):
    try:
        result = {name: str(uuid.UUID(entry[name])) for name in ("tenantId", "clientId")}
        secret = entry["clientSecret"]
        if not isinstance(secret, str) or not secret.strip() or len(secret) > 4096 or any(ord(char) < 32 for char in secret):
            raise ValueError("secret")
        result["clientSecret"] = secret
        return result
    except (ValueError, KeyError, TypeError, AttributeError):
        raise IntuneError("Gueltige Microsoft-Tenant-ID, App-ID und den Secret-Wert angeben (nicht die Secret-ID).") from None


def load_config(tenant_id):
    filename = os.environ.get("ISMS_INTUNE_CONFIG_FILE", "")
    if not filename:
        filename = Path(os.environ.get("ISMS_DATA_DIR", Path(__file__).parent / "data")) / "intune-config.json"
        if not filename.exists():
            return None
    try:
        path = Path(filename)
        if path.stat().st_mode & 0o077:
            raise ValueError("permissions")
        raw = json.loads(path.read_text(encoding="utf-8"))
        entry = raw.get(tenant_id)
        if entry is None:
            return None
        config = {
            "tenantId": str(uuid.UUID(entry["tenantId"])),
            "clientId": str(uuid.UUID(entry["clientId"])),
            "clientSecret": entry["clientSecret"],
        }
        if not isinstance(config["clientSecret"], str) or not config["clientSecret"].strip():
            raise ValueError("secret")
        config["key"] = hashlib.sha256(
            f"{tenant_id}:{config['tenantId']}:{config['clientId']}".encode()
        ).hexdigest()
        return config
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise IntuneError("Intune-Konfiguration ungueltig. Datei und Rechte (0600) serverseitig pruefen.") from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(request, opener=None):
    opener = opener or urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=20) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise IntuneError("Microsoft-Antwort zu gross. Import wurde nicht uebernommen.", 502)
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError("object required")
        return result
    except urllib.error.HTTPError as error:
        # Do not expose OAuth error bodies, request URLs, tokens or customer data.
        retry = error.headers.get("Retry-After", "60")
        error.close()
        retry = min(3600, max(30, int(retry))) if str(retry).isdigit() else 60
        if error.code in (429, 502, 503, 504):
            raise IntuneError("Microsoft ist voruebergehend nicht erreichbar oder begrenzt Anfragen.", 503, retry) from None
        if error.code in (400, 401, 403):
            raise IntuneError("Microsoft-Zugriff abgelehnt. App-Zugang, Adminfreigabe und Intune-Lizenz pruefen.", 502) from None
        raise IntuneError("Microsoft-Anfrage fehlgeschlagen. Es wurden keine Daten uebernommen.", 502) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise IntuneError("Microsoft-Verbindung unterbrochen. Letzter Datenstand bleibt erhalten.", 503, 60) from None
    except (ValueError, TypeError):
        raise IntuneError("Ungueltige Microsoft-Antwort. Import wurde nicht uebernommen.", 502) from None


def normalize_device(item):
    if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"] or len(item["id"]) > 200:
        raise IntuneError("Intune liefert ein Geraet ohne gueltige ID. Import abgebrochen.", 502)
    result = {}
    for key in FIELDS:
        value = item.get(key)
        if key == "isEncrypted":
            result[key] = value if isinstance(value, bool) else None
        else:
            if value is not None and not isinstance(value, str):
                raise IntuneError("Unerwartetes Intune-Datenformat. Import abgebrochen.", 502)
            result[key] = (value or "")[:500]
    return result


def fetch_devices(config, requester=request_json):
    token = requester(urllib.request.Request(
        f"https://login.microsoftonline.com/{config['tenantId']}/oauth2/v2.0/token",
        data=urllib.parse.urlencode({
            "client_id": config["clientId"], "client_secret": config["clientSecret"],
            "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials",
        }).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST",
    )).get("access_token")
    if not isinstance(token, str) or not token or "\n" in token or "\r" in token:
        raise IntuneError("Microsoft hat kein gueltiges Zugriffstoken geliefert.", 502)
    url = f"https://graph.microsoft.com{GRAPH_PATH}?" + urllib.parse.urlencode({"$select": ",".join(FIELDS), "$top": "100"})
    devices, visited = {}, set()
    started = time.monotonic()
    while url:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "graph.microsoft.com" or parsed.path != GRAPH_PATH or parsed.fragment:
            raise IntuneError("Unsichere Microsoft-Folgeseite abgelehnt.", 502)
        if url in visited or len(visited) >= 100 or time.monotonic() - started > 180:
            raise IntuneError("Intune-Importlimit erreicht. Kein Teilimport wurde gespeichert.", 502)
        visited.add(url)
        page = requester(urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}))
        if not isinstance(page.get("value"), list):
            raise IntuneError("Unvollstaendige Microsoft-Geraeteliste.", 502)
        for item in page["value"]:
            device = normalize_device(item)
            devices[device["id"]] = device
        if len(devices) > MAX_DEVICES:
            raise IntuneError("Pilotlimit von 5000 Geraeten erreicht. Import nicht gespeichert.", 502)
        url = page.get("@odata.nextLink")
        if url is not None and not isinstance(url, str):
            raise IntuneError("Ungueltige Microsoft-Folgeseite.", 502)
    return list(devices.values())


def merge_inventory(assets, devices, tenant_id, config, timestamp):
    """Only source-owned metadata is refreshed; human assessments remain untouched."""
    proposed = json.loads(json.dumps(assets))
    by_id = {item.get("id"): item for item in proposed}
    counts = {"new": 0, "updated": 0, "unchanged": 0, "missing": 0}
    preview, seen = [], set()
    for device in devices:
        asset_id = "intune-" + uuid.uuid5(uuid.NAMESPACE_URL, f"{tenant_id}:{config['tenantId']}:{device['id']}").hex
        seen.add(asset_id)
        current = by_id.get(asset_id)
        old_source = (current or {}).get("intune") or {}
        if current and old_source.get("tenantId") != config["tenantId"]:
            raise IntuneError("Asset-ID-Konflikt. Vorhandenen Eintrag manuell pruefen.", 409)
        action = "new" if current is None else "unchanged" if old_source.get("device") == device and not old_source.get("missingSince") else "updated"
        counts[action] += 1
        preview.append({"action": action, "assetId": asset_id, "device": device})
        if current is None:
            current = {"id": asset_id, "name": device["deviceName"] or "Intune-Geraet", "type": "Endgeraet", "owner": "", "criticality": "", "protection": "", "framework": "Pruefen", "status": "Nicht gestartet", "evidence": ""}
            proposed.append(current)
            by_id[asset_id] = current
        current["intune"] = {"tenantId": config["tenantId"], "device": device, "syncedAt": timestamp, "missingSince": None}
    for asset in proposed:
        source = asset.get("intune") or {}
        if source.get("tenantId") == config["tenantId"] and asset["id"] not in seen:
            counts["missing"] += 1
            source["missingSince"] = source.get("missingSince") or timestamp
            preview.append({"action": "missing", "assetId": asset["id"], "device": source.get("device") or {}})
    return proposed, counts, preview
