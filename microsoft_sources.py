"""Read-only, explicitly scoped Microsoft document and incident sources."""

import datetime as dt
import json
import re
import time
import urllib.parse
import urllib.request
import uuid

from intune_connector import IntuneError, request_json, validate_credentials


PROVIDERS = {
    "sharepoint": {"name": "SharePoint", "collection": "documents"},
    "onedrive": {"name": "OneDrive for Business", "collection": "documents"},
    "defender": {"name": "Microsoft Defender", "collection": "incidents"},
}
JOB_TYPES = {f"ms_{provider}_{action}" for provider in PROVIDERS for action in ("preview", "sync")}
MAX_ITEMS = 2000
MAX_PAGES = 200
ID = re.compile(r"[A-Za-z0-9_!-]{1,256}\Z")


def source_config(provider, payload):
    if provider not in PROVIDERS:
        raise IntuneError("Unbekannte Microsoft-Quelle.", 404)
    config = validate_credentials(payload)
    if provider == "defender":
        days = payload.get("days", 30)
        if type(days) is not int or days not in (7, 30, 90):
            raise IntuneError("Defender-Zeitraum muss 7, 30 oder 90 Tage sein.")
        config["days"] = days
    else:
        for name in ("driveId", "folderId"):
            value = payload.get(name)
            if not isinstance(value, str) or not ID.fullmatch(value):
                raise IntuneError("Drive-ID und Ordner-ID angeben. Fuer die Bibliothekswurzel: root.")
            config[name] = value
    return config


def source_url(value, provider):
    if not value:
        return ""
    if not isinstance(value, str) or len(value) > 4096:
        raise IntuneError("Ungueltiger Microsoft-Quellenlink.", 502)
    try:
        url = urllib.parse.urlsplit(value)
        host = url.hostname or ""
        allowed = host == "security.microsoft.com" if provider == "defender" else host.endswith(".sharepoint.com")
        if url.scheme != "https" or not allowed or url.username or url.password or url.port not in (None, 443):
            raise ValueError("host")
    except ValueError:
        raise IntuneError("Unsicherer Microsoft-Quellenlink abgelehnt.", 502) from None
    return value


def text_field(item, name, limit=1000):
    value = item.get(name) or ""
    if not isinstance(value, str) or len(value) > limit:
        raise IntuneError("Ungueltige Microsoft-Metadaten. Kein Teilimport.", 502)
    return value


def normalize_record(provider, item, config):
    if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"] or len(item["id"]) > 256:
        raise IntuneError("Microsoft-Eintrag ohne gueltige ID.", 502)
    if provider == "defender":
        if item.get("tenantId") and str(item["tenantId"]).lower() != config["tenantId"]:
            raise IntuneError("Microsoft-Mandant stimmt nicht mit der Konfiguration ueberein.", 502)
        return {"id": item["id"], "name": text_field(item, "displayName"), "modifiedAt": text_field(item, "lastUpdateDateTime"), "createdAt": text_field(item, "createdDateTime"), "severity": text_field(item, "severity"), "status": text_field(item, "status"), "webUrl": source_url(item.get("incidentWebUrl"), provider)}
    size = item.get("size", 0)
    if type(size) is not int or size < 0:
        raise IntuneError("Ungueltige Dateigroesse.", 502)
    return {"id": item["id"], "name": text_field(item, "name"), "modifiedAt": text_field(item, "lastModifiedDateTime"), "version": text_field(item, "eTag"), "size": size, "webUrl": source_url(item.get("webUrl"), provider)}


def fetch_records(provider, config, requester=request_json):
    started = time.monotonic()
    def request(req):
        if time.monotonic() - started > 180:
            raise IntuneError("Microsoft-Abruflimit erreicht. Kein Teilimport.", 502)
        try:
            return requester(req)
        except IntuneError as exc:
            raise IntuneError("Microsoft-Abruf fehlgeschlagen. App-Zugang, Lesefreigabe, Lizenz und Erreichbarkeit pruefen.", exc.status, exc.retry_after) from None

    token = request(urllib.request.Request(
        f"https://login.microsoftonline.com/{config['tenantId']}/oauth2/v2.0/token",
        data=urllib.parse.urlencode({"client_id": config["clientId"], "client_secret": config["clientSecret"], "grant_type": "client_credentials", "scope": "https://graph.microsoft.com/.default"}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST",
    )).get("access_token")
    if not isinstance(token, str) or not token or "\r" in token or "\n" in token:
        raise IntuneError("Kein gueltiges Microsoft-Zugriffstoken.", 502)
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    visited, records = set(), {}
    def pages(path, query):
        url = "https://graph.microsoft.com" + path + "?" + urllib.parse.urlencode(query)
        while url:
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme != "https" or parsed.netloc != "graph.microsoft.com" or parsed.path != path or parsed.fragment:
                raise IntuneError("Unsichere Microsoft-Folgeseite abgelehnt.", 502)
            if url in visited or len(visited) >= MAX_PAGES:
                raise IntuneError("Microsoft-Seitenlimit erreicht. Kein Teilimport.", 502)
            visited.add(url)
            page = request(urllib.request.Request(url, headers=headers))
            if not isinstance(page.get("value"), list):
                raise IntuneError("Unvollstaendige Microsoft-Antwort.", 502)
            yield from page["value"]
            url = page.get("@odata.nextLink")
            if url is not None and not isinstance(url, str):
                raise IntuneError("Ungueltige Microsoft-Folgeseite.", 502)

    if provider == "defender":
        since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=config["days"])).strftime("%Y-%m-%dT%H:%M:%SZ")
        for item in pages("/v1.0/security/incidents", {"$top": "100", "$filter": f"lastUpdateDateTime ge {since}"}):
            record = normalize_record(provider, item, config)
            records[record["id"]] = record
            if len(records) > MAX_ITEMS:
                raise IntuneError("Pilotlimit: maximal 2000 Eintraege. Zeitraum eingrenzen.", 502)
    else:
        # Walk only the configured folder. Never follow remoteItem shortcuts into another drive.
        folders, seen_folders, total = [config["folderId"]], set(), 0
        while folders:
            folder = folders.pop()
            if folder in seen_folders:
                raise IntuneError("Zyklische Microsoft-Ordnerstruktur.", 502)
            seen_folders.add(folder)
            root = "root" if folder == "root" else "items/" + urllib.parse.quote(folder, safe="")
            path = f"/v1.0/drives/{urllib.parse.quote(config['driveId'], safe='')}/{root}/children"
            fields = "id,name,webUrl,lastModifiedDateTime,eTag,size,file,folder,remoteItem,parentReference,deleted"
            for item in pages(path, {"$top": "100", "$select": fields}):
                total += 1
                if total > MAX_ITEMS:
                    raise IntuneError("Pilotlimit: maximal 2000 Dateien und Ordner. Ordner eingrenzen.", 502)
                if not isinstance(item, dict):
                    raise IntuneError("Ungueltiger Ordnerinhalt.", 502)
                if "remoteItem" in item or "deleted" in item:
                    continue
                parent = item.get("parentReference") or {}
                if parent.get("driveId") and parent["driveId"] != config["driveId"]:
                    raise IntuneError("Datei ausserhalb der ausgewaehlten Bibliothek.", 502)
                if "folder" in item:
                    if not isinstance(item.get("id"), str) or not ID.fullmatch(item["id"]):
                        raise IntuneError("Ungueltige Ordner-ID.", 502)
                    folders.append(item["id"])
                elif "file" in item:
                    record = normalize_record(provider, item, config)
                    records[record["id"]] = record
    return list(records.values())


def merge_records(existing, records, tenant, provider, config, timestamp):
    output = json.loads(json.dumps(existing))
    by_id = {item.get("id"): item for item in output}
    counts = {"new": 0, "updated": 0, "unchanged": 0, "missing": 0}
    changes, seen = [], set()
    source_scope = config.get("driveId", "incidents")
    for record in records:
        identity = f"{tenant}:{provider}:{config['tenantId']}:{source_scope}:{record['id']}"
        record_id = "ms-" + uuid.uuid5(uuid.NAMESPACE_URL, identity).hex
        seen.add(record_id)
        current = by_id.get(record_id)
        previous = (current or {}).get("microsoftSource") or {}
        if current and (previous.get("provider") != provider or previous.get("tenantId") != config["tenantId"]):
            raise IntuneError("Quellen-ID kollidiert mit einem bestehenden Registereintrag.", 409)
        action = "new" if not current else "updated" if previous.get("record") != record or previous.get("missingSince") else "unchanged"
        if current is None:
            if provider == "defender":
                current = {"id": record_id, "title": record["name"] or "Microsoft-Sicherheitsvorfall", "status": "Offen", "severity": {"high": "Hoch", "medium": "Mittel", "low": "Niedrig"}.get(record.get("severity"), "Zu pruefen"), "detected": record.get("createdAt", "")[:10], "owner": "", "framework": "Pruefen", "evidence": "", "note": "Microsoft-Quellenmeldung; fachliche Bewertung ausstehend."}
            else:
                current = {"id": record_id, "name": record["name"] or "Microsoft-Dokumentverweis", "area": PROVIDERS[provider]["name"], "status": "Entwurf", "approval": "Nicht gestartet", "owner": "", "review": "", "version": "", "classification": "Intern", "linkedTo": "", "evidenceFor": "", "note": "Externer Dokumentverweis. Keine lokale Datei und kein archivierter Versionsnachweis."}
            output.append(current)
        current["microsoftSource"] = {"provider": provider, "tenantId": config["tenantId"], "scope": source_scope, "folderId": config.get("folderId", ""), "record": record, "syncedAt": timestamp, "missingSince": None}
        counts[action] += 1
        changes.append({"action": action, "record": record})
    if provider != "defender":
        for current in output:
            source = current.get("microsoftSource") or {}
            if current.get("id") not in seen and source.get("provider") == provider and source.get("tenantId") == config["tenantId"] and source.get("scope") == source_scope and source.get("folderId") == config["folderId"]:
                source["missingSince"] = source.get("missingSince") or timestamp
                counts["missing"] += 1
                changes.append({"action": "missing", "record": source["record"]})
    # Defender's time window is not a complete inventory: absence never closes a local incident.
    return output, counts, changes
