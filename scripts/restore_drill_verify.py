#!/usr/bin/env python3
import argparse
import hashlib
import http.cookiejar
import json
import os
import urllib.request


class Client:
    def __init__(self, base_url, password):
        self.base_url = base_url.rstrip("/")
        self.password = password
        self.csrf = ""
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def request(self, method, path, payload=None, csrf=False):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if csrf and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        with self.opener.open(request, timeout=30) as response:
            raw = response.read()
            if "application/json" in (response.headers.get("Content-Type") or ""):
                return json.loads(raw.decode("utf-8"))
            return raw

    def login(self):
        response = self.request("POST", "/api/auth/login", {"username": "admin", "password": self.password})
        self.csrf = response.get("csrfToken") or ""
        if not self.csrf:
            raise RuntimeError("login did not return a CSRF token")


def state_digest(payload):
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Compare a source instance with an isolated restored instance.")
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--restore-url", required=True)
    parser.add_argument("--backup-name", required=True)
    parser.add_argument("--password", default=os.environ.get("ISMS_ADMIN_PASSWORD", ""))
    parser.add_argument("--max-downloads", type=int, default=10)
    args = parser.parse_args()
    if not args.password:
        raise SystemExit("ISMS_ADMIN_PASSWORD or --password is required")

    source = Client(args.source_url, args.password)
    restored = Client(args.restore_url, args.password)
    source.login()
    restored.login()

    source_health = source.request("GET", "/api/health")
    restore_health = restored.request("GET", "/api/health")
    source_state = source.request("GET", "/api/state")
    restore_state = restored.request("GET", "/api/state")
    source_files = source.request("GET", "/api/files").get("files") or []
    restore_files = restored.request("GET", "/api/files").get("files") or []

    if state_digest(source_state.get("state")) != state_digest(restore_state.get("state")):
        raise RuntimeError("restored workspace state differs from the source")
    source_index = {item["id"]: item for item in source_files}
    restore_index = {item["id"]: item for item in restore_files}
    if set(source_index) != set(restore_index):
        raise RuntimeError("restored file metadata differs from the source")
    for file_id in source_index:
        if source_index[file_id].get("sha256") != restore_index[file_id].get("sha256"):
            raise RuntimeError(f"restored checksum metadata differs for {file_id}")

    verified_downloads = 0
    for file_id in sorted(restore_index)[:max(0, args.max_downloads)]:
        content = restored.request("GET", f"/api/files/{file_id}/download")
        if hashlib.sha256(content).hexdigest() != restore_index[file_id].get("sha256"):
            raise RuntimeError(f"restored download checksum differs for {file_id}")
        verified_downloads += 1

    integrity = restored.request("GET", "/api/audit-log/integrity")
    if not integrity.get("valid"):
        raise RuntimeError("restored audit hash chain is invalid")
    if restore_health.get("database") != "postgres" or restore_health.get("storage") != "s3":
        raise RuntimeError(f"unexpected restored runtime: {restore_health}")

    result = {
        "ok": True,
        "sourceDatabase": source_health.get("database"),
        "restoredDatabase": restore_health.get("database"),
        "restoredStorage": restore_health.get("storage"),
        "workspaceRevision": restore_state.get("revision"),
        "files": len(restore_files),
        "downloadsVerified": verified_downloads,
        "auditEventsChecked": integrity.get("checkedEvents"),
        "auditIntegrity": True,
        "stateMatches": True,
        "fileMetadataMatches": True,
    }
    record = source.request("POST", "/api/restore-drills", {
        "backupName": args.backup_name,
        **result,
    }, csrf=True)
    result["auditRecordedAt"] = record.get("recordedAt")
    result["technicalVerificationOnly"] = bool(record.get("technicalVerificationOnly"))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
